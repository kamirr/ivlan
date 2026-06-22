use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use clap::Parser;
use etherparse::{ArpOperation, NetSlice, SlicedPacket};
use futures::StreamExt;
use iroh::{PublicKey, endpoint::SendStream};
use ivlan_rpc::IvLanService;
use tarpc::{
    server::{Channel, incoming::Incoming as _},
    tokio_serde::formats::Json,
};
use tokio::{io::AsyncReadExt, sync::Mutex};
use tun_rs::{AsyncDevice, DeviceBuilder};

struct Peer {
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    tx: SendStream,
}

struct IvLanStateInner {
    running: bool,
    dev: Arc<AsyncDevice>,
    endpoint: Option<Arc<iroh::Endpoint>>,
    peers: BTreeMap<PublicKey, Peer>,
    ipv4addr: Ipv4Addr,
    ipv4mask: u8,
    ipv6addr: Ipv6Addr,
    ipv6mask: u8,
}

impl IvLanStateInner {
    fn insert_peer(
        &mut self,
        remote: PublicKey,
        tx: SendStream,
    ) -> anyhow::Result<(Ipv4Addr, Ipv6Addr)> {
        if let Some(Peer { ipv4, ipv6, .. }) = self.peers.get(&remote) {
            return Ok((*ipv4, *ipv6));
        }

        let ipv4 = match self.allocate_ipv4() {
            Some(addr) => addr,
            None => {
                log::warn!("Could not allocate IPv4 address for peer {}", remote);
                return Err(anyhow::anyhow!("IPv4 allocation failed"));
            }
        };

        let ipv6 = match self.allocate_ipv6() {
            Some(addr) => addr,
            None => {
                log::warn!("Could not allocate IPv6 address for peer {}", remote);
                return Err(anyhow::anyhow!("IPv6 allocation failed"));
            }
        };

        log::debug!(
            "Allocated addresses for peer {}: IPv4={}, IPv6={}",
            remote,
            ipv4,
            ipv6
        );

        self.peers.insert(remote, Peer { ipv4, ipv6, tx });
        Ok((ipv4, ipv6))
    }

    fn allocate_ipv4(&self) -> Option<Ipv4Addr> {
        if self.ipv4mask >= 31 {
            log::warn!(
                "IPv4 mask {} does not permit peer allocation",
                self.ipv4mask
            );
            return None;
        }

        let host_bits = 32 - self.ipv4mask;
        let max_offset = (1u32 << host_bits) - 2; // Reserve broadcast address

        for offset in 1..=max_offset {
            let candidate = Ipv4Addr::from(u32::from(self.ipv4addr) + offset);

            if candidate == self.ipv4addr {
                continue;
            }

            if self.peers.values().any(|p| p.ipv4 == candidate) {
                continue;
            }

            return Some(candidate);
        }

        None
    }

    fn allocate_ipv6(&self) -> Option<Ipv6Addr> {
        if self.ipv6mask >= 127 {
            log::warn!(
                "IPv6 mask {} does not permit peer allocation",
                self.ipv6mask
            );
            return None;
        }

        let host_bits = 128 - self.ipv6mask;
        let max_offset = (1u128 << host_bits) - 2; // Reserve high address

        for offset in 1..=max_offset {
            let candidate = Ipv6Addr::from(u128::from(self.ipv6addr) + offset);

            if candidate == self.ipv6addr {
                continue;
            }

            if self.peers.values().any(|p| p.ipv6 == candidate) {
                continue;
            }

            return Some(candidate);
        }

        None
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += word as u32;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn recalculate_tcp_checksum_ipv4(
    buf: &mut [u8],
    len: usize,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    tcp_start: usize,
) {
    let tcp_len = len - tcp_start;

    // Zero out checksum field
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]);

    // Build pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + tcp_len(2)
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP protocol
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&buf[tcp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv4(
    buf: &mut [u8],
    len: usize,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    udp_start: usize,
) {
    let udp_len = len - udp_start;

    // Zero out checksum field (only if it's non-zero, IPv4 UDP can have 0 checksum)
    let checksum_offset = udp_start + 6;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17); // UDP protocol
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());

    // Save and zero checksum
    let _saved_checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

    pseudo.extend_from_slice(&buf[udp_start..len]);

    let mut checksum = calculate_checksum(&pseudo);
    if checksum == 0 {
        checksum = 0xffff; // For IPv4, 0 means no checksum, so use 0xffff
    }

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_tcp_checksum_ipv6(
    buf: &mut [u8],
    len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    tcp_start: usize,
) {
    let tcp_len = len - tcp_start;

    // Zero out checksum field
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]);

    // Build pseudo-header: src(16) + dst(16) + payload_len(4) + zeros(3) + next_header(1)
    let mut pseudo = Vec::with_capacity(40 + tcp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]); // zeros + TCP protocol
    pseudo.extend_from_slice(&buf[tcp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv6(
    buf: &mut [u8],
    len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    udp_start: usize,
) {
    let udp_len = len - udp_start;
    let checksum_offset = udp_start + 6;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(40 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]); // zeros + UDP protocol

    // Zero checksum
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

    pseudo.extend_from_slice(&buf[udp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn patch_packet_addresses(
    buf: &mut [u8],
    len: usize,
    src_ipv4: Ipv4Addr,
    src_ipv6: Ipv6Addr,
    dst_ipv4: Ipv4Addr,
    dst_ipv6: Ipv6Addr,
) -> anyhow::Result<Option<(IpAddr, IpAddr)>> {
    let Ok(SlicedPacket { net, .. }) = SlicedPacket::from_ip(&buf[..len]) else {
        anyhow::bail!("Bad packet");
    };

    match net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header_len = (ipv4.header().ihl() as usize) * 4;
            let protocol = ipv4.header().protocol().0;

            let src_offset = 12;
            let dst_offset = 16;
            let checksum_offset = 10;

            buf[src_offset..src_offset + 4].copy_from_slice(&src_ipv4.octets());
            buf[dst_offset..dst_offset + 4].copy_from_slice(&dst_ipv4.octets());
            buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

            let mut sum: u32 = 0;
            for i in (0..header_len).step_by(2) {
                let word = u16::from_be_bytes([buf[i], buf[i + 1]]);
                sum += word as u32;
            }
            while (sum >> 16) > 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let checksum = !sum as u16;
            buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

            // Recalculate TCP/UDP checksums if present
            match protocol {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv4(buf, len, src_ipv4, dst_ipv4, header_len);
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv4(buf, len, src_ipv4, dst_ipv4, header_len);
                }
                _ => {}
            }

            Ok(Some((IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4))))
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let src_offset = 8;
            let dst_offset = 24;
            let next_header = ipv6.header().next_header().0;

            buf[src_offset..src_offset + 16].copy_from_slice(&src_ipv6.octets());
            buf[dst_offset..dst_offset + 16].copy_from_slice(&dst_ipv6.octets());

            // Recalculate TCP/UDP checksums if present
            // IPv6 header is always 40 bytes
            let transport_start = 40;
            match next_header {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv6(buf, len, src_ipv6, dst_ipv6, transport_start);
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv6(buf, len, src_ipv6, dst_ipv6, transport_start);
                }
                _ => {}
            }

            Ok(Some((IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6))))
        }
        _ => Ok(None),
    }
}

#[derive(Clone)]
struct IvLanState {
    inner: Arc<Mutex<IvLanStateInner>>,
}

impl IvLanState {
    pub fn new(
        dev: AsyncDevice,
        ipv4addr: Ipv4Addr,
        ipv4mask: u8,
        ipv6addr: Ipv6Addr,
        ipv6mask: u8,
    ) -> Self {
        IvLanState {
            inner: Arc::new(Mutex::new(IvLanStateInner {
                running: false,
                dev: Arc::new(dev),
                endpoint: None,
                peers: BTreeMap::new(),
                ipv4addr,
                ipv4mask,
                ipv6addr,
                ipv6mask,
            })),
        }
    }

    async fn start_impl(
        self,
        _cx: tarpc::context::Context,
        sk: iroh::SecretKey,
    ) -> anyhow::Result<()> {
        let dev = {
            let mut state = self.inner.lock().await;

            if state.running {
                log::error!("Cannot initialize again.");
                return Ok(());
            }

            state.running = true;
            state.dev.clone()
        };

        log::info!("Start IVLAN as {}.", sk.public());

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![b"ivlan/1.0".to_vec()])
            .secret_key(sk)
            .bind()
            .await?;

        {
            let mut state = self.inner.lock().await;
            state.endpoint = Some(Arc::new(endpoint.clone()));
        }

        let this = self.clone();
        let dev_ = Arc::clone(&dev);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let accepting = match incoming.accept() {
                    Ok(a) => a,
                    Err(e) => {
                        log::warn!("Couldn't accept connection: {}", e);
                        continue;
                    }
                };
                let conn = match accepting.await {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("Couldn't accept connection: {}", e);
                        continue;
                    }
                };

                let (tx, mut rx) = match conn.accept_bi().await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("Couldn't accept bidirectional: {}", e);
                        continue;
                    }
                };

                let remote = conn.remote_id();
                this.inner.lock().await.insert_peer(remote, tx).unwrap();

                let this_inner = Arc::clone(&this.inner);
                let mut buf = vec![0; 65536];
                let dev_ = Arc::clone(&dev_);
                tokio::spawn(async move {
                    loop {
                        let len = rx.read_u16_le().await.unwrap() as usize;
                        rx.read_exact(&mut buf[..len]).await.unwrap();

                        let state = this_inner.lock().await;
                        if let Some(peer) = state.peers.get(&remote) {
                            let patch = patch_packet_addresses(
                                &mut buf,
                                len,
                                peer.ipv4,
                                peer.ipv6,
                                state.ipv4addr,
                                state.ipv6addr,
                            )
                            .unwrap();

                            if let Some((src, dst)) = patch {
                                let txd = dev_.send(&buf[..len]).await.unwrap();
                                log::trace!(
                                    "IV recv/0 src={remote}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                                );
                            } else {
                                log::debug!("IV recv/0 src={remote}, payload={len} | SKIP");
                            }
                        } else {
                            log::warn!("IV recv/0 src={remote}, payload={len} | PEER NOT FOUND");
                        }
                    }
                });
            }
        });

        let this = self;
        tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                let len = dev.recv(&mut buf).await.unwrap() as u16;

                let Ok(SlicedPacket { net: Some(net), .. }) = SlicedPacket::from_ip(&buf) else {
                    log::warn!("Bad packet received");
                    continue;
                };

                let mut state = this.inner.lock().await;

                match net {
                    NetSlice::Ipv4(ipv4) => {
                        let dst = ipv4.header().destination_addr();
                        let peer = state.peers.iter_mut().find(|(_, peer)| peer.ipv4 == dst);

                        if let Some((remote, peer)) = peer {
                            peer.tx.write(&len.to_le_bytes()).await.unwrap();
                            peer.tx.write_all(&buf[..len as usize]).await.unwrap();

                            log::trace!(
                                "IPv4 src={}, dst={}, payload={}, len={} | TX {}",
                                ipv4.header().source_addr(),
                                ipv4.header().destination_addr(),
                                ipv4.payload().payload.len(),
                                len,
                                remote
                            )
                        } else {
                            log::debug!(
                                "IPv4 src={}, dst={}, payload={}, len={} | NO PEER",
                                ipv4.header().source_addr(),
                                ipv4.header().destination_addr(),
                                ipv4.payload().payload.len(),
                                len
                            )
                        }
                    }
                    NetSlice::Ipv6(ipv6) => {
                        let dst = ipv6.header().destination_addr();

                        if dst == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002) {
                            log::trace!(
                                "IPv6 src={}, dst={}, payload={}, len={} | SKIP",
                                ipv6.header().source_addr(),
                                ipv6.header().destination_addr(),
                                ipv6.payload().payload.len(),
                                len
                            );
                            continue;
                        }

                        let peer = state.peers.iter_mut().find(|(_, peer)| peer.ipv6 == dst);

                        if let Some((remote, peer)) = peer {
                            peer.tx.write(&len.to_le_bytes()).await.unwrap();
                            peer.tx.write_all(&buf[..len as usize]).await.unwrap();

                            log::trace!(
                                "IPv6 src={}, dst={}, payload={}, len={} | TX {remote}",
                                ipv6.header().source_addr(),
                                ipv6.header().destination_addr(),
                                ipv6.payload().payload.len(),
                                len
                            )
                        } else {
                            log::debug!(
                                "IPv6 src={}, dst={}, payload={}, len={} | NO PEER",
                                ipv6.header().source_addr(),
                                ipv6.header().destination_addr(),
                                ipv6.payload().payload.len(),
                                len
                            )
                        }
                    }
                    NetSlice::Arp(arp) => {
                        log::trace!(
                            "ARP op={} | SKIP",
                            match arp.operation() {
                                ArpOperation::REQUEST => "request",
                                ArpOperation::REPLY => "reply",
                                _ => "?",
                            }
                        )
                    }
                }
            }
        });

        Ok(())
    }

    async fn connect_impl(
        self,
        _cx: tarpc::context::Context,
        pk: iroh::PublicKey,
    ) -> anyhow::Result<(Ipv4Addr, Ipv6Addr)> {
        {
            let state = self.inner.lock().await;
            if let Some(peer) = state.peers.get(&pk) {
                return Ok((peer.ipv4, peer.ipv6));
            }
        }

        // Peer not found, establish a connection via iroh
        let (endpoint, dev) = {
            let state = self.inner.lock().await;
            let endpoint = state
                .endpoint
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Endpoint not initialized"))?
                .clone();
            let dev = state.dev.clone();

            (endpoint, dev)
        };

        // Connect to the remote peer
        let conn = endpoint.connect(pk, b"ivlan/1.0").await?;
        let (tx, mut rx) = conn.open_bi().await?;

        // Allocate addresses and store peer
        let (peer_ipv4, peer_ipv6) = self.inner.lock().await.insert_peer(conn.remote_id(), tx)?;

        // Spawn task to handle incoming messages from this peer
        let host_ipv4 = self.inner.lock().await.ipv4addr;
        let host_ipv6 = self.inner.lock().await.ipv6addr;

        tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                match rx.read_u16_le().await {
                    Ok(len) => {
                        let len = len as usize;
                        if rx.read_exact(&mut buf[..len]).await.is_err() {
                            log::debug!("Peer {} closed connection", pk);
                            break;
                        }

                        let patch = patch_packet_addresses(
                            &mut buf[..len],
                            len,
                            peer_ipv4,
                            peer_ipv6,
                            host_ipv4,
                            host_ipv6,
                        )
                        .unwrap();

                        if let Some((src, dst)) = patch {
                            let txd = dev.send(&buf[..len]).await.unwrap();
                            log::trace!(
                                "IV recv/1 src={pk}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                            );
                        } else {
                            log::debug!("IV recv/1 src={pk}, payload={len} | SKIP");
                        }
                    }
                    Err(_) => {
                        log::debug!("Peer {} closed connection", pk);
                        break;
                    }
                }
            }
        });

        Ok((peer_ipv4, peer_ipv6))
    }
}

impl IvLanService for IvLanState {
    async fn start(self, cx: tarpc::context::Context, sk: iroh::SecretKey) -> Result<(), String> {
        self.start_impl(cx, sk).await.map_err(|e| e.to_string())
    }

    async fn connect(
        self,
        cx: tarpc::context::Context,
        pk: iroh::PublicKey,
    ) -> Result<(Ipv4Addr, Ipv6Addr), String> {
        self.connect_impl(cx, pk).await.map_err(|e| e.to_string())
    }
}

#[derive(clap::Parser)]
struct Args {
    #[arg(env = "IV_IF_NAME", default_value = "iv")]
    if_name: String,

    #[clap(long, env = "IV_RPC_ADDR", default_value = "127.0.0.1:2334")]
    rpc_addr: SocketAddr,

    #[arg(long, env = "IV_MTU", default_value_t = 1500)]
    mtu: u16,

    #[arg(long, env = "IV_IP4_ADDR", default_value = "121.37.0.0")]
    ip4: Ipv4Addr,
    #[arg(long, env = "IV_IP4_MASK", default_value_t = 24)]
    ip4mask: u8,

    #[arg(long, env = "IV_IP6_ADDR", default_value = "fd00::1")]
    ip6: Ipv6Addr,
    #[arg(long, env = "IV_IP6_MASK", default_value_t = 64)]
    ip6mask: u8,
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();
    let args = Args::parse();

    let builder = DeviceBuilder::new()
        .name(args.if_name)
        .mtu(args.mtu)
        .ipv4(args.ip4, args.ip4mask, None)
        .ipv6(args.ip6, args.ip6mask);

    let dev = builder.build_async()?;
    let state = IvLanState::new(dev, args.ip4, args.ip4mask, args.ip6, args.ip6mask);

    // JSON transport is provided by the json_transport tarpc module. It makes it easy
    // to start up a serde-powered json serialization strategy over TCP.
    let mut listener = tarpc::serde_transport::tcp::listen(args.rpc_addr, Json::default).await?;
    log::info!("Listening on port {}", listener.local_addr().port());

    listener.config_mut().max_frame_length(usize::MAX);
    listener
        .filter_map(|r| futures::future::ready(r.ok()))
        .map(tarpc::server::BaseChannel::with_defaults)
        .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
        .map(|channel| {
            let server = state.clone();
            channel.execute(server.serve()).for_each(spawn)
        })
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    Ok(())
}
