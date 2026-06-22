mod ip_util;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use clap::Parser;
use etherparse::{ArpOperation, NetSlice, SlicedPacket};
use futures::StreamExt as _;
use iroh::{
    PublicKey,
    endpoint::{RecvStream, SendStream},
};
use ivlan_rpc::{IpAddrs, IvLanService};
use tarpc::{
    server::{Channel as _, incoming::Incoming as _},
    tokio_serde::formats::Json,
};
use tokio::{io::AsyncReadExt as _, sync::Mutex};
use tun_rs::{AsyncDevice, DeviceBuilder};

struct Peer {
    addrs: IpAddrs,
    tx: SendStream,
}

struct IvLanStateInner {
    running: bool,
    dev: Arc<AsyncDevice>,
    endpoint: Option<Arc<iroh::Endpoint>>,
    peers: BTreeMap<PublicKey, Peer>,
    addrs: IpAddrs,
    ipv4mask: u8,
    ipv6mask: u8,
}

impl IvLanStateInner {
    fn insert_peer(&mut self, remote: PublicKey, tx: SendStream) -> anyhow::Result<IpAddrs> {
        if let Some(Peer { addrs, .. }) = self.peers.get(&remote) {
            return Ok(*addrs);
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

        let addrs = IpAddrs { v4: ipv4, v6: ipv6 };
        self.peers.insert(remote, Peer { addrs, tx });
        Ok(addrs)
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
            let candidate = Ipv4Addr::from(u32::from(self.addrs.v4) + offset);

            if candidate == self.addrs.v4 {
                continue;
            }

            if self.peers.values().any(|p| p.addrs.v4 == candidate) {
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
            let candidate = Ipv6Addr::from(u128::from(self.addrs.v6) + offset);

            if candidate == self.addrs.v6 {
                continue;
            }

            if self.peers.values().any(|p| p.addrs.v6 == candidate) {
                continue;
            }

            return Some(candidate);
        }

        None
    }

    fn start_rx_stream(&mut self, remote: PublicKey, rx: RecvStream, peer_addrs: IpAddrs) {
        let host_addrs = self.addrs;
        let mut buf = vec![0; 65536];
        let mut rx = rx;
        let dev = Arc::clone(&self.dev);

        tokio::spawn(async move {
            loop {
                let len = rx.read_u16_le().await.unwrap() as usize;
                rx.read_exact(&mut buf[..len]).await.unwrap();

                let patch =
                    ip_util::patch_packet_addresses(&mut buf, len, peer_addrs, host_addrs).unwrap();

                if let Some((src, dst)) = patch {
                    let txd = dev.send(&buf[..len]).await.unwrap();
                    log::trace!(
                        "IV recv/0 src={remote}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                    );
                } else {
                    log::debug!("IV recv/0 src={remote}, payload={len} | SKIP");
                }
            }
        });
    }
}

#[derive(Clone)]
struct IvLanState {
    inner: Arc<Mutex<IvLanStateInner>>,
}

impl IvLanState {
    pub fn new(
        dev: AsyncDevice,
        ipv4: Ipv4Addr,
        ipv4mask: u8,
        ipv6: Ipv6Addr,
        ipv6mask: u8,
    ) -> Self {
        IvLanState {
            inner: Arc::new(Mutex::new(IvLanStateInner {
                running: false,
                dev: Arc::new(dev),
                endpoint: None,
                peers: BTreeMap::new(),
                addrs: IpAddrs { v4: ipv4, v6: ipv6 },
                ipv4mask,
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

                let (tx, rx) = match conn.accept_bi().await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("Couldn't accept bidirectional: {}", e);
                        continue;
                    }
                };

                let remote = conn.remote_id();

                let mut inner = this.inner.lock().await;
                let peer_addrs = inner.insert_peer(remote, tx).unwrap();
                inner.start_rx_stream(remote, rx, peer_addrs);
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
                        let peer = state
                            .peers
                            .iter_mut()
                            .find(|(_, peer)| peer.addrs.v4 == dst);

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

                        let peer = state
                            .peers
                            .iter_mut()
                            .find(|(_, peer)| peer.addrs.v6 == dst);

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
    ) -> anyhow::Result<IpAddrs> {
        let mut state = self.inner.lock().await;
        if let Some(peer) = state.peers.get(&pk) {
            return Ok(peer.addrs);
        }

        // Peer not found, establish a connection via iroh
        let endpoint = state
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Endpoint not initialized"))?
            .clone();

        // Connect to the remote peer
        let conn = endpoint.connect(pk, b"ivlan/1.0").await?;
        let (tx, rx) = conn.open_bi().await?;

        // Allocate addresses and start recv stream
        let peer_addrs = state.insert_peer(conn.remote_id(), tx)?;
        state.start_rx_stream(conn.remote_id(), rx, peer_addrs);

        Ok(peer_addrs)
    }

    async fn lookup_impl(
        self,
        _cx: tarpc::context::Context,
        pk: iroh::PublicKey,
    ) -> anyhow::Result<IpAddrs> {
        let state = self.inner.lock().await;
        if let Some(peer) = state.peers.get(&pk) {
            Ok(peer.addrs)
        } else {
            anyhow::bail!("Peer not connected")
        }
    }

    async fn peers_impl(self, _cx: tarpc::context::Context) -> BTreeMap<iroh::PublicKey, IpAddrs> {
        self.inner
            .lock()
            .await
            .peers
            .iter()
            .map(|(pk, peer)| (*pk, peer.addrs))
            .collect()
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
    ) -> Result<IpAddrs, String> {
        self.connect_impl(cx, pk).await.map_err(|e| e.to_string())
    }

    async fn lookup(
        self,
        cx: tarpc::context::Context,
        pk: iroh::PublicKey,
    ) -> Result<IpAddrs, String> {
        self.lookup_impl(cx, pk).await.map_err(|e| e.to_string())
    }

    async fn peers(self, cx: tarpc::context::Context) -> BTreeMap<iroh::PublicKey, IpAddrs> {
        self.peers_impl(cx).await
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
