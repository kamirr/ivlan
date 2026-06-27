mod ip_util;

use std::{
    collections::BTreeMap,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use clap::Parser;
use dashmap::DashMap;
use etherparse::{ArpOperation, NetSlice, SlicedPacket};
use futures::StreamExt as _;
use iroh::endpoint::{RecvStream, SendStream};
use ivlan_rpc::{IpAddrs, IvLanService, RemoteId};
use tarpc::{
    server::{Channel as _, incoming::Incoming as _},
    tokio_serde::formats::Json,
};
use tokio::{
    io::AsyncReadExt as _,
    sync::{Mutex, mpsc},
    task::AbortHandle,
    time::{Duration, sleep},
};
use tun_rs::{AsyncDevice, DeviceBuilder};

const MAX_QUEUE_BYTES: usize = 1 << 20;

type OutboundMessage = Vec<u8>;

struct Peer {
    addrs: IpAddrs,
    send: Arc<Mutex<Option<SendStream>>>,
    queue_tx: mpsc::UnboundedSender<OutboundMessage>,
    queue_size: Arc<AtomicUsize>,
    rx_task: Option<AbortHandle>,
}

struct IvLanStateInner {
    running: Mutex<bool>,
    dev: Arc<AsyncDevice>,
    endpoint: OnceLock<Arc<iroh::Endpoint>>,
    peers: DashMap<RemoteId, Peer, fxhash::FxBuildHasher>,
    addrs: IpAddrs,
    ipv4mask: u8,
    ipv6mask: u8,
}

impl IvLanStateInner {
    async fn insert_peer(
        self: Arc<Self>,
        remote: RemoteId,
        txrx: Option<(SendStream, RecvStream)>,
    ) -> anyhow::Result<IpAddrs> {
        if let Some(mut peer) = self.peers.get_mut(&remote) {
            if let Some((tx, rx)) = txrx {
                if let Some(prev) = peer.rx_task.take() {
                    prev.abort();
                }

                let mut send_guard = peer.send.lock().await;
                *send_guard = Some(tx);
                drop(send_guard);
                peer.rx_task = Some(self.start_recv_task(remote, rx, peer.addrs));
            }
            return Ok(peer.addrs);
        }

        let (queue_tx, queue_rx) = mpsc::unbounded_channel();
        let queue_size = Arc::new(AtomicUsize::new(0));
        let send = Arc::new(Mutex::new(None));
        self.clone()
            .start_send_task(remote, send.clone(), queue_rx, queue_size.clone());

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
        let rx_task = if let Some((tx, rx)) = txrx {
            let mut send_guard = send.lock().await;
            *send_guard = Some(tx);
            Some(self.start_recv_task(remote, rx, addrs))
        } else {
            None
        };

        self.peers.insert(
            remote,
            Peer {
                addrs,
                send,
                queue_tx,
                queue_size,
                rx_task,
            },
        );
        Ok(addrs)
    }

    fn start_send_task(
        self: Arc<Self>,
        remote: RemoteId,
        send: Arc<Mutex<Option<SendStream>>>,
        mut queue_rx: mpsc::UnboundedReceiver<OutboundMessage>,
        queue_size: Arc<AtomicUsize>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = queue_rx.recv().await {
                loop {
                    let mut send_guard = send.lock().await;
                    if send_guard.is_none() {
                        drop(send_guard);
                        log::debug!("No send stream for peer {}, attempting connect", remote);
                        if let Err(e) = self.clone().ensure_send_stream(remote).await {
                            log::warn!("Failed to establish send stream for {}: {}", remote, e);
                            sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                        continue;
                    }

                    let result = send_guard.as_mut().unwrap().write_all(&msg).await;
                    match result {
                        Ok(()) => {
                            queue_size.fetch_sub(msg.len(), Ordering::AcqRel);
                            break;
                        }
                        Err(e) => {
                            log::warn!("Send failure for {}: {}", remote, e);
                            *send_guard = None;
                            drop(send_guard);
                            sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    }
                }
            }
        });
    }

    fn start_recv_task(
        &self,
        remote: RemoteId,
        rx: RecvStream,
        peer_addrs: IpAddrs,
    ) -> AbortHandle {
        let host_addrs = self.addrs;
        let mut buf = vec![0; 65536];
        let mut rx = rx;
        let dev = Arc::clone(&self.dev);

        tokio::spawn(async move {
            loop {
                let len = rx.read_u16_le().await.unwrap() as usize;
                rx.read_exact(&mut buf[..len]).await.unwrap();

                let patch = match ip_util::patch_packet_addresses(
                    &mut buf[..len],
                    peer_addrs,
                    host_addrs,
                ) {
                    Ok(patch) => patch,
                    Err(e) => {
                        log::warn!("IV recv src={remote}, payload={len} | BAD PACKET | {e}");
                        if len == 0 {
                            panic!();
                        }
                        continue;
                    }
                };

                if let Some((src, dst)) = patch {
                    let txd = dev.send(&buf[..len]).await.unwrap();
                    log::trace!(
                        "IV recv src={remote}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                    );
                } else {
                    log::debug!("IV recv src={remote}, payload={len} | SKIP");
                }
            }
        }).abort_handle()
    }

    async fn ensure_send_stream(self: Arc<Self>, remote: RemoteId) -> anyhow::Result<()> {
        let endpoint = self
            .endpoint
            .get()
            .ok_or_else(|| anyhow::anyhow!("Endpoint not initialized"))?
            .clone();

        let pk: iroh::PublicKey = remote.into();
        let conn = endpoint.connect(pk, b"ivlan/1.0").await?;
        let txrx = conn.open_bi().await?;
        self.clone().insert_peer(remote, Some(txrx)).await?;
        Ok(())
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

            if self.peers.iter().any(|p| p.addrs.v4 == candidate) {
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

            if self.peers.iter().any(|p| p.addrs.v6 == candidate) {
                continue;
            }

            return Some(candidate);
        }

        None
    }
}

#[derive(Clone)]
struct IvLanState {
    inner: Arc<IvLanStateInner>,
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
            inner: Arc::new(IvLanStateInner {
                running: Mutex::new(false),
                dev: Arc::new(dev),
                endpoint: OnceLock::new(),
                peers: DashMap::default(),
                addrs: IpAddrs { v4: ipv4, v6: ipv6 },
                ipv4mask,
                ipv6mask,
            }),
        }
    }

    async fn start_impl(
        self,
        _cx: tarpc::context::Context,
        sk: iroh::SecretKey,
    ) -> anyhow::Result<()> {
        let mut guard = self.inner.running.lock().await;
        if *guard {
            log::error!("Cannot initialize again.");
            return Ok(());
        }

        log::info!("Start IVLAN as {}.", RemoteId::from(sk.public()));

        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![b"ivlan/1.0".to_vec()])
            .secret_key(sk)
            .bind()
            .await?;
        let endpoint = Arc::new(endpoint);

        self.inner.endpoint.set(endpoint.clone()).ok();

        let state = self.inner.clone();
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

                let txrx = match conn.accept_bi().await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("Couldn't accept bidirectional: {}", e);
                        continue;
                    }
                };

                let remote = conn.remote_id().into();
                state.clone().insert_peer(remote, Some(txrx)).await.unwrap();
            }
        });

        let state = self.inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                let len: u16 = state.dev.recv(&mut buf).await.unwrap().try_into().unwrap();

                let Ok(SlicedPacket { net: Some(net), .. }) = SlicedPacket::from_ip(&buf) else {
                    log::warn!("Bad packet received");
                    continue;
                };

                match net {
                    NetSlice::Ipv4(ipv4) => {
                        let dst = ipv4.header().destination_addr();
                        let peer = state.peers.iter_mut().find(|peer| peer.addrs.v4 == dst);

                        if let Some(peer) = peer {
                            let mut msg = Vec::with_capacity(2 + len as usize);
                            msg.extend_from_slice(&len.to_le_bytes());
                            msg.extend_from_slice(&buf[..len as usize]);
                            let msg_len = msg.len();

                            let mut current = peer.queue_size.load(Ordering::Acquire);
                            loop {
                                if current + msg_len > MAX_QUEUE_BYTES {
                                    log::warn!(
                                        "Dropping outbound packet to {}: queue full ({} bytes)",
                                        peer.key(),
                                        current
                                    );
                                    break;
                                }

                                match peer.queue_size.compare_exchange(
                                    current,
                                    current + msg_len,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => {
                                        if peer.queue_tx.send(msg).is_err() {
                                            peer.queue_size.fetch_sub(msg_len, Ordering::AcqRel);
                                            log::warn!(
                                                "Failed to enqueue packet for peer {}",
                                                peer.key()
                                            );
                                        } else {
                                            log::trace!(
                                                "IPv4 src={}, dst={}, payload={}, len={} | QUEUED {}",
                                                ipv4.header().source_addr(),
                                                ipv4.header().destination_addr(),
                                                ipv4.payload().payload.len(),
                                                len,
                                                peer.key()
                                            );
                                        }
                                        break;
                                    }
                                    Err(next) => current = next,
                                }
                            }
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

                        if dst == ip_util::ROUTER_MULTICAST_ADDR {
                            log::trace!(
                                "IPv6 src={}, dst={}, payload={}, len={} | SKIP",
                                ipv6.header().source_addr(),
                                ipv6.header().destination_addr(),
                                ipv6.payload().payload.len(),
                                len
                            );
                            continue;
                        }

                        let peer = state.peers.iter_mut().find(|peer| peer.addrs.v6 == dst);

                        if let Some(peer) = peer {
                            let mut msg = Vec::with_capacity(2 + len as usize);
                            msg.extend_from_slice(&len.to_le_bytes());
                            msg.extend_from_slice(&buf[..len as usize]);
                            let msg_len = msg.len();

                            let mut current = peer.queue_size.load(Ordering::Acquire);
                            loop {
                                if current + msg_len > MAX_QUEUE_BYTES {
                                    log::warn!(
                                        "Dropping outbound packet to {}: queue full ({} bytes)",
                                        peer.key(),
                                        current
                                    );
                                    break;
                                }

                                match peer.queue_size.compare_exchange(
                                    current,
                                    current + msg_len,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => {
                                        if peer.queue_tx.send(msg).is_err() {
                                            peer.queue_size.fetch_sub(msg_len, Ordering::AcqRel);
                                            log::warn!(
                                                "Failed to enqueue packet for peer {}",
                                                peer.key()
                                            );
                                        } else {
                                            log::trace!(
                                                "IPv6 src={}, dst={}, payload={}, len={} | QUEUED {}",
                                                ipv6.header().source_addr(),
                                                ipv6.header().destination_addr(),
                                                ipv6.payload().payload.len(),
                                                len,
                                                peer.key()
                                            );
                                        }
                                        break;
                                    }
                                    Err(next) => current = next,
                                }
                            }
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

        *guard = true;

        Ok(())
    }

    async fn connect_impl(
        self,
        _cx: tarpc::context::Context,
        remote: RemoteId,
    ) -> anyhow::Result<IpAddrs> {
        if let Some(peer) = self.inner.peers.get(&remote) {
            return Ok(peer.addrs);
        }

        let endpoint = self
            .inner
            .endpoint
            .get()
            .ok_or_else(|| anyhow::anyhow!("Endpoint not initialized"))?
            .clone();

        let pk: iroh::PublicKey = remote.into();
        let conn = endpoint.connect(pk, b"ivlan/1.0").await?;
        let txrx = conn.open_bi().await?;

        let peer_addrs = self
            .inner
            .clone()
            .insert_peer(conn.remote_id().into(), Some(txrx))
            .await?;

        Ok(peer_addrs)
    }

    async fn lookup_impl(
        self,
        _cx: tarpc::context::Context,
        remote: RemoteId,
    ) -> anyhow::Result<IpAddrs> {
        if let Some(peer) = self.inner.peers.get(&remote) {
            Ok(peer.addrs)
        } else {
            anyhow::bail!("Peer not connected")
        }
    }

    async fn peers_impl(self, _cx: tarpc::context::Context) -> BTreeMap<RemoteId, IpAddrs> {
        self.inner
            .peers
            .iter()
            .map(|peer| (*peer.key(), peer.addrs))
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
        remote: RemoteId,
    ) -> Result<IpAddrs, String> {
        self.connect_impl(cx, remote)
            .await
            .map_err(|e| e.to_string())
    }

    async fn lookup(
        self,
        cx: tarpc::context::Context,
        remote: RemoteId,
    ) -> Result<IpAddrs, String> {
        self.lookup_impl(cx, remote)
            .await
            .map_err(|e| e.to_string())
    }

    async fn peers(self, cx: tarpc::context::Context) -> BTreeMap<RemoteId, IpAddrs> {
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
