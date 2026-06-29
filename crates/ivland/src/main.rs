mod auth;
mod ip_util;

use std::{
    collections::BTreeMap,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock},
};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use dashmap::DashMap;
use etherparse::{ArpOperation, NetSlice, SlicedPacket};
use futures::StreamExt as _;
use iroh::endpoint::{Connection, RecvStream, SendDatagramError, SendStream};
use ivlan_rpc::{Auth, IpAddrs, IvLanService, RemoteId};
use tarpc::{
    server::{Channel as _, incoming::Incoming as _},
    tokio_serde::formats::Json,
};
use tokio::{
    io::AsyncReadExt as _,
    sync::{
        Mutex,
        mpsc::{self, error::TrySendError},
        oneshot,
    },
    task::AbortHandle,
    time::{Duration, sleep},
};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::auth::AuthResp;

type OutboundMessage = Vec<u8>;

struct AbortRecv {
    stream_ah: AbortHandle,
    datagram_ah: AbortHandle,
}

impl AbortRecv {
    pub fn new(stream_ah: AbortHandle, datagram_ah: AbortHandle) -> Self {
        AbortRecv {
            stream_ah,
            datagram_ah,
        }
    }

    pub fn abort(&self) {
        self.stream_ah.abort();
        self.datagram_ah.abort();
    }
}

struct PeerRx {
    stream: RecvStream,
    conn: Connection,
}

impl PeerRx {
    pub fn new(conn: Connection, stream: RecvStream) -> Self {
        PeerRx { stream, conn }
    }
}

struct PeerTx {
    stream: SendStream,
    conn: Connection,
    datagram_sz_cfg: Option<usize>,
}

impl PeerTx {
    pub fn new(conn: Connection, stream: SendStream) -> Self {
        let datagram_sz_cfg = conn.max_datagram_size();
        PeerTx {
            stream,
            conn,
            datagram_sz_cfg,
        }
    }
}

struct Peer {
    addrs: IpAddrs,
    send: Arc<Mutex<Option<PeerTx>>>,
    queue_tx: mpsc::Sender<OutboundMessage>,
    rx_task: Option<AbortRecv>,
}

struct AuthRules {
    anybody: bool,
    password: Option<String>,
}

struct IvLanStateInner {
    running: Mutex<bool>,
    dev: Arc<AsyncDevice>,
    endpoint: OnceLock<Arc<iroh::Endpoint>>,
    peers: DashMap<RemoteId, Peer, fxhash::FxBuildHasher>,
    addrs: IpAddrs,
    ipv4mask: u8,
    ipv6mask: u8,
    out_queue_cap: usize,
    auth_rules: AuthRules,
}

impl IvLanStateInner {
    fn remove_peer(&self, remote: RemoteId) {
        if let Some((_, mut peer)) = self.peers.remove(&remote) {
            if let Some(rx_task_ab_handle) = peer.rx_task.take() {
                rx_task_ab_handle.abort();
            }

            drop(peer);
        }
    }

    async fn insert_peer(
        self: Arc<Self>,
        remote: RemoteId,
        txrx: Option<(Connection, SendStream, RecvStream)>,
        auth: Auth,
    ) -> anyhow::Result<IpAddrs> {
        if let Some(mut peer) = self.peers.get_mut(&remote) {
            if let Some((conn, tx, rx)) = txrx {
                if let Some(prev) = peer.rx_task.take() {
                    prev.abort();
                }

                let mut send_guard = peer.send.lock().await;
                *send_guard = Some(PeerTx::new(conn.clone(), tx));
                drop(send_guard);
                peer.rx_task = Some(self.start_recv_task(
                    remote,
                    PeerRx::new(conn, rx),
                    peer.send.clone(),
                    peer.addrs,
                ));
            }
            return Ok(peer.addrs);
        }

        let (queue_tx, queue_rx) = mpsc::channel(self.out_queue_cap);
        let send = Arc::new(Mutex::new(None));
        self.clone()
            .start_send_task(remote, send.clone(), queue_rx, auth);

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
        let rx_task = if let Some((conn, tx, rx)) = txrx {
            let mut send_guard = send.lock().await;
            *send_guard = Some(PeerTx::new(conn.clone(), tx));
            Some(self.start_recv_task(remote, PeerRx::new(conn, rx), send.clone(), addrs))
        } else {
            None
        };

        self.peers.insert(
            remote,
            Peer {
                addrs,
                send,
                queue_tx,
                rx_task,
            },
        );
        Ok(addrs)
    }

    fn start_send_task(
        self: Arc<Self>,
        remote: RemoteId,
        send: Arc<Mutex<Option<PeerTx>>>,
        mut queue_rx: mpsc::Receiver<OutboundMessage>,
        auth: Auth,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = queue_rx.recv().await {
                loop {
                    let mut send_guard = send.lock().await;
                    if send_guard.is_none() {
                        drop(send_guard);
                        log::debug!("No send stream for peer {}, attempting connect", remote);
                        if let Err(e) = self.clone().ensure_send_stream(remote, &auth).await {
                            log::warn!("Failed to establish send stream for {}: {}", remote, e);
                            sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                        continue;
                    }

                    let peer_tx = send_guard.as_mut().unwrap();
                    let len = msg.len();

                    if let Some(max_sz) = peer_tx.datagram_sz_cfg
                        && msg.len() <= max_sz
                    {
                        match peer_tx.conn.send_datagram(Bytes::from_owner(msg)) {
                            Ok(_) => {
                                log::trace!("TX DATAGRAM {len}b to {remote}.");
                                break;
                            }
                            Err(SendDatagramError::ConnectionLost(e)) => {
                                log::warn!("Send failure for {}: {}; dropped.", remote, e);
                                *send_guard = None;
                                drop(send_guard);
                                break;
                            }
                            Err(SendDatagramError::Disabled) => {
                                log::warn!("Datagram support disabled locally; dropped.");
                                peer_tx.datagram_sz_cfg = None;
                                break;
                            }
                            Err(SendDatagramError::TooLarge) => {
                                peer_tx.datagram_sz_cfg = peer_tx.conn.max_datagram_size();
                                log::warn!(
                                    "Max datagram size changed, new size is {:?}; dropped.",
                                    peer_tx.datagram_sz_cfg
                                );
                                break;
                            }
                            Err(SendDatagramError::UnsupportedByPeer) => {
                                log::warn!("Datagram support disabled by peer; dropped.");
                                peer_tx.datagram_sz_cfg = None;
                                break;
                            }
                        }
                    }

                    let result = peer_tx.stream.write_all(&msg).await;
                    match result {
                        Ok(()) => {
                            log::trace!("TX STREAM {len}b to {remote}.");
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
        rx: PeerRx,
        tx: Arc<Mutex<Option<PeerTx>>>,
        peer_addrs: IpAddrs,
    ) -> AbortRecv {
        let host_addrs = self.addrs;
        let PeerRx { mut stream, conn } = rx;

        let mut buf = vec![0; 65536];
        let dev = Arc::clone(&self.dev);
        let stream = tokio::spawn(async move {
            loop {
                let len: usize = match stream.read_u16_le().await {
                    Ok(len) => len.into(),
                    Err(e) => {
                        log::info!("IV recv STREAM src={remote} | ERROR | {e}");
                        break;
                    },
                };
                if let Err(e) = stream.read_exact(&mut buf[..len]).await {
                    log::info!("IV recv STREAM src={remote} | ERROR | {e}");
                    break;
                }

                let patch = match ip_util::patch_packet_addresses(
                    &mut buf[..len],
                    peer_addrs,
                    host_addrs,
                ) {
                    Ok(patch) => patch,
                    Err(e) => {
                        log::warn!("IV recv STREAM src={remote}, payload={len} | BAD PACKET | {e}");
                        continue;
                    }
                };

                if let Some((src, dst)) = patch {
                    let txd = dev.send(&buf[..len]).await.unwrap();
                    log::trace!(
                        "IV recv STREAM src={remote}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                    );
                } else {
                    log::debug!("IV recv STREAM src={remote}, payload={len} | SKIP");
                }
            }

            // Delete the corresponding sender to ensure that
            // the connection is dropped or in a bad state ASAP.
            *tx.lock().await = None;
        }).abort_handle();

        let dev = Arc::clone(&self.dev);
        let datagram = tokio::spawn(async move {
            loop {
                let mut bytes = match conn.read_datagram().await {
                    Ok(bytes) => BytesMut::from(bytes), 
                    Err(e) => {
                        log::info!("IV recv DATAGRAM src={remote} | ERROR | {e}");
                        break;
                    }
                };
                let mut packet = &mut bytes[2..];
                let len = packet.len();

                let patch = match ip_util::patch_packet_addresses(
                    &mut packet,
                    peer_addrs,
                    host_addrs,
                ) {
                    Ok(patch) => patch,
                    Err(e) => {
                        log::warn!("IV recv DATAGRAM src={remote}, payload={len} | BAD PACKET | {e}");
                        continue;
                    }
                };

                if let Some((src, dst)) = patch {
                    let txd = dev.send(&packet).await.unwrap();
                    log::trace!(
                        "IV recv DATAGRAM src={remote}, payload={len} | PATCHED src={src}, dst={dst} | WR {txd}"
                    );
                } else {
                    log::debug!("IV recv DATAGRAM src={remote}, payload={len} | SKIP");
                }
            }
        })
        .abort_handle();

        AbortRecv::new(stream, datagram)
    }

    async fn ensure_send_stream(
        self: Arc<Self>,
        remote: RemoteId,
        auth: &Auth,
    ) -> anyhow::Result<()> {
        let endpoint = self
            .endpoint
            .get()
            .ok_or_else(|| anyhow::anyhow!("Endpoint not initialized"))?
            .clone();

        let pk: iroh::PublicKey = remote.into();
        let conn = endpoint.connect(pk, b"ivlan/1.0").await?;
        let (mut tx, mut rx) = conn.open_bi().await?;

        auth::write_auth(auth, &mut tx).await?;

        if auth::read_auth_resp(&mut rx).await? == AuthResp::Bad {
            log::info!("Failed auth with {remote}, remove peer.");
            self.remove_peer(remote);
        }

        self.insert_peer(remote, Some((conn, tx, rx)), auth.clone())
            .await?;

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
        out_queue_cap: usize,
        auth_rules: AuthRules,
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
                out_queue_cap,
                auth_rules,
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
                        log::warn!("Couldn't accept connection: {e}");
                        continue;
                    }
                };
                let conn = match accepting.await {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("Couldn't accept connection: {e}");
                        continue;
                    }
                };

                let (mut tx, mut rx) = match conn.accept_bi().await {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("Couldn't accept bidir from {}: {}", conn.remote_id(), e);
                        continue;
                    }
                };

                let auth = match auth::read_auth(&mut rx).await {
                    Ok(auth) => auth,
                    Err(e) => {
                        log::info!("Bad auth from {}: {}", conn.remote_id(), e);
                        continue;
                    }
                };

                log::info!("Auth from {}: {:?}", conn.remote_id(), auth);

                let resp = if state.auth_rules.anybody {
                    AuthResp::Ok
                } else {
                    if let Some(allow_pass) = &state.auth_rules.password
                        && let Auth::Password(user_pass) = &auth
                        && allow_pass == user_pass
                    {
                        AuthResp::Ok
                    } else {
                        AuthResp::Bad
                    }
                };

                if let Err(e) = auth::write_auth_resp(&resp, &mut tx).await {
                    log::warn!("Couldn't send auth response to {}: {}", conn.remote_id(), e);
                    continue;
                }

                match resp {
                    AuthResp::Ok => {}
                    AuthResp::Bad => {
                        log::warn!("Peer {} rejected: bad auth", conn.remote_id());
                        continue;
                    }
                }

                let remote = conn.remote_id().into();
                state
                    .clone()
                    .insert_peer(remote, Some((conn, tx, rx)), Auth::None)
                    .await
                    .unwrap();
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

                            if let Err(e) = peer.queue_tx.try_send(msg) {
                                match e {
                                    TrySendError::Full(_) => {
                                        log::warn!(
                                            "Dropping outbound packet to {}: queue full",
                                            peer.key(),
                                        );
                                    }
                                    TrySendError::Closed(_) => {
                                        log::warn!("Outbound queue to {} closed", peer.key());
                                        break;
                                    }
                                }
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

                            if let Err(e) = peer.queue_tx.try_send(msg) {
                                match e {
                                    TrySendError::Full(_) => {
                                        log::warn!(
                                            "Dropping outbound packet to {}: queue full",
                                            peer.key(),
                                        );
                                    }
                                    TrySendError::Closed(_) => {
                                        log::warn!("Outbound queue to {} closed", peer.key());
                                        break;
                                    }
                                }
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
        auth: Auth,
    ) -> anyhow::Result<IpAddrs> {
        if let Some(peer) = self.inner.peers.get(&remote) {
            return Ok(peer.addrs);
        }

        let peer_addrs = self.inner.clone().insert_peer(remote, None, auth).await?;
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
        auth: Auth,
    ) -> Result<IpAddrs, String> {
        self.connect_impl(cx, remote, auth)
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
    /// Interface name for the TUN device
    #[arg(env = "IV_IF_NAME", default_value = "iv")]
    if_name: String,

    /// RPC server address
    #[clap(long, env = "IV_RPC_ADDR", default_value = "127.0.0.1:2334")]
    rpc_addr: SocketAddr,

    /// MTU (Maximum Transmission Unit) size
    #[arg(long, env = "IV_MTU", default_value_t = 1500)]
    mtu: u16,

    /// Maximum number of IP packets in the outbound queue per peer
    #[arg(long, env = "IV_OUT_QUEUE", default_value_t = 64)]
    out_queue: usize,

    /// IPv4 address for the interface
    #[arg(long, env = "IV_IP4_ADDR", default_value = "121.37.0.0")]
    ip4: Ipv4Addr,

    /// IPv4 subnet mask (CIDR notation)
    #[arg(long, env = "IV_IP4_MASK", default_value_t = 24)]
    ip4mask: u8,

    /// IPv6 address for the interface
    #[arg(long, env = "IV_IP6_ADDR", default_value = "fd00::1")]
    ip6: Ipv6Addr,

    /// IPv6 subnet mask (CIDR notation)
    #[arg(long, env = "IV_IP6_MASK", default_value_t = 64)]
    ip6mask: u8,

    #[command(flatten)]
    auth: AuthArgs,
}

#[derive(clap::Parser)]
struct AuthArgs {
    #[arg(
        long = "allow-anybody",
        env = "IV_AUTH_ANYBODY",
        default_value_t = false
    )]
    anybody: bool,
    #[arg(long = "allow-password", env = "IV_AUTH_PASSWORD")]
    password: Option<String>,
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
    let state = IvLanState::new(
        dev,
        args.ip4,
        args.ip4mask,
        args.ip6,
        args.ip6mask,
        args.out_queue,
        AuthRules {
            anybody: args.auth.anybody,
            password: args.auth.password,
        },
    );

    let (exit_tx, exit_rx) = oneshot::channel::<()>();

    let state_ = state.inner.clone();
    tokio::task::spawn(async move {
        match exit_rx.await {
            Ok(()) => {
                for mut peer in state_.peers.iter_mut() {
                    if let Some(prev) = peer.rx_task.take() {
                        prev.abort();
                    }
                }
                if let Some(endpoint) = state_.endpoint.get() {
                    log::info!("Closing Iroh endpoint.");
                    endpoint.close().await;
                }
                std::process::exit(0);
            }
            Err(_) => unreachable!(),
        }
    });

    let mut exit_tx = Some(exit_tx);
    ctrlc::set_handler(move || match exit_tx.take() {
        Some(tx) => {
            log::info!("Exiting gracefully. Press Ctrl+C again to force exit.");
            if tx.send(()).is_err() {
                log::warn!("Graceful exit failed.");
                std::process::exit(1)
            }
        }
        None => std::process::exit(0),
    })
    .expect("Error setting Ctrl-C handler");

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
