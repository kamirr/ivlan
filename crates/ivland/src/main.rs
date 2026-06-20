use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use clap::Parser;
use futures::StreamExt;
use ivlan_rpc::IvLanService;
use tarpc::{
    server::{Channel, incoming::Incoming as _},
    tokio_serde::formats::Json,
};
use tokio::sync::Mutex;
use tun_rs::{AsyncDevice, DeviceBuilder};

struct IvLanStateInner {
    dev: Option<AsyncDevice>,
}

#[derive(Clone)]
struct IvLanState {
    inner: Arc<Mutex<IvLanStateInner>>,
}

impl IvLanState {
    pub fn new(dev: AsyncDevice) -> Self {
        IvLanState {
            inner: Arc::new(Mutex::new(IvLanStateInner { dev: Some(dev) })),
        }
    }
}

impl IvLanService for IvLanState {
    async fn start(self, _cx: tarpc::context::Context, _pk: iroh::SecretKey) -> () {
        let dev = self.inner.lock().await.dev.take().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            loop {
                let len = dev.recv(&mut buf).await.unwrap();
                log::trace!("Received packet: {len} bytes");

                // Echo the packet back
                dev.send(&buf[..len]).await.unwrap();
            }
        });
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

    #[arg(long, env = "IV_IP4_ADDR", default_value = "121.37.0.1")]
    ip4: Ipv4Addr,
    #[arg(long, env = "IV_IP4_MASK", default_value_t = 24)]
    ip4mask: u8,

    #[arg(long, env = "IV_IP6_ADDR")]
    ip6: Option<Ipv6Addr>,
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

    let mut builder =
        DeviceBuilder::new()
            .name(args.if_name)
            .mtu(args.mtu)
            .ipv4(args.ip4, args.ip4mask, None);

    if let Some(ip6) = args.ip6 {
        builder = builder.ipv6(ip6, args.ip6mask);
    }

    let dev = builder.build_async()?;
    let state = IvLanState::new(dev);

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
