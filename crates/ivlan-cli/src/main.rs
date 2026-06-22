use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::{Deserialize, Serialize};
use tarpc::tokio_serde::formats::Json;

mod util;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(with = "util::sk_serde")]
    sk: iroh_base::SecretKey,

    peers: BTreeMap<String, PeerData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerData {
    #[serde(with = "util::pk_serde")]
    pk: iroh_base::PublicKey,
}

impl Config {
    fn setup() -> Self {
        Config {
            sk: iroh_base::SecretKey::generate(),
            peers: BTreeMap::new(),
        }
    }

    fn read(path: &Path) -> Self {
        let bytes = std::fs::read(path).expect("Failed to read the configuration file.");
        let config = toml::from_slice(bytes.as_slice())
            .expect("Failed to deserialize the configuration file.");

        config
    }

    fn write(&self, path: &Path) {
        std::fs::write(path, toml::to_string(self).unwrap())
            .expect("Failed to write the configuration file.");
    }
}

#[derive(clap::Parser)]
struct Args {
    #[arg(short, long, env = "IV_CONFIG", default_value = "iv-lan.toml")]
    config: PathBuf,

    #[clap(long, env = "IV_RPC_ADDR", default_value = "127.0.0.1:2334")]
    rpc_addr: SocketAddr,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Setup {
        #[arg(long)]
        force: bool,
    },
    Init,
    Connect {
        remote: iroh_base::PublicKey,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let args = Args::parse();

    match args.cmd {
        Command::Setup { force } => {
            if args.config.exists() && !force {
                eprintln!(
                    "iv-lan configuration file already exists at {}. Use --force to overwrite.",
                    args.config.display()
                );
                std::process::exit(1);
            }

            Config::setup().write(&args.config);
        }
        Command::Init => {
            let config = Config::read(&args.config);

            let mut transport = tarpc::serde_transport::tcp::connect(args.rpc_addr, Json::default);
            transport.config_mut().max_frame_length(usize::MAX);

            let client = ivlan_rpc::IvLanServiceClient::new(
                tarpc::client::Config::default(),
                transport.await?,
            )
            .spawn();

            client
                .start(tarpc::context::current(), config.sk)
                .await
                .unwrap()
                .unwrap();
        }
        Command::Connect { remote } => {
            let mut transport = tarpc::serde_transport::tcp::connect(args.rpc_addr, Json::default);
            transport.config_mut().max_frame_length(usize::MAX);

            let client = ivlan_rpc::IvLanServiceClient::new(
                tarpc::client::Config::default(),
                transport.await?,
            )
            .spawn();

            let (ipv4, ipv6) = client
                .connect(tarpc::context::current(), remote)
                .await
                .unwrap()
                .unwrap();

            println!("ipv4: {ipv4}");
            println!("ipv6: {ipv6}");
        }
    }

    Ok(())
}
