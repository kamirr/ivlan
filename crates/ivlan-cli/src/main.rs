use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::{Deserialize, Serialize};

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

    #[arg(long, env = "IV_RPC_PORT", default_value_t = 2334)]
    rpc_port: u16,

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
}

fn main() {
    dotenv::dotenv().ok();
    let args = Args::parse();
}
