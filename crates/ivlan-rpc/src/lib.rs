use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct IpAddrs {
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
}

#[tarpc::service]
pub trait IvLanService {
    async fn start(_sk: iroh::SecretKey) -> Result<(), String>;
    async fn connect(_pk: iroh::PublicKey) -> Result<IpAddrs, String>;
    async fn lookup(_pk: iroh::PublicKey) -> Result<IpAddrs, String>;
    async fn peers() -> BTreeMap<iroh::PublicKey, IpAddrs>;
}
