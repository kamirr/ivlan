use std::net::{Ipv4Addr, Ipv6Addr};

#[tarpc::service]
pub trait IvLanService {
    async fn start(_sk: iroh::SecretKey) -> Result<(), String>;
    async fn connect(_pk: iroh::PublicKey) -> Result<(Ipv4Addr, Ipv6Addr), String>;
}
