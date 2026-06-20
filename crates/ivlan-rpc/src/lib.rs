#[tarpc::service]
pub trait IvLanService {
    async fn start(_pk: iroh::SecretKey);
}
