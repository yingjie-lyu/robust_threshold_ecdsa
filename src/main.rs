use robust_threshold_ecdsa::{cdn, spdz};


#[tokio::main]
async fn main() {
    spdz::simulate_spdz_signing(10, 9).await;
    cdn::simulate_cdn_signing(10, 9).await;
}
