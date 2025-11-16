use smoo_ublk::SmooUblk;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut ublk = SmooUblk::new().expect("init ublk");

    ublk.setup_device(512, 1, 1, 1).await.expect("setup device");
}
