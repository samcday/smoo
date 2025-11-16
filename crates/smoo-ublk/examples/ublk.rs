use tracing_subscriber::prelude::*;
use smoo_ublk::SmooUblk;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("fuck");
    let mut ublk = SmooUblk::new()?;

    ublk.setup_device(512, 1, 1, 1).await?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    Ok(())
}
