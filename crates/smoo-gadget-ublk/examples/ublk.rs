use anyhow::Context;
use smoo_gadget_ublk::{SmooUblk, UblkOp};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let device = ublk
        .setup_device(512, 1024 * 1024, 1, 16)
        .await
        .context("setup device")?;

    loop {
        let req = device.next_io().await?;
        tracing::info!(
            queue = req.queue_id,
            tag = req.tag,
            ?req.op,
            start = req.sector,
            sectors = req.num_sectors,
            "ublk request"
        );

        // Placeholder completion: pretend we've handled the IO immediately.
        device.complete_io(req, 0).context("complete io")?;

        if matches!(req.op, UblkOp::Unknown(_)) {
            tracing::warn!("unknown op {:?}", req.op);
        }
    }
}
