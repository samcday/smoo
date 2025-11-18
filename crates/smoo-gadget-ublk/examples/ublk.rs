use anyhow::Context;
use smoo_gadget_buffers::VecBufferPool;
use smoo_gadget_ublk::{SmooUblk, UblkOp};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let block_size = 512usize;
    let queue_count = 1;
    let queue_depth = 16;
    let max_io_bytes =
        SmooUblk::max_io_bytes_hint(block_size, queue_depth).context("compute max io bytes")?;
    let mut buffer_pool =
        VecBufferPool::new(queue_count, queue_depth, max_io_bytes).context("init buffer pool")?;
    let buffer_ptrs = buffer_pool
        .buffer_ptrs()
        .context("collect buffer pointers")?;
    let device = ublk
        .setup_device(
            block_size,
            1024 * 1024,
            queue_count,
            queue_depth,
            &buffer_ptrs,
        )
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
