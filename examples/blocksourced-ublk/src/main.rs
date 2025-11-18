//! blocksourced-ublk: ublk device backed by a file or block device.
//!
//! ```bash
//! # Image-backed device
//! sudo RUST_LOG=info,ublk-ctrl=trace,smoo_gadget_ublk=trace \
//!   cargo run -p blocksourced-ublk -- \
//!     --file ./disk.img --block-size 512 --queue-count 1 --queue-depth 16
//!
//! # Real block device
//! sudo RUST_LOG=info,ublk-ctrl=trace,smoo_gadget_ublk=trace \
//!   cargo run -p blocksourced-ublk -- \
//!     --device /dev/nvme0n1p3 --block-size 512
//! ```

use anyhow::{Context, ensure};
use clap::{ArgGroup, Parser};
use smoo_gadget_ublk::{SmooUblk, UblkIoRequest, UblkOp};
use smoo_host_blocksources::{DeviceBlockSource, FileBlockSource};
use smoo_host_core::BlockSource;
use std::{io, path::PathBuf, sync::Arc};
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[command(name = "blocksourced-ublk")]
#[command(about = "Expose a file or block device through a ublk queue", long_about = None)]
#[command(group = ArgGroup::new("backing").args(["file", "device"]).required(true))]
struct Args {
    /// Backing file path
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Backing block device path
    #[arg(long, value_name = "PATH")]
    device: Option<PathBuf>,
    /// Number of ublk queues to configure
    #[arg(long, default_value_t = 1)]
    queue_count: u16,
    /// Depth of each ublk queue
    #[arg(long, default_value_t = 16)]
    queue_depth: u16,
    /// Logical block size presented to the kernel (bytes)
    #[arg(long, default_value_t = 512)]
    block_size: u32,
    /// Logical block count to expose. Defaults to source size / block_size.
    #[arg(long)]
    blocks: Option<u64>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    ensure!(
        args.block_size.is_power_of_two(),
        "block size must be a power-of-two"
    );

    let source = open_source(&args).await.context("open block source")?;
    let block_size = source.block_size() as usize;
    let (block_count, max_blocks) = derive_block_count(source.as_ref(), args.blocks)
        .await
        .context("determine block count")?;

    let shutdown = Arc::new(Notify::new());
    {
        let notify = shutdown.clone();
        ctrlc::set_handler(move || {
            notify.notify_waiters();
        })
        .context("install ctrl-c handler")?;
    }

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let max_io_bytes = SmooUblk::max_io_bytes_hint(block_size, args.queue_depth)
        .context("compute max io bytes")?;
    let device = ublk
        .setup_device(block_size, block_count, args.queue_count, args.queue_depth)
        .await
        .context("setup device")?;
    ensure!(
        device.max_io_bytes() == max_io_bytes,
        "device max io bytes changed during setup"
    );

    info!(
        block_size = block_size,
        max_blocks = max_blocks,
        blocks = block_count,
        queues = args.queue_count,
        depth = args.queue_depth,
        buffer_bytes = max_io_bytes,
        "ublk device configured"
    );

    let mut io_error = None;
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("shutdown signal received");
                break;
            }
            req = device.next_io() => {
                let req = match req {
                    Ok(req) => req,
                    Err(err) => {
                        io_error = Some(err.context("receive ublk io"));
                        break;
                    }
                };
                let req_len = match request_byte_len(&req, block_size) {
                    Ok(len) => len,
                    Err(err) => {
                        let errno = errno_from_io(&err);
                        warn!(
                            queue = req.queue_id,
                            tag = req.tag,
                            errno = errno,
                            ?req.op,
                            "invalid request length: {err}"
                        );
                        device
                            .complete_io(req, -errno)
                            .context("complete invalid length")?;
                        continue;
                    }
                };
                debug!(
                    queue = req.queue_id,
                    tag = req.tag,
                    ?req.op,
                    sector = req.sector,
                    num_sectors = req.num_sectors,
                    bytes = req_len,
                    "handling request"
                );

                let result_bytes = match req.op {
                    UblkOp::Read => {
                        if req_len > device.buffer_len() {
                            warn!(
                                queue = req.queue_id,
                                tag = req.tag,
                                req_bytes = req_len,
                                buf_cap = device.buffer_len(),
                                "read request exceeds buffer capacity"
                            );
                            device
                                .complete_io(req, -libc::EINVAL)
                                .context("complete oversized request")?;
                            continue;
                        }
                        let mut buf = device
                            .checkout_buffer(req.queue_id, req.tag)
                            .context("checkout buffer")?;
                        source
                            .read_blocks(req.sector, &mut buf.as_mut_slice()[..req_len])
                            .await
                            .context("read backing source")?;
                        req_len
                    }
                    UblkOp::Write => {
                        if req_len > device.buffer_len() {
                            warn!(
                                queue = req.queue_id,
                                tag = req.tag,
                                req_bytes = req_len,
                                buf_cap = device.buffer_len(),
                                "write request exceeds buffer pool capacity"
                            );
                            device
                                .complete_io(req, -libc::EINVAL)
                                .context("complete oversized request")?;
                            continue;
                        }
                        let buf = device
                            .checkout_buffer(req.queue_id, req.tag)
                            .context("checkout buffer")?;
                        source
                            .write_blocks(req.sector, &buf.as_slice()[..req_len])
                            .await
                            .context("write backing source")?;
                        req_len
                    }
                    UblkOp::Flush => {
                        source.flush().await.context("flush backing source")?;
                        0
                    }
                    UblkOp::Discard => {
                        source
                            .discard(req.sector, req.num_sectors)
                            .await
                            .context("discard backing source")?;
                        0
                    }
                    UblkOp::Unknown(code) => {
                        warn!(
                            queue = req.queue_id,
                            tag = req.tag,
                            code = code,
                            "unsupported operation"
                        );
                        device
                            .complete_io(req, -libc::EOPNOTSUPP)
                            .context("complete unsupported op")?;
                        continue;
                    }
                };

                let result_code = match i32::try_from(result_bytes) {
                    Ok(val) => val,
                    Err(_) => {
                        warn!(
                            queue = req.queue_id,
                            tag = req.tag,
                            bytes = result_bytes,
                            "io result exceeds i32 range"
                        );
                        -libc::EIO
                    }
                };
                device
                    .complete_io(req, result_code)
                    .context("complete io")?;
            }
        }
    }

    info!("stopping ublk device");
    ublk.stop_dev(device, true).await.context("stop device")?;
    if let Some(err) = io_error {
        return Err(err);
    }
    Ok(())
}

async fn open_source(args: &Args) -> anyhow::Result<Arc<dyn BlockSource>> {
    let block_size = args.block_size;
    let source: Arc<dyn BlockSource> = match (&args.file, &args.device) {
        (Some(path), None) => Arc::new(FileBlockSource::open(path, block_size).await?),
        (None, Some(path)) => Arc::new(DeviceBlockSource::open(path, block_size).await?),
        _ => unreachable!("clap enforces mutually exclusive arguments"),
    };
    Ok(source)
}

async fn derive_block_count(
    source: &dyn BlockSource,
    requested: Option<u64>,
) -> anyhow::Result<(usize, u64)> {
    let max_blocks = source.total_blocks().await.context("read source size")?;
    ensure!(max_blocks > 0, "source smaller than one block");
    let desired = match requested {
        Some(blocks) => {
            ensure!(
                blocks <= max_blocks,
                "requested blocks ({}) exceeds source capacity ({})",
                blocks,
                max_blocks
            );
            blocks
        }
        None => max_blocks,
    };
    let block_count = usize::try_from(desired).context("block count exceeds usize")?;
    Ok((block_count, max_blocks))
}

fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or_else(|| match err.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::UnexpectedEof => libc::EIO,
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    })
}

fn request_byte_len(req: &UblkIoRequest, block_size: usize) -> io::Result<usize> {
    let sectors = usize::try_from(req.num_sectors)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sector count overflow"))?;
    sectors
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow"))
}
