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
//! # Infinite cats demo
//! sudo RUST_LOG=info,ublk-ctrl=trace,smoo_gadget_ublk=trace \
//!   cargo run -p blocksourced-ublk -- \
//!     --meow --block-size 4096
//!
//! ```

use anyhow::{Context, ensure};
use clap::{ArgGroup, Parser};
use smoo_gadget_ublk::{SmooUblk, UblkIoRequest, UblkOp};
use smoo_host_blocksources::{DeviceBlockSource, FileBlockSource};
use smoo_host_core::{BlockSource, BlockSourceError, BlockSourceErrorKind};
use smoo_purrfection::{DebugPatternProvider, Geometry, VirtualFatBlockSource};
use std::{io, path::PathBuf, sync::Arc};
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[command(name = "blocksourced-ublk")]
#[command(about = "Expose a file or block device through a ublk queue", long_about = None)]
#[command(group = ArgGroup::new("backing").args(["file", "device", "meow"]).required(true))]
struct Args {
    /// Backing file path
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Backing block device path
    #[arg(long, value_name = "PATH")]
    device: Option<PathBuf>,
    /// Present the procedural virtual FAT volume of infinite cats
    #[arg(long)]
    meow: bool,
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
    ensure!(
        args.block_size % 512 == 0,
        "block size must be a multiple of 512 bytes"
    );
    ensure!(
        !args.meow || args.block_size == Geometry::BLOCK_SIZE,
        "the --meow volume must use a {}-byte block size",
        Geometry::BLOCK_SIZE
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
                let req_geom = match request_geometry(&req, block_size) {
                    Ok(geom) => geom,
                    Err(err) => {
                        let errno = errno_from_io(&err);
                        warn!(
                            queue = req.queue_id,
                            tag = req.tag,
                            errno = errno,
                            ?req.op,
                            "invalid request geometry: {err}"
                        );
                        device
                            .complete_io(req, -errno)
                            .context("complete invalid geometry")?;
                        continue;
                    }
                };
                let req_len = req_geom.byte_len;
                debug!(
                    queue = req.queue_id,
                    tag = req.tag,
                    ?req.op,
                    sector = req.sector,
                    num_sectors = req.num_sectors,
                    bytes = req_len,
                    "handling request"
                );

                let op_result: Result<usize, BlockSourceError> = match req.op {
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
                        match source
                            .read_blocks(req_geom.lba, &mut buf.as_mut_slice()[..req_len])
                            .await
                        {
                            Ok(_) => Ok(req_len),
                            Err(err) => Err(err),
                        }
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
                        match source
                            .write_blocks(req_geom.lba, &buf.as_slice()[..req_len])
                            .await
                        {
                            Ok(_) => Ok(req_len),
                            Err(err) => Err(err),
                        }
                    }
                    UblkOp::Flush => source.flush().await.map(|_| 0),
                    UblkOp::Discard => {
                        source
                            .discard(req_geom.lba, req_geom.block_count)
                            .await
                            .map(|_| 0)
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
                let result_bytes = match op_result {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let errno = errno_from_blocksource(&err, req.op);
                        warn!(
                            queue = req.queue_id,
                            tag = req.tag,
                            errno = errno,
                            ?req.op,
                            kind = ?err.kind(),
                            "backing source operation failed: {}",
                            err
                        );
                        device
                            .complete_io(req, -errno)
                            .context("complete failed op")?;
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
    let source: Arc<dyn BlockSource> = match (&args.file, &args.device, args.meow) {
        (Some(path), None, false) => Arc::new(FileBlockSource::open(path, block_size).await?),
        (None, Some(path), false) => Arc::new(DeviceBlockSource::open(path, block_size).await?),
        (None, None, true) => Arc::new(VirtualFatBlockSource::new(DebugPatternProvider::default())),
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

fn errno_from_blocksource(err: &BlockSourceError, op: UblkOp) -> i32 {
    match err.kind() {
        BlockSourceErrorKind::InvalidInput => libc::EINVAL,
        BlockSourceErrorKind::OutOfRange => libc::ERANGE,
        BlockSourceErrorKind::Io => libc::EIO,
        BlockSourceErrorKind::Unsupported => {
            if matches!(op, UblkOp::Write) {
                libc::EROFS
            } else {
                libc::EOPNOTSUPP
            }
        }
        BlockSourceErrorKind::Other => libc::EIO,
    }
}

struct RequestGeometry {
    lba: u64,
    block_count: u32,
    byte_len: usize,
}

fn request_geometry(req: &UblkIoRequest, block_size: usize) -> io::Result<RequestGeometry> {
    const SECTOR_BYTES: usize = 512;
    if block_size % SECTOR_BYTES != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "logical block size must be a multiple of 512 bytes",
        ));
    }
    let sectors_per_block = block_size / SECTOR_BYTES;
    let sectors_per_block_u64 = sectors_per_block as u64;
    if req.sector % sectors_per_block_u64 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sector offset not aligned to logical block size",
        ));
    }
    let lba = req.sector / sectors_per_block_u64;
    let sectors_per_block_u32 = sectors_per_block as u32;
    if req.num_sectors % sectors_per_block_u32 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sector count not aligned to logical block size",
        ));
    }
    let block_count = req.num_sectors / sectors_per_block_u32;
    let blocks_usize = usize::try_from(block_count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "block count exceeds addressable range",
        )
    })?;
    let byte_len = blocks_usize.checked_mul(block_size).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow")
    })?;
    Ok(RequestGeometry {
        lba,
        block_count,
        byte_len,
    })
}
