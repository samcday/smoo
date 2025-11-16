//! blocksourced-ublk: ublk device backed by a file or block device.
//!
//! ```bash
//! # Image-backed device
//! sudo RUST_LOG=info,ublk-ctrl=trace,smoo_ublk=trace \
//!   cargo run -p blocksourced-ublk -- \
//!     --file ./disk.img --block-size 512 --queue-count 1 --queue-depth 16
//!
//! # Real block device
//! sudo RUST_LOG=info,ublk-ctrl=trace,smoo_ublk=trace \
//!   cargo run -p blocksourced-ublk -- \
//!     --device /dev/nvme0n1p3 --block-size 512
//! ```

use anyhow::{Context, ensure};
use clap::{ArgGroup, Parser};
use libc;
use smoo_host_core::{BlockSource, DeviceBlockSource, FileBlockSource};
use smoo_ublk::{SmooUblk, UblkIoRequest, UblkOp};
use std::{io, path::PathBuf, sync::Arc};
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

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let device = ublk
        .setup_device(block_size, block_count, args.queue_count, args.queue_depth)
        .await
        .context("setup device")?;
    let mut buffer_pool = BufferPool::new(
        device.queue_count(),
        device.queue_depth(),
        device.max_io_bytes(),
    )
    .context("init buffer pool")?;

    info!(
        block_size = block_size,
        max_blocks = max_blocks,
        blocks = block_count,
        queues = args.queue_count,
        depth = args.queue_depth,
        buffer_bytes = device.max_io_bytes(),
        "ublk device configured"
    );

    loop {
        let req = device.next_io().await.context("receive ublk io")?;
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
                if req_len > buffer_pool.buffer_len() {
                    warn!(
                        queue = req.queue_id,
                        tag = req.tag,
                        req_bytes = req_len,
                        buf_cap = buffer_pool.buffer_len(),
                        "read request exceeds buffer pool capacity"
                    );
                    device
                        .complete_io(req, -libc::EINVAL)
                        .context("complete oversized request")?;
                    continue;
                }
                let mut buf = buffer_pool
                    .checkout(req.queue_id, req.tag)
                    .context("checkout buffer")?;
                source
                    .read_blocks(req.sector, &mut buf[..req_len])
                    .await
                    .context("read backing source")?;
                device
                    .copy_to_kernel(req.queue_id, req.tag, &buf[..req_len])
                    .context("copy read data to kernel")?;
                buffer_pool.checkin(req.queue_id, req.tag, buf);
                req_len
            }
            UblkOp::Write => {
                if req_len > buffer_pool.buffer_len() {
                    warn!(
                        queue = req.queue_id,
                        tag = req.tag,
                        req_bytes = req_len,
                        buf_cap = buffer_pool.buffer_len(),
                        "write request exceeds buffer pool capacity"
                    );
                    device
                        .complete_io(req, -libc::EINVAL)
                        .context("complete oversized request")?;
                    continue;
                }
                let mut buf = buffer_pool
                    .checkout(req.queue_id, req.tag)
                    .context("checkout buffer")?;
                device
                    .copy_from_kernel(req.queue_id, req.tag, &mut buf[..req_len])
                    .context("copy write data from kernel")?;
                source
                    .write_blocks(req.sector, &buf[..req_len])
                    .await
                    .context("write backing source")?;
                buffer_pool.checkin(req.queue_id, req.tag, buf);
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

struct BufferPool {
    slots: Vec<Option<Vec<u8>>>,
    queue_count: usize,
    queue_depth: usize,
    buf_len: usize,
}

impl BufferPool {
    fn new(queue_count: u16, queue_depth: u16, buf_len: usize) -> anyhow::Result<Self> {
        ensure!(buf_len > 0, "buffer length must be positive");
        let queue_count = queue_count as usize;
        let queue_depth = queue_depth as usize;
        let total = queue_count
            .checked_mul(queue_depth)
            .context("buffer pool size overflow")?;
        let mut slots = Vec::with_capacity(total);
        for _ in 0..total {
            slots.push(Some(vec![0u8; buf_len]));
        }
        Ok(Self {
            slots,
            queue_count,
            queue_depth,
            buf_len,
        })
    }

    fn buffer_len(&self) -> usize {
        self.buf_len
    }

    fn checkout(&mut self, queue_id: u16, tag: u16) -> anyhow::Result<Vec<u8>> {
        let idx = self.index(queue_id, tag)?;
        self.slots[idx].take().context("buffer already checked out")
    }

    fn checkin(&mut self, queue_id: u16, tag: u16, mut buf: Vec<u8>) {
        if buf.len() != self.buf_len {
            buf.resize(self.buf_len, 0);
        }
        let idx = self
            .index(queue_id, tag)
            .expect("buffer index out of range");
        let previous = self.slots[idx].replace(buf);
        debug_assert!(previous.is_none(), "buffer slot occupied during checkin");
    }

    fn index(&self, queue_id: u16, tag: u16) -> anyhow::Result<usize> {
        let queue = queue_id as usize;
        let tag = tag as usize;
        ensure!(queue < self.queue_count, "queue id out of range");
        ensure!(tag < self.queue_depth, "tag out of range");
        Ok(queue * self.queue_depth + tag)
    }
}
