use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use smoo_host_core::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
use std::{
    io,
    io::SeekFrom,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};
use tracing::debug;

/// Block source backed by a regular file.
pub struct FileBlockSource {
    inner: BlockFile,
    block_size: u32,
}

impl FileBlockSource {
    /// Open a file-backed block source.
    pub async fn open(path: impl AsRef<Path>, block_size: u32) -> Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        ensure!(block_size > 0, "block size must be non-zero");
        let opened = open_block_file(path.as_ref()).await?;
        Ok(Self {
            inner: BlockFile::new(opened.file, opened.len, opened.writable),
            block_size,
        })
    }

    fn ensure_aligned(&self, len: usize) -> BlockSourceResult<()> {
        if !len.is_multiple_of(self.block_size as usize) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok(())
    }

    fn offset(&self, lba: u64) -> BlockSourceResult<u64> {
        lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })
    }
}

/// Block source backed by a block device node (e.g. `/dev/nvme0n1p3`).
pub struct DeviceBlockSource {
    inner: BlockFile,
    block_size: u32,
}

impl DeviceBlockSource {
    /// Open a device-backed block source.
    pub async fn open(path: impl AsRef<Path>, block_size: u32) -> Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        ensure!(block_size > 0, "block size must be non-zero");
        let opened = open_block_file(path.as_ref()).await?;
        Ok(Self {
            inner: BlockFile::new(opened.file, opened.len, opened.writable),
            block_size,
        })
    }

    fn ensure_aligned(&self, len: usize) -> BlockSourceResult<()> {
        if !len.is_multiple_of(self.block_size as usize) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok(())
    }

    fn offset(&self, lba: u64) -> BlockSourceResult<u64> {
        lba.checked_mul(self.block_size as u64).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })
    }
}

#[async_trait]
impl BlockSource for FileBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.inner
            .size()
            .await
            .map(|bytes| bytes / self.block_size as u64)
            .map_err(io_error)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner.read_at(offset, buf).await.map_err(io_error)?;
        Ok(buf.len())
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner.write_at(offset, buf).await.map_err(io_error)?;
        Ok(buf.len())
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        self.inner.flush().await.map_err(io_error)
    }
}

#[async_trait]
impl BlockSource for DeviceBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.inner
            .size()
            .await
            .map(|bytes| bytes / self.block_size as u64)
            .map_err(io_error)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner.read_at(offset, buf).await.map_err(io_error)?;
        Ok(buf.len())
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let offset = self.offset(lba)?;
        self.inner.write_at(offset, buf).await.map_err(io_error)?;
        Ok(buf.len())
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        self.inner.flush().await.map_err(io_error)
    }
}

fn io_error(err: io::Error) -> BlockSourceError {
    BlockSourceError::with_message(BlockSourceErrorKind::Io, err.to_string())
}

struct BlockFile {
    file: Mutex<File>,
    len: AtomicU64,
    writable: bool,
}

impl BlockFile {
    fn new(file: File, len: u64, writable: bool) -> Self {
        Self {
            file: Mutex::new(file),
            len: AtomicU64::new(len),
            writable,
        }
    }

    async fn size(&self) -> io::Result<u64> {
        Ok(self.len.load(Ordering::Relaxed))
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut file = self.file.lock().await;
        file.seek(SeekFrom::Start(offset)).await?;
        file.read_exact(buf).await?;
        Ok(())
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "block source opened in read-only mode",
            ));
        }

        let mut file = self.file.lock().await;
        file.seek(SeekFrom::Start(offset)).await?;
        file.write_all(buf).await?;

        let written = u64::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "write length exceeds u64"))?;
        let end = offset
            .checked_add(written)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "write offset overflow"))?;
        self.len.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let file = self.file.lock().await;
        file.sync_data().await
    }
}

struct OpenedBlockFile {
    file: File,
    len: u64,
    writable: bool,
}

async fn open_block_file(path: &Path) -> Result<OpenedBlockFile> {
    let path_display = path.display().to_string();
    let rw_result = OpenOptions::new().read(true).write(true).open(path).await;

    let (file, writable) = match rw_result {
        Ok(file) => (file, true),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            let file = OpenOptions::new()
                .read(true)
                .open(path)
                .await
                .with_context(|| format!("open {} read-only", path_display))?;
            debug!(path = %path_display, "opened block source read-only");
            (file, false)
        }
        Err(err) => {
            return Err(err).context(format!("open {}", path_display));
        }
    };

    let len = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path_display))?
        .len();
    if writable {
        debug!(path = %path_display, len = len, "opened block source read-write");
    }

    Ok(OpenedBlockFile {
        file,
        len,
        writable,
    })
}
