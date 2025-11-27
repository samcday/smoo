use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use smoo_host_core::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
use std::{
    io,
    os::unix::fs::FileExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{fs::OpenOptions, task};
use tracing::debug;

/// Block source that produces deterministic pseudo-random data based on a seed.
///
/// Writes are unsupported; callers can use this to exercise read paths without
/// provisioning backing storage.
pub struct RandomBlockSource {
    block_size: u32,
    blocks: u64,
    seed: u64,
}

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

impl RandomBlockSource {
    /// Construct a random block source.
    pub fn new(block_size: u32, total_blocks: u64, seed: u64) -> Result<Self> {
        ensure!(
            block_size.is_power_of_two(),
            "block size must be a power of two"
        );
        ensure!(block_size > 0, "block size must be non-zero");
        ensure!(total_blocks > 0, "total_blocks must be non-zero");
        Ok(Self {
            block_size,
            blocks: total_blocks,
            seed,
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

    fn ensure_in_range(&self, lba: u64, blocks: u64) -> BlockSourceResult<()> {
        let end = lba.checked_add(blocks).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::OutOfRange, "lba overflow")
        })?;
        if end > self.blocks {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::OutOfRange,
                "request past end of device",
            ));
        }
        Ok(())
    }

    fn fill_block(&self, block_id: u64, buf: &mut [u8]) {
        let mut state = self.seed ^ block_id;
        for chunk in buf.chunks_mut(8) {
            state = splitmix64(state);
            let bytes = state.to_le_bytes();
            let copy_len = chunk.len();
            chunk.copy_from_slice(&bytes[..copy_len]);
        }
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
impl BlockSource for RandomBlockSource {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        Ok(self.blocks)
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        if buf.is_empty() {
            return Ok(0);
        }
        let blocks = buf.len() / self.block_size as usize;
        self.ensure_in_range(lba, blocks as u64)?;

        for (idx, chunk) in buf.chunks_mut(self.block_size as usize).enumerate() {
            let block_id = lba + idx as u64;
            self.fill_block(block_id, chunk);
        }

        Ok(buf.len())
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "random block source is read-only",
        ))
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
    file: std::fs::File,
    len: AtomicU64,
    writable: bool,
}

impl BlockFile {
    fn new(file: std::fs::File, len: u64, writable: bool) -> Self {
        Self {
            file,
            len: AtomicU64::new(len),
            writable,
        }
    }

    async fn size(&self) -> io::Result<u64> {
        Ok(self.len.load(Ordering::Relaxed))
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let file = self.file.try_clone()?;
        let len = buf.len();
        let tmp = task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let mut read = 0;
            while read < len {
                let n = file.read_at(&mut tmp[read..], offset + read as u64)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short read from block file",
                    ));
                }
                read += n;
            }
            Ok::<_, io::Error>(tmp)
        })
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))??;
        buf.copy_from_slice(&tmp);
        Ok(())
    }

    async fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "block source opened in read-only mode",
            ));
        }

        let file = self.file.try_clone()?;
        let data = buf.to_vec();
        let len = data.len();
        task::spawn_blocking(move || {
            let mut written = 0;
            while written < len {
                let n = file.write_at(&data[written..], offset + written as u64)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short write to block file",
                    ));
                }
                written += n;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|err| Err(io::Error::new(io::ErrorKind::Other, err.to_string())))?;

        let end = offset
            .checked_add(u64::try_from(len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "write length exceeds u64")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "write offset overflow"))?;
        self.len.fetch_max(end, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let file = self.file.try_clone()?;
        task::spawn_blocking(move || file.sync_data())
            .await
            .unwrap_or_else(|err| {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("flush join error: {err}"),
                ))
            })
    }
}

struct OpenedBlockFile {
    file: std::fs::File,
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

    let file = file.into_std().await;

    Ok(OpenedBlockFile {
        file,
        len,
        writable,
    })
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_block(source: &RandomBlockSource, lba: u64) -> Vec<u8> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut buf = vec![0u8; source.block_size as usize];
        rt.block_on(source.read_blocks(lba, &mut buf)).unwrap();
        buf
    }

    #[test]
    fn random_source_deterministic() {
        let source = RandomBlockSource::new(512, 8, 0xdead_beef).unwrap();
        let a = read_block(&source, 0);
        let b = read_block(&source, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn random_source_changes_per_block() {
        let source = RandomBlockSource::new(512, 8, 0xdead_beef).unwrap();
        let a = read_block(&source, 1);
        let b = read_block(&source, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn random_source_rejects_writes() {
        let source = RandomBlockSource::new(512, 4, 1).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(source.write_blocks(0, &[0u8; 512]))
            .unwrap_err();
        assert_eq!(err.kind(), BlockSourceErrorKind::Unsupported);
    }
}
