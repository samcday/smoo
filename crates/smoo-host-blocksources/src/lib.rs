pub mod device;
pub mod file;
pub mod random;

use anyhow::{Context, Result};
use core::hash::Hasher;
use smoo_host_core::{BlockSourceError, BlockSourceErrorKind};
use std::{
    io,
    os::unix::fs::FileExt,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{fs::OpenOptions, task};
use tracing::debug;

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
        .map_err(|err| io::Error::other(err.to_string()))??;
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
        .unwrap_or_else(|err| Err(io::Error::other(err.to_string())))?;

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
            .unwrap_or_else(|err| Err(io::Error::other(format!("flush join error: {err}"))))
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
