use crate::dir::FileId;
use core::fmt;

/// Errors produced by [`CatDataProvider`] implementations.
#[derive(Debug, Clone, Copy)]
pub enum ProviderError {
    /// Generic I/O style failure.
    Io,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::Io => write!(f, "provider error"),
        }
    }
}

/// Supplies bytes for each synthetic cat image.
pub trait CatDataProvider: Send + Sync {
    /// Logical size of the file in bytes.
    fn file_len(&self, id: FileId) -> u64;

    /// Populate `buf` with file data at a specific offset.
    fn read_at(&self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<(), ProviderError>;
}

/// Simple deterministic provider used for debug/testing.
#[derive(Debug, Clone, Copy)]
pub struct DebugPatternProvider {
    len: u64,
}

impl DebugPatternProvider {
    /// Create a provider that exposes fixed-size files.
    pub const fn new(len: u64) -> Self {
        Self { len }
    }
}

impl Default for DebugPatternProvider {
    fn default() -> Self {
        Self::new(256 * 1024)
    }
}

impl CatDataProvider for DebugPatternProvider {
    fn file_len(&self, _id: FileId) -> u64 {
        self.len
    }

    fn read_at(&self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<(), ProviderError> {
        let size = self.len;
        for (i, byte) in buf.iter_mut().enumerate() {
            let absolute = offset + i as u64;
            if absolute >= size {
                *byte = 0;
                continue;
            }
            let base = ((id.dir_index as u64) << 32) | id.file_index as u64;
            let value = base.wrapping_add(absolute);
            *byte = value as u8;
        }
        Ok(())
    }
}
