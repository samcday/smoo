use alloc::string::String;
use async_trait::async_trait;
use core::fmt;

pub type BlockSourceResult<T> = core::result::Result<T, BlockSourceError>;

/// Describes the failure category for block source operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSourceErrorKind {
    InvalidInput,
    OutOfRange,
    Io,
    Unsupported,
    Other,
}

/// Error surfaced by [`BlockSource`] implementations.
#[derive(Clone, Debug)]
pub struct BlockSourceError {
    kind: BlockSourceErrorKind,
    message: Option<String>,
}

impl BlockSourceError {
    pub const fn new(kind: BlockSourceErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: BlockSourceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> BlockSourceErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for BlockSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BlockSourceError {}

/// Abstraction over a readable/writable block storage source.
///
/// Implementations operate on logical block units (typically 512 bytes) and the caller
/// is expected to pass buffers whose lengths are exact multiples of the reported block size.
#[async_trait]
pub trait BlockSource: Send + Sync {
    /// Logical block size in bytes.
    fn block_size(&self) -> u32;

    /// Total number of logical blocks available.
    async fn total_blocks(&self) -> BlockSourceResult<u64>;

    /// Read one or more blocks starting at `lba` into `buf`.
    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize>;

    /// Write one or more blocks starting at `lba` from `buf`.
    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize>;

    /// Flush outstanding writes to durable media.
    async fn flush(&self) -> BlockSourceResult<()> {
        Ok(())
    }

    /// Hint that the given range may be discarded.
    async fn discard(&self, _lba: u64, _num_blocks: u32) -> BlockSourceResult<()> {
        Ok(())
    }
}
