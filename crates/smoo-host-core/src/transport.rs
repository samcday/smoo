use alloc::{boxed::Box, string::String};
use async_trait::async_trait;
use core::fmt;

pub type TransportResult<T> = core::result::Result<T, TransportError>;

/// High-level transport failure categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportErrorKind {
    NotReady,
    Disconnected,
    Timeout,
    Protocol,
    Unsupported,
    Other,
}

/// Error surfaced by [`Transport`] implementations.
#[derive(Clone, Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: Option<String>,
}

impl TransportError {
    pub const fn new(kind: TransportErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

/// Provides access to vendor control transfers used by the smoo protocol.
#[async_trait]
pub trait ControlTransport: Send + Sync {
    /// Issue a vendor control IN transfer (device → host).
    ///
    /// Implementations handle the correct interface/index internally.
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize>;

    /// Issue a vendor control OUT transfer (host → device).
    ///
    /// Implementations handle the correct interface/index internally.
    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize>;
}

/// Abstracts the USB transport that carries protocol messages between the
/// host and gadget. This trait is intentionally low-level; smoo-specific
/// encoding/decoding is handled in `host-core`.
#[async_trait]
pub trait Transport: ControlTransport + Send + Sync {
    /// Receive bytes from the Request interrupt endpoint (device → host).
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize>;

    /// Send bytes to the Response interrupt endpoint (host → device).
    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize>;

    /// Read a payload from the gadget over the bulk IN endpoint.
    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize>;

    /// Write a payload to the gadget over the bulk OUT endpoint.
    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize>;
}
