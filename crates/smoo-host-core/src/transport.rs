use alloc::string::String;
use async_trait::async_trait;
use core::fmt;
use smoo_proto::{Request, Response};

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

/// Issues vendor control transfers on the smoo interface.
#[async_trait]
pub trait ControlTransport: Send {
    /// Execute a control IN transfer and write the received bytes into `buf`.
    async fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> TransportResult<usize>;

    /// Execute a control OUT transfer with the provided payload.
    async fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> TransportResult<()>;
}

/// Abstracts the USB transport that carries control-plane messages between the
/// host and gadget.
#[async_trait]
pub trait Transport: ControlTransport {
    /// Receive the next Request from the gadget (interrupt IN).
    async fn read_request(&mut self) -> TransportResult<Request>;

    /// Send a Response back to the gadget (interrupt OUT).
    async fn send_response(&mut self, response: Response) -> TransportResult<()>;

    /// Read a full payload from the gadget over the bulk IN endpoint.
    async fn read_bulk(&mut self, buf: &mut [u8]) -> TransportResult<()>;

    /// Write a full payload to the gadget over the bulk OUT endpoint.
    async fn write_bulk(&mut self, buf: &[u8]) -> TransportResult<()>;
}
