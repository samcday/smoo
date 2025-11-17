use alloc::string::String;
use async_trait::async_trait;
use core::fmt;
use smoo_proto::{Ident, Request, Response};

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

/// Abstracts the USB transport that carries control-plane messages between the
/// host and gadget.
#[async_trait]
pub trait Transport: Send {
    /// Execute the FunctionFS Ident handshake and return the gadget's reported Ident.
    async fn setup(&mut self) -> TransportResult<Ident>;

    /// Receive the next Request from the gadget (interrupt IN).
    async fn read_request(&mut self) -> TransportResult<Request>;

    /// Send a Response back to the gadget (interrupt OUT).
    async fn send_response(&mut self, response: Response) -> TransportResult<()>;
}
