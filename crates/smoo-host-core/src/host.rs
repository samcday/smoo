use crate::{BlockSource, BlockSourceError, Transport, TransportError};
use alloc::string::{String, ToString};
use core::fmt;
use smoo_proto::{Ident, OpCode, Request, Response};

/// Host error categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostErrorKind {
    Transport,
    BlockSource,
    InvalidRequest,
    Unsupported,
    NotReady,
}

/// Errors surfaced by [`SmooHost`].
#[derive(Clone, Debug)]
pub struct HostError {
    kind: HostErrorKind,
    message: Option<String>,
}

impl HostError {
    pub fn new(kind: HostErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    pub fn with_message(kind: HostErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    pub fn kind(&self) -> HostErrorKind {
        self.kind
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(msg) => write!(f, "{:?}: {}", self.kind, msg),
            None => write!(f, "{:?}", self.kind),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HostError {}

impl From<TransportError> for HostError {
    fn from(err: TransportError) -> Self {
        HostError::with_message(HostErrorKind::Transport, err.to_string())
    }
}

impl From<BlockSourceError> for HostError {
    fn from(err: BlockSourceError) -> Self {
        HostError::with_message(HostErrorKind::BlockSource, err.to_string())
    }
}

pub type HostResult<T> = core::result::Result<T, HostError>;

/// Core host driver tying a [`Transport`] to a [`BlockSource`].
pub struct SmooHost<T, S> {
    transport: T,
    source: S,
    ident: Option<Ident>,
}

impl<T, S> SmooHost<T, S>
where
    T: Transport,
    S: BlockSource,
{
    pub fn new(transport: T, source: S) -> Self {
        Self {
            transport,
            source,
            ident: None,
        }
    }

    pub fn ident(&self) -> Option<Ident> {
        self.ident
    }

    pub async fn setup(&mut self) -> HostResult<Ident> {
        let ident = self.transport.setup().await?;
        self.ident = Some(ident);
        Ok(ident)
    }

    pub async fn run_once(&mut self) -> HostResult<()> {
        if self.ident.is_none() {
            self.setup().await?;
        }
        let request = self.transport.read_request().await?;
        let response = self.handle_request(request).await?;
        self.transport.send_response(response).await?;
        Ok(())
    }

    async fn handle_request(&mut self, request: Request) -> HostResult<Response> {
        match request.op {
            OpCode::Read | OpCode::Write => Err(HostError::with_message(
                HostErrorKind::Unsupported,
                "data path not implemented",
            )),
            OpCode::Flush => {
                self.source.flush().await?;
                Ok(Response::new(
                    OpCode::Flush,
                    request.lba,
                    request.byte_len,
                    0,
                ))
            }
            OpCode::Discard => {
                let block_size = self.source.block_size();
                let blocks = self.byte_len_to_blocks(request.byte_len, block_size)?;
                self.source.discard(request.lba, blocks).await?;
                Ok(Response::new(
                    OpCode::Discard,
                    request.lba,
                    request.byte_len,
                    0,
                ))
            }
        }
    }

    fn byte_len_to_blocks(&self, byte_len: u32, block_size: u32) -> HostResult<u32> {
        if block_size == 0 {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "block size is zero",
            ));
        }
        if byte_len % block_size != 0 {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "request byte length must align to block size",
            ));
        }
        Ok(byte_len / block_size)
    }
}
