use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, Transport, TransportError,
    TransportErrorKind,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
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
        let request = match self.transport.read_request().await {
            Ok(req) => req,
            Err(err) if err.kind() == TransportErrorKind::Timeout => {
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        let response = self.handle_request(request).await?;
        self.transport.send_response(response).await?;
        Ok(())
    }

    async fn handle_request(&mut self, request: Request) -> HostResult<Response> {
        match request.op {
            OpCode::Read => self.handle_read(request).await,
            OpCode::Write => self.handle_write(request).await,
            OpCode::Flush => match self.source.flush().await {
                Ok(()) => Ok(Response::new(
                    request.export_id,
                    OpCode::Flush,
                    0,
                    request.lba,
                    request.num_blocks,
                    0,
                )),
                Err(err) => Ok(response_from_block_error(request, err)),
            },
            OpCode::Discard => match self.source.discard(request.lba, request.num_blocks).await {
                Ok(()) => Ok(Response::new(
                    request.export_id,
                    OpCode::Discard,
                    0,
                    request.lba,
                    request.num_blocks,
                    0,
                )),
                Err(err) => Ok(response_from_block_error(request, err)),
            },
        }
    }

    async fn handle_read(&mut self, request: Request) -> HostResult<Response> {
        let block_size = self.source.block_size() as usize;
        let byte_len = match self.blocks_to_bytes(request.num_blocks, block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = match self.source.read_blocks(request.lba, &mut buf).await {
                Ok(len) => len,
                Err(err) => return Ok(response_from_block_error(request, err)),
            };
            if read != byte_len {
                return Ok(short_io_response(request));
            }
            self.transport.write_bulk(&buf).await?;
        }
        Ok(Response::new(
            request.export_id,
            OpCode::Read,
            0,
            request.lba,
            request.num_blocks,
            0,
        ))
    }

    async fn handle_write(&mut self, request: Request) -> HostResult<Response> {
        let block_size = self.source.block_size() as usize;
        let byte_len = match self.blocks_to_bytes(request.num_blocks, block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            self.transport.read_bulk(&mut buf).await?;
            let written = match self.source.write_blocks(request.lba, &buf).await {
                Ok(len) => len,
                Err(err) => return Ok(response_from_block_error(request, err)),
            };
            if written != byte_len {
                return Ok(short_io_response(request));
            }
        }
        Ok(Response::new(
            request.export_id,
            OpCode::Write,
            0,
            request.lba,
            request.num_blocks,
            0,
        ))
    }

    fn blocks_to_bytes(&self, num_blocks: u32, block_size: usize) -> HostResult<usize> {
        if block_size == 0 {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "block size is zero",
            ));
        }
        usize::try_from(num_blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(block_size))
            .ok_or_else(|| {
                HostError::with_message(HostErrorKind::InvalidRequest, "request length overflow")
            })
    }
}

const ERRNO_EINVAL: u32 = 22;
const ERRNO_EIO: u32 = 5;
const ERRNO_EOPNOTSUPP: u32 = 95;

fn invalid_request_response(request: Request) -> Response {
    Response::new(
        request.export_id,
        request.op,
        errno_to_status(ERRNO_EINVAL),
        request.lba,
        request.num_blocks,
        0,
    )
}

fn short_io_response(request: Request) -> Response {
    Response::new(
        request.export_id,
        request.op,
        errno_to_status(ERRNO_EIO),
        request.lba,
        request.num_blocks,
        0,
    )
}

fn response_from_block_error(request: Request, err: BlockSourceError) -> Response {
    let errno = match err.kind() {
        BlockSourceErrorKind::InvalidInput | BlockSourceErrorKind::OutOfRange => ERRNO_EINVAL,
        BlockSourceErrorKind::Unsupported => ERRNO_EOPNOTSUPP,
        BlockSourceErrorKind::Io | BlockSourceErrorKind::Other => ERRNO_EIO,
    };
    Response::new(
        request.export_id,
        request.op,
        errno_to_status(errno),
        request.lba,
        request.num_blocks,
        0,
    )
}

fn errno_to_status(errno: u32) -> u8 {
    u8::try_from(errno).unwrap_or(u8::MAX)
}
