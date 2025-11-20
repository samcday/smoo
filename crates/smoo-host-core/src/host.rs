use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, Transport, TransportError,
    TransportErrorKind, TransportResult,
    control::{ConfigExportsV0, fetch_ident, send_config_exports_v0},
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use smoo_proto::{Ident, OpCode, REQUEST_LEN, RESPONSE_LEN, Request, Response};

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

/// Core host driver tying a [`Transport`] to one or more [`BlockSource`]s.
pub struct SmooHost<T, S> {
    transport: T,
    sources: BTreeMap<u32, S>,
    ident: Option<Ident>,
}

impl<T, S> SmooHost<T, S>
where
    T: Transport,
    S: BlockSource,
{
    pub fn new(transport: T, sources: BTreeMap<u32, S>) -> Self {
        Self {
            transport,
            sources,
            ident: None,
        }
    }

    pub fn ident(&self) -> Option<Ident> {
        self.ident
    }

    /// Record a previously obtained Ident to avoid reissuing the control transfer.
    pub fn record_ident(&mut self, ident: Ident) {
        self.ident = Some(ident);
    }

    pub async fn setup(&mut self) -> HostResult<Ident> {
        if let Some(ident) = self.ident {
            return Ok(ident);
        }
        let ident = fetch_ident(&self.transport).await?;
        self.ident = Some(ident);
        Ok(ident)
    }

    /// Send an explicit v0 CONFIG_EXPORTS payload.
    pub async fn configure_exports_v0(&mut self, payload: &ConfigExportsV0) -> HostResult<()> {
        send_config_exports_v0(&self.transport, payload).await?;
        Ok(())
    }

    pub async fn run_once(&mut self) -> HostResult<()> {
        if self.ident.is_none() {
            self.setup().await?;
        }
        let request = match self.read_request().await {
            Ok(req) => req,
            Err(err) if err.kind() == TransportErrorKind::Timeout => {
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        let response = self.handle_request(request).await?;
        self.send_response(response).await?;
        Ok(())
    }

    async fn handle_request(&mut self, request: Request) -> HostResult<Response> {
        let export_id = request.export_id;
        let mut source = match self.sources.remove(&export_id) {
            Some(src) => src,
            None => return Ok(invalid_request_response(request, ERRNO_EINVAL)),
        };
        let result = match request.op {
            OpCode::Read => self.handle_read(&mut source, request).await,
            OpCode::Write => self.handle_write(&mut source, request).await,
            OpCode::Flush => match source.flush().await {
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
            OpCode::Discard => match source.discard(request.lba, request.num_blocks).await {
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
        };
        self.sources.insert(export_id, source);
        result
    }

    async fn handle_read(&mut self, source: &mut S, request: Request) -> HostResult<Response> {
        let block_size = source.block_size();
        let byte_len = match self.blocks_to_bytes(request.num_blocks, block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request, ERRNO_EINVAL)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = match source.read_blocks(request.lba, &mut buf).await {
                Ok(len) => len,
                Err(err) => return Ok(response_from_block_error(request, err)),
            };
            if read != byte_len {
                return Ok(short_io_response(request));
            }
            let written = self.transport.write_bulk(&buf).await?;
            if written != byte_len {
                return Err(protocol_error(format!(
                    "bulk write truncated (expected {byte_len}, wrote {written})"
                ))
                .into());
            }
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

    async fn handle_write(&mut self, source: &mut S, request: Request) -> HostResult<Response> {
        let block_size = source.block_size();
        let byte_len = match self.blocks_to_bytes(request.num_blocks, block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request, ERRNO_EINVAL)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = self.transport.read_bulk(&mut buf).await?;
            if read != byte_len {
                return Err(protocol_error(format!(
                    "bulk read truncated (expected {byte_len}, got {read})"
                ))
                .into());
            }
            let written = match source.write_blocks(request.lba, &buf).await {
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

    fn blocks_to_bytes(&self, num_blocks: u32, block_size: u32) -> HostResult<usize> {
        if block_size == 0 {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "block size is zero",
            ));
        }
        num_blocks
            .checked_mul(block_size)
            .map(|len| len as usize)
            .ok_or_else(|| {
                HostError::with_message(HostErrorKind::InvalidRequest, "request size overflow")
            })
    }

    async fn read_request(&mut self) -> TransportResult<Request> {
        let mut buf = [0u8; REQUEST_LEN];
        let len = self.transport.read_interrupt(&mut buf).await?;
        if len != REQUEST_LEN {
            return Err(protocol_error(format!(
                "request transfer truncated (expected {REQUEST_LEN}, got {len})"
            )));
        }
        Request::decode(buf).map_err(|err| protocol_error(format!("decode request: {err}")))
    }

    async fn send_response(&mut self, response: Response) -> HostResult<()> {
        let data = response.encode();
        let written = self.transport.write_interrupt(&data).await?;
        if written != RESPONSE_LEN {
            return Err(protocol_error(format!(
                "response transfer truncated (expected {RESPONSE_LEN}, wrote {written})"
            ))
            .into());
        }
        Ok(())
    }
}

const ERRNO_EINVAL: u32 = 22;
const ERRNO_EIO: u32 = 5;
const ERRNO_EOPNOTSUPP: u32 = 95;

fn invalid_request_response(request: Request, errno: u32) -> Response {
    Response::new(
        request.export_id,
        request.op,
        errno as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn short_io_response(request: Request) -> Response {
    Response::new(
        request.export_id,
        request.op,
        ERRNO_EIO as u8,
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
        errno as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}
