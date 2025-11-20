use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, Transport, TransportError,
    TransportErrorKind, TransportResult,
    control::{ConfigExportsV0Payload, fetch_ident, send_config_exports_v0},
};
use alloc::{
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

    /// Configure the gadget with a single export matching the provided block size and capacity.
    pub async fn configure_single_export_v0(
        &mut self,
        block_size: u32,
        size_bytes: u64,
    ) -> HostResult<()> {
        let payload = ConfigExportsV0Payload::single_export(block_size, size_bytes);
        self.configure_exports_v0(&payload).await
    }

    /// Send an explicit v0 CONFIG_EXPORTS payload.
    pub async fn configure_exports_v0(
        &mut self,
        payload: &ConfigExportsV0Payload,
    ) -> HostResult<()> {
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
        match request.op {
            OpCode::Read => self.handle_read(request).await,
            OpCode::Write => self.handle_write(request).await,
            OpCode::Flush => match self.source.flush().await {
                Ok(()) => Ok(Response::new(
                    OpCode::Flush,
                    request.lba,
                    request.byte_len,
                    0,
                )),
                Err(err) => Ok(response_from_block_error(request, err)),
            },
            OpCode::Discard => {
                let block_size = self.source.block_size();
                let blocks = match self.byte_len_to_blocks(request.byte_len, block_size) {
                    Ok(value) => value,
                    Err(_) => return Ok(invalid_request_response(request)),
                };
                match self.source.discard(request.lba, blocks).await {
                    Ok(()) => Ok(Response::new(
                        OpCode::Discard,
                        request.lba,
                        request.byte_len,
                        0,
                    )),
                    Err(err) => Ok(response_from_block_error(request, err)),
                }
            }
        }
    }

    async fn handle_read(&mut self, request: Request) -> HostResult<Response> {
        let block_size = self.source.block_size();
        if self
            .byte_len_to_blocks(request.byte_len, block_size)
            .is_err()
        {
            return Ok(invalid_request_response(request));
        }
        let byte_len = request.byte_len as usize;
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = match self.source.read_blocks(request.lba, &mut buf).await {
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
            OpCode::Read,
            request.lba,
            request.byte_len,
            0,
        ))
    }

    async fn handle_write(&mut self, request: Request) -> HostResult<Response> {
        let block_size = self.source.block_size();
        if self
            .byte_len_to_blocks(request.byte_len, block_size)
            .is_err()
        {
            return Ok(invalid_request_response(request));
        }
        let byte_len = request.byte_len as usize;
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = self.transport.read_bulk(&mut buf).await?;
            if read != byte_len {
                return Err(protocol_error(format!(
                    "bulk read truncated (expected {byte_len}, got {read})"
                ))
                .into());
            }
            let written = match self.source.write_blocks(request.lba, &buf).await {
                Ok(len) => len,
                Err(err) => return Ok(response_from_block_error(request, err)),
            };
            if written != byte_len {
                return Ok(short_io_response(request));
            }
        }
        Ok(Response::new(
            OpCode::Write,
            request.lba,
            request.byte_len,
            0,
        ))
    }

    fn byte_len_to_blocks(&self, byte_len: u32, block_size: u32) -> HostResult<u32> {
        if block_size == 0 {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "block size is zero",
            ));
        }
        if !byte_len.is_multiple_of(block_size) {
            return Err(HostError::with_message(
                HostErrorKind::InvalidRequest,
                "request byte length must align to block size",
            ));
        }
        Ok(byte_len / block_size)
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

fn invalid_request_response(request: Request) -> Response {
    Response::new(request.op, request.lba, 0, ERRNO_EINVAL)
}

fn short_io_response(request: Request) -> Response {
    Response::new(request.op, request.lba, 0, ERRNO_EIO)
}

fn response_from_block_error(request: Request, err: BlockSourceError) -> Response {
    let errno = match err.kind() {
        BlockSourceErrorKind::InvalidInput | BlockSourceErrorKind::OutOfRange => ERRNO_EINVAL,
        BlockSourceErrorKind::Unsupported => ERRNO_EOPNOTSUPP,
        BlockSourceErrorKind::Io | BlockSourceErrorKind::Other => ERRNO_EIO,
    };
    Response::new(request.op, request.lba, 0, errno)
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}
