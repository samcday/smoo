use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, Transport, TransportError,
    TransportErrorKind,
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use smoo_proto::{OpCode, Request, Response};

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
    exports: BTreeMap<u32, ExportHandle<S>>,
}

/// Descriptor for a host-side export.
#[derive(Clone)]
pub struct HostExport<S> {
    pub export_id: u32,
    pub source: S,
    pub block_size: u32,
    pub size_bytes: u64,
}

#[derive(Clone)]
struct ExportHandle<S> {
    source: S,
    block_size: u32,
    size_bytes: u64,
}

impl<T, S> SmooHost<T, S>
where
    T: Transport,
    S: BlockSource + Clone,
{
    pub fn new(transport: T, exports: Vec<HostExport<S>>) -> Self {
        let mut map = BTreeMap::new();
        for entry in exports {
            map.insert(
                entry.export_id,
                ExportHandle {
                    source: entry.source,
                    block_size: entry.block_size,
                    size_bytes: entry.size_bytes,
                },
            );
        }
        Self {
            transport,
            exports: map,
        }
    }

    pub async fn run_once(&mut self) -> HostResult<()> {
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
        let export = match self.exports.get(&request.export_id) {
            Some(export) => export.clone(),
            None => return Ok(missing_export_response(&request)),
        };
        match request.op {
            OpCode::Read => self.handle_read(export.clone(), &request).await,
            OpCode::Write => self.handle_write(export.clone(), &request).await,
            OpCode::Flush => match export.source.flush().await {
                Ok(()) => Ok(Response::new(
                    request.export_id,
                    OpCode::Flush,
                    0,
                    request.lba,
                    request.num_blocks,
                    0,
                )),
                Err(err) => Ok(response_from_block_error(&request, err)),
            },
            OpCode::Discard => {
                if !self.validate_bounds(&export, &request) {
                    return Ok(invalid_request_response(&request));
                }
                match export.source.discard(request.lba, request.num_blocks).await {
                    Ok(()) => Ok(Response::new(
                        request.export_id,
                        OpCode::Discard,
                        0,
                        request.lba,
                        request.num_blocks,
                        0,
                    )),
                    Err(err) => Ok(response_from_block_error(&request, err)),
                }
            }
        }
    }

    async fn handle_read(
        &mut self,
        export: ExportHandle<S>,
        request: &Request,
    ) -> HostResult<Response> {
        if !self.validate_bounds(&export, request) {
            return Ok(invalid_request_response(request));
        }
        let byte_len = match blocks_to_bytes(request.num_blocks, export.block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            let read = match export.source.read_blocks(request.lba, &mut buf).await {
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

    async fn handle_write(
        &mut self,
        export: ExportHandle<S>,
        request: &Request,
    ) -> HostResult<Response> {
        if !self.validate_bounds(&export, request) {
            return Ok(invalid_request_response(request));
        }
        let byte_len = match blocks_to_bytes(request.num_blocks, export.block_size) {
            Ok(len) => len,
            Err(_) => return Ok(invalid_request_response(request)),
        };
        if byte_len > 0 {
            let mut buf: Vec<u8> = vec![0u8; byte_len];
            self.transport.read_bulk(&mut buf).await?;
            let written = match export.source.write_blocks(request.lba, &buf).await {
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

    fn validate_bounds(&self, export: &ExportHandle<S>, request: &Request) -> bool {
        if export.block_size == 0 {
            return false;
        }
        if let Some(capacity_blocks) = capacity_blocks(export.size_bytes, export.block_size) {
            let request_blocks = request.num_blocks as u64;
            if request_blocks == 0 {
                return request.lba <= capacity_blocks;
            }
            match request.lba.checked_add(request_blocks) {
                Some(end) => end <= capacity_blocks,
                None => false,
            }
        } else {
            true
        }
    }
}

const ERRNO_EINVAL: u8 = 22;
const ERRNO_EIO: u8 = 5;
const ERRNO_EOPNOTSUPP: u8 = 95;

fn invalid_request_response(request: &Request) -> Response {
    Response::new(
        request.export_id,
        request.op,
        ERRNO_EINVAL,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn short_io_response(request: &Request) -> Response {
    Response::new(
        request.export_id,
        request.op,
        ERRNO_EIO,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn missing_export_response(request: &Request) -> Response {
    Response::new(request.export_id, request.op, ERRNO_EINVAL, 0, 0, 0)
}

fn response_from_block_error(request: &Request, err: BlockSourceError) -> Response {
    let errno = match err.kind() {
        BlockSourceErrorKind::InvalidInput | BlockSourceErrorKind::OutOfRange => ERRNO_EINVAL,
        BlockSourceErrorKind::Unsupported => ERRNO_EOPNOTSUPP,
        BlockSourceErrorKind::Io | BlockSourceErrorKind::Other => ERRNO_EIO,
    };
    Response::new(
        request.export_id,
        request.op,
        errno,
        request.lba,
        request.num_blocks,
        0,
    )
}

fn blocks_to_bytes(num_blocks: u32, block_size: u32) -> HostResult<usize> {
    let block_size = block_size as usize;
    let blocks = num_blocks as usize;
    block_size.checked_mul(blocks).ok_or_else(|| {
        HostError::with_message(HostErrorKind::InvalidRequest, "block count overflow")
    })
}

fn capacity_blocks(size_bytes: u64, block_size: u32) -> Option<u64> {
    if size_bytes == 0 {
        None
    } else {
        Some(size_bytes / block_size as u64)
    }
}
