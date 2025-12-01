use crate::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, ControlTransport, ExportIdentity,
    HostIoPumpHandle, HostIoPumpRequestRx, TransportError, TransportErrorKind,
    control::{ConfigExportsV0, fetch_ident, send_config_exports_v0},
};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use futures_util::{StreamExt, future::FutureExt, stream::FuturesUnordered};
use smoo_proto::{Ident, OpCode, Request, Response};
use tracing::trace;

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

/// Core host driver tying a [`HostIoPumpHandle`] to one or more [`BlockSource`]s.
pub struct SmooHost<S> {
    pump: HostIoPumpHandle,
    requests: HostIoPumpRequestRx,
    sources: BTreeMap<u32, S>,
    ident: Option<Ident>,
    in_flight: FuturesUnordered<InFlightFuture>,
}

type InFlightFuture = Pin<Box<dyn Future<Output = HostResult<Response>> + Send>>;

impl<S> SmooHost<S>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    pub fn new(
        pump: HostIoPumpHandle,
        requests: HostIoPumpRequestRx,
        sources: BTreeMap<u32, S>,
    ) -> Self {
        Self {
            pump,
            requests,
            sources,
            ident: None,
            in_flight: FuturesUnordered::new(),
        }
    }

    pub fn ident(&self) -> Option<Ident> {
        self.ident
    }

    /// Record a previously obtained Ident to avoid reissuing the control transfer.
    pub fn record_ident(&mut self, ident: Ident) {
        self.ident = Some(ident);
    }

    pub async fn setup<C>(&mut self, control: &C) -> HostResult<Ident>
    where
        C: ControlTransport + Sync,
    {
        if let Some(ident) = self.ident {
            return Ok(ident);
        }
        let ident = fetch_ident(control).await?;
        self.ident = Some(ident);
        Ok(ident)
    }

    /// Send an explicit v0 CONFIG_EXPORTS payload.
    pub async fn configure_exports_v0<C>(
        &mut self,
        control: &C,
        payload: &ConfigExportsV0,
    ) -> HostResult<()>
    where
        C: ControlTransport + Sync,
    {
        send_config_exports_v0(control, payload).await?;
        Ok(())
    }

    pub async fn run_once(&mut self) -> HostResult<()> {
        while let Some(resp) = self.in_flight.next().now_or_never().flatten() {
            let response = resp?;
            self.send_response(response).await?;
        }

        let request = match self.requests.next().now_or_never() {
            Some(Some(req)) => req,
            Some(None) => return Err(TransportError::new(TransportErrorKind::Disconnected).into()),
            None => return Ok(()),
        };
        trace!(
            request_id = request.request_id,
            export_id = request.export_id,
            op = ?request.op,
            lba = request.lba,
            blocks = request.num_blocks,
            "host: received Request"
        );
        let source = match self.sources.get(&request.export_id).cloned() {
            Some(src) => src,
            None => {
                self.send_response(invalid_request_response(request, ERRNO_EINVAL))
                    .await?;
                return Ok(());
            }
        };
        let pump = self.pump.clone();
        self.in_flight
            .push(Box::pin(handle_request(pump, source, request)));
        Ok(())
    }

    async fn send_response(&self, response: Response) -> HostResult<()> {
        self.pump.send_response(response).await?;
        Ok(())
    }
}

const ERRNO_EINVAL: u32 = 22;
const ERRNO_EIO: u32 = 5;
const ERRNO_EOPNOTSUPP: u32 = 95;

async fn handle_request<S>(
    pump: HostIoPumpHandle,
    source: S,
    request: Request,
) -> HostResult<Response>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    match request.op {
        OpCode::Read => handle_read(pump, source, request).await,
        OpCode::Write => handle_write(pump, source, request).await,
        OpCode::Flush => match source.flush().await {
            Ok(()) => Ok(Response::new(
                request.export_id,
                request.request_id,
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
                request.request_id,
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

async fn handle_read<S>(pump: HostIoPumpHandle, source: S, request: Request) -> HostResult<Response>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    let block_size = source.block_size();
    let byte_len = match blocks_to_bytes(request.num_blocks, block_size) {
        Ok(len) => len,
        Err(_) => return Ok(invalid_request_response(request, ERRNO_EINVAL)),
    };
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        bytes = byte_len,
        "host: handling read"
    );
    if byte_len > 0 {
        let mut buf: Vec<u8> = vec![0u8; byte_len];
        let read = match source.read_blocks(request.lba, &mut buf).await {
            Ok(len) => len,
            Err(err) => return Ok(response_from_block_error(request, err)),
        };
        if read != byte_len {
            return Ok(short_io_response(request));
        }
        pump.write_bulk(buf).await?;
    }
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        "host: read complete"
    );
    Ok(Response::new(
        request.export_id,
        request.request_id,
        OpCode::Read,
        0,
        request.lba,
        request.num_blocks,
        0,
    ))
}

async fn handle_write<S>(
    pump: HostIoPumpHandle,
    source: S,
    request: Request,
) -> HostResult<Response>
where
    S: BlockSource + ExportIdentity + Clone + Send + 'static,
{
    let block_size = source.block_size();
    let byte_len = match blocks_to_bytes(request.num_blocks, block_size) {
        Ok(len) => len,
        Err(_) => return Ok(invalid_request_response(request, ERRNO_EINVAL)),
    };
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        bytes = byte_len,
        "host: handling write"
    );
    if byte_len > 0 {
        let buf = pump.read_bulk(byte_len).await?;
        let written = match source.write_blocks(request.lba, &buf).await {
            Ok(len) => len,
            Err(err) => return Ok(response_from_block_error(request, err)),
        };
        if written != byte_len {
            return Ok(short_io_response(request));
        }
    }
    trace!(
        request_id = request.request_id,
        export_id = request.export_id,
        lba = request.lba,
        num_blocks = request.num_blocks,
        result = %request.num_blocks,
        "host: write complete"
    );
    Ok(Response::new(
        request.export_id,
        request.request_id,
        OpCode::Write,
        0,
        request.lba,
        request.num_blocks,
        0,
    ))
}

fn blocks_to_bytes(num_blocks: u32, block_size: u32) -> HostResult<usize> {
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

fn invalid_request_response(request: Request, errno: u32) -> Response {
    Response::new(
        request.export_id,
        request.request_id,
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
        request.request_id,
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
        request.request_id,
        request.op,
        errno as u8,
        request.lba,
        request.num_blocks,
        0,
    )
}
