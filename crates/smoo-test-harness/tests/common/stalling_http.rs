//! Stalling HTTP block source and device-read helpers shared by the
//! park-and-replay scenarios (`link_replay`, `udc_rebind`).

// Each scenario binary uses a different subset.
#![allow(dead_code)]

use std::convert::Infallible;
use std::io::SeekFrom;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::BlockSource;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;

/// Assert that a device read is still parked: it neither completes nor fails within `timeout`.
pub async fn assert_device_read_pending(
    task: &mut JoinHandle<Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<()> {
    match tokio::time::timeout(timeout, task).await {
        Ok(joined) => match joined.context("device read task panicked")? {
            Ok(_) => bail!("device read completed while the link was down; expected parked I/O"),
            Err(err) => {
                bail!("device read failed while the link was down; expected parked I/O: {err:#}")
            }
        },
        Err(_) => Ok(()),
    }
}

/// Read `len` bytes at block `lba` of the block device at `path`.
pub async fn read_device_bytes(
    path: PathBuf,
    block_size: u32,
    lba: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let offset = lba
        .checked_mul(block_size as u64)
        .context("read offset overflow")?;
    file.seek(SeekFrom::Start(offset))
        .await
        .with_context(|| format!("seek {} +{offset}", path.display()))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)
        .await
        .with_context(|| format!("read {len} bytes from {}", path.display()))?;
    Ok(buf)
}

/// Compare a device read with the backing bytes and report the first difference.
pub fn ensure_read_matches(actual: &[u8], expected: &[u8]) -> Result<()> {
    ensure!(
        actual.len() == expected.len(),
        "replayed read length mismatch: got {}, expected {}",
        actual.len(),
        expected.len()
    );
    if actual == expected {
        return Ok(());
    }
    let diff = actual
        .iter()
        .zip(expected.iter())
        .position(|(a, e)| a != e)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    let actual_byte = actual.get(diff).copied();
    let expected_byte = expected.get(diff).copied();
    bail!(
        "replayed read returned wrong bytes: first diff at offset {diff} (actual={actual_byte:?} expected={expected_byte:?})"
    );
}

/// HTTP block source that serves every range at once, except one target block.
///
/// Once armed, a request for exactly the target block counts towards
/// [`Self::target_request_count`] and then waits for [`Self::release`]. Tests use this to
/// hold a device read in flight at a known point.
pub struct StallingHttpSource {
    addr: SocketAddr,
    state: Arc<HttpState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl StallingHttpSource {
    pub fn start(block_size: u32, total_blocks: u64, seed: u64, stall_lba: u64) -> Result<Self> {
        let source = Arc::new(RandomBlockSource::new(block_size, total_blocks, seed)?);
        let total_bytes = block_size as u64 * total_blocks;
        let (stall_start, stall_end) = stall_range(block_size, stall_lba)?;
        let state = Arc::new(HttpState {
            source,
            block_size,
            total_bytes,
            stall_start: AtomicU64::new(stall_start),
            stall_end: AtomicU64::new(stall_end),
            armed: AtomicBool::new(false),
            target_requests: AtomicUsize::new(0),
            target_request_notify: Notify::new(),
            stall_generation: AtomicU64::new(1),
            released_generation: AtomicU64::new(0),
            release_notify: Notify::new(),
        });

        let listener = TcpListener::bind("127.0.0.1:0").context("bind HTTP backing source")?;
        listener
            .set_nonblocking(true)
            .context("set HTTP listener nonblocking")?;
        let addr = listener.local_addr().context("HTTP listener local addr")?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let make_service = make_service_fn({
            let state = state.clone();
            move |_| {
                let state = state.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req| handle_http(req, state.clone())))
                }
            }
        });
        let server = Server::from_tcp(listener)
            .context("build HTTP backing server")?
            .serve(make_service)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
        let task = tokio::spawn(async move {
            if let Err(err) = server.await {
                tracing::warn!(error = ?err, "HTTP backing server exited with error");
            }
        });

        Ok(Self {
            addr,
            state,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn url(&self) -> String {
        format!("http://{}/disk.img", self.addr)
    }

    pub fn arm(&self) {
        self.state.armed.store(true, Ordering::Release);
    }

    pub fn disarm(&self) {
        self.state.armed.store(false, Ordering::Release);
    }

    /// Stall block `lba` from now on, until the next [`Self::release`].
    ///
    /// Requests stalled before this call keep waiting for their own release; a release only
    /// ever frees requests that arrived before it.
    pub fn rearm(&self, lba: u64) -> Result<()> {
        let (start, end) = stall_range(self.state.block_size, lba)?;
        self.state.armed.store(false, Ordering::Release);
        self.state.stall_start.store(start, Ordering::Release);
        self.state.stall_end.store(end, Ordering::Release);
        self.state.stall_generation.fetch_add(1, Ordering::AcqRel);
        self.state.armed.store(true, Ordering::Release);
        Ok(())
    }

    pub fn target_request_count(&self) -> usize {
        self.state.target_requests.load(Ordering::Acquire)
    }

    /// The bytes the source serves for `blocks` blocks at `lba`.
    pub async fn expected_bytes(&self, lba: u64, blocks: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; (blocks * self.state.block_size as u64) as usize];
        self.state
            .source
            .read_blocks(lba, &mut buf)
            .await
            .map_err(|err| anyhow::anyhow!("RandomBlockSource read_blocks: {err}"))?;
        Ok(buf)
    }

    pub async fn wait_for_data_requests(&self, expected: usize, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let seen = self.state.target_requests.load(Ordering::Acquire);
            if seen >= expected {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                bail!(
                    "timed out after {timeout:?} waiting for {expected} HTTP data requests (saw {seen})"
                );
            }
            let notified = self.state.target_request_notify.notified();
            if self.state.target_requests.load(Ordering::Acquire) >= expected {
                return Ok(());
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }

    /// Let every target request that has arrived so far complete.
    pub fn release(&self) {
        let generation = self.state.stall_generation.load(Ordering::Acquire);
        self.state
            .released_generation
            .fetch_max(generation, Ordering::AcqRel);
        self.state.release_notify.notify_waiters();
    }
}

impl Drop for StallingHttpSource {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

struct HttpState {
    source: Arc<RandomBlockSource>,
    block_size: u32,
    total_bytes: u64,
    stall_start: AtomicU64,
    stall_end: AtomicU64,
    armed: AtomicBool,
    target_requests: AtomicUsize,
    target_request_notify: Notify,
    /// Incremented by every re-arm; a stalled request waits for its own generation.
    stall_generation: AtomicU64,
    /// The newest generation [`StallingHttpSource::release`] has let go.
    released_generation: AtomicU64,
    release_notify: Notify,
}

fn stall_range(block_size: u32, lba: u64) -> Result<(u64, u64)> {
    let start = lba
        .checked_mul(block_size as u64)
        .context("stall offset overflow")?;
    let end = start
        .checked_add(block_size as u64)
        .and_then(|end| end.checked_sub(1))
        .context("stall range overflow")?;
    Ok((start, end))
}

async fn handle_http(
    req: Request<Body>,
    state: Arc<HttpState>,
) -> Result<Response<Body>, Infallible> {
    Ok(match handle_http_inner(req, state).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(error = ?err, "HTTP backing request failed");
            response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    })
}

async fn handle_http_inner(req: Request<Body>, state: Arc<HttpState>) -> Result<Response<Body>> {
    if req.method() == Method::HEAD {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(ACCEPT_RANGES, "bytes")
            .header(CONTENT_LENGTH, state.total_bytes.to_string())
            .body(Body::empty())
            .expect("valid HEAD response"))
    } else if req.method() == Method::GET {
        let range = req
            .headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_range_header)
            .context("GET missing valid Range header")?;
        range_response(state, range).await
    } else {
        Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        ))
    }
}

async fn range_response(state: Arc<HttpState>, (start, end): (u64, u64)) -> Result<Response<Body>> {
    ensure!(start <= end, "invalid range {start}-{end}");
    ensure!(
        end < state.total_bytes,
        "range {start}-{end} past backing size"
    );

    let should_stall = state.armed.load(Ordering::Acquire)
        && start == state.stall_start.load(Ordering::Acquire)
        && end == state.stall_end.load(Ordering::Acquire);
    if should_stall {
        let generation = state.stall_generation.load(Ordering::Acquire);
        let seen = state.target_requests.fetch_add(1, Ordering::AcqRel) + 1;
        tracing::info!(seen, start, end, "HTTP backing observed target range");
        state.target_request_notify.notify_waiters();
        wait_until_released(&state, generation).await;
    }

    let body = read_range_bytes(&state, start, end).await?;
    Ok(Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(ACCEPT_RANGES, "bytes")
        .header(
            CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", state.total_bytes),
        )
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .expect("valid range response"))
}

async fn wait_until_released(state: &HttpState, generation: u64) {
    let released = || state.released_generation.load(Ordering::Acquire) >= generation;
    loop {
        if released() {
            return;
        }
        let notified = state.release_notify.notified();
        if released() {
            return;
        }
        notified.await;
    }
}

async fn read_range_bytes(state: &HttpState, start: u64, end: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(end - start + 1).context("range length overflows usize")?;
    let block_size = state.block_size as u64;
    let first_block = start / block_size;
    let block_offset = usize::try_from(start % block_size).expect("block offset fits usize");
    let end_exclusive = end.checked_add(1).context("range end overflow")?;
    let block_count = end_exclusive.div_ceil(block_size) - first_block;
    let mut backing = vec![0u8; usize::try_from(block_count * block_size)?];
    state
        .source
        .read_blocks(first_block, &mut backing)
        .await
        .map_err(|err| anyhow::anyhow!("RandomBlockSource read_blocks: {err}"))?;
    Ok(backing[block_offset..block_offset + len].to_vec())
}

fn parse_range_header(value: &str) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn response(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(body.into())
        .expect("valid response")
}
