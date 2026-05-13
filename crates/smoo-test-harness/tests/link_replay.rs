//! Regression: in-flight ublk I/O is parked on host/link loss and replayed
//! after the host reconnects.
//!
//! The backing source is a local HTTP server that completes probe requests but
//! intentionally stalls real range reads. This lets the test put a device read
//! in flight at a deterministic point, kill only `smoo-host`, assert the read
//! remains pending, restart the host, then release the replayed HTTP read and
//! verify the original device read completes with the expected bytes.

mod common;

use std::convert::Infallible;
use std::io::SeekFrom;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use regex::Regex;
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::BlockSource;
use smoo_test_harness::ScenarioBuilder;
use smoo_test_harness::fixture::{GadgetOpts, HostSourceSpec};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;

const SEED: u64 = 0x51A7E;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u64 = 1024;
const READ_LBA: u64 = 123;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn link_replay() -> Result<()> {
    common::init_tracing();

    let server = StallingHttpSource::start(BLOCK_SIZE, TOTAL_BLOCKS, SEED, READ_LBA)?;
    let mut sc = ScenarioBuilder::new("link_replay")
        .with_host_source(HostSourceSpec::Http(server.url()))
        .with_block_size(BLOCK_SIZE)
        .with_gadget_opts(GadgetOpts {
            queue_count: 1,
            queue_depth: 4,
            max_io_bytes: Some(BLOCK_SIZE as u64),
            ..GadgetOpts::default()
        })
        .start()
        .await?;

    let connected_re = Regex::new("connected to smoo gadget")?;
    sc.host()
        .wait_for_log(&connected_re, Duration::from_secs(15))
        .await?;

    let dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(15))
        .await?;
    let dev_path = PathBuf::from(format!("/dev/ublkb{dev_id}"));
    common::wait_for_block_device(&dev_path, Duration::from_secs(5)).await?;

    let expected = expected_bytes(READ_LBA, 1).await?;
    server.arm();
    let initial_data_requests = server.target_request_count();
    let mut read_task = tokio::spawn(read_device_bytes(
        dev_path.clone(),
        READ_LBA,
        BLOCK_SIZE as usize,
    ));

    server
        .wait_for_data_requests(initial_data_requests + 1, Duration::from_secs(15))
        .await?;

    tracing::info!("stopping host with target read in flight");
    sc.stop_host().await?;
    let offline_re = Regex::new(
        "link liveness timeout|link transport offline|request dispatch failed|io pump task exited",
    )?;
    sc.gadget()
        .wait_for_log(&offline_re, Duration::from_secs(10))
        .await?;
    tracing::info!("gadget observed link loss; verifying device read remains parked");
    assert_device_read_pending(&mut read_task, Duration::from_secs(2)).await?;

    let before_restart_data_requests = server.target_request_count();
    tracing::info!("restarting host to trigger parked request replay");
    sc.start_host().await?;
    sc.host()
        .wait_for_log(&connected_re, Duration::from_secs(20))
        .await?;
    server
        .wait_for_data_requests(before_restart_data_requests + 1, Duration::from_secs(15))
        .await?;
    tracing::info!("HTTP backing observed replayed target range; releasing reads");
    server.release();

    let actual = tokio::time::timeout(Duration::from_secs(15), &mut read_task)
        .await
        .context("timed out waiting for parked read to complete after host restart")?
        .context("device read task panicked")??;
    ensure_read_matches(&actual, &expected)?;

    let result = sc.stop().await?;
    if let Some(pcap) = result.pcap_assertions().await? {
        pcap.assert_no_length_mismatch()?;
        pcap.assert_no_orphan_bulk()?;
        pcap.assert_control_handshakes(2)?;
        ensure!(
            pcap.repeated_request_keys() >= 1,
            "link_replay expected at least one repeated request key in {}, got {}",
            pcap.pcap_path().display(),
            pcap.repeated_request_keys()
        );
    }
    // A replayed request is deliberately visible twice on the wire but has only
    // one final response, so strict request/response balance is not meaningful.
    result.assert(true, false).await?;
    Ok(())
}

async fn assert_device_read_pending(
    task: &mut JoinHandle<Result<Vec<u8>>>,
    timeout: Duration,
) -> Result<()> {
    match tokio::time::timeout(timeout, task).await {
        Ok(joined) => match joined.context("device read task panicked")? {
            Ok(_) => bail!("device read completed while host was down; expected parked I/O"),
            Err(err) => {
                bail!("device read failed while host was down; expected parked I/O: {err:#}")
            }
        },
        Err(_) => Ok(()),
    }
}

async fn read_device_bytes(path: PathBuf, lba: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let offset = lba
        .checked_mul(BLOCK_SIZE as u64)
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

async fn expected_bytes(lba: u64, blocks: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; (blocks * BLOCK_SIZE as u64) as usize];
    let source = RandomBlockSource::new(BLOCK_SIZE, TOTAL_BLOCKS, SEED)?;
    source
        .read_blocks(lba, &mut buf)
        .await
        .map_err(|err| anyhow::anyhow!("RandomBlockSource read_blocks: {err}"))?;
    Ok(buf)
}

fn ensure_read_matches(actual: &[u8], expected: &[u8]) -> Result<()> {
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

struct StallingHttpSource {
    addr: SocketAddr,
    state: Arc<HttpState>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl StallingHttpSource {
    fn start(block_size: u32, total_blocks: u64, seed: u64, stall_lba: u64) -> Result<Self> {
        let source = Arc::new(RandomBlockSource::new(block_size, total_blocks, seed)?);
        let total_bytes = block_size as u64 * total_blocks;
        let stall_start = stall_lba
            .checked_mul(block_size as u64)
            .context("stall offset overflow")?;
        let stall_end = stall_start
            .checked_add(block_size as u64)
            .and_then(|end| end.checked_sub(1))
            .context("stall range overflow")?;
        let state = Arc::new(HttpState {
            source,
            block_size,
            total_bytes,
            stall_start,
            stall_end,
            armed: AtomicBool::new(false),
            target_requests: AtomicUsize::new(0),
            target_request_notify: Notify::new(),
            released: AtomicBool::new(false),
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

    fn url(&self) -> String {
        format!("http://{}/disk.img", self.addr)
    }

    fn arm(&self) {
        self.state.armed.store(true, Ordering::Release);
    }

    fn target_request_count(&self) -> usize {
        self.state.target_requests.load(Ordering::Acquire)
    }

    async fn wait_for_data_requests(&self, expected: usize, timeout: Duration) -> Result<()> {
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

    fn release(&self) {
        self.state.released.store(true, Ordering::Release);
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
    stall_start: u64,
    stall_end: u64,
    armed: AtomicBool,
    target_requests: AtomicUsize,
    target_request_notify: Notify,
    released: AtomicBool,
    release_notify: Notify,
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

    let should_stall =
        state.armed.load(Ordering::Acquire) && start == state.stall_start && end == state.stall_end;
    if should_stall {
        let seen = state.target_requests.fetch_add(1, Ordering::AcqRel) + 1;
        tracing::info!(seen, start, end, "HTTP backing observed target range");
        state.target_request_notify.notify_waiters();
        wait_until_released(&state).await;
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

async fn wait_until_released(state: &HttpState) {
    loop {
        if state.released.load(Ordering::Acquire) {
            return;
        }
        let notified = state.release_notify.notified();
        if state.released.load(Ordering::Acquire) {
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
