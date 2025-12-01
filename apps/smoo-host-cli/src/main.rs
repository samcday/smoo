use anyhow::{anyhow, ensure, Context, Result};
use clap::{ArgGroup, Parser};
use smoo_host_blocksource_cached::{CachedBlockSource, MemoryCacheStore};
use smoo_host_blocksource_http::HttpBlockSource;
use smoo_host_blocksources::device::DeviceBlockSource;
use smoo_host_blocksources::file::FileBlockSource;
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::{
    control::{fetch_ident, read_status, send_config_exports_v0, ConfigExportsV0},
    derive_export_id_from_source, start_host_io_pump, BlockSource, BlockSourceHandle,
    BlockSourceResult, ExportIdentity, HostErrorKind, SmooHost, TransportError, TransportErrorKind,
};
use smoo_host_transport_rusb::{RusbControl, RusbTransport};
use smoo_proto::SmooStatusV0;
use std::{collections::BTreeMap, fmt, fs, path::PathBuf, time::Duration};
use tokio::{signal, sync::mpsc, time};
use tracing::{debug, info, warn};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;
const HEARTBEAT_INTERVAL_SECS: u64 = 1;
const DISCOVERY_DELAY_INITIAL: Duration = Duration::from_millis(500);
const DISCOVERY_DELAY_MAX: Duration = Duration::from_secs(5);
const STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(200);
const STATUS_RETRY_ATTEMPTS: usize = 5;
const RECONNECT_PAUSE: Duration = Duration::from_secs(1);

#[derive(Debug, Parser)]
#[command(name = "smoo-host-cli", version)]
#[command(
    about = "Host shim for smoo gadgets",
    long_about = "Host shim for smoo gadgets. By default all visible USB devices are scanned and the first interface matching the vendor triple 0xFF/0x53/0x4D is selected."
)]
#[command(
    group = ArgGroup::new("backing")
        .args(["files", "devices", "http", "cached_http", "random"])
        .required(true)
)]
struct Args {
    /// Optional USB vendor ID filter (hex). Defaults to all vendors.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    vendor_id: Option<u16>,
    /// Optional USB product ID filter (hex). Defaults to all products.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    product_id: Option<u16>,
    /// Disk image backing file(s). Repeatable for multiple exports.
    #[arg(long = "file", value_name = "PATH")]
    files: Vec<PathBuf>,
    /// Raw block device path(s). Repeatable for multiple exports.
    #[arg(long = "device", value_name = "PATH")]
    devices: Vec<PathBuf>,
    /// HTTP backing image(s). Repeatable; must be absolute URLs.
    #[arg(long = "http", value_name = "URL")]
    http: Vec<String>,
    /// HTTP backing image(s) cached in memory. Repeatable; must be absolute URLs.
    #[arg(long = "cached-http", value_name = "URL")]
    cached_http: Vec<String>,
    /// Synthetic random backing sized in blocks. Repeatable.
    #[arg(long = "random", value_name = "BLOCKS")]
    random: Vec<u64>,
    /// Seed for random backing. When multiple --random entries are provided, each uses seed+index.
    #[arg(long, default_value_t = 0)]
    random_seed: u64,
    /// Logical block size exposed through the gadget (bytes)
    #[arg(long, default_value_t = 512)]
    block_size: u32,
    /// Per-transfer timeout in milliseconds (clamped to 200ms for cancellation)
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

enum HostSource {
    File(FileBlockSource),
    Device(DeviceBlockSource),
    Http(HttpBlockSource),
    CachedHttp(CachedBlockSource<HttpBlockSource, MemoryCacheStore>),
    Random(RandomBlockSource),
}

#[async_trait::async_trait]
impl BlockSource for HostSource {
    fn block_size(&self) -> u32 {
        match self {
            HostSource::File(inner) => inner.block_size(),
            HostSource::Device(inner) => inner.block_size(),
            HostSource::Http(inner) => inner.block_size(),
            HostSource::CachedHttp(inner) => inner.block_size(),
            HostSource::Random(inner) => inner.block_size(),
        }
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        match self {
            HostSource::File(inner) => inner.total_blocks().await,
            HostSource::Device(inner) => inner.total_blocks().await,
            HostSource::Http(inner) => inner.total_blocks().await,
            HostSource::CachedHttp(inner) => inner.total_blocks().await,
            HostSource::Random(inner) => inner.total_blocks().await,
        }
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Http(inner) => inner.read_blocks(lba, buf).await,
            HostSource::CachedHttp(inner) => inner.read_blocks(lba, buf).await,
            HostSource::Random(inner) => inner.read_blocks(lba, buf).await,
        }
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Device(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Http(inner) => inner.write_blocks(lba, buf).await,
            HostSource::CachedHttp(inner) => inner.write_blocks(lba, buf).await,
            HostSource::Random(inner) => inner.write_blocks(lba, buf).await,
        }
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.flush().await,
            HostSource::Device(inner) => inner.flush().await,
            HostSource::Http(inner) => inner.flush().await,
            HostSource::CachedHttp(inner) => inner.flush().await,
            HostSource::Random(inner) => inner.flush().await,
        }
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Device(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Http(inner) => inner.discard(lba, num_blocks).await,
            HostSource::CachedHttp(inner) => inner.discard(lba, num_blocks).await,
            HostSource::Random(inner) => inner.discard(lba, num_blocks).await,
        }
    }
}

impl smoo_host_core::ExportIdentity for HostSource {
    fn write_export_id(&self, state: &mut dyn core::hash::Hasher) {
        match self {
            HostSource::File(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Device(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Http(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::CachedHttp(inner) => ExportIdentity::write_export_id(inner, state),
            HostSource::Random(inner) => ExportIdentity::write_export_id(inner, state),
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let (sources, config_payload) = open_sources(&args).await.context("open block sources")?;
    let mut expected_session_id = None;
    let mut has_connected = false;
    loop {
        match run_session(
            &args,
            sources.clone(),
            &config_payload,
            &mut expected_session_id,
            has_connected,
        )
        .await?
        {
            SessionEnd::Shutdown => break,
            SessionEnd::TransportLost => {
                info!("gadget disconnected; waiting for reconnection");
                has_connected = true;
                time::sleep(RECONNECT_PAUSE).await;
            }
        }
    }

    Ok(())
}

enum SessionEnd {
    Shutdown,
    TransportLost,
}

async fn run_session(
    args: &Args,
    sources: BTreeMap<u32, BlockSourceHandle>,
    config_payload: &ConfigExportsV0,
    expected_session_id: &mut Option<u64>,
    has_connected: bool,
) -> Result<SessionEnd> {
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut attempts = 0usize;
    let mut delay = DISCOVERY_DELAY_INITIAL;
    let transfer_timeout = Duration::from_millis(args.timeout_ms.min(200));
    let (transport, control) = loop {
        match RusbTransport::open_matching(
            args.vendor_id,
            args.product_id,
            SMOO_INTERFACE_CLASS,
            SMOO_INTERFACE_SUBCLASS,
            SMOO_INTERFACE_PROTOCOL,
            transfer_timeout,
        )
        .await
        {
            Ok((transport, control)) => break (transport, control),
            Err(err) => {
                if !has_connected && attempts == 0 {
                    warn!(error = %err, "no smoo gadget found; waiting for connection");
                } else {
                    debug!(error = %err, "gadget not present; retrying discovery");
                }
                tokio::select! {
                    _ = &mut shutdown => {
                        info!("shutdown requested");
                        return Ok(SessionEnd::Shutdown);
                    }
                    _ = time::sleep(delay) => {}
                }
                delay = delay.saturating_mul(2).min(DISCOVERY_DELAY_MAX);
                attempts += 1;
            }
        }
    };
    let ident = fetch_ident(&control)
        .await
        .context("IDENT control transfer")?;
    debug!(
        major = ident.major,
        minor = ident.minor,
        "gadget IDENT response"
    );
    send_config_exports_v0(&control, config_payload)
        .await
        .context("CONFIG_EXPORTS control transfer")?;
    info!(
        exports = config_payload.entries().len(),
        "configured gadget exports"
    );
    let initial_status =
        match fetch_status_with_retry(&control, STATUS_RETRY_ATTEMPTS, STATUS_RETRY_INTERVAL).await
        {
            Ok(status) => status,
            Err(err) => {
                warn!(error = %err, "SMOO_STATUS failed after reconnect; gadget not ready");
                return Ok(SessionEnd::TransportLost);
            }
        };
    match expected_session_id {
        Some(expected) => {
            let recorded = *expected;
            ensure!(
                recorded == initial_status.session_id,
                "gadget session changed (expected 0x{recorded:016x}, got 0x{:016x})",
                initial_status.session_id
            );
        }
        None => {
            *expected_session_id = Some(initial_status.session_id);
        }
    }
    debug!(
        session_id = initial_status.session_id,
        export_count = initial_status.export_count,
        "initial gadget status"
    );
    let heartbeat_interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    let (heartbeat_tx, mut heartbeat_rx) = mpsc::unbounded_channel();
    let heartbeat_client = control.clone();
    let session_id = initial_status.session_id;
    let heartbeat_task = tokio::spawn(async move {
        if let Err(err) = run_heartbeat(heartbeat_client, session_id, heartbeat_interval).await {
            let _ = heartbeat_tx.send(err);
        }
    });
    let (pump_handle, request_rx, pump_task) = start_host_io_pump(transport);
    let mut pump_task = tokio::spawn(async move { pump_task.await });
    let mut host = SmooHost::new(pump_handle.clone(), request_rx, sources);
    host.record_ident(ident);
    info!(
        major = ident.major,
        minor = ident.minor,
        "connected to smoo gadget"
    );

    let outcome = loop {
        tokio::select! {
            res = host.run_once() => {
                match res {
                    Ok(()) => {}
                    Err(err) => match err.kind() {
                        HostErrorKind::Unsupported | HostErrorKind::InvalidRequest => {
                            warn!(error = %err, "request handling failed");
                        }
                        HostErrorKind::Transport => {
                            warn!(error = %err, "transport failure");
                            break SessionEnd::TransportLost;
                        }
                        _ => {
                            return Err(anyhow!(err.to_string()));
                        }
                    },
                }
            }
            pump_res = &mut pump_task => {
                match pump_res {
                    Ok(Ok(())) => break SessionEnd::TransportLost,
                    Ok(Err(err)) => {
                        warn!(error = %err, "pump task exited");
                        break SessionEnd::TransportLost;
                    }
                    Err(join_err) => {
                        warn!(error = %join_err, "pump task join failed");
                        break SessionEnd::TransportLost;
                    }
                }
            }
            event = heartbeat_rx.recv() => {
                match event {
                    Some(HeartbeatFailure::TransferFailed(reason)) => {
                        warn!(reason = %reason, "heartbeat transfer failed");
                        break SessionEnd::TransportLost;
                    }
                    Some(other) => {
                        return Err(anyhow!(other.to_string()));
                    }
                    None => {
                        break SessionEnd::TransportLost;
                    }
                }
            }
            _ = &mut shutdown => {
                info!("shutdown requested");
                break SessionEnd::Shutdown;
            }
        }
    };

    if !heartbeat_task.is_finished() {
        heartbeat_task.abort();
    }
    let _ = heartbeat_task.await;

    // Gracefully stop the pump.
    let _ = pump_handle.shutdown().await;
    if !pump_task.is_finished() {
        pump_task.abort();
    }
    let _ = pump_task.await;

    Ok(outcome)
}

async fn open_sources(args: &Args) -> Result<(BTreeMap<u32, BlockSourceHandle>, ConfigExportsV0)> {
    let mut sources = BTreeMap::new();
    let mut entries: Vec<smoo_proto::ConfigExport> = Vec::new();
    let block_size = args.block_size;
    ensure!(
        block_size.is_power_of_two(),
        "block size must be a power of two"
    );
    ensure!(block_size > 0, "block size must be non-zero");

    for path in &args.files {
        let size_bytes = file_size_bytes(path)?;
        let canonical = canonicalize_path(path)?;
        let identity = format!("file:{}", canonical.display());
        let source = BlockSourceHandle::new(
            HostSource::File(FileBlockSource::open(path, block_size).await?),
            identity.clone(),
        );
        register_export(&mut sources, &mut entries, source, block_size, size_bytes)?;
    }

    for path in &args.devices {
        let size_bytes = file_size_bytes(path)?;
        let canonical = canonicalize_path(path)?;
        let identity = format!("device:{}", canonical.display());
        let source = BlockSourceHandle::new(
            HostSource::Device(DeviceBlockSource::open(path, block_size).await?),
            identity.clone(),
        );
        register_export(&mut sources, &mut entries, source, block_size, size_bytes)?;
    }

    for url_str in &args.http {
        let url = url::Url::parse(url_str)
            .with_context(|| format!("parse http backing URL {url_str}"))?;
        ensure!(
            url.scheme() == "http" || url.scheme() == "https",
            "unsupported URL scheme {}",
            url.scheme()
        );
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .context("init HTTP block source")?;
        let size_bytes = source.size_bytes();
        ensure!(
            size_bytes % block_size as u64 == 0,
            "HTTP backing size must align to block size"
        );
        let source_id = format!("http:{}", url);
        let shared = BlockSourceHandle::new(HostSource::Http(source), source_id);
        register_export(&mut sources, &mut entries, shared, block_size, size_bytes)?;
    }

    for url_str in &args.cached_http {
        let url = url::Url::parse(url_str)
            .with_context(|| format!("parse cached-http backing URL {url_str}"))?;
        ensure!(
            url.scheme() == "http" || url.scheme() == "https",
            "unsupported URL scheme {}",
            url.scheme()
        );
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .context("init HTTP block source")?;
        let size_bytes = source.size_bytes();
        ensure!(
            size_bytes % block_size as u64 == 0,
            "HTTP backing size must align to block size"
        );
        let total_blocks = size_bytes / block_size as u64;
        let cache = MemoryCacheStore::new(block_size, total_blocks)
            .context("allocate HTTP cache backing")?;
        let cached = CachedBlockSource::new(source, cache)
            .await
            .context("init cached HTTP block source")?;
        let source_id = format!("cached-http:{}", url);
        let shared = BlockSourceHandle::new(HostSource::CachedHttp(cached), source_id);
        register_export(&mut sources, &mut entries, shared, block_size, size_bytes)?;
    }

    for (idx, blocks) in args.random.iter().copied().enumerate() {
        ensure!(blocks > 0, "random backing requires block count > 0");
        let size_bytes = blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| anyhow!("random backing size overflows u64"))?;
        let seed = args.random_seed.wrapping_add(idx as u64);
        let source = BlockSourceHandle::new(
            HostSource::Random(RandomBlockSource::new(block_size, blocks, seed)?),
            format!("random:{seed}"),
        );
        register_export(&mut sources, &mut entries, source, block_size, size_bytes)?;
    }

    let payload = ConfigExportsV0::from_slice(&entries)
        .map_err(|err| anyhow!("build CONFIG_EXPORTS payload: {err:?}"))?;
    Ok((sources, payload))
}

fn register_export(
    sources: &mut BTreeMap<u32, BlockSourceHandle>,
    entries: &mut Vec<smoo_proto::ConfigExport>,
    source: BlockSourceHandle,
    block_size: u32,
    size_bytes: u64,
) -> Result<()> {
    let identity = source.identity().to_string();
    ensure!(
        source.block_size() == block_size,
        "backing {identity} block size {} disagrees with configuration {}",
        source.block_size(),
        block_size
    );
    ensure!(
        size_bytes.is_multiple_of(block_size as u64),
        "backing size for {identity} must align to block size"
    );
    let block_count = size_bytes / block_size as u64;
    let export_id = derive_export_id_from_source(&source, block_count);
    ensure!(
        !sources.contains_key(&export_id),
        "derived duplicate export_id {export_id} for backing {identity}; check for repeated inputs or adjust backing parameters to avoid collisions"
    );
    sources.insert(export_id, source);
    entries.push(smoo_proto::ConfigExport {
        export_id,
        block_size,
        size_bytes,
    });
    Ok(())
}

fn file_size_bytes(path: &PathBuf) -> Result<u64> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.len())
}

fn canonicalize_path(path: &PathBuf) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

#[derive(Debug, Clone)]
enum HeartbeatFailure {
    SessionChanged { previous: u64, current: u64 },
    TransferFailed(String),
}

impl fmt::Display for HeartbeatFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatFailure::SessionChanged { previous, current } => write!(
                f,
                "gadget session changed (0x{previous:016x} → 0x{current:016x})"
            ),
            HeartbeatFailure::TransferFailed(err) => {
                write!(f, "heartbeat control transfer failed: {err}")
            }
        }
    }
}

async fn run_heartbeat(
    client: RusbControl,
    initial_session_id: u64,
    interval: Duration,
) -> Result<(), HeartbeatFailure> {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match read_status(&client).await {
            Ok(status) => {
                debug!(
                    session_id = status.session_id,
                    export_count = status.export_count,
                    "heartbeat successful"
                );
                if status.session_id != initial_session_id {
                    return Err(HeartbeatFailure::SessionChanged {
                        previous: initial_session_id,
                        current: status.session_id,
                    });
                }
            }
            Err(err) => {
                return Err(HeartbeatFailure::TransferFailed(err.to_string()));
            }
        }
    }
}

async fn fetch_status_with_retry(
    client: &RusbControl,
    attempts: usize,
    delay: Duration,
) -> Result<SmooStatusV0, TransportError> {
    let mut attempt = 0;
    loop {
        match read_status(client).await {
            Ok(status) => return Ok(status),
            Err(err) => {
                if err.kind() == TransportErrorKind::Timeout && attempt == 0 {
                    debug!(error = %err, "SMOO_STATUS timeout before retry");
                }
                attempt += 1;
                if attempt >= attempts {
                    return Err(err);
                }
                warn!(
                    attempt,
                    attempts,
                    error = %err,
                    "SMOO_STATUS attempt failed; retrying"
                );
                time::sleep(delay).await;
            }
        }
    }
}

fn parse_hex_u16(s: &str) -> Result<u16, std::num::ParseIntError> {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16)
}
