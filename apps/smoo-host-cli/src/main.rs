use anyhow::{anyhow, ensure, Context, Result};
use clap::{ArgGroup, Parser};
use rusb::{Direction, TransferType, UsbContext};
use smoo_host_blocksource_cached::{CachedBlockSource, MemoryCacheStore};
use smoo_host_blocksource_http::HttpBlockSource;
use smoo_host_blocksources::device::DeviceBlockSource;
use smoo_host_blocksources::file::FileBlockSource;
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::{
    control::{fetch_ident, read_status, send_config_exports_v0, ConfigExportsV0},
    derive_export_id_from_source, BlockSource, BlockSourceHandle, BlockSourceResult,
    ExportIdentity, HostErrorKind, SmooHost, TransportError, TransportErrorKind,
};
use smoo_host_rusb::{RusbControl, RusbTransport, RusbTransportConfig};
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
    /// Control/interrupt transfer timeout in milliseconds
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
    let (handle, interface) = loop {
        match discover_device(args, attempts == 0 && !has_connected) {
            Ok(found) => break found,
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
    let endpoints = infer_interface_endpoints(&handle, interface).context("discover endpoints")?;
    let transport_config = RusbTransportConfig {
        interface,
        interrupt_in: endpoints.interrupt_in,
        interrupt_out: endpoints.interrupt_out,
        bulk_in: endpoints.bulk_in,
        bulk_out: endpoints.bulk_out,
        timeout: Duration::from_millis(args.timeout_ms),
    };
    let transport = RusbTransport::new(handle, transport_config).context("init transport")?;
    let control = transport.control_handle();
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
    let mut host = SmooHost::new(transport, sources);
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

    Ok(outcome)
}

fn discover_device(args: &Args, log_scan: bool) -> Result<(rusb::DeviceHandle<rusb::Context>, u8)> {
    let context = rusb::Context::new().context("init libusb context")?;
    let devices = context.devices().context("enumerate usb devices")?;
    if log_scan {
        info!(
            vendor_filter = args.vendor_id.map(|v| format!("{:#06x}", v)),
            product_filter = args.product_id.map(|p| format!("{:#06x}", p)),
            "scanning USB devices for smoo gadget"
        );
    } else {
        debug!(
            vendor_filter = args.vendor_id.map(|v| format!("{:#06x}", v)),
            product_filter = args.product_id.map(|p| format!("{:#06x}", p)),
            "probing USB devices for smoo gadget"
        );
    }
    for device in devices.iter() {
        let device_desc = match device.device_descriptor() {
            Ok(desc) => desc,
            Err(err) => {
                warn!(error = %err, "read device descriptor failed");
                continue;
            }
        };
        if let Some(vendor) = args.vendor_id {
            if device_desc.vendor_id() != vendor {
                debug!(
                    vid = format_args!("{:#06x}", device_desc.vendor_id()),
                    pid = format_args!("{:#06x}", device_desc.product_id()),
                    "skipping device due to vendor filter"
                );
                continue;
            }
        } else if log_scan {
            debug!(
                vid = format_args!("{:#06x}", device_desc.vendor_id()),
                pid = format_args!("{:#06x}", device_desc.product_id()),
                "examining usb device"
            );
        }
        if let Some(product) = args.product_id {
            if device_desc.product_id() != product {
                if log_scan {
                    debug!("skipping device due to product filter");
                }
                continue;
            }
        }
        for cfg_idx in 0..device_desc.num_configurations() {
            let config = match device.config_descriptor(cfg_idx) {
                Ok(cfg) => cfg,
                Err(err) => {
                    warn!(error = %err, config = cfg_idx, "read config descriptor failed");
                    continue;
                }
            };
            for interface in config.interfaces() {
                for desc in interface.descriptors() {
                    let iface_num = desc.interface_number();
                    if desc.class_code() == SMOO_INTERFACE_CLASS
                        && desc.sub_class_code() == SMOO_INTERFACE_SUBCLASS
                        && desc.protocol_code() == SMOO_INTERFACE_PROTOCOL
                    {
                        let handle = match device.open() {
                            Ok(handle) => handle,
                            Err(err) => {
                                warn!(error = %err, "failed to open matching usb device");
                                continue;
                            }
                        };
                        handle
                            .set_auto_detach_kernel_driver(true)
                            .context("enable auto-detach")?;
                        info!(
                            vid = format_args!("{:#06x}", device_desc.vendor_id()),
                            pid = format_args!("{:#06x}", device_desc.product_id()),
                            interface = iface_num,
                            "selected smoo-compatible interface"
                        );
                        return Ok((handle, iface_num));
                    }
                }
            }
        }
    }
    Err(anyhow!(
        "No smoo-compatible USB devices found{}.",
        if args.vendor_id.is_some() || args.product_id.is_some() {
            " (after applying filters)"
        } else {
            ""
        }
    ))
}

struct InterfaceEndpoints {
    interrupt_in: u8,
    interrupt_out: u8,
    bulk_in: u8,
    bulk_out: u8,
}

#[derive(Default)]
struct EndpointBuilder {
    interrupt_in: Option<u8>,
    interrupt_out: Option<u8>,
    bulk_in: Option<u8>,
    bulk_out: Option<u8>,
}

impl EndpointBuilder {
    fn record(&mut self, ep: &rusb::EndpointDescriptor) {
        match (ep.transfer_type(), ep.direction()) {
            (TransferType::Interrupt, Direction::In) if self.interrupt_in.is_none() => {
                self.interrupt_in = Some(ep.address());
            }
            (TransferType::Interrupt, Direction::Out) if self.interrupt_out.is_none() => {
                self.interrupt_out = Some(ep.address());
            }
            (TransferType::Bulk, Direction::In) if self.bulk_in.is_none() => {
                self.bulk_in = Some(ep.address());
            }
            (TransferType::Bulk, Direction::Out) if self.bulk_out.is_none() => {
                self.bulk_out = Some(ep.address());
            }
            _ => {}
        }
    }

    fn finish(self) -> Option<InterfaceEndpoints> {
        let (Some(interrupt_in), Some(interrupt_out), Some(bulk_in), Some(bulk_out)) = (
            self.interrupt_in,
            self.interrupt_out,
            self.bulk_in,
            self.bulk_out,
        ) else {
            return None;
        };
        Some(InterfaceEndpoints {
            interrupt_in,
            interrupt_out,
            bulk_in,
            bulk_out,
        })
    }
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

fn infer_interface_endpoints<T: UsbContext>(
    handle: &rusb::DeviceHandle<T>,
    interface: u8,
) -> Result<InterfaceEndpoints> {
    let config = handle
        .device()
        .active_config_descriptor()
        .context("read active config descriptor")?;
    for intf in config.interfaces() {
        for desc in intf.descriptors() {
            if desc.interface_number() != interface {
                continue;
            }
            let mut builder = EndpointBuilder::default();
            for ep in desc.endpoint_descriptors() {
                builder.record(&ep);
            }
            if let Some(endpoints) = builder.finish() {
                return Ok(endpoints);
            }
        }
    }
    Err(anyhow!(
        "required endpoints not found for interface {}",
        interface
    ))
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
    client: RusbControl<rusb::Context>,
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
    client: &RusbControl<rusb::Context>,
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
