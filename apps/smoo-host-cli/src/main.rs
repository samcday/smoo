use anyhow::{anyhow, ensure, Context, Result};
use clap::Parser;
use rusb::{Direction, TransferType, UsbContext};
use smoo_host_blocksources::FileBlockSource;
use smoo_host_core::{
    read_ident, send_config_exports_v0, BlockSource, BlockSourceResult, ConfigExportEntry,
    ConfigExportsV0Payload, HostError, HostErrorKind, HostExport, HostResult, SmooHost,
    StatusClient, TransportError, TransportErrorKind,
};
use smoo_host_rusb::{RusbControlHandle, RusbTransport, RusbTransportConfig};
use smoo_proto::SmooStatusV0;
use std::{fmt, path::PathBuf, sync::Arc, time::Duration};
use tokio::{signal, sync::mpsc, task::JoinHandle, time};
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
#[command(name = "smoo-host-cli")]
#[command(
    about = "Host shim for smoo gadgets",
    long_about = "Host shim for smoo gadgets. By default all visible USB devices are scanned and the first interface matching the vendor triple 0xFF/0x53/0x4D is selected."
)]
struct Args {
    /// Optional USB vendor ID filter (hex). Defaults to all vendors.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    vendor_id: Option<u16>,
    /// Optional USB product ID filter (hex). Defaults to all products.
    #[arg(long, value_name = "HEX", value_parser = parse_hex_u16)]
    product_id: Option<u16>,
    /// Disk image backing file(s). Repeatable for multiple exports.
    #[arg(long = "file", value_name = "PATH", required = true)]
    files: Vec<PathBuf>,
    /// Logical block size exposed through the gadget (bytes)
    #[arg(long, default_value_t = 512)]
    block_size: u32,
    /// Control/interrupt transfer timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

enum HostSource {
    File(FileBlockSource),
}

#[derive(Clone)]
struct SharedSource {
    inner: Arc<HostSource>,
}

impl SharedSource {
    fn new(inner: HostSource) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

#[async_trait::async_trait]
impl BlockSource for HostSource {
    fn block_size(&self) -> u32 {
        match self {
            HostSource::File(inner) => inner.block_size(),
        }
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        match self {
            HostSource::File(inner) => inner.total_blocks().await,
        }
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.read_blocks(lba, buf).await,
        }
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        match self {
            HostSource::File(inner) => inner.write_blocks(lba, buf).await,
        }
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.flush().await,
        }
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        match self {
            HostSource::File(inner) => inner.discard(lba, num_blocks).await,
        }
    }
}

#[async_trait::async_trait]
impl BlockSource for SharedSource {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        self.inner.total_blocks().await
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.inner.read_blocks(lba, buf).await
    }

    async fn write_blocks(&self, lba: u64, buf: &[u8]) -> BlockSourceResult<usize> {
        self.inner.write_blocks(lba, buf).await
    }

    async fn flush(&self) -> BlockSourceResult<()> {
        self.inner.flush().await
    }

    async fn discard(&self, lba: u64, num_blocks: u32) -> BlockSourceResult<()> {
        self.inner.discard(lba, num_blocks).await
    }
}

#[derive(Clone)]
struct ExportSourceConfig {
    export_id: u32,
    source: SharedSource,
    block_size: u32,
    size_bytes: u64,
    path: PathBuf,
}

type HostTransport = RusbTransport<rusb::Context>;
type HostControlHandle = RusbControlHandle<rusb::Context>;
type HostStatusClient = StatusClient<HostControlHandle>;

#[derive(Clone)]
struct HostControllerConfig {
    vendor_id: Option<u16>,
    product_id: Option<u16>,
    timeout: Duration,
}

impl From<&Args> for HostControllerConfig {
    fn from(args: &Args) -> Self {
        Self {
            vendor_id: args.vendor_id,
            product_id: args.product_id,
            timeout: Duration::from_millis(args.timeout_ms),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostSessionState {
    Idle,
    Discovering,
    UsbReady,
    Configuring,
    WaitingStatus,
    Serving,
    TransportLost,
    Shutdown,
}

impl HostSessionState {
    fn as_str(&self) -> &'static str {
        match self {
            HostSessionState::Idle => "idle",
            HostSessionState::Discovering => "discovering",
            HostSessionState::UsbReady => "usb_ready",
            HostSessionState::Configuring => "configuring",
            HostSessionState::WaitingStatus => "waiting_status",
            HostSessionState::Serving => "serving",
            HostSessionState::TransportLost => "transport_lost",
            HostSessionState::Shutdown => "shutdown",
        }
    }

    fn is_serving(&self) -> bool {
        matches!(self, HostSessionState::Serving)
    }
}

struct DiscoveryBackoff {
    delay: Duration,
    next_attempt: time::Instant,
    attempts: usize,
}

impl DiscoveryBackoff {
    fn new() -> Self {
        Self {
            delay: DISCOVERY_DELAY_INITIAL,
            next_attempt: time::Instant::now(),
            attempts: 0,
        }
    }

    fn ready(&self) -> bool {
        self.ready_at(time::Instant::now())
    }

    fn ready_at(&self, now: time::Instant) -> bool {
        now >= self.next_attempt
    }

    fn reset(&mut self) {
        self.delay = DISCOVERY_DELAY_INITIAL;
        self.next_attempt = time::Instant::now();
        self.attempts = 0;
    }

    fn fail(&mut self) {
        self.next_attempt = time::Instant::now() + self.delay;
        self.delay = (self.delay.saturating_mul(2)).min(DISCOVERY_DELAY_MAX);
        self.attempts = self.attempts.saturating_add(1);
    }

    fn attempts(&self) -> usize {
        self.attempts
    }

    fn pause_for(&mut self, duration: Duration) {
        self.next_attempt = time::Instant::now() + duration;
        self.delay = DISCOVERY_DELAY_INITIAL;
        self.attempts = 0;
    }
}

struct SessionRuntime {
    host: SmooHost<HostTransport, SharedSource>,
    heartbeat_task: Option<JoinHandle<()>>,
    session_id: u64,
}

impl SessionRuntime {
    async fn new(
        transport: HostTransport,
        exports: &[ExportSourceConfig],
        heartbeat_client: HostStatusClient,
        session_id: u64,
    ) -> Result<(Self, mpsc::UnboundedReceiver<HeartbeatFailure>)> {
        let host_exports = exports
            .iter()
            .map(|cfg| HostExport {
                export_id: cfg.export_id,
                source: cfg.source.clone(),
                block_size: cfg.block_size,
                size_bytes: cfg.size_bytes,
            })
            .collect();
        let host = SmooHost::new(transport, host_exports);
        let (heartbeat_tx, heartbeat_rx) = mpsc::unbounded_channel();
        let heartbeat_task = tokio::spawn(async move {
            if let Err(err) = run_heartbeat(
                heartbeat_client,
                session_id,
                Duration::from_secs(HEARTBEAT_INTERVAL_SECS),
            )
            .await
            {
                let _ = heartbeat_tx.send(err);
            }
        });
        Ok((
            Self {
                host,
                heartbeat_task: Some(heartbeat_task),
                session_id,
            },
            heartbeat_rx,
        ))
    }

    async fn drive_io(&mut self) -> HostResult<()> {
        self.host.run_once().await
    }

    async fn shutdown(&mut self) {
        if let Some(task) = self.heartbeat_task.take() {
            if !task.is_finished() {
                task.abort();
            }
            let _ = task.await;
        }
        debug!(session_id = self.session_id, "host session runtime drained");
    }
}

struct HostController {
    config: HostControllerConfig,
    exports: Vec<ExportSourceConfig>,
    active_interface: Option<u8>,
    expected_session_id: Option<u64>,
    has_connected: bool,
    state: HostSessionState,
    transport: Option<HostTransport>,
    status_client: Option<HostStatusClient>,
    session_runtime: Option<SessionRuntime>,
    heartbeat_rx: Option<mpsc::UnboundedReceiver<HeartbeatFailure>>,
    discovery: DiscoveryBackoff,
    shutdown_requested: bool,
}

impl HostController {
    fn new(config: HostControllerConfig, exports: Vec<ExportSourceConfig>) -> Self {
        Self {
            config,
            exports,
            active_interface: None,
            expected_session_id: None,
            has_connected: false,
            state: HostSessionState::Idle,
            transport: None,
            status_client: None,
            session_runtime: None,
            heartbeat_rx: None,
            discovery: DiscoveryBackoff::new(),
            shutdown_requested: false,
        }
    }

    async fn run(mut self) -> Result<()> {
        let shutdown = signal::ctrl_c();
        tokio::pin!(shutdown);
        let mut reconcile_tick = time::interval(Duration::from_millis(200));
        loop {
            if self.state.is_serving() {
                let runtime = self
                    .session_runtime
                    .as_mut()
                    .expect("serving state requires session runtime");
                let heartbeat_rx = self
                    .heartbeat_rx
                    .as_mut()
                    .expect("serving state requires heartbeat channel");
                tokio::select! {
                    _ = &mut shutdown => {
                        self.shutdown_requested = true;
                    }
                    res = runtime.drive_io() => {
                        if let Err(err) = res {
                            self.handle_host_error(err).await?;
                        }
                    }
                    event = heartbeat_rx.recv() => {
                        match event {
                            Some(HeartbeatFailure::TransferFailed(reason)) => {
                                warn!(reason = %reason, "heartbeat transfer failed");
                                self.transition(HostSessionState::TransportLost);
                            }
                            Some(other) => {
                                warn!(error = %other, "heartbeat reported failure");
                                self.transition(HostSessionState::TransportLost);
                            }
                            None => {
                                self.transition(HostSessionState::TransportLost);
                            }
                        }
                    }
                    _ = reconcile_tick.tick() => {
                        self.reconcile_once().await?;
                    }
                }
            } else {
                tokio::select! {
                    _ = &mut shutdown => {
                        self.shutdown_requested = true;
                    }
                    _ = reconcile_tick.tick() => {
                        self.reconcile_once().await?;
                    }
                }
            }
            if matches!(self.state, HostSessionState::Shutdown) {
                break;
            }
        }
        Ok(())
    }

    async fn reconcile_once(&mut self) -> Result<()> {
        if self.shutdown_requested && !matches!(self.state, HostSessionState::Shutdown) {
            self.begin_shutdown().await?;
            return Ok(());
        }
        match self.state {
            HostSessionState::Idle => self.transition(HostSessionState::Discovering),
            HostSessionState::Discovering => self.step_discovering().await?,
            HostSessionState::UsbReady => self.step_ident().await?,
            HostSessionState::Configuring => self.step_configure().await?,
            HostSessionState::WaitingStatus => self.step_wait_status().await?,
            HostSessionState::Serving => {}
            HostSessionState::TransportLost => self.reset_after_transport_loss().await?,
            HostSessionState::Shutdown => {}
        }
        Ok(())
    }

    async fn step_discovering(&mut self) -> Result<()> {
        if !self.discovery.ready() {
            return Ok(());
        }
        match discover_device(
            &self.config,
            self.discovery.attempts() == 0 && !self.has_connected,
        ) {
            Ok((handle, interface)) => {
                let endpoints =
                    infer_interface_endpoints(&handle, interface).context("discover endpoints")?;
                let transport_config = RusbTransportConfig {
                    interface,
                    interrupt_in: endpoints.interrupt_in,
                    interrupt_out: endpoints.interrupt_out,
                    bulk_in: endpoints.bulk_in,
                    bulk_out: endpoints.bulk_out,
                    timeout: self.config.timeout,
                };
                let transport =
                    RusbTransport::new(handle, transport_config).context("init transport")?;
                self.status_client = Some(StatusClient::new(transport.control_handle(), interface));
                self.active_interface = Some(interface);
                self.transport = Some(transport);
                self.discovery.reset();
                self.transition(HostSessionState::UsbReady);
            }
            Err(err) => {
                if !self.has_connected && self.discovery.attempts() == 0 {
                    warn!(error = %err, "no smoo gadget found; waiting for connection");
                } else {
                    debug!(error = %err, "gadget not present; retrying discovery");
                }
                self.discovery.fail();
            }
        }
        Ok(())
    }

    async fn step_ident(&mut self) -> Result<()> {
        let Some(transport) = self.transport.as_mut() else {
            self.transition(HostSessionState::Discovering);
            return Ok(());
        };
        let interface = match self.active_interface {
            Some(value) => value,
            None => {
                self.transition(HostSessionState::Discovering);
                return Ok(());
            }
        };
        let ident = read_ident(transport, interface)
            .await
            .context("IDENT control transfer")?;
        debug!(
            major = ident.major,
            minor = ident.minor,
            "gadget IDENT response"
        );
        self.transition(HostSessionState::Configuring);
        Ok(())
    }

    async fn step_configure(&mut self) -> Result<()> {
        let payload = self
            .build_config_payload()
            .context("build CONFIG_EXPORTS payload")?;
        let Some(transport) = self.transport.as_mut() else {
            self.transition(HostSessionState::Discovering);
            return Ok(());
        };
        let interface = match self.active_interface {
            Some(value) => value,
            None => {
                self.transition(HostSessionState::Discovering);
                return Ok(());
            }
        };
        send_config_exports_v0(transport, interface, &payload)
            .await
            .context("CONFIG_EXPORTS control transfer")?;
        info!(count = self.exports.len(), "configured gadget exports");
        for cfg in &self.exports {
            info!(
                export_id = cfg.export_id,
                path = %cfg.path.display(),
                block_size = cfg.block_size,
                size_bytes = cfg.size_bytes,
                "export ready"
            );
        }
        self.transition(HostSessionState::WaitingStatus);
        Ok(())
    }

    async fn step_wait_status(&mut self) -> Result<()> {
        let Some(mut client) = self.status_client.clone() else {
            self.transition(HostSessionState::Discovering);
            return Ok(());
        };
        let status = match fetch_status_with_retry(
            &mut client,
            STATUS_RETRY_ATTEMPTS,
            STATUS_RETRY_INTERVAL,
        )
        .await
        {
            Ok(status) => status,
            Err(err) => {
                warn!(error = %err, "SMOO_STATUS failed; gadget not ready");
                self.transition(HostSessionState::TransportLost);
                return Ok(());
            }
        };
        ensure!(
            status.export_active(),
            "gadget reports no active export after CONFIG_EXPORTS"
        );
        ensure!(
            status.export_count as usize == self.exports.len(),
            "gadget export count mismatch (expected {}, got {})",
            self.exports.len(),
            status.export_count
        );
        match self.expected_session_id {
            Some(expected) => ensure!(
                expected == status.session_id,
                "gadget session changed (expected 0x{expected:016x}, got 0x{:016x})",
                status.session_id
            ),
            None => {
                self.expected_session_id = Some(status.session_id);
            }
        }
        let Some(transport) = self.transport.take() else {
            self.transition(HostSessionState::Discovering);
            return Ok(());
        };
        let heartbeat_client = client.clone();
        let (runtime, heartbeat_rx) = SessionRuntime::new(
            transport,
            &self.exports,
            heartbeat_client,
            status.session_id,
        )
        .await?;
        self.session_runtime = Some(runtime);
        self.heartbeat_rx = Some(heartbeat_rx);
        self.has_connected = true;
        self.transition(HostSessionState::Serving);
        Ok(())
    }

    async fn handle_host_error(&mut self, err: HostError) -> Result<()> {
        match err.kind() {
            HostErrorKind::Unsupported | HostErrorKind::InvalidRequest => {
                warn!(error = %err, "request handling failed");
            }
            HostErrorKind::Transport => {
                warn!(error = %err, "transport failure");
                self.transition(HostSessionState::TransportLost);
            }
            HostErrorKind::BlockSource => {
                warn!(error = %err, "block source error");
            }
            HostErrorKind::NotReady => {
                debug!(error = %err, "host not ready for IO");
            }
        }
        Ok(())
    }

    async fn reset_after_transport_loss(&mut self) -> Result<()> {
        info!("gadget disconnected; waiting for reconnection");
        if let Some(runtime) = self.session_runtime.as_mut() {
            runtime.shutdown().await;
        }
        self.session_runtime = None;
        self.heartbeat_rx = None;
        self.transport = None;
        self.status_client = None;
        self.active_interface = None;
        self.discovery.pause_for(RECONNECT_PAUSE);
        self.transition(HostSessionState::Discovering);
        Ok(())
    }

    async fn begin_shutdown(&mut self) -> Result<()> {
        if let Some(runtime) = self.session_runtime.as_mut() {
            runtime.shutdown().await;
        }
        self.session_runtime = None;
        self.heartbeat_rx = None;
        self.transport = None;
        self.status_client = None;
        self.active_interface = None;
        self.transition(HostSessionState::Shutdown);
        info!("shutdown requested");
        Ok(())
    }

    fn build_config_payload(&self) -> Result<ConfigExportsV0Payload> {
        let entries: Vec<ConfigExportEntry> = self
            .exports
            .iter()
            .map(|cfg| ConfigExportEntry {
                export_id: cfg.export_id,
                block_size: cfg.block_size,
                size_bytes: cfg.size_bytes,
            })
            .collect();
        ConfigExportsV0Payload::new(entries).map_err(|err| anyhow!(err.to_string()))
    }

    fn transition(&mut self, next: HostSessionState) {
        if self.state == next {
            return;
        }
        info!(
            from = self.state.as_str(),
            to = next.as_str(),
            "host controller state transition"
        );
        self.state = next;
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
    let exports = open_sources(&args).await.context("open export sources")?;
    let controller = HostController::new(HostControllerConfig::from(&args), exports);
    controller.run().await
}

async fn open_sources(args: &Args) -> Result<Vec<ExportSourceConfig>> {
    let mut exports = Vec::with_capacity(args.files.len());
    for (idx, path) in args.files.iter().enumerate() {
        let export_id =
            u32::try_from(idx + 1).map_err(|_| anyhow!("too many exports for u32 export_id"))?;
        let source = SharedSource::new(HostSource::File(
            FileBlockSource::open(path, args.block_size).await?,
        ));
        let block_size = source.block_size();
        let size_bytes = match source.total_blocks().await {
            Ok(blocks) => blocks.checked_mul(block_size as u64).unwrap_or(0),
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "determine total blocks failed; advertising dynamic size"
                );
                0
            }
        };
        exports.push(ExportSourceConfig {
            export_id,
            source,
            block_size,
            size_bytes,
            path: path.clone(),
        });
    }
    Ok(exports)
}

#[cfg(test)]
mod host_controller_tests {
    use super::{DiscoveryBackoff, DISCOVERY_DELAY_INITIAL, RECONNECT_PAUSE};
    use tokio::time::Instant;

    #[test]
    fn discovery_backoff_waits_for_next_attempt() {
        let mut backoff = DiscoveryBackoff::new();
        let now = Instant::now();
        assert!(backoff.ready_at(now));
        backoff.fail();
        assert!(!backoff.ready_at(now));
        assert!(backoff.ready_at(now + DISCOVERY_DELAY_INITIAL));
        backoff.pause_for(RECONNECT_PAUSE);
        assert!(!backoff.ready_at(now));
        assert!(backoff.ready_at(now + RECONNECT_PAUSE));
    }
}

fn discover_device(
    config: &HostControllerConfig,
    log_scan: bool,
) -> Result<(rusb::DeviceHandle<rusb::Context>, u8)> {
    let context = rusb::Context::new().context("init libusb context")?;
    let devices = context.devices().context("enumerate usb devices")?;
    if log_scan {
        info!(
            vendor_filter = config.vendor_id.map(|v| format!("{:#06x}", v)),
            product_filter = config.product_id.map(|p| format!("{:#06x}", p)),
            "scanning USB devices for smoo gadget"
        );
    } else {
        debug!(
            vendor_filter = config.vendor_id.map(|v| format!("{:#06x}", v)),
            product_filter = config.product_id.map(|p| format!("{:#06x}", p)),
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
        if let Some(vendor) = config.vendor_id {
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
        if let Some(product) = config.product_id {
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
        if config.vendor_id.is_some() || config.product_id.is_some() {
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
    ExportInactive,
    TransferFailed(String),
}

impl fmt::Display for HeartbeatFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatFailure::SessionChanged { previous, current } => write!(
                f,
                "gadget session changed (0x{previous:016x} → 0x{current:016x})"
            ),
            HeartbeatFailure::ExportInactive => write!(f, "gadget reports no active export"),
            HeartbeatFailure::TransferFailed(err) => {
                write!(f, "heartbeat control transfer failed: {err}")
            }
        }
    }
}

async fn run_heartbeat(
    mut client: HostStatusClient,
    initial_session_id: u64,
    interval: Duration,
) -> Result<(), HeartbeatFailure> {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match client.read_status().await {
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
                if !status.export_active() {
                    return Err(HeartbeatFailure::ExportInactive);
                }
            }
            Err(err) => {
                return Err(HeartbeatFailure::TransferFailed(err.to_string()));
            }
        }
    }
}

async fn fetch_status_with_retry(
    client: &mut HostStatusClient,
    attempts: usize,
    delay: Duration,
) -> Result<SmooStatusV0, TransportError> {
    let mut attempt = 0;
    loop {
        match client.read_status().await {
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
