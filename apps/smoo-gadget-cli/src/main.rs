use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use futures::{stream::FuturesUnordered, StreamExt};
use smoo_gadget_core::{
    ConfigExportsV0, ControlIo, DmaHeap, ExportController, ExportFlags, ExportReconcileContext,
    ExportSpec, ExportState, FunctionfsEndpoints, GadgetConfig, GadgetControl, GadgetStatusReport,
    IoStateKind, PersistedExportRecord, RuntimeTunables, SetupCommand, SetupPacket, SmooGadget,
    StateStore,
};
use smoo_gadget_ublk::{SmooUblk, SmooUblkDevice, UblkBuffer, UblkIoRequest, UblkOp};
use smoo_proto::{Ident, OpCode, Request, Response};
use std::{
    collections::HashMap,
    fs::File,
    io,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use tokio::{
    signal,
    sync::{mpsc, RwLock},
};
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;
use usb_gadget::{
    function::custom::{
        CtrlReceiver, CtrlReq, CtrlSender, Custom, Endpoint, EndpointDirection, Interface,
        TransferType,
    },
    Class, Config, Gadget, Id, RegGadget, Strings,
};

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;
const DEFAULT_MAX_IO_BYTES: usize = 4 * 1024 * 1024;
const SINGLE_EXPORT_ID: u32 = 0;

#[derive(Debug, Parser)]
#[command(name = "smoo-gadget-cli")]
#[command(about = "Expose a smoo gadget backed by FunctionFS + ublk", long_about = None)]
struct Args {
    /// USB vendor ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xDEAD", value_parser = parse_hex_u16)]
    vendor_id: u16,
    /// USB product ID for the gadget (hex).
    #[arg(long, value_name = "HEX", default_value = "0xBEEF", value_parser = parse_hex_u16)]
    product_id: u16,
    /// Number of ublk queues to configure.
    #[arg(long, default_value_t = 1)]
    queue_count: u16,
    /// Depth of each ublk queue.
    #[arg(long, default_value_t = 16)]
    queue_depth: u16,
    /// Disable the DMA-BUF fast path even if the kernel advertises support.
    #[arg(long)]
    no_dma_buf: bool,
    /// DMA-HEAP to allocate from when DMA-BUF mode is enabled.
    #[arg(long, value_enum, default_value_t = DmaHeapSelection::System)]
    dma_heap: DmaHeapSelection,
    /// Path to the recovery state file. When unset, crash recovery is disabled.
    #[arg(long, value_name = "PATH")]
    state_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DmaHeapSelection {
    System,
    Cma,
    Reserved,
}

impl From<DmaHeapSelection> for DmaHeap {
    fn from(value: DmaHeapSelection) -> Self {
        match value {
            DmaHeapSelection::System => DmaHeap::System,
            DmaHeapSelection::Cma => DmaHeap::Cma,
            DmaHeapSelection::Reserved => DmaHeap::Reserved,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let (custom, endpoints, _gadget_guard) = setup_functionfs(&args).context("setup FunctionFS")?;

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let mut state_store = if let Some(path) = args.state_file.as_ref() {
        info!(path = ?path, "state file configured");
        match StateStore::load(path.clone()) {
            Ok(store) => store,
            Err(err) => {
                warn!(path = ?path, error = ?err, "failed to load state file; starting new session");
                StateStore::new_with_path(path.clone())
            }
        }
    } else {
        debug!("state file disabled; crash recovery off");
        StateStore::new()
    };

    initialize_session(&mut ublk, &mut state_store).await?;
    let ident = Ident::new(0, 1);
    let dma_heap = if args.no_dma_buf {
        None
    } else {
        Some(args.dma_heap.into())
    };
    let gadget_config = GadgetConfig::new(
        ident,
        args.queue_count,
        args.queue_depth,
        DEFAULT_MAX_IO_BYTES,
        dma_heap,
    );
    let gadget = SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?;
    info!(
        ident_major = ident.major,
        ident_minor = ident.minor,
        queues = args.queue_count,
        depth = args.queue_depth,
        "smoo gadget initialized"
    );

    let control_handler = gadget.control_handler();
    let (control_tx, control_rx) = mpsc::channel(8);

    let exports = build_initial_exports(&state_store);
    let initial_export_count = exports
        .values()
        .filter(|ctrl| ctrl.device().is_some())
        .count() as u32;
    let status = GadgetStatusShared::new(GadgetStatus::new(
        state_store.session_id(),
        initial_export_count,
    ));
    let control_task = tokio::spawn(control_loop(
        custom,
        control_handler,
        status.clone(),
        control_tx,
    ));
    let tunables = RuntimeTunables {
        queue_count: args.queue_count,
        queue_depth: args.queue_depth,
        max_io_bytes: DEFAULT_MAX_IO_BYTES,
        dma_heap,
    };
    let runtime = RuntimeState {
        state_store,
        status,
        exports,
        tunables,
    };
    let result = run_event_loop(&mut ublk, gadget, runtime, control_rx).await;
    control_task.abort();
    let _ = control_task.await;
    result
}

#[derive(Clone, Copy, Debug)]
struct GadgetStatus {
    session_id: u64,
    export_count: u32,
}

impl GadgetStatus {
    fn new(session_id: u64, export_count: u32) -> Self {
        Self {
            session_id,
            export_count,
        }
    }
}

#[derive(Clone)]
struct GadgetStatusShared {
    inner: Arc<RwLock<GadgetStatus>>,
}

impl GadgetStatusShared {
    fn new(initial: GadgetStatus) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    async fn snapshot(&self) -> GadgetStatus {
        *self.inner.read().await
    }

    async fn report(&self) -> GadgetStatusReport {
        let snapshot = self.snapshot().await;
        GadgetStatusReport::new(snapshot.session_id, snapshot.export_count)
    }

    async fn set_export_count(&self, export_count: u32) {
        let mut guard = self.inner.write().await;
        guard.export_count = export_count;
    }
}

struct RuntimeState {
    state_store: StateStore,
    status: GadgetStatusShared,
    exports: HashMap<u32, ExportController>,
    tunables: RuntimeTunables,
}

impl RuntimeState {
    fn status(&self) -> &GadgetStatusShared {
        &self.status
    }

    fn state_store(&mut self) -> &mut StateStore {
        &mut self.state_store
    }
}

enum ControlMessage {
    Config(ConfigExportsV0),
}

fn build_initial_exports(state_store: &StateStore) -> HashMap<u32, ExportController> {
    let mut exports = HashMap::new();
    if let Some(record) = state_store.records().get(0).cloned() {
        if let Some(dev_id) = record.assigned_dev_id {
            exports.insert(
                record.export_id,
                ExportController::new(
                    record.export_id,
                    record.spec,
                    ExportState::RecoveringPending { dev_id },
                ),
            );
        } else {
            exports.insert(
                record.export_id,
                ExportController::new(record.export_id, record.spec, ExportState::New),
            );
        }
    }
    exports
}

async fn reconcile_exports(ublk: &mut SmooUblk, runtime: &mut RuntimeState) -> Result<()> {
    let RuntimeState {
        state_store,
        exports,
        tunables,
        ..
    } = runtime;
    let tunables = *tunables;
    for controller in exports.values_mut().filter(|ctrl| ctrl.needs_reconcile()) {
        let mut cx = ExportReconcileContext {
            ublk,
            state_store,
            tunables,
        };
        controller.reconcile(&mut cx).await?;
    }
    Ok(())
}

type IoFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = (
                    u32,
                    IoStateKind,
                    u32,
                    anyhow::Result<UblkIoRequest>,
                    SmooUblkDevice,
                ),
            > + Send,
    >,
>;

fn enqueue_io(runtime: &mut RuntimeState, io_futs: &mut FuturesUnordered<IoFuture>) {
    for (export_id, controller) in runtime.exports.iter_mut() {
        if let Some((kind, dev_id, device)) = controller.take_device_for_io() {
            let export_id = *export_id;
            io_futs.push(Box::pin(async move {
                let res = device.next_io().await;
                (export_id, kind, dev_id, res, device)
            }));
        }
    }
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    mut gadget: SmooGadget,
    mut runtime: RuntimeState,
    mut control_rx: mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);
    let mut io_futs: FuturesUnordered<IoFuture> = FuturesUnordered::new();

    let mut io_error = None;
    loop {
        let reconcile_needed = runtime.exports.values().any(|ctrl| ctrl.needs_reconcile());
        if reconcile_needed {
            reconcile_exports(ublk, &mut runtime).await?;
        }
        let active_count = runtime
            .exports
            .values()
            .filter(|ctrl| ctrl.dev_id().is_some())
            .count() as u32;
        runtime.status().set_export_count(active_count).await;
        enqueue_io(&mut runtime, &mut io_futs);

        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            maybe_msg = control_rx.recv() => {
                if let Some(msg) = maybe_msg {
                    process_control_message(msg, ublk, &mut runtime).await?;
                } else {
                    break;
                }
            }
            next_io = io_futs.next(), if !io_futs.is_empty() => {
                if let Some((export_id, kind, dev_id, req_res, device)) = next_io {
                    if let Some(ctrl) = runtime.exports.get_mut(&export_id) {
                        match req_res {
                            Ok(req) => {
                                if let Err(err) = handle_request(&mut gadget, &device, req).await {
                                    ctrl.fail_after_io(dev_id, format!("{err:#}"));
                                    io_error = Some(err);
                                    break;
                                }
                                ctrl.restore_device_after_io(kind, dev_id, device);
                            }
                            Err(err) => {
                                ctrl.fail_after_io(dev_id, format!("{err:#}"));
                                ctrl.restore_device_after_io(kind, dev_id, device);
                                io_error = Some(err.context("receive ublk io"));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    for controller in runtime.exports.values_mut() {
        if let Some(device) = controller.take_device() {
            info!(dev_id = device.dev_id(), "stopping ublk device");
            ublk.stop_dev(device, true)
                .await
                .context("stop ublk device")?;
        }
    }
    runtime.status().set_export_count(0).await;

    // Clean shutdown: remove the state file to avoid retaining stale session info.
    if let Err(err) = runtime.state_store().remove_file() {
        warn!(error = ?err, "failed to remove state file on shutdown");
    } else {
        debug!("state file removed on shutdown");
    }

    if let Some(err) = io_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn handle_request(
    gadget: &mut SmooGadget,
    device: &SmooUblkDevice,
    req: UblkIoRequest,
) -> Result<()> {
    let block_size = device.block_size();
    let req_len = match request_byte_len(&req, block_size) {
        Ok(len) => len,
        Err(err) => {
            let errno = errno_from_io(&err);
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                errno = errno,
                ?req.op,
                "invalid request length: {err}"
            );
            device
                .complete_io(req, -errno)
                .context("complete invalid request")?;
            return Ok(());
        }
    };

    let opcode = match opcode_from_ublk(req.op) {
        Some(op) => op,
        None => {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                op = ?req.op,
                "unsupported ublk opcode"
            );
            device
                .complete_io(req, -libc::EOPNOTSUPP)
                .context("complete unsupported opcode")?;
            return Ok(());
        }
    };

    let mut payload: Option<UblkBuffer<'_>> = None;
    let result = async {
        if matches!(opcode, OpCode::Read | OpCode::Write) && req_len > 0 {
            let capacity = device.buffer_len();
            if req_len > capacity {
                warn!(
                    queue = req.queue_id,
                    tag = req.tag,
                    req_bytes = req_len,
                    buf_cap = capacity,
                    "request exceeds buffer capacity"
                );
                device
                    .complete_io(req, -libc::EINVAL)
                    .context("complete oversized request")?;
                return Ok(());
            }
            payload = Some(
                device
                    .checkout_buffer(req.queue_id, req.tag)
                    .context("checkout bulk buffer")?,
            );
        }

        let byte_len = u32::try_from(req_len).context("request length exceeds protocol limit")?;
        let proto_req = Request::new(opcode, req.sector, byte_len, 0);
        gadget
            .send_request(proto_req)
            .await
            .context("send smoo request")?;

        if opcode == OpCode::Read && req_len > 0 {
            if let Some(buf) = payload.as_mut() {
                gadget
                    .read_bulk_buffer(&mut buf.as_mut_slice()[..req_len])
                    .await
                    .context("read bulk payload")?;
            }
        } else if opcode == OpCode::Write && req_len > 0 {
            if let Some(buf) = payload.as_mut() {
                gadget
                    .write_bulk_buffer(&mut buf.as_mut_slice()[..req_len])
                    .await
                    .context("write bulk payload")?;
            }
        }

        let response = gadget.read_response().await.context("read smoo response")?;

        let status = response_status(&response, req_len)?;
        if status >= 0 && status as usize != req_len {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                expected = req_len,
                reported = status,
                "response byte count mismatch"
            );
        }
        device
            .complete_io(req, status)
            .context("complete ublk request")?;
        Ok(())
    }
    .await;

    result
}

async fn control_loop(
    mut custom: Custom,
    handler: GadgetControl,
    status: GadgetStatusShared,
    tx: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    loop {
        custom
            .wait_event()
            .await
            .context("wait for FunctionFS event")?;
        let event = custom.event().context("read FunctionFS event")?;
        match event {
            usb_gadget::function::custom::Event::Bind => {
                debug!("FunctionFS bind event (control loop)")
            }
            usb_gadget::function::custom::Event::Unbind => {
                debug!("FunctionFS unbind event (control loop)")
            }
            usb_gadget::function::custom::Event::Enable => {
                debug!("FunctionFS enable event (control loop)")
            }
            usb_gadget::function::custom::Event::Disable => {
                debug!("FunctionFS disable event (control loop)")
            }
            usb_gadget::function::custom::Event::Suspend => {
                debug!("FunctionFS suspend event (control loop)")
            }
            usb_gadget::function::custom::Event::Resume => {
                debug!("FunctionFS resume event (control loop)")
            }
            usb_gadget::function::custom::Event::SetupDeviceToHost(sender) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(sender.ctrl_req());
                let mut io = UsbControlIo::from_sender(sender);
                if let Err(err) = handler.handle_setup_packet(&mut io, setup, &report).await {
                    warn!(error = ?err, "vendor setup handling failed");
                    let _ = io.stall().await;
                }
            }
            usb_gadget::function::custom::Event::SetupHostToDevice(receiver) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(receiver.ctrl_req());
                let mut io = UsbControlIo::from_receiver(receiver);
                match handler.handle_setup_packet(&mut io, setup, &report).await {
                    Ok(Some(SetupCommand::Config(payload))) => {
                        if tx.send(ControlMessage::Config(payload)).await.is_err() {
                            anyhow::bail!("control channel closed");
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(error = ?err, "vendor setup handling failed");
                        let _ = io.stall().await;
                    }
                }
            }
            usb_gadget::function::custom::Event::Unknown(code) => {
                debug!(event = code, "FunctionFS unknown event");
            }
            _ => {}
        }
    }
}

fn opcode_from_ublk(op: UblkOp) -> Option<OpCode> {
    match op {
        UblkOp::Read => Some(OpCode::Read),
        UblkOp::Write => Some(OpCode::Write),
        UblkOp::Flush => Some(OpCode::Flush),
        UblkOp::Discard => Some(OpCode::Discard),
        UblkOp::Unknown(_) => None,
    }
}

fn response_status(resp: &Response, expected_len: usize) -> Result<i32> {
    if resp.flags != 0 {
        let errno = i32::try_from(resp.flags).unwrap_or(libc::EIO);
        return Ok(-errno);
    }
    let len = resp.byte_len as usize;
    i32::try_from(len)
        .or_else(|_| i32::try_from(expected_len))
        .map_err(|_| anyhow!("response length exceeds i32"))
}

fn request_byte_len(req: &UblkIoRequest, block_size: usize) -> io::Result<usize> {
    let sectors = usize::try_from(req.num_sectors)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sector count overflow"))?;
    sectors
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow"))
}

fn errno_from_io(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or_else(|| match err.kind() {
        io::ErrorKind::Unsupported => libc::EOPNOTSUPP,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::UnexpectedEof => libc::EIO,
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    })
}

fn setup_from_ctrl_req(ctrl: &CtrlReq) -> SetupPacket {
    SetupPacket::from_fields(
        ctrl.request_type,
        ctrl.request,
        ctrl.value,
        ctrl.index,
        ctrl.length,
    )
}

enum UsbControlInner<'a> {
    In(Option<CtrlSender<'a>>),
    Out(Option<CtrlReceiver<'a>>),
}

struct UsbControlIo<'a> {
    inner: UsbControlInner<'a>,
}

impl<'a> UsbControlIo<'a> {
    fn from_sender(sender: CtrlSender<'a>) -> Self {
        Self {
            inner: UsbControlInner::In(Some(sender)),
        }
    }

    fn from_receiver(receiver: CtrlReceiver<'a>) -> Self {
        Self {
            inner: UsbControlInner::Out(Some(receiver)),
        }
    }
}

#[async_trait::async_trait]
impl ControlIo for UsbControlIo<'_> {
    async fn write_in(&mut self, data: &[u8]) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::In(sender) => {
                let sender = sender.take().context("control sender already used")?;
                sender
                    .send(data)
                    .with_context(|| format!("send control response of {} bytes", data.len()))
                    .map(|_| ())
            }
            UsbControlInner::Out(_) => Ok(()),
        }
    }

    async fn read_out(&mut self, buf: &mut [u8]) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::Out(receiver) => {
                let receiver = receiver.take().context("control receiver already used")?;
                let read = receiver
                    .recv(buf)
                    .with_context(|| format!("read control payload of {} bytes", buf.len()))?;
                ensure!(read == buf.len(), "control payload truncated");
                Ok(())
            }
            UsbControlInner::In(_) => Err(anyhow!("attempted to read_out on IN control transfer")),
        }
    }

    async fn stall(&mut self) -> Result<()> {
        match &mut self.inner {
            UsbControlInner::In(sender) => {
                let sender = sender.take().context("control sender already used")?;
                sender.halt().context("stall control sender")
            }
            UsbControlInner::Out(receiver) => {
                let receiver = receiver.take().context("control receiver already used")?;
                receiver.halt().context("stall control receiver")
            }
        }
    }
}
async fn initialize_session(_ublk: &mut SmooUblk, state_store: &mut StateStore) -> Result<()> {
    if state_store.records().is_empty() {
        if state_store.path().is_some() {
            debug!("state file present but no exports recorded; nothing to recover");
        }
        return Ok(());
    }
    if state_store.records().len() > 1 {
        warn!(
            exports = state_store.records().len(),
            "multi-export state unsupported; clearing state store"
        );
        reset_state_store(state_store);
        let _ = state_store.persist();
        return Ok(());
    }
    Ok(())
}

fn reset_state_store(state_store: &mut StateStore) {
    let path = state_store.path().map(Path::to_path_buf);
    *state_store = match path {
        Some(path) => StateStore::new_with_path(path),
        None => StateStore::new(),
    };
}

async fn process_control_message(
    msg: ControlMessage,
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
) -> Result<()> {
    match msg {
        ControlMessage::Config(config) => {
            if let Err(err) = apply_config(ublk, runtime, config).await {
                warn!(error = ?err, "CONFIG_EXPORTS application failed");
            }
        }
    }
    Ok(())
}

async fn apply_config(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    config: ConfigExportsV0,
) -> Result<()> {
    for controller in runtime.exports.values_mut() {
        if let Some(device) = controller.take_device() {
            ublk.stop_dev(device, true)
                .await
                .context("stop ublk device before applying CONFIG_EXPORTS")?;
        }
    }
    runtime.exports.clear();

    match config.export() {
        None => {
            info!("CONFIG_EXPORTS requested zero exports");
            runtime.state_store().replace_all(Vec::new());
            if let Err(err) = runtime.state_store().persist() {
                warn!(error = ?err, "failed to clear state file");
            }
            runtime.status().set_export_count(0).await;
            Ok(())
        }
        Some(export) => {
            let block_size = export.block_size as usize;
            ensure!(
                export.size_bytes != 0,
                "CONFIG_EXPORTS size_bytes must be non-zero"
            );
            let blocks = export
                .size_bytes
                .checked_div(block_size as u64)
                .context("size bytes smaller than block size")?;
            ensure!(blocks > 0, "export size too small");
            let _block_count =
                usize::try_from(blocks).context("block count exceeds usize capacity")?;
            let spec = ExportSpec {
                block_size: export.block_size,
                size_bytes: export.size_bytes,
                flags: ExportFlags::empty(),
            };
            let controller_spec = spec.clone();
            let record = PersistedExportRecord {
                export_id: SINGLE_EXPORT_ID,
                spec,
                assigned_dev_id: None,
            };
            runtime.state_store().replace_all(vec![record]);
            if let Err(err) = runtime.state_store().persist() {
                warn!(error = ?err, "failed to write state store");
            }
            runtime.exports.insert(
                SINGLE_EXPORT_ID,
                ExportController::new(SINGLE_EXPORT_ID, controller_spec, ExportState::New),
            );
            runtime
                .status()
                .set_export_count(runtime.exports.len() as u32)
                .await;
            Ok(())
        }
    }
}

struct GadgetGuard {
    #[allow(dead_code)]
    registration: RegGadget,
}

fn setup_functionfs(args: &Args) -> Result<(Custom, FunctionfsEndpoints, GadgetGuard)> {
    let builder = Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(SMOO_SUBCLASS, SMOO_PROTOCOL), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    );
    let (mut custom, handle) = builder.build();

    let klass = Class::new(SMOO_CLASS, SMOO_SUBCLASS, SMOO_PROTOCOL);
    let id = Id::new(args.vendor_id, args.product_id);
    let strings = Strings::new("smoo", "smoo gadget", "0001");
    let udc = usb_gadget::default_udc().context("locate UDC")?;
    let gadget =
        Gadget::new(klass, id, strings).with_config(Config::new("config").with_function(handle));
    let reg = gadget.register().context("register gadget")?;

    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;
    reg.bind(Some(&udc)).context("bind gadget to UDC")?;

    let interrupt_in = open_endpoint_fd(ffs_dir.join("ep1")).context("open interrupt IN")?;
    let interrupt_out = open_endpoint_fd(ffs_dir.join("ep2")).context("open interrupt OUT")?;
    let bulk_in = open_endpoint_fd(ffs_dir.join("ep3")).context("open bulk IN")?;
    let bulk_out = open_endpoint_fd(ffs_dir.join("ep4")).context("open bulk OUT")?;
    let endpoints = FunctionfsEndpoints::new(interrupt_in, interrupt_out, bulk_in, bulk_out);

    Ok((custom, endpoints, GadgetGuard { registration: reg }))
}

fn interrupt_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Interrupt, 16)
}

fn interrupt_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Interrupt, 16)
}

fn bulk_in_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::device_to_host();
    make_ep(dir, TransferType::Bulk, 512)
}

fn bulk_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Bulk, 512)
}

fn make_ep(direction: EndpointDirection, ty: TransferType, packet_size: u16) -> Endpoint {
    let mut ep = match ty {
        TransferType::Bulk => Endpoint::bulk(direction),
        _ => Endpoint::custom(direction, ty),
    };
    ep.max_packet_size_hs = packet_size;
    ep.max_packet_size_ss = packet_size;
    ep
}

fn open_endpoint_fd(path: PathBuf) -> Result<OwnedFd> {
    let file = File::options()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    Ok(to_owned_fd(file))
}

fn to_owned_fd(file: File) -> OwnedFd {
    let raw = file.into_raw_fd();
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}
