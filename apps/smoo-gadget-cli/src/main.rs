use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use smoo_gadget_core::{
    ConfigExport, ConfigExportsV0, ControlIo, DeviceHandle, DmaHeap, ExportController, ExportFlags,
    ExportReconcileContext, ExportSpec, ExportState, FunctionfsEndpoints, GadgetConfig,
    GadgetControl, GadgetStatusReport, LinkCommand, LinkController, LinkState,
    PersistedExportRecord, RuntimeTunables, SetupCommand, SetupPacket, SmooGadget, SmooUblk,
    SmooUblkDevice, StateStore, UblkBuffer, UblkIoRequest, UblkOp, UblkQueueRuntime,
};
use smoo_proto::{Ident, OpCode, Request, Response, SMOO_STATUS_REQUEST, SMOO_STATUS_REQ_TYPE};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    signal,
    signal::unix::{signal as unix_signal, SignalKind},
    sync::{mpsc, watch, Mutex, RwLock},
    task::JoinHandle,
};
use tracing::{debug, info, trace, warn};
use tracing_subscriber::prelude::*;
use usb_gadget::{
    function::custom::{
        CtrlReceiver, CtrlReq, CtrlSender, Custom, Endpoint, EndpointDirection, Event, Interface,
        TransferType,
    },
    Class, Config, Gadget, Id, RegGadget, Strings,
};

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;
const DEFAULT_MAX_IO_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "smoo-gadget-cli", version)]
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
    /// Opt-in to the experimental DMA-BUF fast path when supported by the kernel.
    #[arg(long)]
    experimental_dma_buf: bool,
    /// DMA-HEAP to allocate from when DMA-BUF mode is enabled.
    #[arg(long, value_enum, default_value_t = DmaHeapSelection::System)]
    dma_heap: DmaHeapSelection,
    /// Path to the recovery state file. When unset, crash recovery is disabled.
    #[arg(long, value_name = "PATH")]
    state_file: Option<PathBuf>,
    /// Adopt existing ublk devices via user recovery.
    #[arg(long)]
    adopt: bool,
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
    if args.adopt {
        adopt_prepare(&mut ublk, &mut state_store).await?;
    }

    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let (custom, endpoints, _gadget_guard, ffs_dir) =
        setup_functionfs(&args).context("setup FunctionFS")?;

    let ident = Ident::new(0, 1);
    let dma_heap = args.experimental_dma_buf.then(|| args.dma_heap.into());
    let gadget_config = GadgetConfig::new(
        ident,
        args.queue_count,
        args.queue_depth,
        DEFAULT_MAX_IO_BYTES,
        dma_heap,
    );
    let gadget =
        Arc::new(SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?);
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
    let initial_export_count = count_active_exports(&exports);
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
    let link = LinkController::new(Duration::from_secs(3));
    let runtime = RuntimeState {
        state_store,
        status,
        exports,
        queue_tasks: HashMap::new(),
        tunables,
        gadget: Some(gadget),
        gadget_config,
        ffs_dir,
    };
    let result = run_event_loop(&mut ublk, runtime, control_rx, link).await;
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
    queue_tasks: HashMap<u32, QueueTaskSet>,
    tunables: RuntimeTunables,
    gadget: Option<Arc<SmooGadget>>,
    gadget_config: GadgetConfig,
    ffs_dir: PathBuf,
}

impl RuntimeState {
    fn status(&self) -> &GadgetStatusShared {
        &self.status
    }

    fn state_store(&mut self) -> &mut StateStore {
        &mut self.state_store
    }
}

type QueueSender = mpsc::UnboundedSender<QueueEvent>;

struct QueueTaskSet {
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl QueueTaskSet {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

enum QueueEvent {
    Request {
        export_id: u32,
        dev_id: u32,
        request: UblkIoRequest,
        queues: Arc<UblkQueueRuntime>,
    },
    QueueError {
        export_id: u32,
        dev_id: u32,
        error: anyhow::Error,
    },
}

struct OutstandingRequest {
    dev_id: u32,
    request: UblkIoRequest,
    queues: Arc<UblkQueueRuntime>,
}

struct InflightRequest {
    export_id: u32,
    request_id: u32,
    request: UblkIoRequest,
    queues: Arc<UblkQueueRuntime>,
    req_len: usize,
    block_size: usize,
}

enum ControlMessage {
    Config(ConfigExportsV0),
    Ep0Event(Event<'static>),
    StatusPing,
}

fn build_initial_exports(state_store: &StateStore) -> HashMap<u32, ExportController> {
    let mut exports = HashMap::new();
    for record in state_store.records() {
        if exports.contains_key(&record.export_id) {
            warn!(
                export_id = record.export_id,
                "duplicate export_id in state store; skipping"
            );
            continue;
        }
        let state = match record.assigned_dev_id {
            Some(dev_id) => ExportState::RecoveringPending { dev_id },
            None => ExportState::New,
        };
        exports.insert(
            record.export_id,
            ExportController::new(record.export_id, record.spec.clone(), state),
        );
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
    let now = Instant::now();
    for controller in exports
        .values_mut()
        .filter(|ctrl| ctrl.needs_reconcile(now))
    {
        trace!(
            export_id = controller.export_id,
            state = export_state_tag(controller),
            dev_id = controller.dev_id(),
            "reconcile begin"
        );
        let mut cx = ExportReconcileContext {
            ublk,
            state_store,
            tunables,
        };
        controller.reconcile(&mut cx).await?;
        trace!(
            export_id = controller.export_id,
            state = export_state_tag(controller),
            dev_id = controller.dev_id(),
            "reconcile end"
        );
    }
    Ok(())
}

fn spawn_queue_tasks(
    export_id: u32,
    dev_id: u32,
    queues: Arc<UblkQueueRuntime>,
    tx: QueueSender,
) -> QueueTaskSet {
    let (stop, stop_rx) = watch::channel(false);
    let mut handles = Vec::new();
    for queue_id in 0..queues.queue_count() {
        let mut stop_rx = stop_rx.clone();
        let queues = queues.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            queue_task_loop(export_id, dev_id, queue_id, queues, &mut stop_rx, tx).await;
        }));
    }
    QueueTaskSet { stop, handles }
}

async fn queue_task_loop(
    export_id: u32,
    dev_id: u32,
    queue_id: u16,
    queues: Arc<UblkQueueRuntime>,
    stop: &mut watch::Receiver<bool>,
    tx: QueueSender,
) {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_ok() {
                    break;
                } else {
                    break;
                }
            }
            req = queues.next_io(queue_id) => {
                match req {
                    Ok(request) => {
                        if tx.send(QueueEvent::Request { export_id, dev_id, request, queues: queues.clone() }).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        if !*stop.borrow() {
                            let _ = tx.send(QueueEvent::QueueError { export_id, dev_id, error: err });
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn sync_queue_tasks(runtime: &mut RuntimeState, queue_tx: &QueueSender) {
    let mut to_stop: Vec<u32> = runtime
        .queue_tasks
        .keys()
        .cloned()
        .filter(|export_id| !runtime.exports.contains_key(export_id))
        .collect();

    for (&export_id, controller) in runtime.exports.iter() {
        let should_run = controller
            .device_handle()
            .map(|h| h.is_online())
            .unwrap_or(false);
        let running = runtime.queue_tasks.contains_key(&export_id);
        if should_run && !running {
            if let Some(handle) = controller.device_handle() {
                if let Some(queues) = handle.queues() {
                    let tasks =
                        spawn_queue_tasks(export_id, handle.dev_id(), queues, queue_tx.clone());
                    runtime.queue_tasks.insert(export_id, tasks);
                }
            }
        } else if !should_run && running {
            to_stop.push(export_id);
        }
    }

    for export_id in to_stop {
        if let Some(tasks) = runtime.queue_tasks.remove(&export_id) {
            tasks.shutdown().await;
        }
    }
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    mut runtime: RuntimeState,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    mut link: LinkController,
) -> Result<()> {
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);
    let idle_sleep = tokio::time::sleep(Duration::from_millis(10));
    tokio::pin!(idle_sleep);
    let mut liveness_tick = tokio::time::interval(Duration::from_millis(500));
    let mut outstanding: HashMap<u32, HashMap<(u16, u16), OutstandingRequest>> = HashMap::new();
    let mut hup = unix_signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let (queue_tx, mut queue_rx) = mpsc::unbounded_channel::<QueueEvent>();

    let mut io_error = None;
    let mut recovery_exit = false;
    let inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut response_task: Option<JoinHandle<()>> = None;
    loop {
        idle_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(10));
        let now = Instant::now();
        link.tick(now);
        process_link_commands(&mut runtime, &mut link).await?;
        drain_outstanding(&mut runtime, &mut link, &inflight, &mut outstanding).await?;
        let reconcile_needed = runtime
            .exports
            .values()
            .any(|ctrl| ctrl.needs_reconcile(now));
        if reconcile_needed {
            reconcile_exports(ublk, &mut runtime).await?;
        }
        sync_queue_tasks(&mut runtime, &queue_tx).await;
        if runtime.gadget.is_none() {
            if let Some(handle) = response_task.take() {
                handle.abort();
            }
            drain_inflight(&inflight).await;
        } else if response_task.is_none() {
            if let Some(gadget) = runtime.gadget.clone() {
                let inflight_map = inflight.clone();
                let interrupt_out = gadget.response_reader();
                response_task = Some(tokio::spawn(response_loop(interrupt_out, inflight_map)));
            }
        }
        let active_count = count_active_exports(&runtime.exports);
        runtime.status().set_export_count(active_count).await;

        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            Some(_) = hup.recv() => {
                info!("SIGHUP received; initiating user recovery");
                begin_user_recovery(ublk, &mut runtime).await?;
                recovery_exit = true;
                break;
            }
            _ = liveness_tick.tick() => {
                link.tick(Instant::now());
                // trace!(state = ?link.state(), outstanding_exports = outstanding.len(), "liveness tick");
                process_link_commands(&mut runtime, &mut link).await?;
                drain_outstanding(&mut runtime, &mut link, &inflight, &mut outstanding).await?;
                sync_queue_tasks(&mut runtime, &queue_tx).await;
            }
            maybe_msg = control_rx.recv() => {
                if let Some(msg) = maybe_msg {
                    let was_config = matches!(msg, ControlMessage::Config(_));
                    process_control_message(msg, ublk, &mut runtime, &mut link).await?;
                    if was_config {
                        prune_outstanding_for_missing_exports(&mut outstanding, &runtime.exports);
                    }
                    process_link_commands(&mut runtime, &mut link).await?;
                    drain_outstanding(&mut runtime, &mut link, &inflight, &mut outstanding).await?;
                    sync_queue_tasks(&mut runtime, &queue_tx).await;
                } else {
                    break;
                }
            }
            maybe_evt = queue_rx.recv() => {
                if let Some(evt) = maybe_evt {
                    if let Err(err) =
                        handle_queue_event(&mut runtime, &mut link, &inflight, &mut outstanding, evt)
                            .await
                    {
                        io_error = Some(err);
                        break;
                    }
                } else {
                    break;
                }
            }
            _ = &mut idle_sleep => {}
        }
    }

    if recovery_exit {
        return Ok(());
    }
    cleanup_ublk_devices(ublk, &mut runtime).await?;
    runtime.status().set_export_count(0).await;

    // Clean shutdown: remove the state file after teardown to avoid retaining stale session info.
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
    gadget: &SmooGadget,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    queues: Arc<UblkQueueRuntime>,
    req: UblkIoRequest,
) -> Result<()> {
    let block_size = queues.block_size();
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
            queues
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
            queues
                .complete_io(req, -libc::EOPNOTSUPP)
                .context("complete unsupported opcode")?;
            return Ok(());
        }
    };

    trace!(
        export_id,
        dev_id = queues.dev_id(),
        queue = req.queue_id,
        tag = req.tag,
        op = ?req.op,
        req_bytes = req_len,
        block_size,
        "handle_request begin"
    );

    let mut payload: Option<UblkBuffer<'_>> = None;
    let result = async {
        if matches!(opcode, OpCode::Read | OpCode::Write) && req_len > 0 {
            let capacity = queues.buffer_len();
            if req_len > capacity {
                warn!(
                    queue = req.queue_id,
                    tag = req.tag,
                    req_bytes = req_len,
                    buf_cap = capacity,
                    "request exceeds buffer capacity"
                );
                queues
                    .complete_io(req, -libc::EINVAL)
                    .context("complete oversized request")?;
                return Ok(());
            }
            payload = Some(
                queues
                    .checkout_buffer(req.queue_id, req.tag)
                    .context("checkout bulk buffer")?,
            );
        }

        let num_blocks = u32::try_from(req_len / block_size)
            .context("request block count exceeds protocol limit")?;
        let request_id = make_request_id(req.queue_id, req.tag);
        let proto_req = Request::new(export_id, request_id, opcode, req.sector, num_blocks, 0);
        {
            // Track the request before sending it so early Responses can't be dropped as unknown.
            let mut guard = inflight.lock().await;
            let entry = InflightRequest {
                export_id,
                request_id,
                request: req,
                queues: queues.clone(),
                req_len,
                block_size,
            };
            guard
                .entry(export_id)
                .or_default()
                .insert(request_id, entry);
        }
        trace!(
            export_id,
            dev_id = queues.dev_id(),
            queue = req.queue_id,
            tag = req.tag,
            op = ?opcode,
            num_blocks,
            req_bytes = req_len,
            "sending smoo Request"
        );
        gadget
            .send_request(proto_req)
            .await
            .context("send smoo request")?;
        trace!(
            export_id,
            dev_id = queues.dev_id(),
            queue = req.queue_id,
            tag = req.tag,
            "smoo Request sent"
        );

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

        Ok(())
    }
    .await;

    if let Err(err) = result {
        drop_inflight_entry(inflight, export_id, make_request_id(req.queue_id, req.tag)).await;
        return Err(err);
    }

    Ok(())
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
                debug!("FunctionFS bind event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Bind)).await;
            }
            usb_gadget::function::custom::Event::Unbind => {
                debug!("FunctionFS unbind event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Unbind)).await;
            }
            usb_gadget::function::custom::Event::Enable => {
                debug!("FunctionFS enable event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Enable)).await;
            }
            usb_gadget::function::custom::Event::Disable => {
                debug!("FunctionFS disable event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Disable)).await;
            }
            usb_gadget::function::custom::Event::Suspend => {
                debug!("FunctionFS suspend event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Suspend)).await;
            }
            usb_gadget::function::custom::Event::Resume => {
                debug!("FunctionFS resume event (control loop)");
                let _ = tx.send(ControlMessage::Ep0Event(Event::Resume)).await;
            }
            usb_gadget::function::custom::Event::SetupDeviceToHost(sender) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(sender.ctrl_req());
                let mut io = UsbControlIo::from_sender(sender);
                if let Err(err) = handler.handle_setup_packet(&mut io, setup, &report).await {
                    warn!(error = ?err, "vendor setup handling failed");
                    let _ = io.stall().await;
                } else if is_status_setup(&setup) {
                    let _ = tx.send(ControlMessage::StatusPing).await;
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
                    Ok(None) => {
                        if is_status_setup(&setup) {
                            let _ = tx.send(ControlMessage::StatusPing).await;
                        }
                    }
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

fn make_request_id(queue_id: u16, tag: u16) -> u32 {
    ((queue_id as u32) << 16) | tag as u32
}

fn response_status(resp: &Response, expected_len: usize, block_size: usize) -> Result<i32> {
    if resp.status != 0 {
        let errno = i32::from(resp.status);
        return Ok(-errno);
    }
    let len = resp.num_blocks as usize * block_size;
    i32::try_from(len)
        .or_else(|_| i32::try_from(expected_len))
        .map_err(|_| anyhow!("response length exceeds i32"))
}

async fn response_loop(
    interrupt_out: Arc<Mutex<tokio::fs::File>>,
    inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
) {
    loop {
        let response = {
            let mut buf = [0u8; smoo_proto::RESPONSE_LEN];
            let read_res = {
                let mut lock = interrupt_out.lock().await;
                lock.read_exact(&mut buf).await
            };
            if let Err(err) = read_res {
                warn!(error = ?err, "response reader exiting after error");
                break;
            }
            match Response::try_from(buf.as_slice()) {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(error = ?err, "response reader failed to decode Response");
                    continue;
                }
            }
        };
        let entry = {
            let mut guard = inflight.lock().await;
            guard
                .get_mut(&response.export_id)
                .and_then(|m| m.remove(&response.request_id))
        };
        let Some(entry) = entry else {
            warn!(
                request_id = response.request_id,
                export_id = response.export_id,
                op = ?response.op,
                "response for unknown request; dropping"
            );
            continue;
        };
        if response.export_id != entry.export_id || response.request_id != entry.request_id {
            warn!(
                export_id = response.export_id,
                request_id = response.request_id,
                expected_export = entry.export_id,
                expected_request = entry.request_id,
                "response identity mismatch; dropping"
            );
            let _ = entry.queues.complete_io(entry.request, -libc::EBADE);
            continue;
        }
        let status = match response_status(&response, entry.req_len, entry.block_size) {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    request_id = response.request_id,
                    export_id = response.export_id,
                    error = %err,
                    "failed to interpret response"
                );
                -libc::EIO
            }
        };
        if status >= 0 && (status as usize) != entry.req_len {
            warn!(
                request_id = response.request_id,
                export_id = response.export_id,
                expected = entry.req_len,
                reported = status,
                "response byte count mismatch"
            );
        }
        if let Err(err) = entry.queues.complete_io(entry.request, status) {
            warn!(
                request_id = response.request_id,
                export_id = response.export_id,
                error = ?err,
                "failed to complete ublk request from response"
            );
        }
    }
    drain_inflight(&inflight).await;
}

async fn drop_inflight_entry(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) {
    let mut guard = inflight.lock().await;
    if let Some(map) = guard.get_mut(&export_id) {
        map.remove(&request_id);
        if map.is_empty() {
            guard.remove(&export_id);
        }
    }
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

fn is_status_setup(setup: &SetupPacket) -> bool {
    setup.request() == SMOO_STATUS_REQUEST && setup.request_type() == SMOO_STATUS_REQ_TYPE
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

    let mut seen = HashSet::new();
    let mut reset = false;
    for record in state_store.records() {
        if !seen.insert(record.export_id) {
            warn!(
                export_id = record.export_id,
                "state file contains duplicate export_id; clearing state"
            );
            reset = true;
            break;
        }
        if let Err(err) = validate_persisted_record(record) {
            warn!(
                export_id = record.export_id,
                error = ?err,
                "state file entry invalid; clearing state"
            );
            reset = true;
            break;
        }
    }

    if reset {
        reset_state_store(state_store);
        let _ = state_store.persist();
    }
    Ok(())
}

async fn adopt_prepare(ublk: &mut SmooUblk, state_store: &mut StateStore) -> Result<()> {
    let mut dev_ids = Vec::new();
    let mut owner_pids = HashSet::new();
    let mut stale_devices = false;
    for record in state_store.records() {
        if let Some(dev_id) = record.assigned_dev_id {
            dev_ids.push(dev_id);
            match ublk.owner_pid(dev_id).await {
                Ok(pid) => {
                    let alive = pid_is_alive(pid);
                    debug!(dev_id, pid, alive, "queried ublk owner");
                    if pid > 0 && pid != unsafe { libc::getpid() } && alive {
                        owner_pids.insert(pid);
                    } else if pid > 0 && !alive {
                        stale_devices = true;
                    }
                }
                Err(err) => {
                    let missing = error_is_missing(&err);
                    warn!(dev_id, error = ?err, missing, "query owner pid failed");
                    if missing {
                        stale_devices = true;
                    }
                }
            }
        }
    }

    if stale_devices && owner_pids.is_empty() {
        warn!("no surviving owners and stale devices detected; resetting state for fresh session");
        reset_state_store(state_store);
        if let Err(err) = state_store.persist() {
            warn!(error = ?err, "persist state reset failed");
        }
        return Ok(());
    }

    if owner_pids.len() > 1 {
        warn!(
            owners = ?owner_pids,
            "multiple ublk owners detected; resetting state for clean session"
        );
        reset_state_store(state_store);
        if let Err(err) = state_store.persist() {
            warn!(error = ?err, "persist state reset failed");
        }
        anyhow::bail!("multiple ublk owners detected during adopt");
    }

    if let Some(pid) = owner_pids.into_iter().next() {
        info!(pid, "signaling existing smoo-gadget owner for recovery");
        unsafe {
            libc::kill(pid, libc::SIGHUP);
        }
        info!(pid, "waiting for prior owner to exit before adopting");
        wait_for_owner_exit(ublk, &dev_ids, pid, Duration::from_secs(3)).await?;
    }

    Ok(())
}

async fn wait_for_owner_exit(
    ublk: &mut SmooUblk,
    dev_ids: &[u32],
    target_pid: i32,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut still_owned = false;
        for dev_id in dev_ids {
            match ublk.owner_pid(*dev_id).await {
                Ok(pid) => {
                    debug!(dev_id, pid, target_pid, "owner check during adopt wait");
                    if pid == target_pid {
                        still_owned = true;
                    } else if pid > 0 && pid != target_pid {
                        anyhow::bail!(
                            "device {dev_id} now owned by unexpected pid {pid} during adopt"
                        );
                    }
                }
                Err(err) => {
                    warn!(dev_id, error = ?err, "owner pid query failed during adopt wait");
                }
            }
        }
        if !still_owned {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("owner pid {target_pid} still active after adopt wait");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn reset_state_store(state_store: &mut StateStore) {
    let path = state_store.path().map(Path::to_path_buf);
    *state_store = match path {
        Some(path) => StateStore::new_with_path(path),
        None => StateStore::new(),
    };
}

fn count_active_exports(exports: &HashMap<u32, ExportController>) -> u32 {
    exports
        .values()
        .filter(|ctrl| ctrl.is_active_for_status())
        .count() as u32
}

async fn process_control_message(
    msg: ControlMessage,
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    link: &mut LinkController,
) -> Result<()> {
    match msg {
        ControlMessage::Config(config) => {
            if let Err(err) = apply_config(ublk, runtime, config).await {
                warn!(error = ?err, "CONFIG_EXPORTS application failed");
            }
        }
        ControlMessage::Ep0Event(event) => {
            link.on_ep0_event(event);
        }
        ControlMessage::StatusPing => {
            link.on_status_ping();
        }
    }
    Ok(())
}

async fn apply_config(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    config: ConfigExportsV0,
) -> Result<()> {
    let entries = config.entries();
    let desired_records = if entries.is_empty() {
        Vec::new()
    } else {
        config_entries_to_records(entries)?
    };

    // Fast-path: zero exports means tear everything down.
    if desired_records.is_empty() {
        for controller in runtime.exports.values_mut() {
            if let Some((ctrl, queues)) = controller.take_device_handles() {
                ublk.stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                    .await
                    .context("stop ublk device before applying CONFIG_EXPORTS")?;
            }
        }
        runtime.exports.clear();
        runtime.state_store().replace_all(Vec::new());
        if let Err(err) = runtime.state_store().persist() {
            warn!(error = ?err, "failed to clear state file");
        }
        runtime.status().set_export_count(0).await;
        return Ok(());
    }

    let desired_specs: HashMap<u32, ExportSpec> = desired_records
        .iter()
        .map(|record| (record.export_id, record.spec.clone()))
        .collect();

    // Stop and remove exports that are missing or whose geometry changed.
    let mut to_remove = Vec::new();
    for (export_id, controller) in runtime.exports.iter() {
        match desired_specs.get(export_id) {
            Some(spec) if spec == &controller.spec => {}
            _ => to_remove.push(*export_id),
        }
    }
    for export_id in to_remove {
        if let Some(mut controller) = runtime.exports.remove(&export_id) {
            if let Some((ctrl, queues)) = controller.take_device_handles() {
                ublk.stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                    .await
                    .with_context(|| format!("stop ublk device for export {}", export_id))?;
            }
        }
    }

    // Create controllers for any new exports.
    for record in &desired_records {
        runtime.exports.entry(record.export_id).or_insert_with(|| {
            ExportController::new(record.export_id, record.spec.clone(), ExportState::New)
        });
    }

    // Rebuild state store with the desired exports, keeping any assigned dev_ids
    // for controllers we kept alive.
    let mut new_records = Vec::with_capacity(desired_records.len());
    for mut record in desired_records {
        if let Some(ctrl) = runtime.exports.get(&record.export_id) {
            record.assigned_dev_id = ctrl.dev_id();
        }
        new_records.push(record);
    }

    runtime.state_store().replace_all(new_records);
    if let Err(err) = runtime.state_store().persist() {
        warn!(error = ?err, "failed to write state store");
    }
    runtime
        .status()
        .set_export_count(count_active_exports(&runtime.exports))
        .await;
    Ok(())
}

struct GadgetGuard {
    #[allow(dead_code)]
    registration: RegGadget,
}

fn setup_functionfs(args: &Args) -> Result<(Custom, FunctionfsEndpoints, GadgetGuard, PathBuf)> {
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

    let endpoints = open_data_endpoints(&ffs_dir)?;

    Ok((
        custom,
        endpoints,
        GadgetGuard { registration: reg },
        ffs_dir,
    ))
}

fn open_data_endpoints(ffs_dir: &Path) -> Result<FunctionfsEndpoints> {
    let interrupt_in = open_endpoint_fd(ffs_dir.join("ep1")).context("open interrupt IN")?;
    let interrupt_out = open_endpoint_fd(ffs_dir.join("ep2")).context("open interrupt OUT")?;
    let bulk_in = open_endpoint_fd(ffs_dir.join("ep3")).context("open bulk IN")?;
    let bulk_out = open_endpoint_fd(ffs_dir.join("ep4")).context("open bulk OUT")?;
    Ok(FunctionfsEndpoints::new(
        interrupt_in,
        interrupt_out,
        bulk_in,
        bulk_out,
    ))
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

async fn cleanup_ublk_devices(ublk: &mut SmooUblk, runtime: &mut RuntimeState) -> Result<()> {
    for (_, tasks) in runtime.queue_tasks.drain() {
        tasks.shutdown().await;
    }
    let mut force_remove_ids = Vec::new();
    for controller in runtime.exports.values_mut() {
        if let Some((ctrl, queues)) = controller.take_device_handles() {
            let dev_id = ctrl.dev_id();
            info!(dev_id, "stopping ublk device");
            if let Err(err) = ublk
                .stop_dev(SmooUblkDevice::from_parts(ctrl, queues), true)
                .await
            {
                warn!(
                    dev_id,
                    error = ?err,
                    "graceful stop failed; will force-remove"
                );
                force_remove_ids.push(dev_id);
            }
        } else if let Some(dev_id) = controller.dev_id() {
            force_remove_ids.push(dev_id);
        }
    }

    for dev_id in force_remove_ids {
        force_remove_with_retry(ublk, dev_id).await?;
    }
    Ok(())
}

async fn force_remove_with_retry(ublk: &mut SmooUblk, dev_id: u32) -> Result<()> {
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.wrapping_add(1);
        match ublk.force_remove_device(dev_id).await {
            Ok(()) => {
                info!(dev_id, attempt, "force-removed ublk device");
                break;
            }
            Err(err) => {
                if error_is_errno(&err, libc::ENOENT) {
                    info!(dev_id, attempt, "ublk device already absent");
                    break;
                }
                warn!(
                    dev_id,
                    attempt,
                    error = ?err,
                    "force-remove ublk device failed; retrying"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

async fn begin_user_recovery(ublk: &mut SmooUblk, runtime: &mut RuntimeState) -> Result<()> {
    ublk.preserve_devices_on_drop();
    for (_, tasks) in runtime.queue_tasks.drain() {
        tasks.shutdown().await;
    }
    let mut dev_ids = Vec::new();
    for ctrl in runtime.exports.values_mut() {
        if let Some((ctrl, queues)) = ctrl.take_device_handles() {
            dev_ids.push(ctrl.dev_id());
            drop(SmooUblkDevice::from_parts(ctrl, queues));
        } else if let Some(dev_id) = ctrl.dev_id() {
            dev_ids.push(dev_id);
        }
    }
    for dev_id in dev_ids {
        if let Err(err) = ublk.start_user_recovery(dev_id).await {
            warn!(dev_id, error = ?err, "start user recovery failed");
        }
    }
    Ok(())
}

async fn process_link_commands(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
) -> Result<()> {
    while let Some(cmd) = link.take_command() {
        match cmd {
            LinkCommand::DropLink => {
                runtime.gadget = None;
                debug!("link controller requested drop; data plane closed");
            }
            LinkCommand::Reopen => {
                if runtime.gadget.is_some() {
                    continue;
                }
                match open_data_endpoints(&runtime.ffs_dir) {
                    Ok(endpoints) => match SmooGadget::new(endpoints, runtime.gadget_config) {
                        Ok(gadget) => {
                            runtime.gadget = Some(Arc::new(gadget));
                            debug!("link controller reopened data plane");
                        }
                        Err(err) => {
                            warn!(error = ?err, "reopen data plane failed");
                        }
                    },
                    Err(err) => {
                        warn!(error = ?err, "open endpoints failed during reopen");
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_queue_event(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    event: QueueEvent,
) -> Result<()> {
    match event {
        QueueEvent::Request {
            export_id,
            dev_id,
            request,
            queues,
        } => {
            let Some(ctrl) = runtime.exports.get_mut(&export_id) else {
                return Ok(());
            };
            let Some(handle) = ctrl.device_handle() else {
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            };
            if handle.dev_id() != dev_id {
                trace!(export_id, dev_id, "dropping request for stale device id");
                return Ok(());
            }
            if link.state() != LinkState::Online || runtime.gadget.is_none() || !handle.is_online()
            {
                trace!(
                    export_id,
                    queue = request.queue_id,
                    tag = request.tag,
                    "link not online; parking IO"
                );
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            }
            let Some(gadget) = runtime.gadget.clone() else {
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                return Ok(());
            };
            trace!(
                export_id,
                dev_id,
                queue = request.queue_id,
                tag = request.tag,
                op = ?request.op,
                sector = request.sector,
                num_sectors = request.num_sectors,
                "dispatch ublk request to host"
            );
            let result = handle_request(
                gadget.as_ref(),
                inflight,
                export_id,
                queues.clone(),
                request,
            )
            .await;
            if let Err(err) = result {
                let io_err = io_error_from_anyhow(&err);
                link.on_io_error(&io_err);
                park_request(outstanding, export_id, dev_id, queues.clone(), request);
                warn!(export_id, queue = request.queue_id, tag = request.tag, error = ?err, "link error handling request; parked for retry");
            }
        }
        QueueEvent::QueueError {
            export_id,
            dev_id,
            error,
        } => {
            if let Some(ctrl) = runtime.exports.get_mut(&export_id) {
                ctrl.fail_device(format!("device {dev_id} queue task error: {error:#}"));
            }
            if let Some(mut pending) = outstanding.remove(&export_id) {
                for ((_queue_id, _tag), req) in pending.drain() {
                    let _ = req.queues.complete_io(req.request, -libc::ENOLINK);
                }
            }
            link.on_io_error(&io::Error::other("queue task error"));
        }
    }
    Ok(())
}

fn park_request(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    export_id: u32,
    dev_id: u32,
    queues: Arc<UblkQueueRuntime>,
    req: UblkIoRequest,
) {
    let entry = outstanding.entry(export_id).or_default();
    entry.insert(
        (req.queue_id, req.tag),
        OutstandingRequest {
            dev_id,
            request: req,
            queues,
        },
    );
}

fn prune_outstanding_for_missing_exports(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    exports: &HashMap<u32, ExportController>,
) {
    let mut to_fail = Vec::new();
    for export_id in outstanding.keys() {
        if !exports.contains_key(export_id) {
            to_fail.push(*export_id);
        }
    }
    for export_id in to_fail {
        if let Some(mut pending) = outstanding.remove(&export_id) {
            for ((_queue_id, _tag), req) in pending.drain() {
                let _ = req.queues.complete_io(req.request, -libc::ENODEV);
            }
        }
    }
}

async fn drain_outstanding(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
) -> Result<()> {
    if outstanding.is_empty() {
        return Ok(());
    }
    if link.state() != LinkState::Online {
        trace!(
            outstanding_exports = outstanding.len(),
            "link not online; deferring outstanding IO drain"
        );
        return Ok(());
    }
    let Some(gadget) = runtime.gadget.as_mut() else {
        trace!(
            outstanding_exports = outstanding.len(),
            "no gadget endpoints available; deferring outstanding IO drain"
        );
        return Ok(());
    };
    loop {
        let next = {
            let mut next = None;
            for (export_id, reqs) in outstanding.iter() {
                if let Some((&(queue_id, tag), _)) = reqs.iter().next() {
                    next = Some((*export_id, queue_id, tag));
                    break;
                }
            }
            next
        };
        let Some((export_id, queue_id, tag)) = next else {
            break;
        };
        let pending = {
            let map = outstanding.get_mut(&export_id);
            let req = map.and_then(|m| m.remove(&(queue_id, tag)));
            if let Some(map) = outstanding.get(&export_id) {
                if map.is_empty() {
                    outstanding.remove(&export_id);
                }
            }
            req
        };
        let Some(pending) = pending else {
            continue;
        };
        let Some(ctrl) = runtime.exports.get(&export_id) else {
            let _ = pending.queues.complete_io(pending.request, -libc::ENODEV);
            continue;
        };
        let Some(handle) = ctrl.device_handle() else {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        };
        if handle.dev_id() != pending.dev_id {
            trace!(
                export_id,
                stale_dev = pending.dev_id,
                current_dev = handle.dev_id(),
                "dropping outstanding for stale device"
            );
            continue;
        }
        if !handle.is_online() {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        }
        let Some(queues) = handle.queues() else {
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                pending.request,
            );
            break;
        };
        let req = pending.request;
        trace!(
            export_id,
            dev_id = pending.dev_id,
            queue = req.queue_id,
            tag = req.tag,
            "replaying outstanding IO to host"
        );
        let result = handle_request(gadget, inflight, export_id, queues.clone(), req).await;
        if let Err(err) = result {
            let io_err = io_error_from_anyhow(&err);
            link.on_io_error(&io_err);
            park_request(
                outstanding,
                export_id,
                pending.dev_id,
                pending.queues.clone(),
                req,
            );
            warn!(
                export_id,
                queue = req.queue_id,
                tag = req.tag,
                error = ?err,
                "link error replaying outstanding IO; parked again"
            );
            break;
        }
    }
    Ok(())
}

async fn drain_inflight(inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>) {
    let mut guard = inflight.lock().await;
    for (_export, mut requests) in guard.drain() {
        for (_req_id, req) in requests.drain() {
            let _ = req.queues.complete_io(req.request, -libc::ENOLINK);
        }
    }
}

fn io_error_from_anyhow(err: &anyhow::Error) -> io::Error {
    if let Some(cause) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
    {
        io::Error::new(cause.kind(), cause.to_string())
    } else {
        io::Error::other(err.to_string())
    }
}

fn error_is_errno(err: &anyhow::Error, code: i32) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        == Some(code)
}

fn error_is_missing(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(|io_err| io_err.raw_os_error())
        .is_some_and(|code| code == libc::ENOENT || code == libc::EINVAL)
}

fn pid_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let res = unsafe { libc::kill(pid, 0) };
    if res == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    !matches!(err.raw_os_error(), Some(libc::ESRCH))
}

fn export_state_tag(controller: &ExportController) -> &'static str {
    match &controller.state {
        ExportState::New => "new",
        ExportState::RecoveringPending { .. } => "recovering_pending",
        ExportState::Device(handle) => match handle {
            DeviceHandle::Starting { .. } => "starting",
            DeviceHandle::Online { .. } => "online",
            DeviceHandle::ShuttingDown { .. } => "shutting_down",
            DeviceHandle::Failed { .. } => "failed",
        },
        ExportState::Deleted => "deleted",
    }
}

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}

fn validate_persisted_record(record: &PersistedExportRecord) -> Result<()> {
    ensure!(
        record.export_id != 0,
        "persisted export_id must be non-zero"
    );
    let block_size = record.spec.block_size;
    ensure!(
        block_size.is_power_of_two(),
        "persisted block size must be power-of-two"
    );
    ensure!(
        (512..=65536).contains(&block_size),
        "persisted block size out of range"
    );
    ensure!(
        record.spec.size_bytes != 0,
        "persisted export size_bytes must be non-zero"
    );
    ensure!(
        record.spec.size_bytes.is_multiple_of(block_size as u64),
        "persisted export size_bytes must be multiple of block_size"
    );
    let blocks = record
        .spec
        .size_bytes
        .checked_div(block_size as u64)
        .context("persisted size_bytes smaller than block_size")?;
    ensure!(blocks > 0, "persisted export size too small");
    usize::try_from(blocks).context("persisted export block count overflows usize")?;
    Ok(())
}

fn config_entries_to_records(entries: &[ConfigExport]) -> Result<Vec<PersistedExportRecord>> {
    let mut seen = HashSet::new();
    let mut records = Vec::with_capacity(entries.len());
    for export in entries {
        ensure!(
            seen.insert(export.export_id),
            "duplicate export_id {} in CONFIG_EXPORTS",
            export.export_id
        );
        let spec = build_spec_from_export(*export)?;
        records.push(PersistedExportRecord {
            export_id: export.export_id,
            spec,
            assigned_dev_id: None,
        });
    }
    Ok(records)
}

fn build_spec_from_export(export: ConfigExport) -> Result<ExportSpec> {
    let block_size = export.block_size as usize;
    ensure!(
        export.size_bytes != 0,
        "CONFIG_EXPORTS size_bytes must be non-zero"
    );
    ensure!(
        export.size_bytes.is_multiple_of(block_size as u64),
        "CONFIG_EXPORTS size_bytes must be multiple of block_size"
    );
    let blocks = export
        .size_bytes
        .checked_div(block_size as u64)
        .context("size bytes smaller than block size")?;
    ensure!(blocks > 0, "export size too small");
    usize::try_from(blocks).context("export block count overflows usize")?;
    Ok(ExportSpec {
        block_size: export.block_size,
        size_bytes: export.size_bytes,
        flags: ExportFlags::empty(),
    })
}
