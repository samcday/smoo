use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use rand::{rngs::OsRng, RngCore};
use smoo_gadget_core::{
    ConfigExportsV0, DmaHeap, Ep0Controller, Ep0Event, ExportConfig, FunctionfsEndpoints,
    GadgetConfig, SetupPacket, SmooGadget, CONFIG_EXPORTS_REQUEST, SMOO_CONFIG_REQ_TYPE,
};
use smoo_gadget_ublk::{SmooUblk, SmooUblkDevice, UblkBuffer, UblkIoRequest, UblkOp};
use smoo_proto::{
    Ident, OpCode, Request, Response, SmooStatusV0, IDENT_LEN, IDENT_REQUEST,
    SMOO_STATUS_FLAG_EXPORT_ACTIVE, SMOO_STATUS_LEN, SMOO_STATUS_REQUEST, SMOO_STATUS_REQ_TYPE,
};
use std::{
    cmp,
    collections::{HashMap, HashSet},
    fs::File,
    io,
    io::Write,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    signal,
    sync::{mpsc, oneshot, RwLock},
    task::JoinHandle,
};
use tracing::{debug, info, warn};
use tracing_subscriber::prelude::*;
use usb_gadget::{
    function::custom::{Custom, Endpoint, EndpointDirection, Interface, TransferType},
    Class, Config, Gadget, Id, RegGadget, Strings,
};

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;
const SMOO_IDENT_REQ_TYPE: u8 = 0xC1;
const DEFAULT_MAX_IO_BYTES: usize = 4 * 1024 * 1024;

use state::{ExportState, StateFile, StateSnapshot};

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
    let (endpoints, _gadget_guard) = setup_functionfs(&args).context("setup FunctionFS")?;

    let mut ublk = SmooUblk::new().context("init ublk")?;
    let state_file = args
        .state_file
        .as_ref()
        .map(|path| StateFile::new(path.clone()));
    if let Some(file) = &state_file {
        info!(path = ?file.path(), "state file configured");
    } else {
        debug!("state file disabled; crash recovery off");
    }

    let (session_id, recovered_exports) =
        initialize_session(&mut ublk, state_file.as_ref()).await?;
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
    let mut gadget = SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?;
    enum SetupAwait {
        Configured,
        Interrupted,
    }
    let setup_outcome = {
        #[allow(unused_mut)]
        let mut setup_fut = gadget.setup();
        tokio::pin!(setup_fut);
        #[allow(unused_mut)]
        let mut setup_shutdown = signal::ctrl_c();
        tokio::pin!(setup_shutdown);
        tokio::select! {
            res = &mut setup_fut => {
                res.context("complete FunctionFS setup")?;
                SetupAwait::Configured
            }
            res = &mut setup_shutdown => {
                if let Err(err) = res {
                    warn!(error = ?err, "ctrl-c listener failed during FunctionFS setup");
                }
                SetupAwait::Interrupted
            }
        }
    };

    if matches!(setup_outcome, SetupAwait::Interrupted) {
        info!("shutdown requested before host completed ident exchange");
        return Ok(());
    }
    info!(
        ident_major = ident.major,
        ident_minor = ident.minor,
        queues = args.queue_count,
        depth = args.queue_depth,
        "smoo gadget initialized"
    );

    let ep0 = gadget
        .take_ep0_controller()
        .context("ep0 controller already taken")?;
    let (control_tx, control_rx) = mpsc::channel(8);
    let (pending_tx, pending_rx) = mpsc::channel(64);
    let status = GadgetStatusShared::new(GadgetStatus::new(session_id, 0));
    let control_task = tokio::spawn(control_loop(ep0, ident, status.clone(), control_tx));
    let runtime = RuntimeConfig {
        queue_count: args.queue_count,
        queue_depth: args.queue_depth,
        state_file: state_file.clone(),
        status,
        pending_requests: pending_tx.clone(),
    };
    let mut exports_runtime = ExportsRuntime::new();
    for slot in recovered_exports {
        exports_runtime.insert(slot);
    }
    let result = run_event_loop(
        &mut ublk,
        gadget,
        runtime,
        exports_runtime,
        control_rx,
        pending_rx,
    )
    .await;
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

    fn export_active(&self) -> bool {
        self.export_count > 0
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

    async fn session_id(&self) -> u64 {
        self.inner.read().await.session_id
    }

    async fn set_export_count(&self, export_count: u32) {
        let mut guard = self.inner.write().await;
        guard.export_count = export_count;
    }
}

#[derive(Clone)]
struct RuntimeConfig {
    queue_count: u16,
    queue_depth: u16,
    state_file: Option<StateFile>,
    status: GadgetStatusShared,
    pending_requests: mpsc::Sender<PendingRequest>,
}

impl RuntimeConfig {
    fn state_file(&self) -> Option<&StateFile> {
        self.state_file.as_ref()
    }

    fn status(&self) -> &GadgetStatusShared {
        &self.status
    }

    fn pending_tx(&self) -> mpsc::Sender<PendingRequest> {
        self.pending_requests.clone()
    }
}

struct PendingRequest {
    export_id: u32,
    request: UblkIoRequest,
}

struct ExportSlot {
    export_id: u32,
    block_size: u32,
    size_bytes: u64,
    device: SmooUblkDevice,
    request_task: Option<JoinHandle<()>>,
}

impl ExportSlot {
    fn new(export_id: u32, block_size: u32, size_bytes: u64, device: SmooUblkDevice) -> Self {
        Self {
            export_id,
            block_size,
            size_bytes,
            device,
            request_task: None,
        }
    }

    fn start_request_task(&mut self, tx: mpsc::Sender<PendingRequest>) -> Result<()> {
        if self.request_task.is_some() {
            return Ok(());
        }
        let receiver = self
            .device
            .take_request_receiver()
            .context("request channel unavailable")?;
        let export_id = self.export_id;
        let task = tokio::spawn(async move {
            while let Ok(request) = receiver.recv().await {
                if tx
                    .send(PendingRequest { export_id, request })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        self.request_task = Some(task);
        Ok(())
    }

    fn stop_request_task(&mut self) {
        if let Some(handle) = self.request_task.take() {
            handle.abort();
        }
    }

    fn device(&self) -> &SmooUblkDevice {
        &self.device
    }

    fn device_mut(&mut self) -> &mut SmooUblkDevice {
        &mut self.device
    }

    fn export_state(&self) -> ExportState {
        ExportState {
            export_id: self.export_id,
            block_size: self.block_size,
            size_bytes: self.size_bytes,
            ublk_dev_id: self.device.dev_id(),
        }
    }

    fn capacity_blocks(&self) -> Option<u64> {
        if self.size_bytes == 0 {
            None
        } else {
            Some(self.size_bytes / self.block_size as u64)
        }
    }
}

struct ExportsRuntime {
    entries: HashMap<u32, ExportSlot>,
}

impl ExportsRuntime {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn insert(&mut self, slot: ExportSlot) {
        self.entries.insert(slot.export_id, slot);
    }

    fn get(&self, export_id: u32) -> Option<&ExportSlot> {
        self.entries.get(&export_id)
    }

    fn get_mut(&mut self, export_id: u32) -> Option<&mut ExportSlot> {
        self.entries.get_mut(&export_id)
    }

    async fn remove(&mut self, export_id: u32, ublk: &mut SmooUblk) -> Result<()> {
        if let Some(mut slot) = self.entries.remove(&export_id) {
            slot.stop_request_task();
            ublk.stop_dev(slot.device, true)
                .await
                .with_context(|| format!("stop ublk device for export {export_id}"))?;
        }
        Ok(())
    }

    async fn clear(&mut self, ublk: &mut SmooUblk) -> Result<()> {
        let ids: Vec<u32> = self.entries.keys().copied().collect();
        for id in ids {
            self.remove(id, ublk).await?;
        }
        Ok(())
    }

    fn export_states(&self) -> Vec<ExportState> {
        self.entries
            .values()
            .map(|slot| slot.export_state())
            .collect()
    }
}

fn generate_session_id() -> u64 {
    loop {
        let candidate = OsRng.next_u64();
        if candidate != 0 {
            return candidate;
        }
    }
}

struct ConfigCommand {
    payload: ConfigExportsV0,
    respond_to: oneshot::Sender<Result<()>>,
}

enum ControlMessage {
    Config(ConfigCommand),
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    mut gadget: SmooGadget,
    runtime: RuntimeConfig,
    mut exports: ExportsRuntime,
    mut control_rx: mpsc::Receiver<ControlMessage>,
    mut pending_rx: mpsc::Receiver<PendingRequest>,
) -> Result<()> {
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut io_error = None;
    loop {
        if exports.is_empty() {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received");
                    break;
                }
                msg = control_rx.recv() => {
                    if let Some(msg) = msg {
                        process_control_message(
                            msg,
                            ublk,
                            &mut exports,
                            &runtime,
                        )
                        .await?;
                    } else {
                        break;
                    }
                }
            }
        } else {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutdown signal received");
                    break;
                }
                msg = control_rx.recv() => {
                    if let Some(msg) = msg {
                        process_control_message(
                            msg,
                            ublk,
                            &mut exports,
                            &runtime,
                        )
                        .await?;
                    } else {
                        break;
                    }
                }
                pending = pending_rx.recv() => {
                    match pending {
                        Some(pending_req) => {
                            let Some(slot) = exports.get(pending_req.export_id) else {
                                warn!(
                                    export_id = pending_req.export_id,
                                    "received request for unknown export"
                                );
                                continue;
                            };
                            if let Err(err) = handle_request(
                                &mut gadget,
                                slot.export_id,
                                slot,
                                pending_req.request,
                            )
                            .await
                            {
                                io_error = Some(err);
                                break;
                            }
                        }
                        None => {
                            warn!("pending request channel closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    exports.clear(ublk).await?;
    runtime.status().set_export_count(0).await;
    if let Some(state_file) = runtime.state_file() {
        if let Err(err) = state_file.clear() {
            warn!(error = ?err, "failed to remove state file during shutdown");
        } else {
            debug!("state file cleared on shutdown");
        }
    }
    if let Some(err) = io_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn handle_request(
    gadget: &mut SmooGadget,
    export_id: u32,
    slot: &ExportSlot,
    req: UblkIoRequest,
) -> Result<()> {
    let block_size = slot.block_size as usize;
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
            slot.device()
                .complete_io(req, -errno)
                .context("complete invalid request")?;
            return Ok(());
        }
    };
    let num_blocks = match u32::try_from(req_len / block_size) {
        Ok(val) => val,
        Err(_) => {
            slot.device()
                .complete_io(req, -libc::EINVAL)
                .context("complete request with excessive block count")?;
            return Ok(());
        }
    };
    if !request_within_bounds(slot, req.sector, num_blocks) {
        warn!(
            queue = req.queue_id,
            tag = req.tag,
            lba = req.sector,
            blocks = num_blocks,
            "request exceeds export bounds"
        );
        slot.device()
            .complete_io(req, -libc::ERANGE)
            .context("complete out-of-range request")?;
        return Ok(());
    }

    let opcode = match opcode_from_ublk(req.op) {
        Some(op) => op,
        None => {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                op = ?req.op,
                "unsupported ublk opcode"
            );
            slot.device()
                .complete_io(req, -libc::EOPNOTSUPP)
                .context("complete unsupported opcode")?;
            return Ok(());
        }
    };

    let mut payload: Option<UblkBuffer<'_>> = None;
    let result = async {
        if matches!(opcode, OpCode::Read | OpCode::Write) && req_len > 0 {
            let capacity = slot.device().buffer_len();
            if req_len > capacity {
                warn!(
                    queue = req.queue_id,
                    tag = req.tag,
                    req_bytes = req_len,
                    buf_cap = capacity,
                    "request exceeds buffer capacity"
                );
                slot.device()
                    .complete_io(req, -libc::EINVAL)
                    .context("complete oversized request")?;
                return Ok(());
            }
            payload = Some(
                slot.device()
                    .checkout_buffer(req.queue_id, req.tag)
                    .context("checkout bulk buffer")?,
            );
        }

        let proto_req = Request::new(export_id, opcode, req.sector, num_blocks, 0);
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
        if status >= 0 && response.num_blocks as usize != num_blocks as usize {
            warn!(
                queue = req.queue_id,
                tag = req.tag,
                expected_blocks = num_blocks,
                reported_blocks = response.num_blocks,
                "response block count mismatch"
            );
        }
        slot.device()
            .complete_io(req, status)
            .context("complete ublk request")?;
        Ok(())
    }
    .await;

    result
}

async fn control_loop(
    mut ep0: Ep0Controller,
    ident: Ident,
    status: GadgetStatusShared,
    mut tx: mpsc::Sender<ControlMessage>,
) -> Result<()> {
    loop {
        let event = ep0
            .next_event()
            .await
            .context("read FunctionFS control event")?;
        match event {
            Ep0Event::Bind => debug!("FunctionFS bind event (control loop)"),
            Ep0Event::Unbind => debug!("FunctionFS unbind event (control loop)"),
            Ep0Event::Enable => debug!("FunctionFS enable event (control loop)"),
            Ep0Event::Disable => debug!("FunctionFS disable event (control loop)"),
            Ep0Event::Suspend => debug!("FunctionFS suspend event (control loop)"),
            Ep0Event::Resume => debug!("FunctionFS resume event (control loop)"),
            Ep0Event::Setup(setup) => {
                if setup.request() == IDENT_REQUEST && setup.request_type() == SMOO_IDENT_REQ_TYPE {
                    if let Err(err) = respond_ident(&mut ep0, ident, setup).await {
                        warn!(error = ?err, "failed to reply to IDENT");
                        ep0.stall().await.context("stall IDENT failure")?;
                    }
                    continue;
                }
                if setup.request() == CONFIG_EXPORTS_REQUEST
                    && setup.request_type() == SMOO_CONFIG_REQ_TYPE
                {
                    if let Err(err) = handle_config_request(&mut ep0, setup, &mut tx).await {
                        warn!(error = ?err, "CONFIG_EXPORTS failed");
                        ep0.stall().await.context("stall CONFIG_EXPORTS failure")?;
                    }
                    continue;
                }
                if setup.request() == SMOO_STATUS_REQUEST
                    && setup.request_type() == SMOO_STATUS_REQ_TYPE
                {
                    if let Err(err) = respond_status(&mut ep0, setup, &status).await {
                        warn!(error = ?err, "SMOO_STATUS failed");
                        ep0.stall().await.context("stall SMOO_STATUS failure")?;
                    }
                    continue;
                }
                warn!(
                    request = setup.request(),
                    request_type = setup.request_type(),
                    length = setup.length(),
                    "unsupported control request"
                );
                ep0.stall().await.context("stall unsupported request")?;
            }
        }
    }
}

async fn respond_ident(ep0: &mut Ep0Controller, ident: Ident, setup: SetupPacket) -> Result<()> {
    ensure!(
        setup.request_type() & 0x80 != 0,
        "IDENT must be an IN transfer"
    );
    ensure!(
        setup.length() as usize >= IDENT_LEN,
        "IDENT buffer too small"
    );
    let encoded = ident.encode();
    let len = cmp::min(encoded.len(), setup.length() as usize);
    ep0.write_in(&encoded[..len])
        .await
        .context("write IDENT response")
}

async fn respond_status(
    ep0: &mut Ep0Controller,
    setup: SetupPacket,
    status: &GadgetStatusShared,
) -> Result<()> {
    ensure!(
        setup.request_type() == SMOO_STATUS_REQ_TYPE,
        "SMOO_STATUS request type mismatch"
    );
    ensure!(
        setup.request_type() & 0x80 != 0,
        "SMOO_STATUS must be an IN transfer"
    );
    ensure!(
        setup.length() as usize >= SMOO_STATUS_LEN,
        "SMOO_STATUS buffer too small"
    );
    let snapshot = status.snapshot().await;
    let mut flags = 0;
    if snapshot.export_active() {
        flags |= SMOO_STATUS_FLAG_EXPORT_ACTIVE;
    }
    let payload = SmooStatusV0::new(flags, snapshot.export_count, snapshot.session_id);
    debug!(
        export_count = snapshot.export_count,
        export_active = snapshot.export_active(),
        session_id = snapshot.session_id,
        "responding to SMOO_STATUS"
    );
    let encoded = payload.encode();
    let len = cmp::min(encoded.len(), setup.length() as usize);
    ep0.write_in(&encoded[..len])
        .await
        .context("write SMOO_STATUS response")
}

async fn handle_config_request(
    ep0: &mut Ep0Controller,
    setup: SetupPacket,
    tx: &mut mpsc::Sender<ControlMessage>,
) -> Result<()> {
    let length = setup.length() as usize;
    ensure!(
        length >= ConfigExportsV0::HEADER_LEN,
        "CONFIG_EXPORTS payload too short"
    );
    let max_len =
        ConfigExportsV0::HEADER_LEN + ConfigExportsV0::MAX_EXPORTS * ConfigExportsV0::ENTRY_LEN;
    ensure!(
        length <= max_len,
        "CONFIG_EXPORTS payload too large ({length} bytes)"
    );
    let mut buf = vec![0u8; length];
    ep0.read_out(&mut buf)
        .await
        .context("read CONFIG_EXPORTS")?;
    let config = ConfigExportsV0::parse(&buf).context("parse CONFIG_EXPORTS payload")?;
    let (respond_to, response_rx) = oneshot::channel();
    let cmd = ConfigCommand {
        payload: config,
        respond_to,
    };
    if tx.send(ControlMessage::Config(cmd)).await.is_err() {
        anyhow::bail!("control channel closed");
    }
    match response_rx.await {
        Ok(Ok(())) => {
            ep0.write_in(&[]).await.context("ACK CONFIG_EXPORTS")?;
            Ok(())
        }
        Ok(Err(err)) => Err(err),
        Err(_) => anyhow::bail!("config responder dropped"),
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
    if resp.status != 0 {
        return Ok(-i32::from(resp.status));
    }
    i32::try_from(expected_len).map_err(|_| anyhow!("response length exceeds i32"))
}

fn request_byte_len(req: &UblkIoRequest, block_size: usize) -> io::Result<usize> {
    let sectors = usize::try_from(req.num_sectors)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sector count overflow"))?;
    sectors
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "request byte length overflow"))
}

fn request_within_bounds(slot: &ExportSlot, lba: u64, num_blocks: u32) -> bool {
    if let Some(capacity) = slot.capacity_blocks() {
        let num = num_blocks as u64;
        match lba.checked_add(num) {
            Some(end) => end <= capacity,
            None => false,
        }
    } else {
        true
    }
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

async fn initialize_session(
    ublk: &mut SmooUblk,
    state_file: Option<&StateFile>,
) -> Result<(u64, Vec<ExportSlot>)> {
    if let Some(state_file) = state_file {
        match state_file.load() {
            Ok(Some(snapshot)) => match recover_exports(ublk, state_file, &snapshot).await {
                Ok(slots) => {
                    info!(
                        session_id = snapshot.session_id,
                        exports = slots.len(),
                        "restored gadget session from state file"
                    );
                    Ok((snapshot.session_id, slots))
                }
                Err(err) => {
                    warn!(error = ?err, "state file invalid; starting new gadget session");
                    let session_id = generate_session_id();
                    Ok((session_id, Vec::new()))
                }
            },
            Ok(None) => {
                let session_id = generate_session_id();
                info!(
                    session_id,
                    "state file missing or empty; starting cold session"
                );
                Ok((session_id, Vec::new()))
            }
            Err(err) => {
                warn!(
                    path = ?state_file.path(),
                    error = ?err,
                    "failed to read state file; ignoring"
                );
                let _ = state_file.clear();
                let session_id = generate_session_id();
                info!(
                    session_id,
                    "state file cleared after read failure; starting new session"
                );
                Ok((session_id, Vec::new()))
            }
        }
    } else {
        let session_id = generate_session_id();
        info!(
            session_id,
            "state tracking disabled; starting new gadget session"
        );
        Ok((session_id, Vec::new()))
    }
}

async fn recover_exports(
    ublk: &mut SmooUblk,
    state_file: &StateFile,
    snapshot: &StateSnapshot,
) -> Result<Vec<ExportSlot>> {
    if snapshot.exports.is_empty() {
        debug!(
            path = ?state_file.path(),
            "state file present but no exports recorded; nothing to recover"
        );
        return Ok(Vec::new());
    }
    let mut slots = Vec::new();
    for export_state in &snapshot.exports {
        info!(
            path = ?state_file.path(),
            export_id = export_state.export_id,
            dev_id = export_state.ublk_dev_id,
            "state file found, attempting ublk recovery"
        );
        let cdev_path = format!("/dev/ublkc{}", export_state.ublk_dev_id);
        if !Path::new(&cdev_path).exists() {
            warn!(?cdev_path, "ublk device missing; removing state file");
            let _ = state_file.clear();
            return Err(anyhow!("ublk device {} missing", export_state.ublk_dev_id));
        }
        match ublk.recover_existing_device(export_state.ublk_dev_id).await {
            Ok(device) => {
                ensure!(
                    device.block_size() as u32 == export_state.block_size,
                    "recovered export block size mismatch"
                );
                let expected_blocks = export_state
                    .size_bytes
                    .checked_div(export_state.block_size as u64)
                    .context("state file size smaller than block size")?;
                ensure!(expected_blocks > 0, "state file export size too small");
                ensure!(
                    device.block_count() as u64 == expected_blocks,
                    "recovered export capacity mismatch"
                );
                slots.push(ExportSlot::new(
                    export_state.export_id,
                    export_state.block_size,
                    export_state.size_bytes,
                    device,
                ));
            }
            Err(err) => {
                warn!(
                    dev_id = export_state.ublk_dev_id,
                    error = ?err,
                    "ublk recovery failed; removing state file"
                );
                if Path::new(&cdev_path).exists() {
                    if let Err(clean_err) = ublk.force_remove_device(export_state.ublk_dev_id).await
                    {
                        warn!(
                            dev_id = export_state.ublk_dev_id,
                            error = ?clean_err,
                            "failed to remove stale ublk device"
                        );
                    }
                }
                for slot in slots.drain(..) {
                    if let Err(stop_err) = ublk.stop_dev(slot.device, true).await {
                        warn!(error = ?stop_err, "failed to stop recovered device during cleanup");
                    }
                }
                let _ = state_file.clear();
                return Err(anyhow!("ublk recovery failed"));
            }
        }
    }
    Ok(slots)
}

async fn process_control_message(
    msg: ControlMessage,
    ublk: &mut SmooUblk,
    exports: &mut ExportsRuntime,
    runtime: &RuntimeConfig,
) -> Result<()> {
    match msg {
        ControlMessage::Config(cmd) => {
            let result = apply_config(ublk, exports, runtime, cmd.payload).await;
            let reply = result.map(|_| ());
            let _ = cmd.respond_to.send(reply);
        }
    }
    Ok(())
}

async fn apply_config(
    ublk: &mut SmooUblk,
    exports: &mut ExportsRuntime,
    runtime: &RuntimeConfig,
    config: ConfigExportsV0,
) -> Result<()> {
    let desired = config.entries();
    let desired_ids: HashSet<u32> = desired.iter().map(|entry| entry.export_id).collect();
    let current_ids: Vec<u32> = exports.entries.keys().copied().collect();
    for export_id in current_ids {
        if !desired_ids.contains(&export_id) {
            info!(export_id, "CONFIG_EXPORTS removing export");
            exports.remove(export_id, ublk).await?;
        }
    }
    for entry in desired {
        match exports.get_mut(entry.export_id) {
            Some(slot) => {
                if slot.device().recovery_pending() {
                    ensure!(
                        slot.block_size == entry.block_size,
                        "recovered export {} block size mismatch",
                        entry.export_id
                    );
                    let required_blocks = required_block_count(entry)?;
                    ensure!(
                        slot.device().block_count() == required_blocks,
                        "recovered export {} capacity mismatch",
                        entry.export_id
                    );
                    ensure!(
                        slot.device().queue_count() == runtime.queue_count
                            && slot.device().queue_depth() == runtime.queue_depth,
                        "recovered export {} queue geometry mismatch",
                        entry.export_id
                    );
                    info!(
                        export_id = entry.export_id,
                        "CONFIG_EXPORTS matches recovered export; finalizing recovery"
                    );
                    ublk.finalize_recovery(slot.device_mut())
                        .await
                        .context("complete ublk recovery")?;
                    slot.start_request_task(runtime.pending_tx())?;
                } else {
                    info!(
                        export_id = entry.export_id,
                        "CONFIG_EXPORTS replacing active export"
                    );
                    exports.remove(entry.export_id, ublk).await?;
                    let mut slot = new_export_slot(ublk, runtime, entry).await?;
                    slot.start_request_task(runtime.pending_tx())?;
                    exports.insert(slot);
                }
            }
            None => {
                info!(
                    export_id = entry.export_id,
                    "CONFIG_EXPORTS creating export"
                );
                let mut slot = new_export_slot(ublk, runtime, entry).await?;
                slot.start_request_task(runtime.pending_tx())?;
                exports.insert(slot);
            }
        }
    }
    runtime
        .status()
        .set_export_count(exports.len() as u32)
        .await;
    if let Some(state_file) = runtime.state_file() {
        let session_id = runtime.status().session_id().await;
        if exports.len() > 0 {
            let states = exports.export_states();
            if let Err(err) = state_file.store(session_id, &states) {
                warn!(error = ?err, "failed to write state file");
            }
        } else if let Err(err) = state_file.clear() {
            warn!(error = ?err, "failed to clear state file");
        }
    }
    Ok(())
}

fn required_block_count(entry: &ExportConfig) -> Result<usize> {
    ensure!(
        entry.size_bytes != 0,
        "CONFIG_EXPORTS size_bytes must be non-zero for export {}",
        entry.export_id
    );
    let blocks = entry
        .size_bytes
        .checked_div(entry.block_size as u64)
        .context("size bytes smaller than block size")?;
    ensure!(blocks > 0, "export {} size too small", entry.export_id);
    usize::try_from(blocks).context("block count exceeds usize capacity")
}

async fn new_export_slot(
    ublk: &mut SmooUblk,
    runtime: &RuntimeConfig,
    entry: &ExportConfig,
) -> Result<ExportSlot> {
    let block_count = required_block_count(entry)?;
    let device = ublk
        .setup_device(
            entry.block_size as usize,
            block_count,
            runtime.queue_count,
            runtime.queue_depth,
        )
        .await
        .context("setup ublk device from CONFIG_EXPORTS")?;
    Ok(ExportSlot::new(
        entry.export_id,
        entry.block_size,
        entry.size_bytes,
        device,
    ))
}

struct GadgetGuard {
    #[allow(dead_code)]
    custom: Custom,
    #[allow(dead_code)]
    registration: RegGadget,
}

fn setup_functionfs(args: &Args) -> Result<(FunctionfsEndpoints, GadgetGuard)> {
    let mut builder = Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(SMOO_SUBCLASS, SMOO_PROTOCOL), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    );
    builder.ffs_no_init = true;
    let (ffs_descs, ffs_strings) = builder.ffs_descriptors_and_strings()?;
    let (mut custom, handle) = builder.build();

    let klass = Class::new(SMOO_CLASS, SMOO_SUBCLASS, SMOO_PROTOCOL);
    let id = Id::new(args.vendor_id, args.product_id);
    let strings = Strings::new("smoo", "smoo gadget", "0001");
    let udc = usb_gadget::default_udc().context("locate UDC")?;
    let gadget =
        Gadget::new(klass, id, strings).with_config(Config::new("config").with_function(handle));
    let reg = gadget.register().context("register gadget")?;

    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;
    let mut ep0 = File::options()
        .read(true)
        .write(true)
        .open(ffs_dir.join("ep0"))
        .context("open ep0")?;
    ep0.write_all(&ffs_descs).context("write descriptors")?;
    ep0.write_all(&ffs_strings).context("write strings")?;

    reg.bind(Some(&udc)).context("bind gadget to UDC")?;

    let interrupt_in = open_endpoint_fd(ffs_dir.join("ep1")).context("open interrupt IN")?;
    let interrupt_out = open_endpoint_fd(ffs_dir.join("ep2")).context("open interrupt OUT")?;
    let bulk_in = open_endpoint_fd(ffs_dir.join("ep3")).context("open bulk IN")?;
    let bulk_out = open_endpoint_fd(ffs_dir.join("ep4")).context("open bulk OUT")?;
    let endpoints = FunctionfsEndpoints::new(
        to_owned_fd(ep0),
        interrupt_in,
        interrupt_out,
        bulk_in,
        bulk_out,
    );

    Ok((
        endpoints,
        GadgetGuard {
            custom,
            registration: reg,
        },
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

fn parse_hex_u16(input: &str) -> Result<u16, String> {
    let trimmed = input.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(trimmed, 16).map_err(|err| err.to_string())
}

mod state {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };
    const SNAPSHOT_VERSION: u32 = 1;

    #[derive(Clone)]
    pub struct StateFile {
        path: PathBuf,
    }

    impl StateFile {
        pub fn new(path: PathBuf) -> Self {
            Self { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn load(&self) -> Result<Option<StateSnapshot>> {
            let data = match fs::read(&self.path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(err) => {
                    return Err(err).context(format!("read state file {}", self.path.display()))
                }
            };
            let snapshot: StateSnapshot =
                serde_json::from_slice(&data).context("decode state file")?;
            ensure!(
                snapshot.version == SNAPSHOT_VERSION,
                "unsupported state file version {}",
                snapshot.version
            );
            Ok(Some(snapshot))
        }

        pub fn store(&self, session_id: u64, exports: &[ExportState]) -> Result<()> {
            if let Some(dir) = self.path.parent() {
                fs::create_dir_all(dir).context(format!("create {}", dir.display()))?;
            }
            let snapshot = StateSnapshot {
                version: SNAPSHOT_VERSION,
                session_id,
                exports: exports.to_vec(),
            };
            let data = serde_json::to_vec_pretty(&snapshot).context("encode state snapshot")?;
            let tmp_path = self.path.with_extension("tmp");
            fs::write(&tmp_path, &data).context(format!("write {}", tmp_path.display()))?;
            fs::rename(&tmp_path, &self.path).context(format!("commit {}", self.path.display()))
        }

        pub fn clear(&self) -> Result<()> {
            match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err).context(format!("remove state file {}", self.path.display())),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExportState {
        pub export_id: u32,
        pub block_size: u32,
        pub size_bytes: u64,
        pub ublk_dev_id: u32,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct StateSnapshot {
        pub version: u32,
        pub session_id: u64,
        #[serde(default)]
        pub exports: Vec<ExportState>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::tempdir;

        #[test]
        fn round_trip_state_file() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("state.json");
            let state_file = StateFile::new(path.clone());
            let exports = vec![ExportState {
                export_id: 0,
                block_size: 4096,
                size_bytes: 4096 * 128,
                ublk_dev_id: 7,
            }];
            state_file.store(42, &exports).unwrap();
            let loaded = state_file.load().unwrap().expect("snapshot");
            assert_eq!(
                StateSnapshot {
                    version: SNAPSHOT_VERSION,
                    session_id: 42,
                    exports
                },
                loaded
            );
            state_file.clear().unwrap();
            assert!(state_file.load().unwrap().is_none());
        }
    }
}
