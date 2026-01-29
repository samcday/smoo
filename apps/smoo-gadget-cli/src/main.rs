use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, ValueEnum};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request as HttpRequest, Response as HttpResponse, Server, StatusCode};
use metrics_exporter_prometheus::PrometheusBuilder;
use smoo_gadget_core::{
    ConfigExport, ConfigExportsV0, ControlIo, DeviceHandle, DmaHeap, ExportController, ExportFlags,
    ExportReconcileContext, ExportSpec, ExportState, FunctionfsEndpoints, GadgetConfig,
    GadgetControl, GadgetStatusReport, IoPumpHandle, IoWork, LinkCommand, LinkController,
    LinkState, PersistedExportRecord, RuntimeTunables, SetupCommand, SetupPacket, SmooGadget,
    SmooUblk, SmooUblkDevice, StateStore, UblkIoRequest, UblkOp, UblkQueueRuntime,
};
use smoo_proto::{Ident, OpCode, Request, Response, SMOO_STATUS_REQUEST, SMOO_STATUS_REQ_TYPE};
use std::io::{Read, Write};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    ffi::{CString, OsStr},
    fs::File,
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    os::unix::fs::FileTypeExt,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    signal,
    signal::unix::{signal as unix_signal, SignalKind},
    sync::{
        mpsc,
        mpsc::error::{TryRecvError, TrySendError},
        oneshot, watch, Mutex, Notify, RwLock,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use usb_gadget::{
    function::{
        custom::{
            CtrlReceiver, CtrlReq, CtrlSender, Custom, CustomBuilder, Endpoint, EndpointDirection,
            Event, Interface, TransferType,
        },
        serial::{Serial, SerialClass},
    },
    Class, Config, Gadget, Id, RegGadget, Strings,
};

struct KmsgWriter {
    file: File,
}

impl Write for KmsgWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

struct KmsgMakeWriter;

impl<'a> MakeWriter<'a> for KmsgMakeWriter {
    type Writer = Box<dyn Write + Send>;

    fn make_writer(&'a self) -> Self::Writer {
        match File::options().write(true).open("/dev/kmsg") {
            Ok(file) => Box::new(KmsgWriter { file }),
            Err(_) => Box::new(io::sink()),
        }
    }
}

const SMOO_CLASS: u8 = 0xFF;
const SMOO_SUBCLASS: u8 = 0x53;
const SMOO_PROTOCOL: u8 = 0x4D;
const DEFAULT_MAX_IO_BYTES: usize = 4 * 1024 * 1024;
const CONFIG_CHANNEL_DEPTH: usize = 32;
const QUEUE_CHANNEL_DEPTH: usize = 128;
const QUEUE_BATCH_MAX: usize = 32;
const OUTSTANDING_BATCH_MAX: usize = 32;
const IDLE_INTERVAL_MS: u64 = 10;
const LIVENESS_INTERVAL_MS: u64 = 500;
const MAINTENANCE_SLICE_MS: u64 = 200;
const RECONCILE_TIMEOUT_MS: u64 = 200;
const GRACEFUL_SHUTDOWN_TIMEOUT_MS: u64 = 5_000;

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
    /// Maximum per-I/O size in bytes to advertise to ublk (block-aligned).
    #[arg(long = "max-io", value_name = "BYTES")]
    max_io_bytes: Option<usize>,
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
    /// Expose Prometheus metrics on this TCP port (0 disables).
    #[arg(long, default_value_t = 0)]
    metrics_port: u16,
    /// Run as the initramfs PID1 wrapper (auto-enabled when argv0 == /init).
    #[arg(long)]
    pid1: bool,
    /// Internal flag for the forked gadget child.
    #[arg(long, hide = true)]
    pid1_child: bool,
    /// Use an existing FunctionFS directory and skip configfs management.
    #[arg(long, value_name = "PATH")]
    ffs_dir: Option<PathBuf>,
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
    let result = main_impl().await;
    if let Err(err) = &result {
        error!(error = ?err, "smoo-gadget-cli exiting with error");
    }
    result
}

async fn main_impl() -> Result<()> {
    let mut args = Args::parse();
    let argv0 = std::env::args().next().unwrap_or_default();
    let auto_pid1 = argv0 == "/init";
    if (args.pid1 || auto_pid1) && !args.pid1_child {
        args.pid1 = true;
        init_logging(true);
        run_pid1(&args).context("pid1 initramfs flow")?;
        return Ok(());
    }
    init_logging(args.pid1_child);
    let metrics_shutdown = CancellationToken::new();
    let metrics_task = spawn_metrics_listener(args.metrics_port, metrics_shutdown.clone())?;
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

    let (custom, endpoints, _gadget_guard, ffs_dir) =
        setup_configfs(&args).context("setup ConfigFS")?;

    let ident = Ident::new(0, 1);
    let dma_heap = args.experimental_dma_buf.then(|| args.dma_heap.into());
    let max_io_bytes = args.max_io_bytes.unwrap_or(DEFAULT_MAX_IO_BYTES);
    let gadget_config = GadgetConfig::new(
        ident,
        args.queue_count,
        args.queue_depth,
        max_io_bytes,
        dma_heap,
    );
    let gadget =
        Arc::new(SmooGadget::new(endpoints, gadget_config).context("init smoo gadget core")?);
    info!(
        ident_major = ident.major,
        ident_minor = ident.minor,
        queues = args.queue_count,
        depth = args.queue_depth,
        max_io_bytes = max_io_bytes,
        "smoo gadget initialized"
    );

    let control_handler = gadget.control_handler();
    let (control_tx, control_rx) = mpsc::channel(CONFIG_CHANNEL_DEPTH);
    let (control_stop_tx, control_stop_rx) = watch::channel(false);

    let exports = build_initial_exports(&state_store);
    let initial_export_count = count_active_exports(&exports);
    let status = GadgetStatusShared::new(GadgetStatus::new(
        state_store.session_id(),
        initial_export_count,
    ));
    let ep0_signals = Ep0Signals::new();
    let control_task = tokio::spawn(control_loop(
        custom,
        control_handler,
        status.clone(),
        ep0_signals.clone(),
        control_stop_rx,
        control_tx,
    ));
    let tunables = RuntimeTunables {
        queue_count: args.queue_count,
        queue_depth: args.queue_depth,
        max_io_bytes: args.max_io_bytes,
        dma_heap,
    };
    let link = LinkController::new(Duration::from_secs(3));
    let io_pump_capacity = args.queue_count as usize * args.queue_depth as usize;
    let runtime = RuntimeState {
        state_store,
        status,
        exports,
        queue_tasks: HashMap::new(),
        tunables,
        gadget: Some(gadget),
        io_pump: None,
        io_pump_task: None,
        io_pump_capacity,
        gadget_config,
        ffs_dir,
        reconcile_queue: VecDeque::new(),
    };
    let result = run_event_loop(
        &mut ublk,
        runtime,
        control_rx,
        link,
        ep0_signals,
        control_stop_tx.clone(),
    )
    .await;
    metrics_shutdown.cancel();
    if let Some(task) = metrics_task {
        let _ = task.await;
    }
    let _ = control_stop_tx.send(true);
    control_task.abort();
    let _ = control_task.await;
    result
}

fn init_logging(pid1: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if pid1 {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(KmsgMakeWriter),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

struct KmsgPump {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

impl KmsgPump {
    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

fn spawn_kmsg_pump_if_enabled() -> Option<KmsgPump> {
    if !cmdline_bool("smoo.acm") {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_task = stop.clone();
    let handle = std::thread::spawn(move || {
        if let Err(err) = kmsg_pump_loop(stop_task) {
            warn!(error = ?err, "kmsg pump stopped");
        }
    });
    Some(KmsgPump { stop, handle })
}

fn kmsg_pump_loop(stop: Arc<AtomicBool>) -> Result<()> {
    let mut kmsg = File::options()
        .read(true)
        .open("/dev/kmsg")
        .context("open /dev/kmsg")?;
    set_nonblocking(&kmsg).context("set /dev/kmsg nonblocking")?;
    let mut tty: Option<File> = None;
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        if tty.is_none() {
            match File::options().write(true).open("/dev/ttyGS0") {
                Ok(file) => tty = Some(file),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                Err(err) => {
                    warn!(error = ?err, "kmsg pump: tty open failed; retrying");
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            }
        }
        match kmsg.read(&mut buf) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(len) => {
                let mut reset_tty = false;
                if let Some(ref mut tty) = tty {
                    if let Err(err) = tty.write_all(&buf[..len]) {
                        warn!(error = ?err, "kmsg pump write failed; reopening tty");
                        reset_tty = true;
                    }
                }
                if reset_tty {
                    tty = None;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(err).context("read /dev/kmsg"),
        }
    }
    Ok(())
}

fn set_nonblocking(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_GETFL)");
    }
    let res = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if res < 0 {
        return Err(io::Error::last_os_error()).context("fcntl(F_SETFL)");
    }
    Ok(())
}

fn run_pid1(args: &Args) -> Result<()> {
    ensure!(unsafe { libc::getpid() } == 1, "pid1 mode requires PID 1");

    info!("pid1: starting smoo initramfs flow");
    if args.ffs_dir.is_some() {
        warn!("pid1: ignoring --ffs-dir; pid1 manages gadget configfs");
    }
    std::fs::create_dir_all("/proc").ok();
    std::fs::create_dir_all("/sys").ok();
    std::fs::create_dir_all("/dev").ok();
    std::fs::create_dir_all("/run").ok();
    mount_fs(Some("proc"), "/proc", Some("proc"), 0, None).context("mount proc")?;
    mount_fs(Some("sysfs"), "/sys", Some("sysfs"), 0, None).context("mount sysfs")?;
    mount_fs(Some("devtmpfs"), "/dev", Some("devtmpfs"), 0, None).context("mount devtmpfs")?;
    mount_fs(Some("tmpfs"), "/run", Some("tmpfs"), 0, None).context("mount tmpfs /run")?;
    debug!("pid1: mounted proc/sys/dev/run");

    let default_modules = [
        "configfs",
        "ublk",
        "ublk_drv",
        "overlay",
        "erofs",
        "libcomposite",
        "usb_f_fs",
    ];
    let modules = load_modules_from_dir("/etc/modules-load.d")
        .filter(|list| !list.is_empty())
        .unwrap_or_else(|| default_modules.iter().map(|s| s.to_string()).collect());
    match ModuleIndex::load() {
        Ok(module_index) => {
            for module in modules {
                if let Err(err) = module_index.load_module_by_name(&module) {
                    warn!("module load failed for {module}: {err:#}");
                }
            }
        }
        Err(err) => {
            warn!("module index unavailable: {err:#}");
        }
    }

    std::fs::create_dir_all("/sys/kernel/config").ok();
    mount_fs(
        Some("configfs"),
        "/sys/kernel/config",
        Some("configfs"),
        0,
        None,
    )
    .context("mount configfs")?;
    debug!("pid1: mounted configfs");

    let udc_wait_secs = 15;
    info!("pid1: waiting for UDC (timeout {udc_wait_secs}s)");
    if !wait_for_udc(Duration::from_secs(udc_wait_secs))? {
        error!("pid1: fatal UDC not ready after {udc_wait_secs}s");
        return Err(anyhow!("UDC not ready after {udc_wait_secs}s"));
    }

    let gadget_guard = setup_pid1_configfs(args).context("setup pid1 configfs")?;
    let ffs_dir = gadget_guard.ffs_dir.clone();
    info!(
        ffs_dir = %ffs_dir.display(),
        "pid1: configfs gadget configured"
    );

    info!("pid1: spawning gadget child");
    let mut child = spawn_gadget_child(Some(&ffs_dir)).context("spawn gadget child")?;
    info!("pid1: gadget child pid {}", child.id());
    let ffs_wait_secs = 15;
    info!("pid1: waiting for FunctionFS endpoints (timeout {ffs_wait_secs}s)");
    if !wait_for_ffs_endpoints(&ffs_dir, Duration::from_secs(ffs_wait_secs), &mut child)? {
        error!("pid1: fatal FunctionFS endpoints not ready after {ffs_wait_secs}s");
        return Err(anyhow!(
            "FunctionFS endpoints not ready after {ffs_wait_secs}s"
        ));
    }

    let udc = usb_gadget::default_udc().context("locate UDC")?;
    gadget_guard
        .registration
        .bind(Some(&udc))
        .context("bind gadget to UDC")?;
    info!("pid1: gadget bound to UDC");
    let kmsg_pump = spawn_kmsg_pump_if_enabled();
    let ublk_dev = "/dev/ublkb0";
    let wait_secs = 30;
    debug!("pid1: waiting for block device {ublk_dev} (timeout {wait_secs}s)");
    if !wait_for_block_device(ublk_dev, Duration::from_secs(wait_secs), &mut child)? {
        error!("pid1: fatal timeout waiting for {ublk_dev} after {wait_secs}s");
        return Err(anyhow!("timed out waiting for {ublk_dev}"));
    }
    info!("pid1: found ublk device {ublk_dev}");

    std::fs::create_dir_all("/lower").ok();
    std::fs::create_dir_all("/upper").ok();
    std::fs::create_dir_all("/newroot").ok();

    debug!("pid1: mounting lower erofs from {ublk_dev}");
    mount_fs(
        Some(ublk_dev),
        "/lower",
        Some("erofs"),
        libc::MS_RDONLY as libc::c_ulong,
        None,
    )
    .context("mount erofs lower")?;
    debug!("pid1: mounted lower EROFS");
    debug!("pid1: mounting upper tmpfs");
    mount_fs(Some("tmpfs"), "/upper", Some("tmpfs"), 0, None).context("mount tmpfs upper")?;
    std::fs::create_dir_all("/upper/upper").ok();
    std::fs::create_dir_all("/upper/work").ok();
    if !filesystem_available("overlay")? {
        return Err(anyhow!("overlayfs not available in kernel"));
    }
    debug!("pid1: mounting overlay root");
    mount_fs(
        Some("overlay"),
        "/newroot",
        Some("overlay"),
        0,
        Some("lowerdir=/lower,upperdir=/upper/upper,workdir=/upper/work"),
    )
    .context("mount overlay root")?;
    debug!("pid1: mounted overlay root");

    // Avoid EINVAL from pivot_root on shared mount trees.
    debug!("pid1: making / private");
    mount_fs(None, "/", None, libc::MS_PRIVATE | libc::MS_REC, None).context("make / private")?;

    if matches!(cmdline_value("smoo.break").as_deref(), Some("1")) {
        debug_shell("smoo.break requested")?;
    }

    std::fs::create_dir_all("/newroot/proc").ok();
    std::fs::create_dir_all("/newroot/sys").ok();
    std::fs::create_dir_all("/newroot/dev").ok();
    std::fs::create_dir_all("/newroot/run").ok();

    debug!("pid1: bind-mounting proc/sys/dev/run into newroot");
    bind_mount_if_needed("/proc", "/newroot/proc", true)?;
    bind_mount_if_needed("/sys", "/newroot/sys", true)?;
    bind_mount_if_needed("/dev", "/newroot/dev", true)?;
    bind_mount_if_needed("/run", "/newroot/run", false)?;
    debug!("pid1: bind mounts into newroot complete");

    std::env::set_current_dir("/newroot").ok();
    debug!("pid1: moving newroot to /");
    mount_fs(
        Some("/newroot"),
        "/",
        None,
        libc::MS_MOVE as libc::c_ulong,
        None,
    )
    .context("move newroot to /")?;
    debug!("pid1: chrooting to new root");
    chroot_to(".").context("chroot to new root")?;
    std::env::set_current_dir("/").ok();
    info!("pid1: switched root");

    ensure_kernel_mounts()?;
    log_mountinfo("before exec /sbin/init");
    for path in [
        "/proc/self/mountinfo",
        "/sys/fs/cgroup",
        "/dev/console",
        "/proc",
        "/sys",
        "/dev",
        "/run",
    ] {
        if !Path::new(path).exists() {
            warn!("pid1: missing required path {path} before exec");
        }
    }

    std::fs::create_dir_all("/run/systemd/system").ok();
    if Path::new("/run/systemd/system").exists() {
        info!("pid1: ensured /run/systemd/system");
    } else {
        warn!("pid1: /run/systemd/system missing before exec");
    }

    let systemd_path = if Path::new("/lib/systemd/systemd").exists() {
        "/lib/systemd/systemd"
    } else {
        "/sbin/init"
    };
    info!("pid1: exec {}", systemd_path);
    if let Some(pump) = kmsg_pump {
        pump.stop();
    }
    let err = std::process::Command::new(systemd_path).exec();
    Err(anyhow!("exec {} failed: {err}", systemd_path))
}

fn cmdline_value(key: &str) -> Option<String> {
    let data = std::fs::read_to_string("/proc/cmdline").ok()?;
    for token in data.split_whitespace() {
        if let Some(value) = token.strip_prefix(&format!("{key}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn cmdline_flag(key: &str) -> bool {
    let Ok(data) = std::fs::read_to_string("/proc/cmdline") else {
        return false;
    };
    data.split_whitespace().any(|token| token == key)
}

fn cmdline_bool(key: &str) -> bool {
    if let Some(raw) = cmdline_value(key) {
        return match raw.as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                warn!("pid1: invalid {key} value '{raw}'");
                false
            }
        };
    }
    cmdline_flag(key)
}

fn log_mountinfo(context: &str) {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(data) => {
            info!("pid1: mountinfo ({context})\n{data}");
        }
        Err(err) => {
            warn!("pid1: failed to read mountinfo ({context}): {err}");
        }
    }
}

fn ensure_kernel_mounts() -> Result<()> {
    ensure_cgroup2_mount()?;
    ensure_bpffs_mount()?;
    ensure_securityfs_mount()?;
    ensure_devpts_mount()?;
    ensure_dev_shm_mount()?;
    Ok(())
}

fn ensure_cgroup2_mount() -> Result<()> {
    let cgroup_path = "/sys/fs/cgroup";
    std::fs::create_dir_all(cgroup_path).ok();
    if is_mount_point(cgroup_path)? {
        info!("pid1: cgroup already mounted at {cgroup_path}");
    } else {
        mount_fs(Some("cgroup2"), cgroup_path, Some("cgroup2"), 0, None)
            .context("mount cgroup2")?;
        info!("pid1: mounted cgroup2 at {cgroup_path}");
    }
    if let Ok(controllers) = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
        let controllers = controllers.trim();
        info!(
            "pid1: cgroup controllers: {}",
            if controllers.is_empty() {
                "<empty>"
            } else {
                controllers
            }
        );
    }
    Ok(())
}

fn ensure_bpffs_mount() -> Result<()> {
    let path = "/sys/fs/bpf";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: bpffs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("bpffs"), path, Some("bpf"), 0, None).context("mount bpffs")?;
    info!("pid1: mounted bpffs at {path}");
    Ok(())
}

fn ensure_securityfs_mount() -> Result<()> {
    let path = "/sys/kernel/security";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: securityfs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("securityfs"), path, Some("securityfs"), 0, None).context("mount securityfs")?;
    info!("pid1: mounted securityfs at {path}");
    Ok(())
}

fn ensure_devpts_mount() -> Result<()> {
    let path = "/dev/pts";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: devpts already mounted at {path}");
        return Ok(());
    }
    mount_fs(
        Some("devpts"),
        path,
        Some("devpts"),
        0,
        Some("mode=620,ptmxmode=666"),
    )
    .context("mount devpts")?;
    info!("pid1: mounted devpts at {path}");
    Ok(())
}

fn ensure_dev_shm_mount() -> Result<()> {
    let path = "/dev/shm";
    std::fs::create_dir_all(path).ok();
    if is_mount_point(path)? {
        info!("pid1: tmpfs already mounted at {path}");
        return Ok(());
    }
    mount_fs(Some("tmpfs"), path, Some("tmpfs"), 0, Some("mode=1777")).context("mount /dev/shm")?;
    info!("pid1: mounted tmpfs at {path}");
    Ok(())
}

fn cmdline_u16(key: &str) -> Option<u16> {
    let raw = cmdline_value(key)?;
    match raw.parse::<u16>() {
        Ok(value) => Some(value),
        Err(_) => {
            warn!("pid1: invalid {key} value '{raw}'");
            None
        }
    }
}

fn cmdline_usize(key: &str) -> Option<usize> {
    let raw = cmdline_value(key)?;
    match raw.parse::<usize>() {
        Ok(value) => Some(value),
        Err(_) => {
            warn!("pid1: invalid {key} value '{raw}'");
            None
        }
    }
}

fn load_modules_from_dir(path: &str) -> Option<Vec<String>> {
    let mut modules = Vec::new();
    let entries = std::fs::read_dir(path).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".conf") {
            if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    modules.push(trimmed.to_string());
                }
            }
        }
    }
    Some(modules)
}

struct ModuleIndex {
    base_dir: PathBuf,
    name_to_path: HashMap<String, String>,
    path_to_deps: HashMap<String, Vec<String>>,
    aliases: Vec<(String, String)>,
}

impl ModuleIndex {
    fn load() -> Result<Self> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .context("read /proc/sys/kernel/osrelease")?;
        let base_dir = PathBuf::from("/lib/modules").join(release.trim());
        let dep_path = base_dir.join("modules.dep");
        let alias_path = base_dir.join("modules.alias");

        let mut name_to_path = HashMap::new();
        let mut path_to_deps = HashMap::new();
        let dep_contents = std::fs::read_to_string(&dep_path)
            .with_context(|| format!("read {}", dep_path.display()))?;
        for line in dep_contents.lines() {
            let (path, deps) = match line.split_once(':') {
                Some(parts) => parts,
                None => continue,
            };
            let path = path.trim().to_string();
            let deps = deps
                .split_whitespace()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            let name = module_name_from_path(&path);
            name_to_path.entry(name).or_insert_with(|| path.clone());
            path_to_deps.insert(path, deps);
        }

        let mut aliases = Vec::new();
        if let Ok(alias_contents) = std::fs::read_to_string(&alias_path) {
            for line in alias_contents.lines() {
                let line = line.trim();
                if !line.starts_with("alias ") {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let _ = parts.next();
                if let (Some(pattern), Some(target)) = (parts.next(), parts.next()) {
                    aliases.push((pattern.to_string(), target.to_string()));
                }
            }
        }

        Ok(Self {
            base_dir,
            name_to_path,
            path_to_deps,
            aliases,
        })
    }

    fn load_module_by_name(&self, name: &str) -> Result<()> {
        let path = self
            .resolve_module_path(name)
            .ok_or_else(|| anyhow!("module {name} not found"))?;
        let mut loaded = HashSet::new();
        let mut stack = HashSet::new();
        self.load_module_recursive(&path, &mut loaded, &mut stack)
    }

    fn resolve_module_path(&self, name: &str) -> Option<String> {
        if let Some(path) = self.name_to_path.get(name) {
            return Some(path.clone());
        }
        for (pattern, target) in &self.aliases {
            if glob_match(pattern, name) {
                if let Some(path) = self.name_to_path.get(target) {
                    return Some(path.clone());
                }
            }
        }
        None
    }

    fn load_module_recursive(
        &self,
        rel_path: &str,
        loaded: &mut HashSet<String>,
        stack: &mut HashSet<String>,
    ) -> Result<()> {
        if loaded.contains(rel_path) {
            return Ok(());
        }
        if !stack.insert(rel_path.to_string()) {
            return Err(anyhow!("dependency cycle at {rel_path}"));
        }

        let deps = self.path_to_deps.get(rel_path).cloned().unwrap_or_default();
        for dep in deps {
            self.load_module_recursive(&dep, loaded, stack)?;
        }

        let path = self.base_dir.join(rel_path);
        let params = CString::new("")?;
        let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let fd = file.as_raw_fd();
        let res = if is_compressed_module(&path) {
            // Let the kernel handle module decompression when supported.
            finit_module(fd, &params, MODULE_INIT_COMPRESSED_FILE)
        } else {
            finit_module(fd, &params, 0)
        };
        if res != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                warn!("pid1: module {} load failed: {}", path.display(), err);
                return Err(err).with_context(|| format!("finit_module {}", path.display()));
            }
        }
        info!("pid1: module {} load ok", path.display());

        loaded.insert(rel_path.to_string());
        stack.remove(rel_path);
        Ok(())
    }
}

fn finit_module(fd: libc::c_int, params: &CString, flags: libc::c_int) -> libc::c_long {
    unsafe { libc::syscall(libc::SYS_finit_module, fd, params.as_ptr(), flags) }
}

const MODULE_INIT_COMPRESSED_FILE: libc::c_int = 4;

fn module_name_from_path(path: &str) -> String {
    let filename = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    let mut name = filename.to_string();
    for suffix in [".xz", ".zst", ".gz"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            name = stripped.to_string();
        }
    }
    if let Some(stripped) = name.strip_suffix(".ko") {
        name = stripped.to_string();
    }
    name
}

fn is_compressed_module(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("xz") | Some("zst") | Some("gz")
    )
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, None);
    let p = pattern.as_bytes();
    let t = text.as_bytes();

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = Some(ti);
            pi += 1;
            continue;
        }
        if let (Some(sp), Some(st)) = (star_pi, star_ti) {
            pi = sp + 1;
            ti = st + 1;
            star_ti = Some(ti);
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn debug_shell(reason: &str) -> Result<()> {
    warn!("pid1: dropping to shell ({reason})");
    for dev in ["/dev/ttyMSM0", "/dev/console"] {
        if let Ok(meta) = std::fs::metadata(dev) {
            if meta.file_type().is_char_device() {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dev)
                    .with_context(|| format!("open {dev}"))?;
                let _ = unsafe { libc::setsid() };
                let err = std::process::Command::new("/bin/sh")
                    .arg("-i")
                    .stdin(file.try_clone()?)
                    .stdout(file.try_clone()?)
                    .stderr(file)
                    .exec();
                return Err(anyhow!("exec /bin/sh failed: {err}"));
            }
        }
    }
    Err(anyhow!("no console device available for debug shell"))
}

fn wait_for_udc(timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    let mut warned_missing = false;
    let mut ticks: u32 = 0;
    loop {
        if Path::new("/sys/class/udc").exists() {
            if let Ok(entries) = std::fs::read_dir("/sys/class/udc") {
                if let Some(entry) = entries.filter_map(Result::ok).next() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    info!("pid1: UDC ready ({name})");
                    return Ok(true);
                }
            }
        } else if !warned_missing {
            warn!("pid1: /sys/class/udc missing");
            warned_missing = true;
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!("pid1: UDC not ready yet");
        }
        if start.elapsed() >= timeout {
            warn!("pid1: UDC wait timed out");
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_block_device(
    path: &str,
    timeout: Duration,
    child: &mut std::process::Child,
) -> Result<bool> {
    let start = Instant::now();
    let mut ticks: u32 = 0;
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.file_type().is_block_device() {
                return Ok(true);
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            error!("pid1: gadget child exited while waiting for {path}: {status}");
            return Err(anyhow!("gadget child exited: {status}"));
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!("pid1: waiting for {path}");
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_ffs_endpoints(
    ffs_dir: &Path,
    timeout: Duration,
    child: &mut std::process::Child,
) -> Result<bool> {
    let start = Instant::now();
    let mut ticks: u32 = 0;
    let ep1 = ffs_dir.join("ep1");
    loop {
        if ep1.exists() {
            return Ok(true);
        }
        if let Ok(Some(status)) = child.try_wait() {
            error!("pid1: gadget child exited while waiting for FunctionFS endpoints: {status}");
            return Err(anyhow!("gadget child exited: {status}"));
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            debug!(
                ffs_dir = %ffs_dir.display(),
                "pid1: waiting for FunctionFS endpoints"
            );
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn spawn_gadget_child(ffs_dir: Option<&Path>) -> Result<std::process::Child> {
    let exe = std::env::current_exe().context("locate self")?;
    let mut child_args = Vec::new();
    let mut args = std::env::args_os();
    let Some(argv0) = args.next() else {
        return Err(anyhow!("missing argv0"));
    };
    child_args.push(argv0);

    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == OsStr::new("--pid1") || arg == OsStr::new("--pid1-child") {
            continue;
        }
        let arg_str = arg.to_string_lossy();
        if matches!(
            arg_str.as_ref(),
            "--queue-depth" | "--queue-count" | "--max-io" | "--ffs-dir"
        ) {
            skip_next = true;
            continue;
        }
        if arg_str.starts_with("--queue-depth=")
            || arg_str.starts_with("--queue-count=")
            || arg_str.starts_with("--max-io=")
            || arg_str.starts_with("--ffs-dir=")
        {
            continue;
        }
        child_args.push(arg);
    }
    if let Some(queue_depth) =
        cmdline_u16("smoo.queue_depth").or_else(|| cmdline_u16("smoo.queue_size"))
    {
        child_args.push(OsStr::new("--queue-depth").to_os_string());
        child_args.push(OsStr::new(&queue_depth.to_string()).to_os_string());
        info!("pid1: using queue depth {queue_depth} from cmdline");
    }
    if let Some(queue_count) = cmdline_u16("smoo.queue_count") {
        child_args.push(OsStr::new("--queue-count").to_os_string());
        child_args.push(OsStr::new(&queue_count.to_string()).to_os_string());
        info!("pid1: using queue count {queue_count} from cmdline");
    }
    if let Some(max_io_bytes) =
        cmdline_usize("smoo.max_io_bytes").or_else(|| cmdline_usize("smoo.max_io"))
    {
        child_args.push(OsStr::new("--max-io").to_os_string());
        child_args.push(OsStr::new(&max_io_bytes.to_string()).to_os_string());
        info!("pid1: using max io bytes {max_io_bytes} from cmdline");
    }
    if let Some(ffs_dir) = ffs_dir {
        child_args.push(OsStr::new("--ffs-dir").to_os_string());
        child_args.push(ffs_dir.as_os_str().to_os_string());
    }
    child_args.push(OsStr::new("--pid1-child").to_os_string());
    let mut cmd = std::process::Command::new(exe);
    if let Some(log_level) = cmdline_value("smoo.log") {
        cmd.env("RUST_LOG", log_level);
        info!("pid1: set RUST_LOG from smoo.log");
    }
    debug!(
        "pid1: spawning gadget child exe={:?} args={:?}",
        cmd.get_program(),
        child_args
    );
    cmd.args(child_args.iter().skip(1));
    cmd.stdin(std::process::Stdio::null());
    cmd.spawn().context("spawn gadget process")
}

fn filesystem_available(name: &str) -> Result<bool> {
    let data = std::fs::read_to_string("/proc/filesystems").context("read /proc/filesystems")?;
    Ok(data
        .lines()
        .any(|line| line.split_whitespace().last() == Some(name)))
}

fn chroot_to(path: &str) -> Result<()> {
    let path = CString::new(path)?;
    let res = unsafe { libc::chroot(path.as_ptr()) };
    if res != 0 {
        return Err(io::Error::last_os_error()).context("chroot syscall failed");
    }
    Ok(())
}

fn bind_mount_if_needed(src: &str, dst: &str, recursive: bool) -> Result<()> {
    if !Path::new(src).exists() {
        warn!("pid1: bind mount source {src} missing, skipping");
        return Ok(());
    }
    if is_mount_point(dst)? {
        info!("pid1: {dst} already a mount point");
        return Ok(());
    }
    let mut flags = libc::MS_BIND as libc::c_ulong;
    if recursive {
        flags |= libc::MS_REC as libc::c_ulong;
    }
    mount_fs(Some(src), dst, None, flags, None)
        .with_context(|| format!("bind mount {src} -> {dst}"))?;
    Ok(())
}

fn is_mount_point(path: &str) -> Result<bool> {
    let data =
        std::fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        if let Some(mount_point) = parts.next() {
            if mount_point == path {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn mount_fs(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let target = CString::new(target)?;
    let source = source.map(CString::new).transpose()?;
    let fstype = fstype.map(CString::new).transpose()?;
    let data = data.map(CString::new).transpose()?;
    let data_ptr = data
        .as_ref()
        .map(|s| s.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());
    let res = unsafe {
        libc::mount(
            source
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            target.as_ptr(),
            fstype
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null()),
            flags,
            data_ptr,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error()).context("mount failed");
    }
    Ok(())
}

fn spawn_metrics_listener(
    port: u16,
    shutdown: CancellationToken,
) -> Result<Option<JoinHandle<()>>> {
    if port == 0 {
        return Ok(None);
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("install Prometheus metrics recorder")?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let task = tokio::spawn(async move {
        let make_svc = make_service_fn(move |_conn| {
            let handle = handle.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: HttpRequest<Body>| {
                    let handle = handle.clone();
                    async move {
                        if req.uri().path() != "/metrics" {
                            return Ok::<_, Infallible>(
                                HttpResponse::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("not found"))
                                    .unwrap(),
                            );
                        }
                        let body = handle.render();
                        Ok::<_, Infallible>(
                            HttpResponse::builder()
                                .status(StatusCode::OK)
                                .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                                .body(Body::from(body))
                                .unwrap(),
                        )
                    }
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        let graceful = server.with_graceful_shutdown(async {
            shutdown.cancelled().await;
        });

        if let Err(err) = graceful.await {
            warn!(error = %err, %addr, "metrics server error");
        }
    });

    info!(%addr, "metrics listener started");
    Ok(Some(task))
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

#[derive(Clone)]
struct Ep0Signals {
    status_seq: Arc<AtomicU64>,
    lifecycle_seq: Arc<AtomicU64>,
    lifecycle: Arc<Mutex<Vec<Event<'static>>>>,
    notify: Arc<Notify>,
}

impl Ep0Signals {
    fn new() -> Self {
        Self {
            status_seq: Arc::new(AtomicU64::new(0)),
            lifecycle_seq: Arc::new(AtomicU64::new(0)),
            lifecycle: Arc::new(Mutex::new(Vec::new())),
            notify: Arc::new(Notify::new()),
        }
    }

    fn status_seq(&self) -> u64 {
        self.status_seq.load(Ordering::Relaxed)
    }

    fn lifecycle_seq(&self) -> u64 {
        self.lifecycle_seq.load(Ordering::Relaxed)
    }

    fn mark_status_ping(&self) {
        self.status_seq.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    async fn push_lifecycle(&self, event: Event<'static>) {
        let mut guard = self.lifecycle.lock().await;
        guard.push(event);
        self.lifecycle_seq.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    async fn take_lifecycle(&self) -> Vec<Event<'static>> {
        let mut guard = self.lifecycle.lock().await;
        guard.drain(..).collect()
    }

    fn notifier(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

struct RuntimeState {
    state_store: StateStore,
    status: GadgetStatusShared,
    exports: HashMap<u32, ExportController>,
    queue_tasks: HashMap<u32, QueueTaskSet>,
    tunables: RuntimeTunables,
    gadget: Option<Arc<SmooGadget>>,
    io_pump: Option<IoPumpHandle>,
    io_pump_task: Option<JoinHandle<()>>,
    io_pump_capacity: usize,
    gadget_config: GadgetConfig,
    ffs_dir: PathBuf,
    reconcile_queue: VecDeque<u32>,
}

impl RuntimeState {
    fn status(&self) -> &GadgetStatusShared {
        &self.status
    }

    fn state_store(&mut self) -> &mut StateStore {
        &mut self.state_store
    }
}

type QueueSender = mpsc::Sender<QueueEvent>;

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

    fn abort(self) {
        let _ = self.stop.send(true);
        for handle in self.handles {
            handle.abort();
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
    sent: bool,
}

fn update_request_gauges(map: &HashMap<u32, HashMap<u32, InflightRequest>>) {
    let pending = map.values().map(|m| m.len()).sum::<usize>();
    let inflight = map
        .values()
        .map(|m| m.values().filter(|req| req.sent).count())
        .sum::<usize>();
    smoo_gadget_core::record_pending_requests(pending);
    smoo_gadget_core::record_inflight_requests(inflight);
}

async fn take_inflight_entry(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) -> Option<InflightRequest> {
    let mut guard = inflight.lock().await;
    let entry = guard
        .get_mut(&export_id)
        .and_then(|map| map.remove(&request_id));
    if let Some(map) = guard.get(&export_id) {
        if map.is_empty() {
            guard.remove(&export_id);
        }
    }
    update_request_gauges(&guard);
    entry
}

async fn mark_request_sent(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    export_id: u32,
    request_id: u32,
) {
    let mut guard = inflight.lock().await;
    if let Some(entry) = guard
        .get_mut(&export_id)
        .and_then(|map| map.get_mut(&request_id))
    {
        entry.sent = true;
    }
    update_request_gauges(&guard);
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
            _changed = stop.changed() => {
                break;
            }
            req = queues.next_io(queue_id) => {
                match req {
                    Ok(request) => {
                        let send_fut = tx.send(QueueEvent::Request { export_id, dev_id, request, queues: queues.clone() });
                        tokio::select! {
                            res = send_fut => {
                                if res.is_err() {
                                    break;
                                }
                            }
                            _ = stop.changed() => break,
                        }
                    }
                    Err(err) => {
                        if !*stop.borrow() {
                            let send_fut = tx.send(QueueEvent::QueueError { export_id, dev_id, error: err });
                            let _ = tokio::select! {
                                res = send_fut => res,
                                _ = stop.changed() => Ok(()),
                            };
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn sync_queue_tasks(runtime: &mut RuntimeState, queue_tx: &QueueSender) {
    if runtime.io_pump.is_none() {
        stop_all_queue_tasks(runtime).await;
        return;
    }
    let mut to_stop: Vec<u32> = runtime
        .queue_tasks
        .keys()
        .cloned()
        .filter(|export_id| !runtime.exports.contains_key(export_id))
        .collect();

    for (&export_id, controller) in runtime.exports.iter() {
        let should_run = controller
            .device_handle()
            .map(|h| {
                matches!(
                    h,
                    DeviceHandle::Online { .. } | DeviceHandle::Starting { .. }
                )
            })
            .unwrap_or(false);
        let running = runtime.queue_tasks.contains_key(&export_id);
        if should_run && runtime.io_pump.is_some() && !running {
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

async fn stop_all_queue_tasks(runtime: &mut RuntimeState) {
    let mut tasks = std::mem::take(&mut runtime.queue_tasks);
    for (_, taskset) in tasks.drain() {
        taskset.shutdown().await;
    }
}

async fn ensure_data_plane(
    runtime: &mut RuntimeState,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    response_task: &mut Option<JoinHandle<()>>,
) {
    if runtime.gadget.is_none() {
        if let Some(pump) = runtime.io_pump.take() {
            drop(pump);
        }
        if let Some(task) = runtime.io_pump_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(handle) = response_task.take() {
            handle.abort();
            let _ = handle.await;
        }
        return;
    }

    if runtime.io_pump.is_none() {
        if let Some(gadget) = runtime.gadget.clone() {
            let (handle, task) = IoPumpHandle::spawn(gadget, runtime.io_pump_capacity);
            runtime.io_pump = Some(handle);
            runtime.io_pump_task = Some(task);
        }
    }
    if response_task.is_none() {
        if let Some(gadget) = runtime.gadget.clone() {
            let inflight_map = inflight.clone();
            let interrupt_out = gadget.response_reader();
            *response_task = Some(tokio::spawn(response_loop(
                gadget,
                interrupt_out,
                inflight_map,
            )));
        }
    }
}

async fn drain_ep0_signals(
    ep0_signals: &Ep0Signals,
    last_status_seq: &mut u64,
    last_lifecycle_seq: &mut u64,
    link: &mut LinkController,
) {
    let status_seq = ep0_signals.status_seq();
    if status_seq != *last_status_seq {
        *last_status_seq = status_seq;
        link.on_status_ping();
    }
    if ep0_signals.lifecycle_seq() != *last_lifecycle_seq {
        let events = ep0_signals.take_lifecycle().await;
        *last_lifecycle_seq = ep0_signals.lifecycle_seq();
        for event in events {
            link.on_ep0_event(event);
        }
    }
}

async fn drain_queue_batch(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    queue_rx: &mut mpsc::Receiver<QueueEvent>,
) -> Result<()> {
    let mut processed = 0;
    while processed < QUEUE_BATCH_MAX.saturating_sub(1) {
        match queue_rx.try_recv() {
            Ok(evt) => {
                handle_queue_event(runtime, link, inflight, outstanding, evt).await?;
                processed += 1;
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }
    if processed >= QUEUE_BATCH_MAX.saturating_sub(1) {
        trace!(processed, "queue batch truncated; will continue next tick");
    }
    Ok(())
}

fn pop_next_outstanding(
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
) -> Option<(u32, u16, u16, OutstandingRequest)> {
    let (export_id, (queue_id, tag)) = outstanding.iter().find_map(|(export_id, reqs)| {
        reqs.keys()
            .next()
            .map(|(queue, tag)| (*export_id, (*queue, *tag)))
    })?;
    let pending = outstanding
        .get_mut(&export_id)
        .and_then(|map| map.remove(&(queue_id, tag)))?;
    if let Some(map) = outstanding.get(&export_id) {
        if map.is_empty() {
            outstanding.remove(&export_id);
        }
    }
    Some((export_id, queue_id, tag, pending))
}

async fn drain_outstanding_bounded(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    deadline: Instant,
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
    let Some(pump) = runtime.io_pump.as_ref() else {
        trace!(
            outstanding_exports = outstanding.len(),
            "no gadget endpoints available; deferring outstanding IO drain"
        );
        return Ok(());
    };

    let mut processed = 0usize;
    while processed < OUTSTANDING_BATCH_MAX && Instant::now() < deadline {
        let Some((export_id, _queue_id, _tag, pending)) = pop_next_outstanding(outstanding) else {
            break;
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
        if let Err(err) =
            handle_request(pump.clone(), inflight, export_id, queues.clone(), req).await
        {
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
        processed += 1;
    }

    if !outstanding.is_empty() {
        trace!(
            remaining_exports = outstanding.len(),
            processed,
            "outstanding drain truncated"
        );
    }
    Ok(())
}

async fn run_reconcile_slice(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    deadline: Instant,
) -> Result<()> {
    let now = Instant::now();
    for (&export_id, ctrl) in runtime.exports.iter() {
        if ctrl.needs_reconcile(now) && !runtime.reconcile_queue.contains(&export_id) {
            runtime.reconcile_queue.push_back(export_id);
        }
    }

    while Instant::now() < deadline {
        let Some(export_id) = runtime.reconcile_queue.pop_front() else {
            break;
        };
        let now = Instant::now();
        let needs_reconcile = runtime
            .exports
            .get(&export_id)
            .is_some_and(|ctrl| ctrl.needs_reconcile(now));
        if !needs_reconcile {
            continue;
        }

        let tunables = runtime.tunables;
        let mut controller = match runtime.exports.remove(&export_id) {
            Some(ctrl) => ctrl,
            None => continue,
        };
        {
            let mut cx = ExportReconcileContext {
                ublk,
                state_store: runtime.state_store(),
                tunables,
            };
            match tokio::time::timeout(
                Duration::from_millis(RECONCILE_TIMEOUT_MS),
                controller.reconcile(&mut cx),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => {
                    warn!(export_id, "reconcile timed out; backing off");
                    controller.fail_device("reconcile timed out".to_string());
                }
            }
        }
        let needs_more = controller.needs_reconcile(Instant::now());
        runtime.exports.insert(export_id, controller);
        if needs_more {
            runtime.reconcile_queue.push_back(export_id);
        }

        if Instant::now() >= deadline {
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_runtime(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    queue_tx: Option<&QueueSender>,
    response_task: &mut Option<JoinHandle<()>>,
    allow_reconcile: bool,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(MAINTENANCE_SLICE_MS);
    link.tick(Instant::now());
    process_link_commands(runtime, link, inflight, outstanding, response_task).await?;
    ensure_data_plane(runtime, inflight, response_task).await;
    if let Some(tx) = queue_tx {
        sync_queue_tasks(runtime, tx).await;
    }
    drain_outstanding_bounded(runtime, link, inflight, outstanding, deadline).await?;
    if allow_reconcile {
        run_reconcile_slice(ublk, runtime, deadline).await?;
    }
    let active_count = count_active_exports(&runtime.exports);
    runtime.status().set_export_count(active_count).await;
    Ok(())
}

async fn handle_config_message(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    response_task: &mut Option<JoinHandle<()>>,
    config: ConfigExportsV0,
) -> Result<()> {
    apply_config(ublk, runtime, config).await?;
    prune_outstanding_for_missing_exports(outstanding, &runtime.exports);
    process_link_commands(runtime, link, inflight, outstanding, response_task).await?;
    Ok(())
}

async fn stop_accepting_new_io(runtime: &mut RuntimeState, queue_tx: &mut Option<QueueSender>) {
    stop_all_queue_tasks(runtime).await;
    *queue_tx = None;
}

enum ShutdownState {
    Running,
    Graceful { deadline: Instant },
    Forceful,
}

async fn run_event_loop(
    ublk: &mut SmooUblk,
    mut runtime: RuntimeState,
    mut control_rx: mpsc::Receiver<ConfigExportsV0>,
    mut link: LinkController,
    ep0_signals: Ep0Signals,
    control_stop: watch::Sender<bool>,
) -> Result<()> {
    let mut shutdown = Some(Box::pin(signal::ctrl_c()));
    let mut hup = unix_signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    let idle_sleep = tokio::time::sleep(Duration::from_millis(IDLE_INTERVAL_MS));
    tokio::pin!(idle_sleep);
    let mut liveness_tick = tokio::time::interval(Duration::from_millis(LIVENESS_INTERVAL_MS));
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut outstanding: HashMap<u32, HashMap<(u16, u16), OutstandingRequest>> = HashMap::new();
    let (queue_tx_init, mut queue_rx) = mpsc::channel::<QueueEvent>(QUEUE_CHANNEL_DEPTH);
    let mut queue_tx: Option<QueueSender> = Some(queue_tx_init);
    let inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut response_task: Option<JoinHandle<()>> = None;
    let ep0_notify = ep0_signals.notifier();

    let mut io_error = None;
    let mut recovery_exit = false;
    let mut shutdown_state = ShutdownState::Running;
    let mut last_status_seq = ep0_signals.status_seq();
    let mut last_lifecycle_seq = ep0_signals.lifecycle_seq();

    loop {
        idle_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_millis(IDLE_INTERVAL_MS));

        drain_ep0_signals(
            &ep0_signals,
            &mut last_status_seq,
            &mut last_lifecycle_seq,
            &mut link,
        )
        .await;
        process_link_commands(
            &mut runtime,
            &mut link,
            &inflight,
            &mut outstanding,
            &mut response_task,
        )
        .await?;
        // Make sure the data plane (io pump + response reader) is up before we
        // start draining queue events so early responses can't be missed.
        ensure_data_plane(&mut runtime, &inflight, &mut response_task).await;

        if let ShutdownState::Graceful { deadline } = shutdown_state {
            if Instant::now() >= deadline {
                warn!("graceful shutdown timed out; forcing shutdown");
                shutdown_state = ShutdownState::Forceful;
            }
        }

        if matches!(shutdown_state, ShutdownState::Forceful) {
            break;
        }

        let ep0_notified = ep0_notify.notified();
        tokio::pin!(ep0_notified);
        tokio::select! { biased;
            _ = async {
                if let Some(fut) = shutdown.as_mut() {
                    let _ = fut.as_mut().await;
                }
            }, if shutdown.is_some() => {
                shutdown = None;
                match shutdown_state {
                    ShutdownState::Running => {
                        info!("shutdown signal received; entering graceful shutdown");
                        shutdown_state = ShutdownState::Graceful {
                            deadline: Instant::now() + Duration::from_millis(GRACEFUL_SHUTDOWN_TIMEOUT_MS),
                        };
                        stop_accepting_new_io(&mut runtime, &mut queue_tx).await;
                        let _ = control_stop.send(true);
                    }
                    ShutdownState::Graceful { .. } => {
                        warn!("second shutdown signal; forcing shutdown");
                        shutdown_state = ShutdownState::Forceful;
                        break;
                    }
                    ShutdownState::Forceful => break,
                }
            }
            Some(_) = hup.recv() => {
                info!("SIGHUP received; initiating user recovery");
                let _ = control_stop.send(true);
                begin_user_recovery(ublk, &mut runtime).await?;
                recovery_exit = true;
                break;
            }
            Some(config) = control_rx.recv(), if matches!(shutdown_state, ShutdownState::Running) => {
                if let Err(err) = handle_config_message(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &mut outstanding,
                    &inflight,
                    &mut response_task,
                    config,
                )
                .await
                {
                    warn!(error = ?err, "CONFIG_EXPORTS application failed");
                }
            }
            _ = ep0_notified.as_mut() => {
                continue;
            }
            maybe_evt = queue_rx.recv(), if !matches!(shutdown_state, ShutdownState::Forceful) && runtime.io_pump.is_some() => {
                if let Some(evt) = maybe_evt {
                    if let Err(err) = handle_queue_event(&mut runtime, &mut link, &inflight, &mut outstanding, evt).await {
                        io_error = Some(err);
                        break;
                    }
                    if let Err(err) = drain_queue_batch(&mut runtime, &mut link, &inflight, &mut outstanding, &mut queue_rx).await {
                        io_error = Some(err);
                        break;
                    }
                    if let Err(err) = drive_runtime(
                        ublk,
                        &mut runtime,
                        &mut link,
                        &inflight,
                        &mut outstanding,
                        queue_tx.as_ref(),
                        &mut response_task,
                        false,
                    ).await {
                        io_error = Some(err);
                        break;
                    }
                }
            }
            _ = liveness_tick.tick() => {
                if let Err(err) = drive_runtime(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &inflight,
                    &mut outstanding,
                    queue_tx.as_ref(),
                    &mut response_task,
                    false,
                ).await {
                    io_error = Some(err);
                    break;
                }
            }
            _ = &mut idle_sleep => {
                let allow_reconcile = matches!(shutdown_state, ShutdownState::Running);
                if let Err(err) = drive_runtime(
                    ublk,
                    &mut runtime,
                    &mut link,
                    &inflight,
                    &mut outstanding,
                    queue_tx.as_ref(),
                    &mut response_task,
                    allow_reconcile,
                ).await {
                    io_error = Some(err);
                    break;
                }
            }
        }

        if let ShutdownState::Graceful { deadline } = shutdown_state {
            if let Err(err) = drive_runtime(
                ublk,
                &mut runtime,
                &mut link,
                &inflight,
                &mut outstanding,
                queue_tx.as_ref(),
                &mut response_task,
                false,
            )
            .await
            {
                io_error = Some(err);
                break;
            }
            let inflight_empty = inflight.lock().await.is_empty();
            let outstanding_empty = outstanding.is_empty();
            let queue_drained = queue_rx.is_closed() && queue_rx.is_empty();
            if inflight_empty && outstanding_empty && queue_drained {
                info!("graceful shutdown complete; exiting");
                break;
            }
            if Instant::now() >= deadline {
                warn!("graceful shutdown deadline reached; forcing shutdown");
                shutdown_state = ShutdownState::Forceful;
                shutdown = None;
            }
        }
    }

    if let Some(pump) = runtime.io_pump.take() {
        drop(pump);
    }
    if let Some(task) = runtime.io_pump_task.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(handle) = response_task.take() {
        handle.abort();
        let _ = handle.await;
    }
    drain_inflight(&inflight).await;

    if recovery_exit {
        return Ok(());
    }

    let _ = control_stop.send(true);
    cleanup_ublk_devices(
        ublk,
        &mut runtime,
        matches!(shutdown_state, ShutdownState::Forceful),
    )
    .await?;
    runtime.status().set_export_count(0).await;

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
    pump: IoPumpHandle,
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
            sent: false,
        };
        guard
            .entry(export_id)
            .or_default()
            .insert(request_id, entry);
        update_request_gauges(&guard);
    }
    trace!(
        export_id,
        dev_id = queues.dev_id(),
        queue = req.queue_id,
        tag = req.tag,
        op = ?opcode,
        num_blocks,
        req_bytes = req_len,
        "queueing smoo Request through pump"
    );

    let inflight_map = inflight.clone();
    let inflight_for_sent = inflight.clone();
    let (sent_tx, sent_rx) = oneshot::channel();
    let sent_marker = tokio::spawn(async move {
        if sent_rx.await.is_ok() {
            mark_request_sent(&inflight_for_sent, export_id, request_id).await;
        }
    });
    tokio::spawn(async move {
        let work = IoWork {
            request: proto_req,
            req_len,
            queue_id: req.queue_id,
            tag: req.tag,
            op: opcode,
            queues: queues.clone(),
            on_request_sent: Some(sent_tx),
        };
        if let Err(err) = pump.submit(work).await {
            if let Some(entry) = take_inflight_entry(&inflight_map, export_id, request_id).await {
                let _ = entry.queues.complete_io(entry.request, -libc::ENOLINK);
            }
            warn!(
                export_id,
                queue = req.queue_id,
                tag = req.tag,
                error = ?err,
                "io pump error dispatching request"
            );
        }
        let _ = sent_marker.await;
    });

    Ok(())
}

async fn control_loop(
    mut custom: Custom,
    handler: GadgetControl,
    status: GadgetStatusShared,
    signals: Ep0Signals,
    mut stop: watch::Receiver<bool>,
    tx: mpsc::Sender<ConfigExportsV0>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = stop.changed() => {
                debug!("control loop stopping on shutdown signal");
                return Ok(());
            }
            result = custom.wait_event() => {
                result.context("wait for FunctionFS event")?;
            }
        }
        let event = custom.event().context("read FunctionFS event")?;
        match event {
            usb_gadget::function::custom::Event::Bind => {
                debug!("FunctionFS bind event (control loop)");
                signals.push_lifecycle(Event::Bind).await;
            }
            usb_gadget::function::custom::Event::Unbind => {
                debug!("FunctionFS unbind event (control loop)");
                signals.push_lifecycle(Event::Unbind).await;
            }
            usb_gadget::function::custom::Event::Enable => {
                debug!("FunctionFS enable event (control loop)");
                signals.push_lifecycle(Event::Enable).await;
            }
            usb_gadget::function::custom::Event::Disable => {
                debug!("FunctionFS disable event (control loop)");
                signals.push_lifecycle(Event::Disable).await;
            }
            usb_gadget::function::custom::Event::Suspend => {
                debug!("FunctionFS suspend event (control loop)");
                signals.push_lifecycle(Event::Suspend).await;
            }
            usb_gadget::function::custom::Event::Resume => {
                debug!("FunctionFS resume event (control loop)");
                signals.push_lifecycle(Event::Resume).await;
            }
            usb_gadget::function::custom::Event::SetupDeviceToHost(sender) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(sender.ctrl_req());
                let mut io = UsbControlIo::from_sender(sender);
                if let Err(err) = handler.handle_setup_packet(&mut io, setup, &report).await {
                    warn!(error = ?err, "vendor setup handling failed");
                    let _ = io.stall().await;
                } else if is_status_setup(&setup) {
                    signals.mark_status_ping();
                }
            }
            usb_gadget::function::custom::Event::SetupHostToDevice(receiver) => {
                let report = status.report().await;
                let setup = setup_from_ctrl_req(receiver.ctrl_req());
                let mut io = UsbControlIo::from_receiver(receiver);
                match handler.handle_setup_packet(&mut io, setup, &report).await {
                    Ok(Some(SetupCommand::Config(payload))) => match tx.try_send(payload) {
                        Ok(()) => {}
                        Err(TrySendError::Closed(_)) => {
                            warn!("CONFIG_EXPORTS channel closed; dropping payload");
                        }
                        Err(TrySendError::Full(_)) => {
                            warn!("CONFIG_EXPORTS channel full; dropping payload");
                        }
                    },
                    Ok(None) => {
                        if is_status_setup(&setup) {
                            signals.mark_status_ping();
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

struct BulkOutWork {
    entry: InflightRequest,
    read_len: usize,
    status: i32,
    completion: oneshot::Sender<BulkOutResult>,
}

struct BulkOutResult {
    entry: InflightRequest,
    status: i32,
    result: Result<()>,
}

async fn response_loop(
    gadget: Arc<SmooGadget>,
    interrupt_out: Arc<Mutex<tokio::fs::File>>,
    inflight: Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
) {
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<BulkOutWork>(64);
    let bulk_gadget = gadget.clone();
    let bulk_task = tokio::spawn(async move {
        while let Some(work) = bulk_rx.recv().await {
            let result = async {
                let mut buffer = work
                    .entry
                    .queues
                    .checkout_buffer(work.entry.request.queue_id, work.entry.request.tag)
                    .map_err(|err| anyhow!("checkout buffer for bulk out: {err:#}"))?;
                bulk_gadget
                    .read_bulk_buffer(&mut buffer.as_mut_slice()[..work.read_len])
                    .await
                    .map_err(|err| anyhow!("bulk OUT read failed: {err:#}"))?;
                Ok(())
            }
            .await;
            let _ = work.completion.send(BulkOutResult {
                entry: work.entry,
                status: work.status,
                result,
            });
        }
    });
    loop {
        let response = {
            let mut buf = [0u8; smoo_proto::RESPONSE_LEN];
            let start = Instant::now();
            let read_res = {
                let mut lock = interrupt_out.lock().await;
                lock.read_exact(&mut buf).await
            };
            if let Err(err) = read_res {
                warn!(error = ?err, "response reader exiting after error");
                break;
            }
            smoo_gadget_core::observe_interrupt_out(buf.len(), start.elapsed());
            match Response::try_from(buf.as_slice()) {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(error = ?err, "response reader failed to decode Response");
                    continue;
                }
            }
        };
        let entry = take_inflight_entry(&inflight, response.export_id, response.request_id).await;
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
        if response.op == OpCode::Read && status > 0 {
            let read_len = usize::try_from(status).unwrap_or(entry.req_len);
            let read_len = read_len.min(entry.req_len);
            let (completion_tx, completion_rx) = oneshot::channel();
            if bulk_tx
                .send(BulkOutWork {
                    entry,
                    read_len,
                    status,
                    completion: completion_tx,
                })
                .await
                .is_err()
            {
                warn!(
                    request_id = response.request_id,
                    export_id = response.export_id,
                    "bulk OUT worker stopped"
                );
                continue;
            }
            tokio::spawn(async move {
                match completion_rx.await {
                    Ok(result) => match result.result {
                        Ok(()) => {
                            if let Err(err) = result
                                .entry
                                .queues
                                .complete_io(result.entry.request, result.status)
                            {
                                warn!(
                                    request_id = result.entry.request_id,
                                    export_id = result.entry.export_id,
                                    error = ?err,
                                    "failed to complete ublk request after bulk OUT"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(error = ?err, "bulk OUT worker error");
                            let _ = result
                                .entry
                                .queues
                                .complete_io(result.entry.request, -libc::EIO);
                        }
                    },
                    Err(_) => {
                        warn!("bulk OUT completion channel dropped");
                    }
                }
            });
            continue;
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
    drop(bulk_tx);
    let _ = bulk_task.await;
    drain_inflight(&inflight).await;
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
        runtime.reconcile_queue.clear();
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
        .reconcile_queue
        .retain(|export_id| runtime.exports.contains_key(export_id));
    runtime
        .status()
        .set_export_count(count_active_exports(&runtime.exports))
        .await;
    Ok(())
}

struct GadgetGuard {
    registration: RegGadget,
    ffs_dir: PathBuf,
}

fn setup_pid1_configfs(args: &Args) -> Result<GadgetGuard> {
    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let mut builder = configfs_builder();
    builder.ffs_no_init = true;
    let (mut custom, handle) = builder.build();

    let klass = Class::new(SMOO_CLASS, SMOO_SUBCLASS, SMOO_PROTOCOL);
    let id = Id::new(args.vendor_id, args.product_id);
    let strings = Strings::new("smoo", "smoo gadget", "0001");
    let mut config = Config::new("config").with_function(handle);

    if cmdline_bool("smoo.acm") {
        let (_serial, serial_handle) = Serial::new(SerialClass::Acm);
        config = config.with_function(serial_handle);
        info!("pid1: enabled USB ACM function");
    }

    let gadget = Gadget::new(klass, id, strings).with_config(config);
    let reg = gadget.register().context("register gadget")?;
    let ffs_dir = custom.ffs_dir().context("resolve FunctionFS dir")?;

    Ok(GadgetGuard {
        registration: reg,
        ffs_dir,
    })
}

fn setup_configfs(
    args: &Args,
) -> Result<(Custom, FunctionfsEndpoints, Option<GadgetGuard>, PathBuf)> {
    if let Some(ffs_dir) = args.ffs_dir.as_ref() {
        info!(
            ffs_dir = %ffs_dir.display(),
            "using existing FunctionFS directory; skipping configfs setup"
        );
        let custom = configfs_builder()
            .existing(ffs_dir)
            .context("initialize FunctionFS in existing directory")?;
        let endpoints = open_data_endpoints(ffs_dir)?;
        return Ok((custom, endpoints, None, ffs_dir.clone()));
    }

    usb_gadget::remove_all().context("remove existing USB gadgets")?;
    let (mut custom, handle) = configfs_builder().build();

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
        Some(GadgetGuard {
            registration: reg,
            ffs_dir: ffs_dir.clone(),
        }),
        ffs_dir,
    ))
}

fn configfs_builder() -> CustomBuilder {
    Custom::builder().with_interface(
        Interface::new(Class::vendor_specific(SMOO_SUBCLASS, SMOO_PROTOCOL), "smoo")
            .with_endpoint(interrupt_in_ep())
            .with_endpoint(interrupt_out_ep())
            .with_endpoint(bulk_in_ep())
            .with_endpoint(bulk_out_ep()),
    )
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
    make_ep(dir, TransferType::Interrupt, 1024)
}

fn interrupt_out_ep() -> Endpoint {
    let (_, dir) = EndpointDirection::host_to_device();
    make_ep(dir, TransferType::Interrupt, 1024)
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
    if matches!(ty, TransferType::Interrupt) {
        ep.interval = 1;
    }
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

async fn cleanup_ublk_devices(
    ublk: &mut SmooUblk,
    runtime: &mut RuntimeState,
    forceful: bool,
) -> Result<()> {
    for (_, tasks) in runtime.queue_tasks.drain() {
        if forceful {
            tasks.abort();
        } else {
            tasks.shutdown().await;
        }
    }
    let mut force_remove_ids = Vec::new();
    for controller in runtime.exports.values_mut() {
        if let Some((ctrl, queues)) = controller.take_device_handles() {
            let dev_id = ctrl.dev_id();
            if forceful {
                info!(dev_id, "forceful shutdown: dropping ublk device handles");
                drop(SmooUblkDevice::from_parts(ctrl, queues));
                force_remove_ids.push(dev_id);
            } else {
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

async fn park_inflight_requests(
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
) {
    let mut guard = inflight.lock().await;
    let mut drained = Vec::new();
    for (export_id, mut requests) in guard.drain() {
        for (_req_id, req) in requests.drain() {
            drained.push((export_id, req));
        }
    }
    update_request_gauges(&guard);
    drop(guard);

    for (export_id, req) in drained {
        park_request(
            outstanding,
            export_id,
            req.request.dev_id,
            req.queues,
            req.request,
        );
    }
}

async fn process_link_commands(
    runtime: &mut RuntimeState,
    link: &mut LinkController,
    inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>,
    outstanding: &mut HashMap<u32, HashMap<(u16, u16), OutstandingRequest>>,
    response_task: &mut Option<JoinHandle<()>>,
) -> Result<()> {
    while let Some(cmd) = link.take_command() {
        match cmd {
            LinkCommand::DropLink => {
                park_inflight_requests(inflight, outstanding).await;
                if let Some(pump) = runtime.io_pump.take() {
                    drop(pump);
                }
                if let Some(task) = runtime.io_pump_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                if let Some(task) = response_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                runtime.gadget = None;
                warn!("link controller requested drop; data plane closed");
            }
            LinkCommand::Reopen => {
                if runtime.gadget.is_some() {
                    continue;
                }
                match open_data_endpoints(&runtime.ffs_dir) {
                    Ok(endpoints) => match SmooGadget::new(endpoints, runtime.gadget_config) {
                        Ok(gadget) => {
                            let gadget = Arc::new(gadget);
                            let (handle, task) =
                                IoPumpHandle::spawn(gadget.clone(), runtime.io_pump_capacity);
                            runtime.io_pump = Some(handle);
                            runtime.io_pump_task = Some(task);
                            runtime.gadget = Some(gadget);
                            warn!("link controller reopened data plane");
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
            let handle_ready = matches!(
                handle,
                DeviceHandle::Online { .. } | DeviceHandle::Starting { .. }
            );
            if !matches!(link.state(), LinkState::Online)
                || runtime.gadget.is_none()
                || !handle_ready
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
            let Some(pump) = runtime.io_pump.as_ref() else {
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
            if let Err(err) =
                handle_request(pump.clone(), inflight, export_id, queues.clone(), request).await
            {
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

async fn drain_inflight(inflight: &Arc<Mutex<HashMap<u32, HashMap<u32, InflightRequest>>>>) {
    let mut guard = inflight.lock().await;
    for (_export, mut requests) in guard.drain() {
        for (_req_id, req) in requests.drain() {
            let _ = req.queues.complete_io(req.request, -libc::ENOLINK);
        }
    }
    update_request_gauges(&guard);
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
