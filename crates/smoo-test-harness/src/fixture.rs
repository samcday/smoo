//! RAII fixtures: [`KernelFixture`], [`GadgetFixture`], [`HostFixture`].
//!
//! Each test calls [`KernelFixture::ensure`] (cheap, idempotent), then
//! [`KernelFixture::allocate_slot`] for a unique `(udc_idx, vid, pid, ...)`.
//! The slot is fed to [`GadgetFixture::spawn`] and [`HostFixture::spawn`],
//! which spawn the real `smoo-gadget` and `smoo-host` binaries against the
//! configfs/FunctionFS state the harness owns.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;
use tokio::process::Command;

use crate::configfs::GadgetConfigFs;
use crate::dummy_hcd::{
    DEFAULT_NUM_INSTANCES, Slot, SlotPool, allocate_slot as pool_allocate_slot, probe_kernel,
};
use crate::process::ChildProcess;

/// Process-wide fixture: probes kernel state and shares a single
/// [`SlotPool`] across concurrent tests.
pub struct KernelFixture {
    pool: Arc<Mutex<SlotPool>>,
}

impl KernelFixture {
    /// Probe required kernel capabilities and return a fixture. Cheap to call
    /// per-test; the slot pool is shared across calls.
    pub fn ensure() -> Result<Self> {
        static POOL: OnceLock<Arc<Mutex<SlotPool>>> = OnceLock::new();
        probe_kernel().context("kernel pre-flight")?;
        let pool = POOL.get_or_init(|| Arc::new(Mutex::new(SlotPool::new(DEFAULT_NUM_INSTANCES))));
        Ok(Self {
            pool: Arc::clone(pool),
        })
    }

    pub fn allocate_slot(&self) -> Result<Slot> {
        pool_allocate_slot(&self.pool)
    }
}

#[derive(Debug, Clone)]
pub struct GadgetOpts {
    pub queue_count: u32,
    pub queue_depth: u32,
    pub max_io_bytes: Option<u64>,
    pub extra_args: Vec<String>,
    pub readiness_timeout: Duration,
    pub rust_log: String,
}

impl Default for GadgetOpts {
    fn default() -> Self {
        Self {
            queue_count: 1,
            queue_depth: 16,
            max_io_bytes: None,
            extra_args: Vec::new(),
            readiness_timeout: Duration::from_secs(15),
            rust_log: "info".to_string(),
        }
    }
}

pub struct GadgetFixture {
    /// The child smoo-gadget process. Rust drops fields in declaration order,
    /// so this releases FunctionFS endpoint FDs before configfs is removed.
    pub child: ChildProcess,
    pub configfs: GadgetConfigFs,
    observed_ublk_dev_ids: Mutex<Vec<u32>>,
    /// Keep the slot guard last so the dummy_hcd index is returned only after
    /// the child and configfs teardown have run on implicit Drop.
    pub slot: Slot,
}

impl GadgetFixture {
    /// Spawn `smoo-gadget --ffs-dir <harness-mount>` against the per-test
    /// FunctionFS instance. Waits for the gadget's "smoo gadget initialized"
    /// log line, then writes the UDC binding so the device becomes visible
    /// on the dummy_hcd bus.
    pub async fn spawn(slot: Slot, opts: GadgetOpts, log_dir: &Path) -> Result<Self> {
        let configfs = GadgetConfigFs::create(&slot).context("configfs setup")?;

        let bin = smoo_gadget_path()?;
        let mut cmd = Command::new(&bin);
        cmd.arg("--vendor-id")
            .arg(format!("0x{:04x}", slot.vid))
            .arg("--product-id")
            .arg(format!("0x{:04x}", slot.pid))
            .arg("--queue-count")
            .arg(opts.queue_count.to_string())
            .arg("--queue-depth")
            .arg(opts.queue_depth.to_string())
            .arg("--ffs-dir")
            .arg(&configfs.ffs_mount_dir);
        if let Some(max_io) = opts.max_io_bytes {
            cmd.arg("--max-io-bytes").arg(max_io.to_string());
        }
        for arg in &opts.extra_args {
            cmd.arg(arg);
        }
        apply_rust_log(&mut cmd, &opts.rust_log);

        let child = ChildProcess::spawn("smoo-gadget", cmd, log_dir)
            .await
            .context("spawn smoo-gadget")?;

        // Wait for the gadget to log readiness — fires from
        // crates/smoo-gadget-app/src/lib.rs:193 after FunctionFS descriptors
        // have been written and ep1-4 opened. The CLI's tracing-subscriber
        // writes to stdout by default; use either stream so this works
        // regardless of how a future caller configures it.
        let re = Regex::new(r"smoo gadget initialized").unwrap();
        child
            .wait_for_either(&re, opts.readiness_timeout)
            .await
            .context("waiting for 'smoo gadget initialized'")?;

        configfs.bind_udc().context("bind UDC")?;

        Ok(Self {
            child,
            configfs,
            observed_ublk_dev_ids: Mutex::new(Vec::new()),
            slot,
        })
    }

    /// Wait for the gadget to log a regex-matching line on either stream.
    /// Useful for tests that need to observe e.g. ublk dev_id assignment.
    pub async fn wait_for_log(&self, re: &Regex, timeout: Duration) -> Result<String> {
        self.child.wait_for_either(re, timeout).await
    }

    /// Wait for the `start_dev completed` log line (emitted by
    /// `smoo-gadget-ublk` after `UBLK_CMD_START_DEV` succeeds) and parse the
    /// associated `dev_id`. The corresponding block device is `/dev/ublkb<id>`.
    pub async fn wait_for_ublk_dev_id(&self, timeout: Duration) -> Result<u32> {
        let line_re = Regex::new(r"start_dev completed").unwrap();
        let line = self.child.wait_for_either(&line_re, timeout).await?;
        let id_re = Regex::new(r"dev_id=(\d+)").unwrap();
        let caps = id_re.captures(&line).ok_or_else(|| {
            anyhow::anyhow!("'start_dev completed' line had no dev_id field: {line}")
        })?;
        let id: u32 = caps[1].parse().context("parse dev_id from gadget log")?;
        let mut observed = self
            .observed_ublk_dev_ids
            .lock()
            .expect("observed ublk dev-id mutex poisoned");
        if !observed.contains(&id) {
            observed.push(id);
        }
        Ok(id)
    }

    pub fn observed_ublk_dev_ids(&self) -> Vec<u32> {
        self.observed_ublk_dev_ids
            .lock()
            .expect("observed ublk dev-id mutex poisoned")
            .clone()
    }

    /// SIGTERM the gadget, wait, then drop configfs (which umounts FFS and
    /// rmdir's the gadget tree).
    pub async fn shutdown(self) -> Result<ExitStatus> {
        let GadgetFixture {
            slot,
            child,
            configfs,
            observed_ublk_dev_ids: _,
        } = self;
        let status = child.shutdown().await?;
        drop(configfs);
        drop(slot);
        Ok(status)
    }
}

#[derive(Debug, Clone)]
pub struct HostOpts {
    pub block_size: u32,
    pub timeout_ms: u64,
    pub extra_args: Vec<String>,
    pub rust_log: String,
}

impl Default for HostOpts {
    fn default() -> Self {
        Self {
            block_size: 4096,
            timeout_ms: 1000,
            extra_args: Vec::new(),
            rust_log: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HostSourceSpec {
    /// `--random <blocks>` with `--random-seed <seed>`.
    Random { blocks: u64, seed: u64 },
    /// `--file <path>`.
    File(PathBuf),
}

pub struct HostFixture {
    pub child: ChildProcess,
}

impl HostFixture {
    /// Spawn `smoo-host` filtered to the slot's vid/pid, with the given
    /// block sources.
    pub async fn spawn(
        slot: &Slot,
        sources: &[HostSourceSpec],
        opts: HostOpts,
        log_dir: &Path,
    ) -> Result<Self> {
        let bin = smoo_host_path()?;
        let mut cmd = Command::new(&bin);
        cmd.arg("--vendor-id")
            .arg(format!("0x{:04x}", slot.vid))
            .arg("--product-id")
            .arg(format!("0x{:04x}", slot.pid))
            .arg("--block-size")
            .arg(opts.block_size.to_string())
            .arg("--timeout-ms")
            .arg(opts.timeout_ms.to_string());

        let mut seed_seen = false;
        for source in sources {
            match source {
                HostSourceSpec::Random { blocks, seed } => {
                    cmd.arg("--random").arg(blocks.to_string());
                    if !seed_seen {
                        cmd.arg("--random-seed").arg(seed.to_string());
                        seed_seen = true;
                    }
                }
                HostSourceSpec::File(path) => {
                    cmd.arg("--file").arg(path);
                }
            }
        }
        for arg in &opts.extra_args {
            cmd.arg(arg);
        }
        apply_rust_log(&mut cmd, &opts.rust_log);

        let child = ChildProcess::spawn("smoo-host", cmd, log_dir)
            .await
            .context("spawn smoo-host")?;
        Ok(Self { child })
    }

    /// Wait for the host to log a regex match on either stream. Tests use
    /// this to assert "session connected" or similar.
    pub async fn wait_for_log(&self, re: &Regex, timeout: Duration) -> Result<String> {
        self.child.wait_for_either(re, timeout).await
    }

    pub async fn shutdown(self) -> Result<ExitStatus> {
        self.child.shutdown().await
    }
}

/// Set `RUST_LOG` on a child command. The harness's caller-set value
/// (typically the `"info"` default in [`GadgetOpts`] / [`HostOpts`]) is
/// applied only when the parent process doesn't already have `RUST_LOG`
/// in its environment — that way `RUST_LOG=trace cargo xtask integration`
/// reaches the spawned smoo binaries unchanged. `tokio::process::Command`
/// inherits the parent env by default, so we only need to *not clobber* it.
fn apply_rust_log(cmd: &mut Command, fallback: &str) {
    if std::env::var_os("RUST_LOG").is_none() {
        cmd.env("RUST_LOG", fallback);
    }
}

/// Resolve the `smoo-gadget` binary path. Honours `SMOO_GADGET_PATH` if set;
/// otherwise looks under the workspace target directory (`debug` or
/// `release` per `cfg!(debug_assertions)`).
pub fn smoo_gadget_path() -> Result<PathBuf> {
    binary_path("smoo-gadget", "SMOO_GADGET_PATH")
}

/// Resolve the `smoo-host` binary path.
pub fn smoo_host_path() -> Result<PathBuf> {
    binary_path("smoo-host", "SMOO_HOST_PATH")
}

fn binary_path(name: &str, env_override: &str) -> Result<PathBuf> {
    if let Ok(p) = std::env::var(env_override) {
        let path = PathBuf::from(p);
        if !path.exists() {
            anyhow::bail!(
                "{env_override}={} but the binary does not exist",
                path.display()
            );
        }
        return Ok(path);
    }
    let path = workspace_target_dir().join(name);
    if !path.exists() {
        anyhow::bail!(
            "binary {} not found at {} — run `cargo build --bins -p smoo-gadget-cli -p smoo-host-cli` first",
            name,
            path.display()
        );
    }
    Ok(path)
}

fn workspace_target_dir() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if let Ok(custom) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(custom).join(profile);
    }
    // CARGO_MANIFEST_DIR = .../crates/smoo-test-harness; workspace root = grandparent.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has no grandparent — unexpected workspace layout");
    workspace.join("target").join(profile)
}
