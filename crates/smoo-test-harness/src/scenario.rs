//! Scenario builder + handle: the test-author-facing API.
//!
//! A scenario is one `#[tokio::test]`. It builds up exports and options via
//! [`ScenarioBuilder`], starts the gadget+host+capture via
//! [`ScenarioBuilder::start`], and then operates on the [`RunningScenario`]
//! handle. [`RunningScenario::stop`] cleans up and returns a
//! [`ScenarioResult`] that the test asserts on.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use crate::artifacts::{ArtifactBundle, ExitInfo, Metadata, OpMixSer, kernel_release};
use crate::capture::CaptureSession;
use crate::dummy_hcd::Slot;
use crate::fixture::{GadgetFixture, GadgetOpts, HostFixture, HostOpts, HostSourceSpec, KernelFixture};
use crate::verify::pcap::PcapAssertions;

#[derive(Debug, Clone)]
pub struct ExportSpec {
    pub block_size: u32,
    pub total_blocks: u64,
    pub seed: u64,
}

impl ExportSpec {
    pub fn random(block_size: u32, total_blocks: u64, seed: u64) -> Self {
        Self {
            block_size,
            total_blocks,
            seed,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.block_size as u64 * self.total_blocks
    }
}

pub struct ScenarioBuilder {
    name: String,
    exports: Vec<ExportSpec>,
    extra_host_sources: Vec<HostSourceSpec>,
    block_size: u32,
    gadget_opts: GadgetOpts,
    host_opts: HostOpts,
    capture_enabled: bool,
    artifact_root: PathBuf,
}

impl ScenarioBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            exports: Vec::new(),
            extra_host_sources: Vec::new(),
            block_size: 4096,
            gadget_opts: GadgetOpts::default(),
            host_opts: HostOpts::default(),
            capture_enabled: true,
            artifact_root: default_artifact_root(),
        }
    }

    pub fn with_export(mut self, e: ExportSpec) -> Self {
        self.exports.push(e);
        self
    }

    pub fn with_host_source(mut self, s: HostSourceSpec) -> Self {
        self.extra_host_sources.push(s);
        self
    }

    pub fn with_block_size(mut self, bs: u32) -> Self {
        self.block_size = bs;
        self
    }

    pub fn with_capture(mut self, enabled: bool) -> Self {
        self.capture_enabled = enabled;
        self
    }

    pub fn with_gadget_opts(mut self, opts: GadgetOpts) -> Self {
        self.gadget_opts = opts;
        self
    }

    pub fn with_host_opts(mut self, opts: HostOpts) -> Self {
        self.host_opts = opts;
        self
    }

    pub fn with_artifact_root(mut self, root: PathBuf) -> Self {
        self.artifact_root = root;
        self
    }

    /// Start the kernel fixture, allocate a slot, mount FunctionFS, spawn the
    /// gadget, start capture, spawn the host, and return a handle ready for
    /// the test body to run against.
    pub async fn start(self) -> Result<RunningScenario> {
        let artifacts = ArtifactBundle::create(&self.artifact_root, &self.name)
            .context("artifact bundle")?;

        let kernel = KernelFixture::ensure().context("kernel fixture")?;
        let slot = kernel.allocate_slot().context("slot allocation")?;

        // Build host source list: each ExportSpec → one HostSourceSpec::Random.
        // Tests using FileBlockSource etc. should pass them via with_host_source.
        let mut host_sources: Vec<HostSourceSpec> = self
            .exports
            .iter()
            .map(|e| HostSourceSpec::Random {
                blocks: e.total_blocks,
                seed: e.seed,
            })
            .collect();
        host_sources.extend(self.extra_host_sources.iter().cloned());

        let mut host_opts = self.host_opts;
        if host_opts.block_size == HostOpts::default().block_size {
            host_opts.block_size = self.block_size;
        }

        // Start capture before UDC bind so IDENT/CONFIG_EXPORTS land in the pcap.
        // If `dumpcap` isn't on PATH (common on minimal/bootc systems), skip
        // capture with a warning rather than failing — pcap assertions then
        // become no-ops in `assert_clean`.
        let capture = if self.capture_enabled && capture_available() {
            Some(
                CaptureSession::start(slot.bus_id, artifacts.pcap_path(), artifacts.log_dir())
                    .await
                    .context("start capture")?,
            )
        } else {
            if self.capture_enabled {
                tracing::warn!(
                    "dumpcap not on PATH; running without packet capture (install wireshark-cli for wire-level assertions)"
                );
            }
            None
        };

        let gadget = GadgetFixture::spawn(slot, self.gadget_opts.clone(), artifacts.log_dir())
            .await
            .context("spawn gadget fixture")?;

        // After the gadget is bound to UDC, it appears on the dummy_hcd bus.
        // The host can now claim it.
        let host = HostFixture::spawn(&gadget.slot, &host_sources, host_opts, artifacts.log_dir())
            .await
            .context("spawn host fixture")?;

        Ok(RunningScenario {
            name: self.name,
            artifacts,
            kernel,
            gadget: Some(gadget),
            host: Some(host),
            capture,
            exports: self.exports,
        })
    }
}

pub struct RunningScenario {
    pub name: String,
    pub artifacts: ArtifactBundle,
    pub kernel: KernelFixture,
    pub gadget: Option<GadgetFixture>,
    pub host: Option<HostFixture>,
    pub capture: Option<CaptureSession>,
    pub exports: Vec<ExportSpec>,
}

impl RunningScenario {
    /// Borrow gadget for log polling / inspection. Panics if already shut down.
    pub fn gadget(&self) -> &GadgetFixture {
        self.gadget.as_ref().expect("gadget already shut down")
    }

    pub fn host(&self) -> &HostFixture {
        self.host.as_ref().expect("host already shut down")
    }

    pub fn slot(&self) -> &Slot {
        &self.gadget().slot
    }

    /// Shut down host, gadget, then capture. Returns a result that the test
    /// can call [`ScenarioResult::assert_clean`] on.
    pub async fn stop(mut self) -> Result<ScenarioResult> {
        let host_exit = match self.host.take() {
            Some(h) => Some(h.shutdown().await.context("host shutdown")?),
            None => None,
        };
        let gadget_exit = match self.gadget.take() {
            Some(g) => Some(g.shutdown().await.context("gadget shutdown")?),
            None => None,
        };
        let pcap = match self.capture.take() {
            Some(c) => Some(c.stop().await.context("stop capture")?),
            None => None,
        };

        Ok(ScenarioResult {
            name: self.name,
            artifacts: self.artifacts,
            gadget_exit,
            host_exit,
            pcap_path: pcap,
            exports: self.exports,
        })
    }
}

pub struct ScenarioResult {
    pub name: String,
    pub artifacts: ArtifactBundle,
    pub gadget_exit: Option<ExitStatus>,
    pub host_exit: Option<ExitStatus>,
    pub pcap_path: Option<PathBuf>,
    pub exports: Vec<ExportSpec>,
}

impl ScenarioResult {
    pub fn pcap_path(&self) -> Option<&Path> {
        self.pcap_path.as_deref()
    }

    /// Run all the standard checks: clean exits + balanced wire framing +
    /// no length-mismatch + no orphan bulks. Writes `metadata.json` either
    /// way.
    pub async fn assert_clean(self) -> Result<()> {
        self.assert(true, true).await
    }

    /// More granular: choose whether to enforce wire and exit checks.
    pub async fn assert(self, check_exits: bool, check_pcap: bool) -> Result<()> {
        let mut failure_msg: Option<String> = None;
        let mut op_mix = None;

        if check_exits
            && let Err(err) = check_exit_codes(&self.gadget_exit, &self.host_exit)
        {
            failure_msg = Some(err.to_string());
        }

        if check_pcap && failure_msg.is_none()
            && let Some(pcap) = self.pcap_path.as_ref()
        {
            match analyse_pcap(pcap).await {
                Ok(assertions) => {
                    op_mix = Some(assertions.op_counts());
                    if let Err(err) = assertions.assert_no_length_mismatch() {
                        failure_msg = Some(err.to_string());
                    } else if let Err(err) = assertions.assert_no_orphan_bulk() {
                        failure_msg = Some(err.to_string());
                    } else if let Err(err) = assertions.assert_request_response_balanced() {
                        failure_msg = Some(err.to_string());
                    }
                }
                Err(err) => {
                    failure_msg = Some(format!("pcap analysis: {err}"));
                }
            }
        }

        let metadata = Metadata {
            scenario: self.name.clone(),
            kernel_version: kernel_release(),
            started_at_unix: self.artifacts.started_at_unix,
            elapsed_ms: self.artifacts.elapsed_ms(),
            gadget_exit: self.gadget_exit.map(ExitInfo::from_status),
            host_exit: self.host_exit.map(ExitInfo::from_status),
            pcap_path: self.pcap_path.as_ref().map(|p| p.display().to_string()),
            op_mix: op_mix.map(OpMixSer::from),
            passed: failure_msg.is_none(),
            failure: failure_msg.clone(),
        };
        if let Err(err) = self.artifacts.write_metadata(&metadata) {
            tracing::warn!(error = ?err, "write metadata.json failed");
        }

        if let Some(msg) = failure_msg {
            anyhow::bail!(
                "scenario `{}` failed: {} (artifacts: {})",
                self.name,
                msg,
                self.artifacts.root.display()
            );
        }
        Ok(())
    }
}

fn check_exit_codes(
    gadget: &Option<ExitStatus>,
    host: &Option<ExitStatus>,
) -> Result<()> {
    if let Some(g) = gadget {
        check_exit("gadget", *g)?;
    }
    if let Some(h) = host {
        check_exit("host", *h)?;
    }
    Ok(())
}

fn check_exit(name: &str, status: ExitStatus) -> Result<()> {
    use std::os::unix::process::ExitStatusExt;
    if status.success() {
        return Ok(());
    }
    // Allow SIGTERM (the harness's own SIGTERM during shutdown).
    if status.signal() == Some(libc::SIGTERM) {
        return Ok(());
    }
    anyhow::bail!(
        "{name} exited unsuccessfully (code={:?}, signal={:?})",
        status.code(),
        status.signal()
    )
}

async fn analyse_pcap(pcap: &Path) -> Result<PcapAssertions> {
    let lua = workspace_path("tools/wireshark/smoo.lua")?;
    PcapAssertions::from_pcap(pcap, &lua).await
}

fn capture_available() -> bool {
    which("dumpcap").is_some()
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn default_artifact_root() -> PathBuf {
    let target = match std::env::var("CARGO_TARGET_DIR") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("target"))
                .unwrap_or_else(|| PathBuf::from("target"))
        }
    };
    target.join("integration-artifacts")
}

fn workspace_path(rel: &str) -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("workspace root not resolvable"))?;
    let p = workspace.join(rel);
    if !p.exists() {
        anyhow::bail!("{} not found", p.display());
    }
    Ok(p)
}

/// Convenience: run an arbitrary command (e.g. `dd`, `fio`) against the
/// scenario's `/dev/ublkbN`. Tees output to the artifact directory and
/// returns the exit status.
pub async fn run_tool(
    scenario: &RunningScenario,
    name: &str,
    cmd: Command,
) -> Result<ExitStatus> {
    let log_dir = scenario.artifacts.log_dir();
    let mut child = crate::process::ChildProcess::spawn(name, cmd, log_dir)
        .await
        .context("spawn tool")?;
    // Drain logs into files; wait for tool to exit naturally.
    let status = loop {
        match child.try_wait()? {
            Some(s) => break s,
            None => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    Ok(status)
}
