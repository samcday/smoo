//! `dumpcap`-driven usbmon capture session.
//!
//! Each scenario starts capture before the gadget is bound to its UDC so the
//! IDENT setup transfer is recorded. Drop sends SIGTERM and waits for the
//! file to flush.
//!
//! ## Why we open the pcap file ourselves
//!
//! `dumpcap` is shipped on Fedora/RHEL with `cap_net_admin,cap_net_raw=ep`
//! file capabilities, and it deliberately drops *all* capabilities after
//! binding the usbmon socket — a hardening step. After the drop, even though
//! the process still runs as uid 0 (we're invoked under sudo), the kernel no
//! longer grants CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE, so it cannot
//! traverse paths like `/var/home/sam` (mode `0710`) to open the output file.
//!
//! Workaround: we open the pcap file ourselves *before* exec'ing dumpcap, and
//! pass that fd as dumpcap's stdout via `-w -`. The fd is inherited; no path
//! traversal is needed once dumpcap drops caps.
//!
//! See `man dumpcap` and the strace excerpt that nailed this down:
//! `capset(..., {effective=0, permitted=0, inheritable=0})` immediately
//! before `openat(..., O_WRONLY|O_CREAT|O_TRUNC) = -1 EACCES`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

use crate::process::LogBuffer;

/// How long we wait for `dumpcap` to write the pcapng file header before we
/// declare the capture broken.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// SIGTERM grace period before SIGKILL on shutdown.
const TERM_GRACE: Duration = Duration::from_secs(5);

pub struct CaptureSession {
    pub pcap_path: PathBuf,
    pub bus_id: u32,
    pub stderr_path: PathBuf,
    pub stderr_buf: Arc<LogBuffer>,
    child: Child,
    _stderr_task: JoinHandle<()>,
}

impl CaptureSession {
    /// Start dumpcap on `usbmon<bus_id>`, writing pcapng to `pcap_path`.
    /// Returns once dumpcap has written the pcapng file header.
    ///
    /// `snaplen` truncates each captured packet to N bytes. `Some(256)` is
    /// the harness default — it preserves the usbmon URB header + the full
    /// 28-byte smoo Request/Response while dropping bulk read/write payloads
    /// that would otherwise dominate the file size *and* the lua dissector's
    /// runtime. The `usb.data_len` field in the URB header is the
    /// pre-capture length, so length-mismatch / orphan-bulk assertions still
    /// work correctly against truncated payloads. Pass `None` (which becomes
    /// `dumpcap -s 0` — "no truncation") to capture everything; tests doing
    /// that should expect the pcap to be ~8x larger and the analyser ~15x
    /// slower.
    pub async fn start(
        bus_id: u32,
        pcap_path: PathBuf,
        log_dir: &Path,
        snaplen: Option<u32>,
    ) -> Result<Self> {
        if let Some(parent) = pcap_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        tokio::fs::create_dir_all(log_dir)
            .await
            .with_context(|| format!("mkdir {}", log_dir.display()))?;

        let pcap_file = File::create(&pcap_path)
            .with_context(|| format!("open pcap output {}", pcap_path.display()))?;

        let stderr_path = log_dir.join(format!("dumpcap-bus{bus_id}.stderr.log"));
        let interface = format!("usbmon{bus_id}");

        let mut cmd = Command::new("dumpcap");
        cmd.arg("-i")
            .arg(&interface)
            .arg("-w")
            .arg("-")
            .arg("-q")
            .arg("-s")
            .arg(snaplen.unwrap_or(0).to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(pcap_file))
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn dumpcap on {interface}"))?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("dumpcap stderr missing"))?;

        let stderr_buf = Arc::new(LogBuffer::default());
        let stderr_task = tokio::spawn(crate::process::pump_stream(
            stderr,
            stderr_path.clone(),
            Arc::clone(&stderr_buf),
            format!("dumpcap-bus{bus_id}/stderr"),
        ));

        if let Err(err) = wait_for_capture_started(&pcap_path, READY_TIMEOUT).await {
            // Surface dumpcap's own error message — usually permissions or a
            // missing usbmon interface — instead of a bare timeout.
            let stderr_lines = stderr_buf.snapshot().await;
            let tail = stderr_lines
                .iter()
                .rev()
                .take(5)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "dumpcap on {interface} never wrote pcapng header to {}: {err}\n\
                 last stderr lines:\n{tail}",
                pcap_path.display()
            );
        }

        Ok(Self {
            pcap_path,
            bus_id,
            stderr_path,
            stderr_buf,
            child,
            _stderr_task: stderr_task,
        })
    }

    /// SIGTERM dumpcap and wait for it to flush the capture file. Returns the
    /// path to the pcap on success.
    pub async fn stop(mut self) -> Result<PathBuf> {
        if let Some(pid) = self.child.id() {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        match tokio::time::timeout(TERM_GRACE, self.child.wait()).await {
            Ok(res) => {
                let _ = res.context("waiting for dumpcap after SIGTERM")?;
            }
            Err(_) => {
                tracing::warn!(
                    bus_id = self.bus_id,
                    "dumpcap did not exit on SIGTERM, sending SIGKILL"
                );
                let _ = self.child.start_kill();
                let _ = self
                    .child
                    .wait()
                    .await
                    .context("waiting for dumpcap after SIGKILL")?;
            }
        }
        self.stderr_buf.close();
        Ok(self.pcap_path)
    }
}

async fn wait_for_capture_started(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(meta) = tokio::fs::metadata(path).await
            && meta.len() > 0
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("file {} never grew above 0 bytes", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
