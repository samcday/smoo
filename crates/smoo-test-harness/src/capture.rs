//! `dumpcap`-driven usbmon capture session.
//!
//! Each scenario starts capture before the gadget is bound to its UDC so the
//! IDENT setup transfer is recorded. Drop sends SIGTERM and waits for the
//! file to flush.
//!
//! ## Snaplen vs. the usbmon ring buffer
//!
//! libpcap sizes the kernel-side usbmon ring from the snaplen: the ring is
//! `5 * (snaplen - 64)` bytes, clamped to 8 KiB..1200 KiB (`pcap-usb-linux.c`,
//! `usb_set_ring_size`), and `dumpcap -B` is ignored for usbmon. Capturing
//! with `-s 256` therefore leaves the kernel an 8 KiB ring, which a burst of
//! sixteen 32 KiB bulk URBs overflows instantly; usbmon then drops whole
//! events (`cnt_lost`), the dissector sees Requests without Responses or bulk
//! payloads without a queued Request, and the wire assertions flake. So
//! dumpcap always captures untruncated (max ring), and the requested snaplen
//! is applied afterwards with `editcap -s` so the artifact and the Lua
//! analyser still only see the URB header plus the 28-byte control messages.
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
use std::os::unix::fs::PermissionsExt;
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
    snaplen: Option<u32>,
    _stderr_task: JoinHandle<()>,
}

impl CaptureSession {
    /// Start dumpcap on `usbmon<bus_id>`, writing pcapng to `pcap_path`.
    /// Returns once dumpcap has written the pcapng file header.
    ///
    /// `snaplen` truncates each captured packet to N bytes once the capture
    /// has stopped (see the module docs for why it is not passed to dumpcap).
    /// `Some(256)` is the harness default — it preserves the usbmon URB
    /// header + the full 28-byte smoo Request/Response while dropping bulk
    /// read/write payloads that would otherwise dominate the file size *and*
    /// the lua dissector's runtime. The `usb.data_len` field in the URB
    /// header is the pre-capture length, so length-mismatch / orphan-bulk
    /// assertions still work correctly against truncated payloads. Pass
    /// `None` to keep everything; tests doing that should expect the pcap to
    /// be ~8x larger and the analyser ~15x slower.
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

        // `-s 0` = no truncation, which is also what gives usbmon its
        // largest ring; the caller's snaplen is applied in `stop()`.
        let mut cmd = Command::new("dumpcap");
        cmd.arg("-i")
            .arg(&interface)
            .arg("-w")
            .arg("-")
            .arg("-q")
            .arg("-s")
            .arg("0")
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
            snaplen,
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
        if let Some(snaplen) = self.snaplen {
            truncate_capture(&self.pcap_path, snaplen).await?;
        }
        Ok(self.pcap_path)
    }
}

/// Rewrite `pcap_path` in place with every packet cut to `snaplen` bytes.
/// Missing `editcap` is not fatal: the untruncated capture is still valid for
/// every assertion, just larger and slower to analyse.
async fn truncate_capture(pcap_path: &Path, snaplen: u32) -> Result<()> {
    let truncated = pcap_path.with_extension("truncated.pcapng");
    let output = Command::new("editcap")
        .arg("-s")
        .arg(snaplen.to_string())
        .arg(pcap_path)
        .arg(&truncated)
        .stdin(Stdio::null())
        .output()
        .await;
    let output = match output {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                pcap = %pcap_path.display(),
                "editcap not on PATH; keeping the untruncated capture (install wireshark-cli)"
            );
            return Ok(());
        }
        Err(err) => return Err(err).context("spawn editcap"),
    };
    if !output.status.success() {
        let _ = tokio::fs::remove_file(&truncated).await;
        bail!(
            "editcap -s {snaplen} on {} failed ({:?}): {}",
            pcap_path.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    tokio::fs::rename(&truncated, pcap_path)
        .await
        .with_context(|| {
            format!(
                "replace {} with truncated capture {}",
                pcap_path.display(),
                truncated.display()
            )
        })?;
    // dumpcap created the original world-readable for the privilege-dropped
    // tshark (see verify::pcap); editcap's output inherits the umask instead.
    let mut perms = tokio::fs::metadata(pcap_path)
        .await
        .with_context(|| format!("stat {}", pcap_path.display()))?
        .permissions();
    perms.set_mode(0o644);
    tokio::fs::set_permissions(pcap_path, perms)
        .await
        .with_context(|| format!("chmod {}", pcap_path.display()))?;
    Ok(())
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
