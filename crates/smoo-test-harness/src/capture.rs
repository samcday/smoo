//! `dumpcap`-driven usbmon capture session.
//!
//! Each scenario starts capture before the gadget is bound to its UDC so the
//! IDENT setup transfer is recorded. Drop sends SIGTERM and waits for the
//! file to flush.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::process::ChildProcess;

/// How long we wait for `dumpcap` to write the first bytes of its capture
/// file before we declare the capture broken.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct CaptureSession {
    pub pcap_path: PathBuf,
    pub bus_id: u32,
    /// Wrapped `dumpcap` child. Public so tests can introspect logs on
    /// failure (e.g. "permission denied on usbmon").
    pub child: ChildProcess,
}

impl CaptureSession {
    /// Start dumpcap on `usbmon<bus_id>`, writing pcapng to `pcap_path`.
    /// Returns once dumpcap has written its file header — guaranteeing that
    /// any subsequently observed packet is in the capture.
    pub async fn start(bus_id: u32, pcap_path: PathBuf, log_dir: &Path) -> Result<Self> {
        if let Some(parent) = pcap_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }

        let interface = format!("usbmon{bus_id}");
        let mut cmd = Command::new("dumpcap");
        cmd.arg("-i")
            .arg(&interface)
            .arg("-w")
            .arg(&pcap_path)
            // Ring buffer disabled: one file per scenario.
            .arg("-q");

        let child =
            ChildProcess::spawn(&format!("dumpcap-bus{bus_id}"), cmd, log_dir)
                .await
                .context("spawn dumpcap")?;

        wait_for_capture_started(&pcap_path, READY_TIMEOUT)
            .await
            .with_context(|| format!("dumpcap on {interface} never wrote to {}", pcap_path.display()))?;

        Ok(Self {
            pcap_path,
            bus_id,
            child,
        })
    }

    pub async fn stop(self) -> Result<PathBuf> {
        let _status = self.child.shutdown().await?;
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
