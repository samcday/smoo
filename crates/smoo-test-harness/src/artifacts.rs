//! On-failure artifact bundle: pcap + logs + metadata.json.
//!
//! A scenario's artifact directory always exists (logs are tee'd in real
//! time). On test pass, the directory contents are still useful for local
//! debugging; in CI we only upload it when the test fails.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

pub struct ArtifactBundle {
    pub root: PathBuf,
    pub scenario_name: String,
    pub started_at: Instant,
    pub started_at_unix: u64,
}

impl ArtifactBundle {
    /// Create (or wipe + recreate) `<root>/<scenario_name>/`.
    pub fn create(root: &Path, scenario_name: &str) -> Result<Self> {
        let dir = root.join(scenario_name);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("rm -rf {} for fresh run", dir.display()))?;
        }
        fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let started_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(Self {
            root: dir,
            scenario_name: scenario_name.to_string(),
            started_at: Instant::now(),
            started_at_unix,
        })
    }

    pub fn log_dir(&self) -> &Path {
        &self.root
    }

    pub fn pcap_path(&self) -> PathBuf {
        self.root.join("capture.pcapng")
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.root.join("metadata.json")
    }

    pub fn write_metadata(&self, meta: &Metadata) -> Result<()> {
        let json = serde_json::to_string_pretty(meta).context("serialise metadata")?;
        fs::write(self.metadata_path(), json)
            .with_context(|| format!("write {}", self.metadata_path().display()))?;
        Ok(())
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub scenario: String,
    pub kernel_version: String,
    pub started_at_unix: u64,
    pub elapsed_ms: u64,
    pub gadget_exit: Option<ExitInfo>,
    pub host_exit: Option<ExitInfo>,
    pub pcap_path: Option<String>,
    pub op_mix: Option<OpMixSer>,
    pub passed: bool,
    pub failure: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExitInfo {
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OpMixSer {
    pub requests: u64,
    pub responses: u64,
    pub bulk_in: u64,
    pub bulk_out: u64,
}

impl From<crate::verify::pcap::OpMix> for OpMixSer {
    fn from(m: crate::verify::pcap::OpMix) -> Self {
        Self {
            requests: m.requests,
            responses: m.responses,
            bulk_in: m.bulk_in,
            bulk_out: m.bulk_out,
        }
    }
}

/// Read the running kernel version (`uname -r` equivalent). Used to
/// stamp metadata. Returns "unknown" on any error.
pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
