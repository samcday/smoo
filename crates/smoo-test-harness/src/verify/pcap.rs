//! Wire-level assertions via `tshark` + `tools/wireshark/smoo.lua`.
//!
//! After a scenario stops capture, [`PcapAssertions::from_pcap`] runs:
//!
//! ```sh
//! tshark -X lua_script:tools/wireshark/smoo.lua -r <pcap> -T fields \
//!   -e frame.number -e smoo.request.op -e smoo.response.op \
//!   -e smoo.bulk.dir -e smoo.bulk.len_mismatch -e smoo.bulk.orphan \
//!   -e smoo.config.export_id -Y smoo
//! ```
//!
//! The dissector only emits `smoo.bulk.len_mismatch` and `smoo.bulk.orphan`
//! when the corresponding condition fires (see
//! `tools/wireshark/smoo.lua:253-260`), so we key on *field presence*
//! (non-empty TSV cell) — independent of how tshark serialises a boolean
//! ProtoField. tshark's default field separator is `\t` and absent fields
//! render as empty strings, which is the signal we want.
//!
//! ## Privilege drop
//!
//! tshark refuses to load Lua scripts when running as uid 0 — the postdissector
//! never registers, and `-Y "smoo"` then fails with "not a valid protocol".
//! When the harness is invoked under sudo (typical: `cargo xtask integration`
//! shells out to `sudo cargo test`), we honour `$SUDO_USER` and re-exec
//! tshark via `sudo -u <user>`. The pcap file is created world-readable by
//! [`crate::capture`], and the artifact dir lives under `target/` which is
//! traversable by the original user, so the dropped-privilege tshark can read
//! it without further chown gymnastics.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

#[derive(Debug, Clone, Copy, Default)]
pub struct OpMix {
    pub requests: u64,
    pub responses: u64,
    pub bulk_in: u64,
    pub bulk_out: u64,
}

#[derive(Debug, Default, Clone)]
struct Summary {
    requests: u64,
    responses: u64,
    bulk_in: u64,
    bulk_out: u64,
    config_exports_count: u64,
    length_mismatch_frames: Vec<u64>,
    orphan_frames: Vec<u64>,
    smoo_frame_count: u64,
}

pub struct PcapAssertions {
    summary: Summary,
    pcap_path: PathBuf,
}

impl PcapAssertions {
    pub async fn from_pcap(pcap: &Path, lua: &Path) -> Result<Self> {
        let mut cmd = build_tshark_command();
        cmd.arg("-X")
            .arg(format!("lua_script:{}", lua.display()))
            .arg("-r")
            .arg(pcap)
            .arg("-T")
            .arg("fields")
            .arg("-e")
            .arg("frame.number")
            .arg("-e")
            .arg("smoo.request.op")
            .arg("-e")
            .arg("smoo.response.op")
            .arg("-e")
            .arg("smoo.bulk.dir")
            .arg("-e")
            .arg("smoo.bulk.len_mismatch")
            .arg("-e")
            .arg("smoo.bulk.orphan")
            .arg("-e")
            .arg("smoo.config.export_id")
            .arg("-Y")
            .arg("smoo");
        let output = cmd.output().await.context("spawn tshark")?;
        if !output.status.success() {
            bail!(
                "tshark failed (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let tsv = std::str::from_utf8(&output.stdout).context("tshark output not utf-8")?;
        let summary = summarize(tsv);
        Ok(Self {
            summary,
            pcap_path: pcap.to_path_buf(),
        })
    }

    pub fn op_counts(&self) -> OpMix {
        OpMix {
            requests: self.summary.requests,
            responses: self.summary.responses,
            bulk_in: self.summary.bulk_in,
            bulk_out: self.summary.bulk_out,
        }
    }

    pub fn smoo_frame_count(&self) -> u64 {
        self.summary.smoo_frame_count
    }

    pub fn config_exports_count(&self) -> u64 {
        self.summary.config_exports_count
    }

    pub fn pcap_path(&self) -> &Path {
        &self.pcap_path
    }

    pub fn assert_no_length_mismatch(&self) -> Result<()> {
        if !self.summary.length_mismatch_frames.is_empty() {
            bail!(
                "{} bulk length mismatches in {} (frames: {:?})",
                self.summary.length_mismatch_frames.len(),
                self.pcap_path.display(),
                self.summary.length_mismatch_frames
            );
        }
        Ok(())
    }

    pub fn assert_no_orphan_bulk(&self) -> Result<()> {
        if !self.summary.orphan_frames.is_empty() {
            bail!(
                "{} orphan bulk transfers in {} (frames: {:?})",
                self.summary.orphan_frames.len(),
                self.pcap_path.display(),
                self.summary.orphan_frames
            );
        }
        Ok(())
    }

    /// Allow up to `tolerated_in_flight` unanswered requests at the tail of
    /// the capture — those represent ublk requests that were issued just
    /// before SIGTERM and never got a response. With ublk read-ahead, even a
    /// "single block read" scenario can have 1+ in-flight at teardown. Set
    /// this to your effective queue depth.
    pub fn assert_request_response_balanced(&self, tolerated_in_flight: u64) -> Result<()> {
        let s = &self.summary;
        if s.responses > s.requests {
            bail!(
                "more responses than requests: {} requests, {} responses",
                s.requests,
                s.responses
            );
        }
        let unanswered = s.requests - s.responses;
        if unanswered > tolerated_in_flight {
            bail!(
                "request/response imbalance: {} requests, {} responses ({} unanswered, tolerance {})",
                s.requests,
                s.responses,
                unanswered,
                tolerated_in_flight
            );
        }
        Ok(())
    }
}

/// Build a `tshark` Command, dropping privileges to `$SUDO_USER` if we're
/// running under sudo. tshark silently disables Lua scripts when uid==0; the
/// smoo postdissector then never registers and `-Y "smoo"` errors out.
fn build_tshark_command() -> Command {
    if unsafe { libc::geteuid() } == 0
        && let Ok(user) = std::env::var("SUDO_USER")
        && !user.is_empty()
        && user != "root"
    {
        let mut cmd = Command::new("sudo");
        cmd.arg("-u").arg(user).arg("--").arg("tshark");
        return cmd;
    }
    Command::new("tshark")
}

/// Parse tshark's tab-separated `-T fields` output. Column order must match
/// the `-e` flags in [`PcapAssertions::from_pcap`]: frame.number,
/// smoo.request.op, smoo.response.op, smoo.bulk.dir,
/// smoo.bulk.len_mismatch, smoo.bulk.orphan, smoo.config.export_id.
/// Empty cells indicate the field was absent on that frame.
fn summarize(tsv: &str) -> Summary {
    let mut s = Summary::default();
    for line in tsv.lines() {
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let frame_no = cols.next().and_then(|c| c.parse::<u64>().ok()).unwrap_or(0);
        let req = cols.next().unwrap_or("");
        let resp = cols.next().unwrap_or("");
        let bulk_dir = cols.next().unwrap_or("");
        let len_mismatch = cols.next().unwrap_or("");
        let orphan = cols.next().unwrap_or("");
        let export_id = cols.next().unwrap_or("");

        s.smoo_frame_count += 1;
        if !req.is_empty() {
            s.requests += 1;
        }
        if !resp.is_empty() {
            s.responses += 1;
        }
        // Dissector labels: bulk_out endpoint == "read" (host→gadget,
        // read-response payload); bulk_in endpoint == "write" (gadget→host,
        // write-data payload). Map back to wire direction.
        match bulk_dir {
            "read" => s.bulk_out += 1,
            "write" => s.bulk_in += 1,
            _ => {}
        }
        if !len_mismatch.is_empty() {
            s.length_mismatch_frames.push(frame_no);
        }
        if !orphan.is_empty() {
            s.orphan_frames.push(frame_no);
        }
        if !export_id.is_empty() {
            s.config_exports_count += 1;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Column order: frame.number, request.op, response.op, bulk.dir,
    // len_mismatch, orphan, config.export_id. Tab-separated, empty cells
    // mean field-absent.

    #[test]
    fn summarize_empty_returns_zero() {
        let s = summarize("");
        assert_eq!(s.smoo_frame_count, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn summarize_counts_requests_and_responses() {
        let tsv = "1\t0\t\t\t\t\t\n\
                   2\t\t0\t\t\t\t\n\
                   3\t\t\twrite\t\t\t\n";
        let s = summarize(tsv);
        assert_eq!(s.smoo_frame_count, 3);
        assert_eq!(s.requests, 1);
        assert_eq!(s.responses, 1);
        assert_eq!(s.bulk_in, 1);
        assert_eq!(s.bulk_out, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn summarize_flags_mismatch_and_orphan() {
        let tsv = "5\t\t\tread\t1\t\t\n\
                   7\t\t\twrite\t\t1\t\n";
        let s = summarize(tsv);
        assert_eq!(s.length_mismatch_frames, vec![5]);
        assert_eq!(s.orphan_frames, vec![7]);
    }
}
