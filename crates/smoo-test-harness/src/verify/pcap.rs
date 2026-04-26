//! Wire-level assertions via `tshark` + `tools/wireshark/smoo.lua`.
//!
//! After a scenario stops capture, [`PcapAssertions::from_pcap`] runs:
//!
//! ```sh
//! tshark -X lua_script:tools/wireshark/smoo.lua -r <pcap> -T json -Y "smoo"
//! ```
//!
//! and parses the result. The dissector only emits `smoo.bulk.len_mismatch`
//! and `smoo.bulk.orphan` when the corresponding condition fires (see
//! `tools/wireshark/smoo.lua:253-260`), so we use *field presence* as the
//! signal — independent of how tshark serialises a boolean ProtoField.
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
use serde_json::Value;
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
            .arg("json")
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
        let raw: Value = serde_json::from_slice(&output.stdout)
            .context("parse tshark JSON output")?;
        let summary = summarize(&raw);
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

fn summarize(raw: &Value) -> Summary {
    let mut s = Summary::default();
    let Some(arr) = raw.as_array() else {
        return s;
    };
    for entry in arr {
        let Some(layers) = entry
            .get("_source")
            .and_then(|v| v.get("layers"))
            .and_then(|v| v.as_object())
        else {
            continue;
        };
        let Some(smoo) = layers.get("smoo").and_then(|v| v.as_object()) else {
            continue;
        };
        s.smoo_frame_count += 1;

        let frame_no = layers
            .get("frame")
            .and_then(|v| v.get("frame.number"))
            .and_then(value_to_u64)
            .unwrap_or(0);

        if smoo.contains_key("smoo.request.op") {
            s.requests += 1;
        }
        if smoo.contains_key("smoo.response.op") {
            s.responses += 1;
        }
        if let Some(dir) = smoo.get("smoo.bulk.dir").and_then(|v| v.as_str()) {
            // Dissector labels: bulk_out endpoint == "read" (host-to-gadget,
            // i.e. read-response payload), bulk_in endpoint == "write".
            // For test reasoning we want the wire direction, so map back.
            match dir {
                "read" => s.bulk_out += 1, // host → gadget
                "write" => s.bulk_in += 1, // gadget → host
                _ => {}
            }
        }
        if smoo.contains_key("smoo.bulk.len_mismatch") {
            s.length_mismatch_frames.push(frame_no);
        }
        if smoo.contains_key("smoo.bulk.orphan") {
            s.orphan_frames.push(frame_no);
        }
        if smoo.contains_key("smoo.config.export_id") {
            s.config_exports_count += 1;
        }
    }
    s
}

fn value_to_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summarize_empty_returns_zero() {
        let s = summarize(&json!([]));
        assert_eq!(s.smoo_frame_count, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn summarize_counts_requests_and_responses() {
        let raw = json!([
            {
                "_source": { "layers": {
                    "frame": { "frame.number": "1" },
                    "smoo": { "smoo.request.op": "0", "smoo.request.export_id": "0" }
                }}
            },
            {
                "_source": { "layers": {
                    "frame": { "frame.number": "2" },
                    "smoo": { "smoo.response.op": "0", "smoo.response.status": "0" }
                }}
            },
            {
                "_source": { "layers": {
                    "frame": { "frame.number": "3" },
                    "smoo": { "smoo.bulk.dir": "write", "smoo.bulk.actual_len": "4096" }
                }}
            }
        ]);
        let s = summarize(&raw);
        assert_eq!(s.smoo_frame_count, 3);
        assert_eq!(s.requests, 1);
        assert_eq!(s.responses, 1);
        assert_eq!(s.bulk_in, 1);
        assert_eq!(s.bulk_out, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn summarize_flags_mismatch_and_orphan() {
        let raw = json!([
            {
                "_source": { "layers": {
                    "frame": { "frame.number": "5" },
                    "smoo": {
                        "smoo.bulk.dir": "read",
                        "smoo.bulk.actual_len": "4096",
                        "smoo.bulk.len_mismatch": "1"
                    }
                }}
            },
            {
                "_source": { "layers": {
                    "frame": { "frame.number": "7" },
                    "smoo": {
                        "smoo.bulk.dir": "write",
                        "smoo.bulk.actual_len": "8192",
                        "smoo.bulk.orphan": "1"
                    }
                }}
            }
        ]);
        let s = summarize(&raw);
        assert_eq!(s.length_mismatch_frames, vec![5]);
        assert_eq!(s.orphan_frames, vec![7]);
    }
}
