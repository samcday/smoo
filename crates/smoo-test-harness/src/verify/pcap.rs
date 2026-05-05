//! Wire-level assertions via `tshark` + `tools/wireshark/smoo.lua`.
//!
//! After a scenario stops capture, [`PcapAssertions::from_pcap`] runs:
//!
//! ```sh
//! tshark -X lua_script:tools/wireshark/smoo.lua -r <pcap> -T fields \
//!   -e frame.number \
//!   -e smoo.request.op -e smoo.request.export_id -e smoo.request.request_id \
//!   -e smoo.response.op -e smoo.response.export_id -e smoo.response.request_id \
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

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::fs;
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
    peak_inflight: u32,
}

pub struct PcapAssertions {
    summary: Summary,
    pcap_path: PathBuf,
}

const TSHARK_COLUMNS: &[&str] = &[
    // Keep the original summary columns first; summarize() depends on this
    // order and older unit-test fixtures intentionally omit the appended
    // diagnostics columns.
    "frame.number",
    "smoo.request.op",
    "smoo.request.export_id",
    "smoo.request.request_id",
    "smoo.response.op",
    "smoo.response.export_id",
    "smoo.response.request_id",
    "smoo.bulk.dir",
    "smoo.bulk.len_mismatch",
    "smoo.bulk.orphan",
    "smoo.config.export_id",
    // Extra fields persisted to capture.smoo.tsv for post-failure triage.
    "frame.time_epoch",
    "usb.bus_id",
    "usb.device_address",
    "usb.endpoint_address",
    "usb.transfer_type",
    "usb.urb_type",
    "usb.data_len",
    "smoo.request.lba",
    "smoo.request.num_blocks",
    "smoo.request.flags",
    "smoo.response.status",
    "smoo.response.lba",
    "smoo.response.num_blocks",
    "smoo.response.flags",
    "smoo.bulk.export_id",
    "smoo.bulk.request_id",
    "smoo.bulk.lba",
    "smoo.bulk.num_blocks",
    "smoo.bulk.expected_len",
    "smoo.bulk.actual_len",
];

const COL_FRAME_NO: usize = 0;
const COL_REQ_OP: usize = 1;
const COL_REQ_EXPORT_ID: usize = 2;
const COL_REQ_REQUEST_ID: usize = 3;
const COL_RESP_OP: usize = 4;
const COL_RESP_EXPORT_ID: usize = 5;
const COL_RESP_REQUEST_ID: usize = 6;
const COL_BULK_DIR: usize = 7;
const COL_LEN_MISMATCH: usize = 8;
const COL_ORPHAN: usize = 9;
const COL_CONFIG_EXPORT_ID: usize = 10;
const COL_TIME_EPOCH: usize = 11;
const COL_USB_BUS_ID: usize = 12;
const COL_USB_DEVICE_ADDRESS: usize = 13;
const COL_USB_ENDPOINT_ADDRESS: usize = 14;
const COL_USB_TRANSFER_TYPE: usize = 15;
const COL_USB_URB_TYPE: usize = 16;
const COL_USB_DATA_LEN: usize = 17;
const COL_REQ_LBA: usize = 18;
const COL_REQ_BLOCKS: usize = 19;
const COL_REQ_FLAGS: usize = 20;
const COL_RESP_STATUS: usize = 21;
const COL_RESP_LBA: usize = 22;
const COL_RESP_BLOCKS: usize = 23;
const COL_RESP_FLAGS: usize = 24;

impl PcapAssertions {
    pub async fn from_pcap(pcap: &Path, lua: &Path) -> Result<Self> {
        let mut cmd = build_tshark_command();
        cmd.arg("-X")
            .arg(format!("lua_script:{}", lua.display()))
            .arg("-r")
            .arg(pcap)
            .arg("-T")
            .arg("fields");
        for column in TSHARK_COLUMNS {
            cmd.arg("-e").arg(column);
        }
        cmd.arg("-Y").arg("smoo");
        let output = cmd.output().await.context("spawn tshark")?;
        if !output.status.success() {
            bail!(
                "tshark failed (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let tsv = std::str::from_utf8(&output.stdout).context("tshark output not utf-8")?;
        write_pcap_diagnostics(pcap, tsv);
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

    /// Maximum number of `(export_id, request_id)` pairs observed in flight at
    /// any point during the capture. Computed by walking smoo frames in
    /// capture order, inserting on request frames and removing on response
    /// frames. Zero if no smoo traffic was captured.
    ///
    /// A peak ≥ 2 is direct wire-level evidence that pipelining occurred.
    pub fn peak_inflight(&self) -> u32 {
        self.summary.peak_inflight
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
                "more responses than requests: {} requests, {} responses (diagnostics: {})",
                s.requests,
                s.responses,
                diagnostics_path(&self.pcap_path).display()
            );
        }
        let unanswered = s.requests - s.responses;
        if unanswered > tolerated_in_flight {
            bail!(
                "request/response imbalance: {} requests, {} responses ({} unanswered, tolerance {}, diagnostics: {})",
                s.requests,
                s.responses,
                unanswered,
                tolerated_in_flight,
                diagnostics_path(&self.pcap_path).display()
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

fn write_pcap_diagnostics(pcap: &Path, tsv: &str) {
    let columns = format!("{}\n", TSHARK_COLUMNS.join("\n"));
    let diagnostics = build_diagnostic_report(tsv);
    for (path, contents) in [
        (pcap.with_extension("smoo.tsv"), tsv.to_string()),
        (pcap.with_extension("smoo-columns.txt"), columns),
        (diagnostics_path(pcap), diagnostics.report),
        (
            pcap.with_extension("smoo-anomaly-context.tsv"),
            diagnostics.context_tsv,
        ),
    ] {
        if let Err(err) = fs::write(&path, contents) {
            tracing::warn!(?err, path = %path.display(), "write pcap diagnostic artifact failed");
        }
    }
}

fn diagnostics_path(pcap: &Path) -> PathBuf {
    pcap.with_extension("smoo-anomalies.txt")
}

#[derive(Clone, Debug, Default)]
struct DiagnosticReport {
    report: String,
    context_tsv: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct MessageTuple {
    op: String,
    export_id: String,
    request_id: String,
    lba: String,
    blocks: String,
    flags: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct RequestKey {
    export_id: String,
    request_id: String,
}

#[derive(Clone, Debug)]
struct FrameRef {
    frame_no: u64,
    time_epoch: String,
    bus_id: String,
    device_address: String,
    endpoint: String,
    transfer_type: String,
    urb_type: String,
    data_len: String,
    status: Option<String>,
}

fn build_diagnostic_report(tsv: &str) -> DiagnosticReport {
    let mut request_tuples: BTreeMap<MessageTuple, Vec<FrameRef>> = BTreeMap::new();
    let mut response_tuples: BTreeMap<MessageTuple, Vec<FrameRef>> = BTreeMap::new();
    let mut request_keys: BTreeMap<RequestKey, Vec<FrameRef>> = BTreeMap::new();
    let mut response_keys: BTreeMap<RequestKey, Vec<FrameRef>> = BTreeMap::new();
    let mut anomaly_frames = BTreeSet::new();

    for line in tsv.lines() {
        if line.is_empty() {
            continue;
        }
        let cols: Vec<_> = line.split('\t').collect();
        let frame = frame_ref(&cols, None);

        if !col(&cols, COL_REQ_OP).is_empty() {
            let tuple = MessageTuple {
                op: col(&cols, COL_REQ_OP).to_string(),
                export_id: col(&cols, COL_REQ_EXPORT_ID).to_string(),
                request_id: col(&cols, COL_REQ_REQUEST_ID).to_string(),
                lba: col(&cols, COL_REQ_LBA).to_string(),
                blocks: col(&cols, COL_REQ_BLOCKS).to_string(),
                flags: col(&cols, COL_REQ_FLAGS).to_string(),
            };
            let key = RequestKey {
                export_id: tuple.export_id.clone(),
                request_id: tuple.request_id.clone(),
            };
            request_tuples.entry(tuple).or_default().push(frame.clone());
            request_keys.entry(key).or_default().push(frame.clone());
        }

        if !col(&cols, COL_RESP_OP).is_empty() {
            let tuple = MessageTuple {
                op: col(&cols, COL_RESP_OP).to_string(),
                export_id: col(&cols, COL_RESP_EXPORT_ID).to_string(),
                request_id: col(&cols, COL_RESP_REQUEST_ID).to_string(),
                lba: col(&cols, COL_RESP_LBA).to_string(),
                blocks: col(&cols, COL_RESP_BLOCKS).to_string(),
                flags: col(&cols, COL_RESP_FLAGS).to_string(),
            };
            let key = RequestKey {
                export_id: tuple.export_id.clone(),
                request_id: tuple.request_id.clone(),
            };
            let frame = frame_ref(&cols, Some(col(&cols, COL_RESP_STATUS).to_string()));
            response_tuples
                .entry(tuple)
                .or_default()
                .push(frame.clone());
            response_keys.entry(key).or_default().push(frame);
        }
    }

    let summary = summarize(tsv);

    let mut report = String::new();
    writeln!(
        report,
        "counts: smoo_frames={} requests={} responses={} bulk_in={} bulk_out={} config_exports={} peak_inflight={}",
        summary.smoo_frame_count,
        summary.requests,
        summary.responses,
        summary.bulk_in,
        summary.bulk_out,
        summary.config_exports_count,
        summary.peak_inflight,
    )
    .ok();
    writeln!(report).ok();

    append_tuple_imbalances(
        &mut report,
        &request_tuples,
        &response_tuples,
        &mut anomaly_frames,
    );
    append_key_imbalances(
        &mut report,
        &request_keys,
        &response_keys,
        &mut anomaly_frames,
    );
    append_flagged_frames(
        &mut report,
        "bulk length mismatch frames",
        &summary.length_mismatch_frames,
        &mut anomaly_frames,
    );
    append_flagged_frames(
        &mut report,
        "orphan bulk frames",
        &summary.orphan_frames,
        &mut anomaly_frames,
    );

    let context_tsv = build_context_tsv(tsv, &anomaly_frames);
    DiagnosticReport {
        report,
        context_tsv,
    }
}

fn append_tuple_imbalances(
    report: &mut String,
    requests: &BTreeMap<MessageTuple, Vec<FrameRef>>,
    responses: &BTreeMap<MessageTuple, Vec<FrameRef>>,
    anomaly_frames: &mut BTreeSet<u64>,
) {
    let mut keys: BTreeSet<MessageTuple> = requests.keys().cloned().collect();
    keys.extend(responses.keys().cloned());

    writeln!(report, "exact request/response tuple imbalances:").ok();
    let mut count = 0usize;
    for tuple in keys {
        let req_frames = requests.get(&tuple).map(Vec::as_slice).unwrap_or(&[]);
        let resp_frames = responses.get(&tuple).map(Vec::as_slice).unwrap_or(&[]);
        if req_frames.len() == resp_frames.len() {
            continue;
        }
        count += 1;
        for frame in req_frames.iter().chain(resp_frames.iter()) {
            anomaly_frames.insert(frame.frame_no);
        }
        writeln!(
            report,
            "  op={} export_id={} request_id={} lba={} blocks={} flags={} requests={} responses={}",
            tuple.op,
            tuple.export_id,
            tuple.request_id,
            tuple.lba,
            tuple.blocks,
            tuple.flags,
            req_frames.len(),
            resp_frames.len(),
        )
        .ok();
        append_frame_refs(report, "request frames", req_frames);
        append_frame_refs(report, "response frames", resp_frames);
    }
    if count == 0 {
        writeln!(report, "  none").ok();
    }
    writeln!(report).ok();
}

fn append_key_imbalances(
    report: &mut String,
    requests: &BTreeMap<RequestKey, Vec<FrameRef>>,
    responses: &BTreeMap<RequestKey, Vec<FrameRef>>,
    anomaly_frames: &mut BTreeSet<u64>,
) {
    let mut keys: BTreeSet<RequestKey> = requests.keys().cloned().collect();
    keys.extend(responses.keys().cloned());

    writeln!(report, "request-id key imbalances:").ok();
    let mut count = 0usize;
    for key in keys {
        let req_frames = requests.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        let resp_frames = responses.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        if req_frames.len() == resp_frames.len() {
            continue;
        }
        count += 1;
        for frame in req_frames.iter().chain(resp_frames.iter()) {
            anomaly_frames.insert(frame.frame_no);
        }
        writeln!(
            report,
            "  export_id={} request_id={} requests={} responses={}",
            key.export_id,
            key.request_id,
            req_frames.len(),
            resp_frames.len(),
        )
        .ok();
        append_frame_refs(report, "request frames", req_frames);
        append_frame_refs(report, "response frames", resp_frames);
    }
    if count == 0 {
        writeln!(report, "  none").ok();
    }
    writeln!(report).ok();
}

fn append_flagged_frames(
    report: &mut String,
    label: &str,
    frames: &[u64],
    anomaly_frames: &mut BTreeSet<u64>,
) {
    writeln!(report, "{label}:").ok();
    if frames.is_empty() {
        writeln!(report, "  none").ok();
        writeln!(report).ok();
        return;
    }
    for frame in frames {
        anomaly_frames.insert(*frame);
    }
    writeln!(report, "  {frames:?}").ok();
    writeln!(report).ok();
}

fn append_frame_refs(report: &mut String, label: &str, frames: &[FrameRef]) {
    write!(report, "    {label}:").ok();
    if frames.is_empty() {
        writeln!(report, " none").ok();
        return;
    }
    for frame in frames.iter().take(24) {
        write!(
            report,
            " {}@{} bus={} dev={} ep={} xfer={} urb={} len={}",
            frame.frame_no,
            frame.time_epoch,
            frame.bus_id,
            frame.device_address,
            frame.endpoint,
            frame.transfer_type,
            frame.urb_type,
            frame.data_len,
        )
        .ok();
        if let Some(status) = &frame.status {
            write!(report, " status={status}").ok();
        }
        write!(report, ";").ok();
    }
    if frames.len() > 24 {
        write!(report, " ... +{} more", frames.len() - 24).ok();
    }
    writeln!(report).ok();
}

fn build_context_tsv(tsv: &str, anomaly_frames: &BTreeSet<u64>) -> String {
    let mut context_frames = BTreeSet::new();
    for frame in anomaly_frames {
        let start = frame.saturating_sub(8);
        let end = frame.saturating_add(8);
        for context_frame in start..=end {
            context_frames.insert(context_frame);
        }
    }

    let mut out = String::new();
    writeln!(out, "{}", TSHARK_COLUMNS.join("\t")).ok();
    for line in tsv.lines() {
        let cols: Vec<_> = line.split('\t').collect();
        if let Some(frame) = parse_u64(col(&cols, COL_FRAME_NO))
            && context_frames.contains(&frame)
        {
            writeln!(out, "{line}").ok();
        }
    }
    out
}

fn frame_ref(cols: &[&str], status: Option<String>) -> FrameRef {
    FrameRef {
        frame_no: parse_u64(col(cols, COL_FRAME_NO)).unwrap_or(0),
        time_epoch: col(cols, COL_TIME_EPOCH).to_string(),
        bus_id: col(cols, COL_USB_BUS_ID).to_string(),
        device_address: col(cols, COL_USB_DEVICE_ADDRESS).to_string(),
        endpoint: col(cols, COL_USB_ENDPOINT_ADDRESS).to_string(),
        transfer_type: col(cols, COL_USB_TRANSFER_TYPE).to_string(),
        urb_type: col(cols, COL_USB_URB_TYPE).to_string(),
        data_len: col(cols, COL_USB_DATA_LEN).to_string(),
        status,
    }
}

fn col<'a>(cols: &'a [&'a str], index: usize) -> &'a str {
    cols.get(index).copied().unwrap_or("")
}

fn parse_u64(value: &str) -> Option<u64> {
    value.parse().ok()
}

/// Parse tshark's tab-separated `-T fields` output. Column order must match
/// the `-e` flags in [`PcapAssertions::from_pcap`]: frame.number,
/// smoo.request.op, smoo.request.export_id, smoo.request.request_id,
/// smoo.response.op, smoo.response.export_id, smoo.response.request_id,
/// smoo.bulk.dir, smoo.bulk.len_mismatch, smoo.bulk.orphan,
/// smoo.config.export_id.
/// Empty cells indicate the field was absent on that frame.
fn summarize(tsv: &str) -> Summary {
    let mut s = Summary::default();
    let mut inflight: HashSet<(u64, u64)> = HashSet::new();

    for line in tsv.lines() {
        if line.is_empty() {
            continue;
        }
        let cols: Vec<_> = line.split('\t').collect();
        let frame_no = parse_u64(col(&cols, COL_FRAME_NO)).unwrap_or(0);
        let req = col(&cols, COL_REQ_OP);
        let req_export_id = col(&cols, COL_REQ_EXPORT_ID);
        let req_request_id = col(&cols, COL_REQ_REQUEST_ID);
        let resp = col(&cols, COL_RESP_OP);
        let resp_export_id = col(&cols, COL_RESP_EXPORT_ID);
        let resp_request_id = col(&cols, COL_RESP_REQUEST_ID);
        let bulk_dir = col(&cols, COL_BULK_DIR);
        let len_mismatch = col(&cols, COL_LEN_MISMATCH);
        let orphan = col(&cols, COL_ORPHAN);
        let export_id = col(&cols, COL_CONFIG_EXPORT_ID);

        s.smoo_frame_count += 1;
        if !req.is_empty() {
            s.requests += 1;
            if let Some(key) = request_key(req_export_id, req_request_id) {
                inflight.insert(key);
                s.peak_inflight = s.peak_inflight.max(inflight.len() as u32);
            }
        }
        if !resp.is_empty() {
            s.responses += 1;
            if let Some(key) = request_key(resp_export_id, resp_request_id) {
                inflight.remove(&key);
            }
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

fn request_key(export_id: &str, request_id: &str) -> Option<(u64, u64)> {
    Some((export_id.parse().ok()?, request_id.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Column order: frame.number, request.op, request.export_id,
    // request.request_id, response.op, response.export_id,
    // response.request_id, bulk.dir, len_mismatch, orphan,
    // config.export_id. Tab-separated, empty cells mean field-absent.

    #[test]
    fn summarize_empty_returns_zero() {
        let s = summarize("");
        assert_eq!(s.smoo_frame_count, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn summarize_counts_requests_and_responses() {
        let tsv = format!(
            "{}{}{}",
            request_line(1, 0, 1),
            response_line(2, 0, 1),
            "3\t\t\t\t\t\t\twrite\t\t\t\n"
        );
        let s = summarize(&tsv);
        assert_eq!(s.smoo_frame_count, 3);
        assert_eq!(s.requests, 1);
        assert_eq!(s.responses, 1);
        assert_eq!(s.bulk_in, 1);
        assert_eq!(s.bulk_out, 0);
        assert!(s.length_mismatch_frames.is_empty());
    }

    #[test]
    fn peak_inflight_zero_when_no_smoo() {
        let s = summarize("");
        assert_eq!(s.peak_inflight, 0);
    }

    #[test]
    fn peak_inflight_sequential_is_one() {
        // req(0,1) → resp(0,1) → req(0,2) → resp(0,2): never more than 1 open.
        let tsv = format!(
            "{}{}{}{}",
            request_line(1, 0, 1),
            response_line(2, 0, 1),
            request_line(3, 0, 2),
            response_line(4, 0, 2)
        );
        let s = summarize(&tsv);
        assert_eq!(s.peak_inflight, 1);
    }

    #[test]
    fn peak_inflight_three_overlapping_is_three() {
        // Three requests open before any response → peak 3, even though pairs
        // come back interleaved afterwards.
        let tsv = format!(
            "{}{}{}{}{}{}",
            request_line(1, 0, 1),
            request_line(2, 0, 2),
            request_line(3, 1, 1),
            response_line(4, 0, 2),
            response_line(5, 0, 1),
            response_line(6, 1, 1)
        );
        let s = summarize(&tsv);
        assert_eq!(s.peak_inflight, 3);
    }

    fn request_line(frame_no: u64, export_id: u64, request_id: u64) -> String {
        format!("{frame_no}\t0\t{export_id}\t{request_id}\t\t\t\t\t\t\t\n")
    }

    fn response_line(frame_no: u64, export_id: u64, request_id: u64) -> String {
        format!("{frame_no}\t\t\t\t0\t{export_id}\t{request_id}\t\t\t\t\n")
    }

    #[test]
    fn summarize_flags_mismatch_and_orphan() {
        let tsv = "5\t\t\t\t\t\t\tread\t1\t\t\n\
                   7\t\t\t\t\t\t\twrite\t\t1\t\n";
        let s = summarize(tsv);
        assert_eq!(s.length_mismatch_frames, vec![5]);
        assert_eq!(s.orphan_frames, vec![7]);
    }
}
