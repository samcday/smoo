//! Scenario 3: pipelining stress.
//!
//! Two file-backed exports (so both halves' multi-export concurrency is
//! exercised), `queue_count=2 queue_depth=16` on the gadget, and concurrent
//! fio mixed-RW workloads against both ublk devices simultaneously.
//!
//! The intent is to put genuine pressure on:
//!
//! * the gadget's in-flight registry and bulk FIFOs (multiple Requests open
//!   per export across both queues),
//! * the host's `FuturesUnordered` dispatcher (multiple BlockSourceHandles
//!   serving in parallel — single-export tests never engage this code path),
//! * the bulk-OUT / bulk-IN ordering invariants under naturally interleaved
//!   completions (mixed read/write at depth 16 across two devices).
//!
//! A peak in-flight ≥ 8 on the wire is the gate: anything serialised would
//! never get there.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use smoo_test_harness::ScenarioBuilder;
use smoo_test_harness::fixture::{GadgetOpts, HostSourceSpec};
use smoo_test_harness::scenario::run_tool;
use tokio::process::Command;

const BLOCK_SIZE: u32 = 4096;
const FILE_SIZE: u64 = 16 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread")]
async fn pipelined_io() -> Result<()> {
    common::init_tracing();

    let backing_tmp = tempfile::tempdir().context("backing tempdir")?;
    let backing_a = backing_tmp.path().join("a.img");
    let backing_b = backing_tmp.path().join("b.img");
    for path in [&backing_a, &backing_b] {
        let f = std::fs::File::create(path)
            .with_context(|| format!("create backing file {}", path.display()))?;
        f.set_len(FILE_SIZE)
            .with_context(|| format!("size backing file {}", path.display()))?;
    }

    let sc = ScenarioBuilder::new("pipelined_io")
        .with_host_source(HostSourceSpec::File(backing_a.clone()))
        .with_host_source(HostSourceSpec::File(backing_b.clone()))
        .with_block_size(BLOCK_SIZE)
        .with_gadget_opts(GadgetOpts {
            queue_count: 2,
            queue_depth: 16,
            ..GadgetOpts::default()
        })
        .start()
        .await?;

    let dev_ids = sc
        .gadget()
        .wait_for_ublk_dev_ids(2, Duration::from_secs(20))
        .await?;
    let dev_paths: Vec<PathBuf> = dev_ids
        .iter()
        .map(|id| PathBuf::from(format!("/dev/ublkb{id}")))
        .collect();
    for p in &dev_paths {
        common::wait_for_block_device(p, Duration::from_secs(5)).await?;
    }

    let tmp = tempfile::tempdir().context("tempdir")?;
    let cwd_a = tmp.path().join("a");
    let cwd_b = tmp.path().join("b");

    // Spawn fio against both devices concurrently. tokio::join! drives both
    // futures to completion regardless of ordering.
    let fio_a = run_fio(&sc, &cwd_a, &dev_paths[0], "fio-a");
    let fio_b = run_fio(&sc, &cwd_b, &dev_paths[1], "fio-b");
    let (status_a, status_b) = tokio::join!(fio_a, fio_b);
    let status_a = status_a?;
    let status_b = status_b?;
    ensure!(
        status_a.success(),
        "fio against {:?} exited {status_a:?}",
        dev_paths[0]
    );
    ensure!(
        status_b.success(),
        "fio against {:?} exited {status_b:?}",
        dev_paths[1]
    );

    let result = sc.stop().await?;
    if let Some(pcap) = result.pcap_assertions().await? {
        let peak = pcap.peak_inflight();
        ensure!(
            peak >= 8,
            "pipelined_io expected peak_inflight >= 8 (two exports x iodepth=16 \
             = 32 theoretical), got {peak} — pipelining likely regressed"
        );
    }
    result.assert_clean().await?;
    Ok(())
}

async fn run_fio(
    sc: &smoo_test_harness::scenario::RunningScenario,
    cwd: &std::path::Path,
    dev_path: &std::path::Path,
    name: &str,
) -> Result<std::process::ExitStatus> {
    std::fs::create_dir_all(cwd).context("create fio cwd")?;
    let mut cmd = Command::new("fio");
    cmd.current_dir(cwd) // verify-state lands here, not the workspace
        .arg(format!("--filename={}", dev_path.display()))
        .arg(format!("--name={name}"))
        .arg("--rw=randrw")
        .arg("--rwmixread=70")
        .arg("--bs=4k")
        .arg("--io_size=8M")
        .arg("--numjobs=2")
        .arg("--iodepth=16")
        .arg("--ioengine=libaio")
        .arg("--direct=1")
        .arg("--group_reporting=1")
        .arg("--time_based=0");
    run_tool(sc, name, cmd)
        .await
        .with_context(|| format!("run {name}"))
}
