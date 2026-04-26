//! Scenario 2: short fio randwrite-with-verify against a host-file-backed
//! ublk device.
//!
//! Backing: a 16 MB tmpfs file on the host side (`HostSourceSpec::File`).
//! Workload: `fio --rw=randwrite --bs=4k --io_size=8M --verify=md5 --do_verify=1
//! --numjobs=2 --iodepth=16` against a gadget configured with `queue_count=2`,
//! `queue_depth=16` — pushes the data path into pipelined territory rather
//! than the serialised default.
//!
//! Asserts: fio exits 0, both processes shut down cleanly, pcap is balanced
//! and free of length-mismatch / orphan bulks, and pipelining was actually
//! exercised on the wire (`peak_inflight >= 4`).

mod common;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use smoo_test_harness::fixture::GadgetOpts;
use smoo_test_harness::scenario::run_tool;
use smoo_test_harness::{HostSourceSpec, ScenarioBuilder};
use tokio::process::Command;

const BLOCK_SIZE: u32 = 4096;
const FILE_SIZE: u64 = 16 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn rw_modest() -> Result<()> {
    common::init_tracing();

    let tmp = tempfile::tempdir().context("tempdir")?;
    let backing = tmp.path().join("backing.img");
    {
        // Pre-allocate the file with zeros — host's FileBlockSource derives
        // total_blocks from len.
        let f = std::fs::File::create(&backing)?;
        f.set_len(FILE_SIZE)?;
    }

    let sc = ScenarioBuilder::new("rw_modest")
        .with_host_source(HostSourceSpec::File(backing.clone()))
        .with_block_size(BLOCK_SIZE)
        .with_gadget_opts(GadgetOpts {
            queue_count: 2,
            queue_depth: 16,
            ..GadgetOpts::default()
        })
        .start()
        .await?;

    let dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(15))
        .await?;
    let dev_path = PathBuf::from(format!("/dev/ublkb{dev_id}"));
    common::wait_for_block_device(&dev_path, Duration::from_secs(5)).await?;

    let mut cmd = Command::new("fio");
    cmd.current_dir(tmp.path()) // fio writes its verify-state file in CWD
        .arg(format!("--filename={}", dev_path.display()))
        .arg("--name=integrity")
        .arg("--rw=randwrite")
        .arg("--bs=4k")
        .arg("--io_size=8M")
        .arg("--numjobs=2")
        .arg("--iodepth=16")
        .arg("--ioengine=libaio")
        .arg("--direct=1")
        .arg("--verify=md5")
        .arg("--do_verify=1")
        .arg("--group_reporting=1")
        .arg("--time_based=0");

    let status = run_tool(&sc, "fio", cmd).await.context("run fio")?;
    ensure!(status.success(), "fio exited {status:?}");

    let result = sc.stop().await?;
    if let Some(pcap) = result.pcap_assertions().await? {
        let peak = pcap.peak_inflight();
        ensure!(
            peak >= 4,
            "rw_modest expected pipelined wire activity (peak_inflight >= 4), \
             got {peak} — pipelining may have regressed to serial"
        );
    }
    result.assert_clean().await?;
    Ok(())
}
