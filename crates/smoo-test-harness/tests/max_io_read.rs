//! Regression: large fio reads through a random host source with ublk max_io
//! above the FunctionFS exact-AIO chunk size.
//!
//! This exercises the READ path (host -> gadget bulk OUT) with multi-chunk
//! FunctionFS endpoint reads. A lost AIO eventfd wakeup used to hang this path
//! as soon as `max_io` exceeded 16 KiB.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use smoo_test_harness::fixture::GadgetOpts;
use smoo_test_harness::scenario::run_tool;
use smoo_test_harness::{ExportSpec, ScenarioBuilder};
use tokio::process::Command;

const SEED: u64 = 0xBEEF;
const BLOCK_SIZE: u32 = 512;
const TOTAL_BLOCKS: u64 = 102_400;
const MAX_IO_BYTES: u64 = 32 * 1024;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn max_io_read() -> Result<()> {
    common::init_tracing();

    let tmp = tempfile::tempdir().context("tempdir")?;
    let sc = ScenarioBuilder::new("max_io_read")
        .with_export(ExportSpec::random(BLOCK_SIZE, TOTAL_BLOCKS, SEED))
        .with_block_size(BLOCK_SIZE)
        .with_gadget_opts(GadgetOpts {
            queue_count: 2,
            queue_depth: 16,
            max_io_bytes: Some(MAX_IO_BYTES),
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
    cmd.current_dir(tmp.path())
        .arg(format!("--filename={}", dev_path.display()))
        .arg("--name=max-io-read")
        .arg("--rw=read")
        .arg("--bs=256K")
        .arg("--io_size=8M")
        .arg("--iodepth=16")
        .arg("--numjobs=1")
        .arg("--ioengine=libaio")
        .arg("--direct=1")
        .arg("--group_reporting=1")
        .arg("--time_based=0");

    let status = run_tool(&sc, "fio", cmd).await.context("run fio")?;
    ensure!(status.success(), "fio exited {status:?}");

    let result = sc.stop().await?;
    result.assert_clean().await?;
    Ok(())
}
