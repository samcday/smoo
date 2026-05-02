//! Reproduces shutdown while host-side I/O is unavailable.
//!
//! The host is intentionally terminated before the gadget. If the gadget is
//! awaiting a response for ublk read-ahead, shutdown must still preempt that
//! data-plane wait and remove the ublk device instead of waiting until the
//! harness SIGKILL fallback fires.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use smoo_test_harness::{BlockPatternVerifier, ExportSpec, ScenarioBuilder};

const SEED: u64 = 0xDEAD;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u64 = 1024; // 4 MiB

#[tokio::test(flavor = "multi_thread")]
#[ignore = "known-broken shutdown scenario; keep for reproducing host-loss shutdown behavior"]
async fn gadget_shutdown_preempts_in_flight_io_after_host_loss() -> Result<()> {
    common::init_tracing();

    let sc = ScenarioBuilder::new("shutdown_host_loss")
        .with_export(ExportSpec::random(BLOCK_SIZE, TOTAL_BLOCKS, SEED))
        .with_block_size(BLOCK_SIZE)
        .start()
        .await?;

    let dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(15))
        .await?;
    let dev_path = PathBuf::from(format!("/dev/ublkb{dev_id}"));
    common::wait_for_block_device(&dev_path, Duration::from_secs(5)).await?;

    let verifier = BlockPatternVerifier::new(SEED, BLOCK_SIZE, TOTAL_BLOCKS)?;
    verifier.verify_device_read(&dev_path, 0, 1).await?;

    let result = sc.stop_host_then_gadget().await?;
    result.assert(true, false).await?;
    Ok(())
}
