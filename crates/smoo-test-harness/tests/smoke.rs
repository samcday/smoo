//! Scenario 1: handshake + single read against a deterministic
//! `RandomBlockSource` pattern.
//!
//! Asserts: `/dev/ublkbN` appears, the first 4 KiB matches the bytes the
//! host's `RandomBlockSource(seed=0xDEAD)` would generate locally, both
//! processes exit cleanly on SIGTERM, and the pcap shows balanced
//! request/response counts with no length-mismatch / orphan bulks.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use smoo_test_harness::{BlockPatternVerifier, ExportSpec, ScenarioBuilder};

const SEED: u64 = 0xDEAD;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u64 = 1024; // 4 MiB

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn smoke() -> Result<()> {
    common::init_tracing();

    let sc = ScenarioBuilder::new("smoke")
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

    let result = sc.stop().await?;
    result.assert_clean().await?;
    Ok(())
}
