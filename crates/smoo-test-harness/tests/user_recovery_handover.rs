//! Regression: a successor smoo-gadget can adopt an existing ublk device via
//! ublk user recovery while preserving the block device identity.

mod common;

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::BlockSource;
use smoo_test_harness::ScenarioBuilder;
use smoo_test_harness::fixture::{GadgetOpts, HostSourceSpec};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const SEED: u64 = 0xAD0A7;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u64 = 1024;
const READ_LBA: u64 = 17;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn user_recovery_handover() -> Result<()> {
    common::init_tracing();

    let state_path = temp_state_path("user_recovery_handover")?;
    let state_arg = state_path.display().to_string();
    let initial_opts = GadgetOpts {
        queue_count: 1,
        queue_depth: 4,
        max_io_bytes: Some(BLOCK_SIZE as u64),
        extra_args: vec!["--state-file".to_string(), state_arg.clone()],
        readiness_timeout: Duration::from_secs(20),
        ..GadgetOpts::default()
    };

    let mut sc = ScenarioBuilder::new("user_recovery_handover")
        .with_host_source(HostSourceSpec::Random {
            blocks: TOTAL_BLOCKS,
            seed: SEED,
        })
        .with_block_size(BLOCK_SIZE)
        .with_capture(false)
        .with_gadget_opts(initial_opts.clone())
        .start()
        .await?;

    let dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(15))
        .await?;
    let dev_path = PathBuf::from(format!("/dev/ublkb{dev_id}"));
    common::wait_for_block_device(&dev_path, Duration::from_secs(5)).await?;

    let expected = expected_bytes(READ_LBA, 1).await?;
    let before = read_device_bytes(&dev_path, READ_LBA, BLOCK_SIZE as usize).await?;
    ensure_read_matches(&before, &expected)?;

    let mut adopt_opts = initial_opts;
    adopt_opts.readiness_timeout = Duration::from_secs(35);
    adopt_opts.extra_args.push("--adopt".to_string());
    adopt_opts
        .extra_args
        .extend(["--adopt-deadline".to_string(), "25s".to_string()]);
    let old_status = sc.adopt_restart_gadget(adopt_opts).await?;
    ensure!(
        old_status.success(),
        "prior gadget exited unsuccessfully: {old_status:?}"
    );

    let recovered_dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(20))
        .await?;
    ensure!(
        recovered_dev_id == dev_id,
        "handover changed ublk dev_id: before={dev_id} after={recovered_dev_id}"
    );

    let after = tokio::time::timeout(
        Duration::from_secs(30),
        read_device_bytes(&dev_path, READ_LBA, BLOCK_SIZE as usize),
    )
    .await
    .context("timed out reading device after user-recovery handover")??;
    ensure_read_matches(&after, &expected)?;

    let result = sc.stop().await?;
    // This test already verifies bytes across handover above.
    result.assert(true, false).await?;
    let _ = tokio::fs::remove_file(&state_path).await;
    Ok(())
}

fn temp_state_path(name: &str) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX_EPOCH")?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("smoo-{name}-{}-{nanos}.json", std::process::id())))
}

async fn read_device_bytes(path: &Path, lba: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let offset = lba
        .checked_mul(BLOCK_SIZE as u64)
        .context("read offset overflow")?;
    file.seek(SeekFrom::Start(offset))
        .await
        .with_context(|| format!("seek {} +{offset}", path.display()))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)
        .await
        .with_context(|| format!("read {len} bytes from {}", path.display()))?;
    Ok(buf)
}

async fn expected_bytes(lba: u64, blocks: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; (blocks * BLOCK_SIZE as u64) as usize];
    let source = RandomBlockSource::new(BLOCK_SIZE, TOTAL_BLOCKS, SEED)?;
    source
        .read_blocks(lba, &mut buf)
        .await
        .map_err(|err| anyhow::anyhow!("RandomBlockSource read_blocks: {err}"))?;
    Ok(buf)
}

fn ensure_read_matches(actual: &[u8], expected: &[u8]) -> Result<()> {
    ensure!(
        actual.len() == expected.len(),
        "read length mismatch: got {}, expected {}",
        actual.len(),
        expected.len()
    );
    if actual == expected {
        return Ok(());
    }
    let diff = actual
        .iter()
        .zip(expected.iter())
        .position(|(a, e)| a != e)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    let actual_byte = actual.get(diff).copied();
    let expected_byte = expected.get(diff).copied();
    bail!(
        "read returned wrong bytes: first diff at offset {diff} (actual={actual_byte:?} expected={expected_byte:?})"
    );
}
