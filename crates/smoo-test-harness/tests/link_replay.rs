//! Regression: in-flight ublk I/O is parked on host/link loss and replayed
//! after the host reconnects.
//!
//! The backing source is a local HTTP server that completes probe requests but
//! intentionally stalls real range reads. This lets the test put a device read
//! in flight at a deterministic point, kill only `smoo-host`, assert the read
//! remains pending, restart the host, then release the replayed HTTP read and
//! verify the original device read completes with the expected bytes.

mod common;
#[path = "common/stalling_http.rs"]
mod stalling_http;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use smoo_test_harness::ScenarioBuilder;
use smoo_test_harness::fixture::{GadgetOpts, HostSourceSpec};
use stalling_http::{
    StallingHttpSource, assert_device_read_pending, ensure_read_matches, read_device_bytes,
};

const SEED: u64 = 0x51A7E;
const BLOCK_SIZE: u32 = 4096;
const TOTAL_BLOCKS: u64 = 1024;
const READ_LBA: u64 = 123;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn link_replay() -> Result<()> {
    common::init_tracing();

    let server = StallingHttpSource::start(BLOCK_SIZE, TOTAL_BLOCKS, SEED, READ_LBA)?;
    let mut sc = ScenarioBuilder::new("link_replay")
        .with_host_source(HostSourceSpec::Http(server.url()))
        .with_block_size(BLOCK_SIZE)
        .with_gadget_opts(GadgetOpts {
            queue_count: 1,
            queue_depth: 4,
            max_io_bytes: Some(BLOCK_SIZE as u64),
            ..GadgetOpts::default()
        })
        .start()
        .await?;

    let connected_re = Regex::new("connected to smoo gadget")?;
    sc.host()
        .wait_for_log(&connected_re, Duration::from_secs(15))
        .await?;

    let dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(15))
        .await?;
    let dev_path = PathBuf::from(format!("/dev/ublkb{dev_id}"));
    common::wait_for_block_device(&dev_path, Duration::from_secs(5)).await?;

    let expected = server.expected_bytes(READ_LBA, 1).await?;
    server.arm();
    let initial_data_requests = server.target_request_count();
    let mut read_task = tokio::spawn(read_device_bytes(
        dev_path.clone(),
        BLOCK_SIZE,
        READ_LBA,
        BLOCK_SIZE as usize,
    ));

    server
        .wait_for_data_requests(initial_data_requests + 1, Duration::from_secs(15))
        .await?;

    tracing::info!("stopping host with target read in flight");
    sc.stop_host().await?;
    let offline_re = Regex::new(
        "link liveness timeout|link transport offline|request dispatch failed|io pump task exited",
    )?;
    sc.gadget()
        .wait_for_log(&offline_re, Duration::from_secs(10))
        .await?;
    tracing::info!("gadget observed link loss; verifying device read remains parked");
    // The HTTP source still holds the backing read, so successful recovery must
    // leave the kernel read pending here rather than completing or failing it.
    assert_device_read_pending(&mut read_task, Duration::from_secs(2)).await?;

    let before_restart_data_requests = server.target_request_count();
    tracing::info!("restarting host to trigger parked request replay");
    sc.start_host().await?;
    sc.host()
        .wait_for_log(&connected_re, Duration::from_secs(20))
        .await?;
    server
        .wait_for_data_requests(before_restart_data_requests + 1, Duration::from_secs(15))
        .await?;
    tracing::info!("HTTP backing observed replayed target range; releasing reads");
    server.release();

    let actual = tokio::time::timeout(Duration::from_secs(15), &mut read_task)
        .await
        .context("timed out waiting for parked read to complete after host restart")?
        .context("device read task panicked")??;
    ensure_read_matches(&actual, &expected)?;

    let result = sc.stop().await?;
    if let Some(pcap) = result.pcap_assertions().await? {
        pcap.assert_no_length_mismatch()?;
        pcap.assert_no_orphan_bulk()?;
        pcap.assert_control_handshakes(2)?;
        ensure!(
            pcap.repeated_request_keys() >= 1,
            "link_replay expected at least one repeated request key in {}, got {}",
            pcap.pcap_path().display(),
            pcap.repeated_request_keys()
        );
    }
    // A replayed request is deliberately visible twice on the wire but has only
    // one final response, so strict request/response balance is not meaningful.
    result.assert(true, false).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn user_recovery_handover_drains_inflight_io() -> Result<()> {
    common::init_tracing();

    let server = StallingHttpSource::start(BLOCK_SIZE, TOTAL_BLOCKS, SEED, READ_LBA)?;
    let state_path = temp_state_path("user_recovery_handover_drains_inflight_io")?;
    let state_arg = state_path.display().to_string();
    let initial_opts = GadgetOpts {
        queue_count: 1,
        queue_depth: 4,
        max_io_bytes: Some(BLOCK_SIZE as u64),
        extra_args: vec!["--state-file".to_string(), state_arg.clone()],
        readiness_timeout: Duration::from_secs(20),
        ..GadgetOpts::default()
    };

    let mut sc = ScenarioBuilder::new("user_recovery_handover_drains_inflight_io")
        .with_host_source(HostSourceSpec::Http(server.url()))
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

    server.arm();
    let expected = server.expected_bytes(READ_LBA, 1).await?;
    let initial_data_requests = server.target_request_count();
    let mut read_task = tokio::spawn(read_device_bytes(
        dev_path.clone(),
        BLOCK_SIZE,
        READ_LBA,
        BLOCK_SIZE as usize,
    ));
    server
        .wait_for_data_requests(initial_data_requests + 1, Duration::from_secs(15))
        .await?;

    let mut adopt_opts = initial_opts;
    adopt_opts.readiness_timeout = Duration::from_secs(35);
    adopt_opts.extra_args.push("--adopt".to_string());
    adopt_opts
        .extra_args
        .extend(["--adopt-deadline".to_string(), "25s".to_string()]);
    let mut adopt_fut = Box::pin(sc.adopt_restart_gadget(adopt_opts));

    assert_device_read_pending(&mut read_task, Duration::from_secs(2)).await?;
    match tokio::time::timeout(Duration::from_secs(2), adopt_fut.as_mut()).await {
        Ok(Ok(status)) => bail!(
            "adopt completed while HTTP read was still stalled; prior gadget status={status:?}"
        ),
        Ok(Err(err)) => bail!("adopt failed while HTTP read was still stalled: {err:#}"),
        Err(_) => {}
    }

    server.release();
    let actual = tokio::time::timeout(Duration::from_secs(15), &mut read_task)
        .await
        .context("timed out waiting for handover read to drain")?
        .context("device read task panicked")??;
    ensure_read_matches(&actual, &expected)?;
    ensure!(
        server.target_request_count() == initial_data_requests + 1,
        "handover reissued the stalled read instead of draining it first"
    );

    let old_status = tokio::time::timeout(Duration::from_secs(20), adopt_fut.as_mut())
        .await
        .context("timed out waiting for adopting gadget to finish handover")??;
    drop(adopt_fut);
    ensure!(
        old_status.success(),
        "prior gadget exited unsuccessfully: {old_status:?}"
    );
    server.disarm();

    let recovered_dev_id = sc
        .gadget()
        .wait_for_ublk_dev_id(Duration::from_secs(20))
        .await?;
    ensure!(
        recovered_dev_id == dev_id,
        "handover changed ublk dev_id: before={dev_id} after={recovered_dev_id}"
    );
    let after_lba = READ_LBA + 1;
    let after_expected = server.expected_bytes(after_lba, 1).await?;
    let after = tokio::time::timeout(
        Duration::from_secs(30),
        read_device_bytes(dev_path, BLOCK_SIZE, after_lba, BLOCK_SIZE as usize),
    )
    .await
    .context("timed out reading device after user-recovery handover")??;
    ensure_read_matches(&after, &after_expected)?;

    let result = sc.stop().await?;
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
