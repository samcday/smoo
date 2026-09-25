//! Regression: a UDC unbind and rebind with ublk I/O in flight is survived by
//! the same `smoo-gadget` process.
//!
//! USB mode managers (usb-signaller) switch modes by unbinding the gadget's
//! UDC and binding it again while smoo-gadget keeps running. FunctionFS then
//! sees DISABLE/UNBIND and later BIND/ENABLE on the same ep0, the host sees
//! the device vanish and re-enumerate, and every read in flight must be parked
//! and replayed rather than failed.
//!
//! Each cycle holds a device read in flight at the HTTP backing source,
//! unbinds the UDC, keeps it unbound for the cycle's gap while asserting the
//! read stays parked, rebinds, waits for the reconnected host to replay the
//! read, releases it and checks the bytes. After every cycle the FunctionFS
//! instance must still report ready and no control-plane loss may be logged.

mod common;
#[path = "common/stalling_http.rs"]
mod stalling_http;

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use smoo_test_harness::fixture::{GadgetOpts, HostSourceSpec};
use smoo_test_harness::{RunningScenario, ScenarioBuilder};
use stalling_http::{StallingHttpSource, ensure_read_matches};
use tokio::sync::oneshot;

const SEED: u64 = 0x0DC_2EB1;
const BLOCK_SIZE: u32 = 4096;
/// 64 MiB, so every cycle can read a block no earlier cycle has pulled into
/// the page cache.
const TOTAL_BLOCKS: u64 = 16 * 1024;
const FIRST_LBA: u64 = 1024;
/// 2 MiB between the blocks read by consecutive cycles, well beyond the
/// block layer's readahead window.
const LBA_STRIDE: u64 = 512;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn udc_rebind() -> Result<()> {
    common::init_tracing();
    let gaps = [
        Duration::from_millis(100),
        Duration::from_secs(2),
        Duration::from_secs(10),
    ];
    run_rebind_cycles("udc_rebind", &gaps).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires dummy_hcd/ublk/configfs; run via cargo xtask integration or vm-integration"]
async fn udc_rebind_loop() -> Result<()> {
    common::init_tracing();
    let gaps = [Duration::from_millis(100); 20];
    run_rebind_cycles("udc_rebind_loop", &gaps).await
}

async fn run_rebind_cycles(name: &str, gaps: &[Duration]) -> Result<()> {
    let last_lba = FIRST_LBA + LBA_STRIDE * gaps.len() as u64;
    ensure!(
        last_lba < TOTAL_BLOCKS,
        "{name}: {} cycles do not fit the backing source",
        gaps.len()
    );

    let server = StallingHttpSource::start(BLOCK_SIZE, TOTAL_BLOCKS, SEED, FIRST_LBA)?;
    let sc = ScenarioBuilder::new(name)
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

    // Log a failure while `sc` is still alive: dropping it tears down the
    // gadget's configfs state synchronously, and a teardown that blocks must
    // not hide the error that caused it.
    if let Err(err) = drive_cycles(&sc, &server, gaps).await {
        tracing::error!(error = ?err, "UDC rebind scenario failed");
        return Err(err);
    }

    server.disarm();
    let result = sc.stop().await?;
    // Replayed requests are visible twice on the wire with one final response,
    // so strict request/response balance is not meaningful here.
    result.assert(true, false).await?;
    Ok(())
}

/// Wait for the host to attach the device, then run one unbind/rebind cycle
/// per gap.
async fn drive_cycles(
    sc: &RunningScenario,
    server: &StallingHttpSource,
    gaps: &[Duration],
) -> Result<()> {
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
    assert_gadget_serving(sc, "before the first unbind").await?;

    for (cycle, gap) in gaps.iter().copied().enumerate() {
        let lba = FIRST_LBA + LBA_STRIDE * cycle as u64;
        let expected = server.expected_bytes(lba, 1).await?;
        let requests_before = server.target_request_count();
        server.rearm(lba)?;
        let mut read = spawn_device_read(dev_path.clone(), lba);
        server
            .wait_for_data_requests(requests_before + 1, Duration::from_secs(15))
            .await
            .with_context(|| format!("cycle {cycle}: read never reached the host"))?;

        tracing::info!(cycle, ?gap, lba, "unbinding UDC with a read in flight");
        sc.gadget().configfs.unbind_udc();
        // The unbind gap doubles as the parked-read check: the read must
        // neither complete nor fail while the gadget has no UDC.
        if let Ok(outcome) = tokio::time::timeout(gap, &mut read).await {
            bail!(
                "cycle {cycle}: read finished while the UDC was unbound for {gap:?}, expected it to stay parked: {:?}",
                outcome.map(|r| r.map(|bytes| bytes.len()))
            );
        }
        sc.gadget()
            .configfs
            .bind_udc()
            .with_context(|| format!("cycle {cycle}: rebind UDC"))?;

        // The host reconnects to the re-enumerated gadget, which replays the
        // parked read: a second request for the same block.
        server
            .wait_for_data_requests(requests_before + 2, Duration::from_secs(30))
            .await
            .with_context(|| format!("cycle {cycle}: parked read was not replayed after rebind"))?;
        server.release();

        let actual = tokio::time::timeout(Duration::from_secs(15), &mut read)
            .await
            .with_context(|| format!("cycle {cycle}: read did not complete after rebind"))?
            .context("device read thread exited without a result")??;
        ensure_read_matches(&actual, &expected)
            .with_context(|| format!("cycle {cycle}: replayed read"))?;
        assert_gadget_serving(sc, &format!("after cycle {cycle}")).await?;
        tracing::info!(cycle, ?gap, "read completed after UDC rebind");
    }
    Ok(())
}

/// Read block `lba` of `path` on a plain OS thread.
///
/// A parked read sleeps in the kernel until the gadget answers it. On a
/// dedicated thread it cannot hold up the tokio runtime's shutdown when the
/// test fails with the read still parked; process exit kills the thread.
fn spawn_device_read(path: PathBuf, lba: u64) -> oneshot::Receiver<Result<Vec<u8>>> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let file =
                std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
            let mut buf = vec![0u8; BLOCK_SIZE as usize];
            file.read_exact_at(&mut buf, lba * BLOCK_SIZE as u64)
                .with_context(|| format!("read block {lba} of {}", path.display()))?;
            Ok(buf)
        })();
        let _ = tx.send(result);
    });
    rx
}

/// The same smoo-gadget process still owns a ready FunctionFS instance on a
/// bound UDC, and has not reported losing its control plane.
async fn assert_gadget_serving(sc: &RunningScenario, when: &str) -> Result<()> {
    let gadget = sc.gadget();
    let configfs = &gadget.configfs;

    let ready_path = configfs
        .gadget_dir
        .join(format!("functions/ffs.{}/ready", configfs.ffs_instance));
    match read_sysfs(&ready_path) {
        Ok(ready) => ensure!(
            ready == "1",
            "{when}: {} reads {ready:?}, expected FunctionFS to stay ready",
            ready_path.display()
        ),
        // The attribute exists since Linux 6.9.
        Err(err) if ready_path.exists() => return Err(err),
        Err(_) => tracing::warn!(path = %ready_path.display(), "no FunctionFS ready attribute"),
    }

    let udc = read_sysfs(&configfs.gadget_dir.join("UDC"))?;
    ensure!(
        udc == configfs.udc_name,
        "{when}: gadget bound to {udc:?}, expected {:?}",
        configfs.udc_name
    );

    let lost_re = Regex::new("control plane lost|control loop failed|control loop exited")?;
    let stdout = gadget.child.stdout_buf.snapshot().await;
    let stderr = gadget.child.stderr_buf.snapshot().await;
    if let Some(line) = stdout
        .iter()
        .chain(stderr.iter())
        .find(|l| lost_re.is_match(l))
    {
        bail!("{when}: smoo-gadget lost its control plane: {line}");
    }
    Ok(())
}

fn read_sysfs(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_string())
}
