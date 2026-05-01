//! Shared helpers for integration tests.

use std::path::Path;
use std::time::Duration;

/// Set up `tracing-subscriber` so harness logs land on stderr (which cargo
/// captures and surfaces on test failure). Idempotent — safe to call once
/// per test.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("info,smoo_test_harness=debug")
            }),
        )
        .with_writer(std::io::stderr)
        .with_test_writer()
        .try_init();
}

/// Poll a block device path for existence (the kernel may take a beat to
/// expose `/dev/ublkbN` after `start_dev completed`).
pub async fn wait_for_block_device(path: &Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "block device {} did not appear within {:?}",
                path.display(),
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
