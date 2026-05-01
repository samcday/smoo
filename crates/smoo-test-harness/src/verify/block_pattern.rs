//! Cross-check a ublk device's bytes against a deterministic
//! [`smoo_host_blocksources::random::RandomBlockSource`].
//!
//! Reads a block-aligned region from the device file (e.g. `/dev/ublkbN`),
//! recomputes the same region locally from the seeded source, and asserts
//! the bytes match. The first differing offset is reported on failure.

use std::io::SeekFrom;
use std::path::Path;

use anyhow::{Context, Result};
use smoo_host_blocksources::random::RandomBlockSource;
use smoo_host_core::BlockSource;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub struct BlockPatternVerifier {
    source: RandomBlockSource,
    block_size: u32,
    total_blocks: u64,
}

impl BlockPatternVerifier {
    pub fn new(seed: u64, block_size: u32, total_blocks: u64) -> Result<Self> {
        let source = RandomBlockSource::new(block_size, total_blocks, seed)
            .context("construct RandomBlockSource")?;
        Ok(Self {
            source,
            block_size,
            total_blocks,
        })
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    pub fn total_bytes(&self) -> u64 {
        self.block_size as u64 * self.total_blocks
    }

    /// Read `blocks` blocks starting at `lba` from `path` and assert the
    /// bytes match the deterministic pattern.
    pub async fn verify_device_read(&self, path: &Path, lba: u64, blocks: u64) -> Result<()> {
        let len = blocks
            .checked_mul(self.block_size as u64)
            .context("blocks * block_size overflow")? as usize;
        let offset = lba
            .checked_mul(self.block_size as u64)
            .context("lba * block_size overflow")?;

        let mut file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::Start(offset))
            .await
            .with_context(|| format!("seek {} +{offset}", path.display()))?;
        let mut actual = vec![0u8; len];
        file.read_exact(&mut actual)
            .await
            .with_context(|| format!("read {len} bytes from {}", path.display()))?;

        let mut expected = vec![0u8; len];
        self.source
            .read_blocks(lba, &mut expected)
            .await
            .map_err(|e| anyhow::anyhow!("RandomBlockSource read_blocks: {e}"))?;

        if actual != expected {
            let diff = first_diff(&actual, &expected).expect("vectors differ but no diff index");
            let (a, e) = (actual[diff], expected[diff]);
            anyhow::bail!(
                "byte mismatch reading {blocks} blocks at lba {lba}: first diff at offset {diff} (actual=0x{a:02x} expected=0x{e:02x})"
            );
        }
        Ok(())
    }

    /// Borrow the underlying RandomBlockSource for direct use (e.g. when
    /// configuring the host CLI to serve the same pattern).
    pub fn source(&self) -> &RandomBlockSource {
        &self.source
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .or_else(|| {
            if a.len() != b.len() {
                Some(a.len().min(b.len()))
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verifies_against_self() -> Result<()> {
        let v = BlockPatternVerifier::new(0xCAFE, 4096, 4)?;
        // Write the deterministic pattern to a temp file, then verify.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("data.bin");
        let total = v.total_bytes() as usize;
        let mut buf = vec![0u8; total];
        v.source.read_blocks(0, &mut buf).await.unwrap();
        std::fs::write(&path, &buf)?;

        v.verify_device_read(&path, 0, v.total_blocks()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn detects_corruption() -> Result<()> {
        let v = BlockPatternVerifier::new(0xCAFE, 512, 2)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("data.bin");
        let total = v.total_bytes() as usize;
        let mut buf = vec![0u8; total];
        v.source.read_blocks(0, &mut buf).await.unwrap();
        // Corrupt one byte
        buf[100] ^= 0xFF;
        std::fs::write(&path, &buf)?;

        let err = v
            .verify_device_read(&path, 0, v.total_blocks())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("offset 100"), "got: {err}");
        Ok(())
    }
}
