use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
const SNAPSHOT_VERSION: u32 = 0;

#[derive(Clone)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<StateSnapshot>> {
        let data = match fs::read(&self.path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).context(format!("read state file {}", self.path.display()))
            }
        };
        let snapshot: StateSnapshot = serde_json::from_slice(&data).context("decode state file")?;
        ensure!(
            snapshot.version == SNAPSHOT_VERSION,
            "unsupported state file version {}",
            snapshot.version
        );
        Ok(Some(snapshot))
    }

    pub fn store(&self, session_id: u64, exports: &[ExportState]) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).context(format!("create {}", dir.display()))?;
        }
        let snapshot = StateSnapshot {
            version: SNAPSHOT_VERSION,
            session_id,
            exports: exports.to_vec(),
        };
        let data = serde_json::to_vec_pretty(&snapshot).context("encode state snapshot")?;
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, &data).context(format!("write {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &self.path).context(format!("commit {}", self.path.display()))
    }

    pub fn clear(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context(format!("remove state file {}", self.path.display())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportState {
    pub export_id: u32,
    pub ublk_dev_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub version: u32,
    pub session_id: u64,
    #[serde(default)]
    pub exports: Vec<ExportState>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_state_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state_file = StateFile::new(path.clone());
        let exports = vec![ExportState {
            export_id: 0,
            ublk_dev_id: 7,
        }];
        state_file.store(42, &exports).unwrap();
        let loaded = state_file.load().unwrap().expect("snapshot");
        assert_eq!(
            StateSnapshot {
                version: SNAPSHOT_VERSION,
                session_id: 42,
                exports
            },
            loaded
        );
        state_file.clear().unwrap();
        assert!(state_file.load().unwrap().is_none());
    }
}
