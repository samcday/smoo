use crate::{ExportSpec, PersistedExportRecord, StateStore};
use anyhow::Result;
use smoo_gadget_ublk::SmooUblk;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RuntimeTunables {
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_io_bytes: usize,
    pub dma_heap: Option<crate::DmaHeap>,
}

pub enum ExportState {
    New,
    Recovering {
        dev_id: u32,
        device: smoo_gadget_ublk::SmooUblkDevice,
    },
    Starting {
        dev_id: u32,
        device: smoo_gadget_ublk::SmooUblkDevice,
    },
    Online {
        dev_id: u32,
        device: smoo_gadget_ublk::SmooUblkDevice,
    },
    ShuttingDown {
        dev_id: u32,
        device: smoo_gadget_ublk::SmooUblkDevice,
    },
    Failed {
        dev_id: Option<u32>,
        device: Option<smoo_gadget_ublk::SmooUblkDevice>,
        last_error: String,
        retry_at: Instant,
    },
    Deleted,
}

pub struct ExportReconcileContext<'a> {
    pub ublk: &'a mut SmooUblk,
    pub state_store: &'a mut StateStore,
    pub tunables: RuntimeTunables,
}

pub struct ExportController {
    pub export_id: u32,
    pub spec: ExportSpec,
    pub state: ExportState,
    pub retry_backoff: Duration,
}

impl ExportController {
    pub fn new(export_id: u32, spec: ExportSpec, state: ExportState) -> Self {
        Self {
            export_id,
            spec,
            state,
            retry_backoff: Duration::from_secs(1),
        }
    }

    pub async fn reconcile(&mut self, _cx: &mut ExportReconcileContext<'_>) -> Result<()> {
        // Reconciliation logic will be added in follow-up changes.
        Ok(())
    }
}

pub struct GadgetRuntime {
    pub exports: HashMap<u32, ExportController>,
    pub state_store: StateStore,
    pub tunables: RuntimeTunables,
}

impl GadgetRuntime {
    pub fn new(state_store: StateStore, tunables: RuntimeTunables) -> Self {
        Self {
            exports: HashMap::new(),
            state_store,
            tunables,
        }
    }

    pub fn rebuild_exports(&mut self, records: Vec<PersistedExportRecord>) {
        self.exports = records
            .into_iter()
            .map(|record| {
                let controller =
                    ExportController::new(record.export_id, record.spec, ExportState::New);
                (record.export_id, controller)
            })
            .collect();
    }
}
