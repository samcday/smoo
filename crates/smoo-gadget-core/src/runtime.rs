use crate::{ExportSpec, PersistedExportRecord, StateStore};
use anyhow::{Result, anyhow, ensure};
use smoo_gadget_ublk::SmooUblk;
use smoo_gadget_ublk::SmooUblkDevice;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub struct RuntimeTunables {
    pub queue_count: u16,
    pub queue_depth: u16,
    pub max_io_bytes: usize,
    pub dma_heap: Option<crate::DmaHeap>,
}

pub enum ExportState {
    New,
    RecoveringPending {
        dev_id: u32,
    },
    Recovering {
        dev_id: u32,
        device: SmooUblkDevice,
    },
    Starting {
        dev_id: u32,
        device: SmooUblkDevice,
    },
    Online {
        dev_id: u32,
        device: SmooUblkDevice,
    },
    ShuttingDown {
        dev_id: u32,
        device: SmooUblkDevice,
    },
    IoInFlight {
        dev_id: u32,
        kind: IoStateKind,
    },
    Failed {
        dev_id: Option<u32>,
        device: Option<SmooUblkDevice>,
        last_error: String,
        retry_at: Instant,
    },
    Deleted,
}

#[derive(Clone, Copy, Debug)]
pub enum IoStateKind {
    Recovering,
    Starting,
    Online,
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

    pub fn device(&self) -> Option<&SmooUblkDevice> {
        match &self.state {
            ExportState::RecoveringPending { .. } => None,
            ExportState::Recovering { device, .. }
            | ExportState::Starting { device, .. }
            | ExportState::Online { device, .. }
            | ExportState::ShuttingDown { device, .. } => Some(device),
            ExportState::Failed { device, .. } => device.as_ref(),
            _ => None,
        }
    }

    pub fn device_mut(&mut self) -> Option<&mut SmooUblkDevice> {
        match &mut self.state {
            ExportState::RecoveringPending { .. } => None,
            ExportState::Recovering { device, .. }
            | ExportState::Starting { device, .. }
            | ExportState::Online { device, .. }
            | ExportState::ShuttingDown { device, .. } => Some(device),
            ExportState::Failed { device, .. } => device.as_mut(),
            _ => None,
        }
    }

    pub fn dev_id(&self) -> Option<u32> {
        match &self.state {
            ExportState::RecoveringPending { dev_id }
            | ExportState::Recovering { dev_id, .. }
            | ExportState::Starting { dev_id, .. }
            | ExportState::Online { dev_id, .. }
            | ExportState::ShuttingDown { dev_id, .. } => Some(*dev_id),
            ExportState::Failed { dev_id, .. } => *dev_id,
            _ => None,
        }
    }

    pub fn take_device(&mut self) -> Option<SmooUblkDevice> {
        let mut result = None;
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::Recovering { device, .. }
            | ExportState::Starting { device, .. }
            | ExportState::Online { device, .. }
            | ExportState::ShuttingDown { device, .. } => {
                result = Some(device);
                ExportState::Deleted
            }
            ExportState::Failed {
                dev_id,
                device,
                last_error,
                retry_at,
            } => {
                result = device;
                ExportState::Failed {
                    dev_id,
                    device: None,
                    last_error,
                    retry_at,
                }
            }
            other => other,
        };
        result
    }

    pub fn take_device_for_io(&mut self) -> Option<(IoStateKind, u32, SmooUblkDevice)> {
        let mut result = None;
        self.state = match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::Recovering { dev_id, device } => {
                result = Some((IoStateKind::Recovering, dev_id, device));
                ExportState::IoInFlight {
                    dev_id,
                    kind: IoStateKind::Recovering,
                }
            }
            ExportState::Starting { dev_id, device } => {
                result = Some((IoStateKind::Starting, dev_id, device));
                ExportState::IoInFlight {
                    dev_id,
                    kind: IoStateKind::Starting,
                }
            }
            ExportState::Online { dev_id, device } => {
                result = Some((IoStateKind::Online, dev_id, device));
                ExportState::IoInFlight {
                    dev_id,
                    kind: IoStateKind::Online,
                }
            }
            ExportState::ShuttingDown { dev_id, device } => {
                result = Some((IoStateKind::Online, dev_id, device));
                ExportState::IoInFlight {
                    dev_id,
                    kind: IoStateKind::Online,
                }
            }
            other => other,
        };
        result
    }

    pub fn restore_device_after_io(
        &mut self,
        kind: IoStateKind,
        dev_id: u32,
        device: SmooUblkDevice,
    ) {
        self.state = match kind {
            IoStateKind::Recovering => ExportState::Recovering { dev_id, device },
            IoStateKind::Starting => ExportState::Starting { dev_id, device },
            IoStateKind::Online => ExportState::Online { dev_id, device },
        };
    }

    pub fn fail_after_io(&mut self, dev_id: u32, err: String) {
        self.state = ExportState::Failed {
            dev_id: Some(dev_id),
            device: None,
            last_error: err,
            retry_at: Instant::now() + self.retry_backoff,
        };
    }

    pub fn needs_reconcile(&self) -> bool {
        !matches!(
            self.state,
            ExportState::Online { .. } | ExportState::IoInFlight { .. }
        )
    }

    pub async fn reconcile(&mut self, cx: &mut ExportReconcileContext<'_>) -> Result<()> {
        match std::mem::replace(&mut self.state, ExportState::New) {
            ExportState::New => {
                let block_size = self.spec.block_size as usize;
                let blocks = self
                    .spec
                    .size_bytes
                    .checked_div(block_size as u64)
                    .unwrap_or(0);
                ensure!(blocks > 0, "export size too small");
                let block_count =
                    usize::try_from(blocks).map_err(|_| anyhow!("block count overflow"))?;
                let device = cx
                    .ublk
                    .setup_device(
                        block_size,
                        block_count,
                        cx.tunables.queue_count,
                        cx.tunables.queue_depth,
                    )
                    .await?;
                let dev_id = device.dev_id();
                cx.state_store.upsert_record(PersistedExportRecord {
                    export_id: self.export_id,
                    spec: self.spec.clone(),
                    assigned_dev_id: Some(dev_id),
                });
                cx.state_store.persist()?;
                self.state = ExportState::Starting { dev_id, device };
            }
            ExportState::RecoveringPending { dev_id } => {
                match cx.ublk.recover_existing_device(dev_id).await {
                    Ok(device) => {
                        self.state = ExportState::Recovering { dev_id, device };
                    }
                    Err(err) => {
                        cx.state_store
                            .update_record(self.export_id, |record| record.assigned_dev_id = None)
                            .ok();
                        cx.state_store.persist().ok();
                        self.state = ExportState::Failed {
                            dev_id: Some(dev_id),
                            device: None,
                            last_error: format!("recover device {dev_id} failed: {err:#}"),
                            retry_at: Instant::now() + self.retry_backoff,
                        };
                    }
                }
            }
            ExportState::Recovering { dev_id, mut device } => {
                if device.recovery_pending() {
                    cx.ublk.finalize_recovery(&mut device).await?;
                }
                self.state = ExportState::Online { dev_id, device };
            }
            ExportState::Starting { dev_id, device } => {
                self.state = ExportState::Online { dev_id, device };
            }
            ExportState::Online { dev_id, device } => {
                self.state = ExportState::Online { dev_id, device };
            }
            ExportState::ShuttingDown { dev_id: _, device } => {
                cx.ublk.stop_dev(device, true).await?;
                cx.state_store
                    .update_record(self.export_id, |record| record.assigned_dev_id = None)
                    .ok();
                cx.state_store.persist().ok();
                self.state = ExportState::Deleted;
            }
            ExportState::IoInFlight { dev_id, kind } => {
                // If reconcile runs while a device is temporarily out for IO, keep
                // the placeholder so the main loop can restore it.
                self.state = ExportState::IoInFlight { dev_id, kind };
            }
            ExportState::Failed {
                dev_id,
                device,
                last_error,
                retry_at,
            } => {
                let now = Instant::now();
                if now < retry_at {
                    self.state = ExportState::Failed {
                        dev_id,
                        device,
                        last_error,
                        retry_at,
                    };
                } else {
                    if let Some(device) = device {
                        let _ = cx.ublk.stop_dev(device, true).await;
                    }
                    cx.state_store
                        .update_record(self.export_id, |record| record.assigned_dev_id = None)
                        .ok();
                    cx.state_store.persist().ok();
                    self.state = ExportState::New;
                }
            }
            ExportState::Deleted => {
                self.state = ExportState::Deleted;
            }
        }
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
