use std::collections::{HashMap, HashSet};

use crate::state::Export;

/// Observed ublk device state keyed by export_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedExport {
    pub export_id: u32,
    pub ublk_dev_id: u32,
    pub block_size: u32,
    pub block_count: u64,
}

/// Actions emitted by [`ExportsController`] to drive ublk reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportAction {
    Ensure(Export),
    Remove { export_id: u32 },
}

/// Outcome of reconciling one export_id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileResult {
    pub action: Option<ExportAction>,
    pub requeue_after: Option<std::time::Duration>,
}

impl ReconcileResult {
    pub fn idle() -> Self {
        Self {
            action: None,
            requeue_after: None,
        }
    }

    pub fn with_action(action: ExportAction) -> Self {
        Self {
            action: Some(action),
            requeue_after: None,
        }
    }
}

/// Supervises CONFIG_EXPORTS and observed devices; stateless reconcile per export_id.
pub struct ExportsController {
    session_id: u64,
    desired: HashMap<u32, Export>,
    observed: HashMap<u32, ObservedExport>,
    backoff: HashMap<u32, Backoff>,
    functionfs_ready: bool,
}

impl ExportsController {
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            desired: HashMap::new(),
            observed: HashMap::new(),
            backoff: HashMap::new(),
            functionfs_ready: false,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Update desired exports and return the keys to enqueue for reconciliation.
    pub fn update_desired(
        &mut self,
        session_id: u64,
        exports: impl IntoIterator<Item = Export>,
    ) -> Vec<u32> {
        self.session_id = session_id;
        let mut keys: HashSet<u32> = self.desired.keys().copied().collect();
        let mut new_desired = HashMap::new();
        for export in exports {
            keys.insert(export.export_id);
            new_desired.insert(export.export_id, export);
        }
        self.desired = new_desired;
        keys.into_iter().collect()
    }

    /// Record an observed ublk device state for reconciliation comparisons.
    pub fn observe(&mut self, export: ObservedExport) {
        self.observed.insert(export.export_id, export);
    }

    /// Clear observed state for an export id (after teardown).
    pub fn clear_observed(&mut self, export_id: u32) {
        self.observed.remove(&export_id);
    }

    /// Emit export_ids to reconcile when FunctionFS readiness flips.
    pub fn set_functionfs_ready(&mut self, ready: bool) -> Vec<u32> {
        if self.functionfs_ready == ready {
            return Vec::new();
        }
        self.functionfs_ready = ready;
        let keys: HashSet<u32> = self
            .desired
            .keys()
            .copied()
            .chain(self.observed.keys().copied())
            .collect();
        keys.into_iter().collect()
    }

    /// Run one reconciliation pass for an export_id, returning an action and optional backoff.
    pub fn reconcile(&mut self, export_id: u32) -> ReconcileResult {
        let desired = self.desired.get(&export_id).cloned();
        let observed = self.observed.get(&export_id).cloned();

        if !self.functionfs_ready {
            if observed.is_some() {
                return ReconcileResult::with_action(ExportAction::Remove { export_id });
            }
            return ReconcileResult::idle();
        }

        match (desired, observed) {
            (None, None) => ReconcileResult::idle(),
            (None, Some(_)) => ReconcileResult::with_action(ExportAction::Remove { export_id }),
            (Some(export), None) => {
                self.reset_backoff(export_id);
                ReconcileResult::with_action(ExportAction::Ensure(export))
            }
            (Some(export), Some(observed)) => {
                if Self::geom_different(&export, &observed) {
                    self.reset_backoff(export_id);
                    ReconcileResult::with_action(ExportAction::Ensure(export))
                } else {
                    ReconcileResult::idle()
                }
            }
        }
    }

    /// Returns the next backoff for a failed reconcile of `export_id`.
    pub fn next_backoff(&mut self, export_id: u32) -> std::time::Duration {
        self.backoff
            .entry(export_id)
            .or_insert_with(Backoff::default)
            .next_delay()
    }

    /// Reset backoff after a successful reconcile of `export_id`.
    pub fn reset_backoff(&mut self, export_id: u32) {
        if let Some(backoff) = self.backoff.get_mut(&export_id) {
            backoff.reset();
        } else {
            self.backoff.insert(export_id, Backoff::default());
        }
    }

    fn geom_different(desired: &Export, observed: &ObservedExport) -> bool {
        desired.block_size != observed.block_size || desired.block_count != observed.block_count
    }
}

/// Exponential backoff helper capped at max_delay.
#[derive(Clone, Debug)]
pub struct Backoff {
    attempt: u32,
    base_delay: std::time::Duration,
    max_delay: std::time::Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(
            std::time::Duration::from_millis(200),
            std::time::Duration::from_secs(15),
        )
    }
}

impl Backoff {
    pub fn new(base_delay: std::time::Duration, max_delay: std::time::Duration) -> Self {
        Self {
            attempt: 0,
            base_delay,
            max_delay,
        }
    }

    pub fn next_delay(&mut self) -> std::time::Duration {
        let capped_attempt = self.attempt.min(16);
        self.attempt = self.attempt.saturating_add(1);
        let millis = self
            .base_delay
            .as_millis()
            .saturating_mul(2u128.saturating_pow(capped_attempt));
        std::time::Duration::from_millis(millis as u64).min(self.max_delay)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(export_id: u32, block_size: u32, size_bytes: u64) -> Export {
        let block_count = size_bytes / block_size as u64;
        Export {
            export_id,
            ublk_dev_id: None,
            block_size,
            block_count,
        }
    }

    #[test]
    fn add_remove_and_recreate_delta() {
        let mut controller = ExportsController::new(1);
        let keys = controller.update_desired(1, [export(1, 4096, 4096)]);
        assert_eq!(keys, vec![1]);

        controller.set_functionfs_ready(true);
        let result = controller.reconcile(1);
        assert_eq!(
            result,
            ReconcileResult::with_action(ExportAction::Ensure(Export {
                export_id: 1,
                ublk_dev_id: None,
                block_size: 4096,
                block_count: 1
            }))
        );
        controller.observe(ObservedExport {
            export_id: 1,
            ublk_dev_id: 7,
            block_size: 4096,
            block_count: 1,
        });

        let _ = controller.update_desired(1, [export(1, 4096, 8192)]);
        let result = controller.reconcile(1);
        assert_eq!(
            result,
            ReconcileResult::with_action(ExportAction::Ensure(Export {
                export_id: 1,
                ublk_dev_id: None,
                block_size: 4096,
                block_count: 2
            }))
        );

        let _ = controller.update_desired(1, [export(2, 4096, 4096)]);
        let result = controller.reconcile(1);
        assert_eq!(
            result,
            ReconcileResult::with_action(ExportAction::Remove { export_id: 1 })
        );
        let result = controller.reconcile(2);
        assert_eq!(
            result,
            ReconcileResult::with_action(ExportAction::Ensure(Export {
                export_id: 2,
                ublk_dev_id: None,
                block_size: 4096,
                block_count: 1
            }))
        );
    }

    #[test]
    fn functionfs_disable_triggers_remove() {
        let mut controller = ExportsController::new(7);
        controller.update_desired(7, [export(1, 4096, 4096)]);
        controller.observe(ObservedExport {
            export_id: 1,
            ublk_dev_id: 2,
            block_size: 4096,
            block_count: 1,
        });
        controller.set_functionfs_ready(true);
        controller.reconcile(1);
        let keys = controller.set_functionfs_ready(false);
        assert!(keys.contains(&1));
        let result = controller.reconcile(1);
        assert_eq!(
            result,
            ReconcileResult::with_action(ExportAction::Remove { export_id: 1 })
        );
    }
}
