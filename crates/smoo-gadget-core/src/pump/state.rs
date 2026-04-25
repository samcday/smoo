//! Shared run-state for the pipelined pump.
//!
//! Each worker task observes a `watch::Receiver<PumpState>` and exits when the
//! supervisor (or any peer task that hit a fatal error) transitions to
//! `Faulted` or `Shutdown`. There is no recovery — the caller respawns the
//! whole pump on link recover, mirroring the existing top-level supervision
//! loop in `smoo-gadget-app`.

use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PumpState {
    /// Normal operation; tasks process I/O.
    Running,
    /// One of the worker tasks observed a fatal transport error. Other tasks
    /// must drain and exit; in-flight registry entries resolve to LinkLost.
    Faulted,
    /// Supervisor requested an orderly shutdown (link teardown, app exit).
    Shutdown,
}

impl PumpState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, PumpState::Faulted | PumpState::Shutdown)
    }
}

#[derive(Clone)]
pub(crate) struct PumpStateHandle {
    tx: watch::Sender<PumpState>,
}

impl PumpStateHandle {
    pub(crate) fn new() -> (Self, watch::Receiver<PumpState>) {
        let (tx, rx) = watch::channel(PumpState::Running);
        (Self { tx }, rx)
    }

    /// Transition to `Faulted` if currently `Running`. No-op if already
    /// terminal. Returns `true` if this call performed the transition.
    pub(crate) fn fault(&self) -> bool {
        self.transition(PumpState::Faulted)
    }

    /// Request graceful shutdown. No-op if already terminal.
    pub(crate) fn shutdown(&self) -> bool {
        self.transition(PumpState::Shutdown)
    }

    #[allow(dead_code)] // used by tests; readers in workers go through state_rx
    pub(crate) fn current(&self) -> PumpState {
        *self.tx.borrow()
    }

    fn transition(&self, next: PumpState) -> bool {
        let mut transitioned = false;
        self.tx.send_if_modified(|state| {
            if state.is_terminal() {
                false
            } else {
                *state = next;
                transitioned = true;
                true
            }
        });
        transitioned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_then_shutdown_is_noop() {
        let (h, rx) = PumpStateHandle::new();
        assert_eq!(*rx.borrow(), PumpState::Running);
        assert!(h.fault());
        assert_eq!(h.current(), PumpState::Faulted);
        assert!(!h.shutdown(), "shutdown after fault should be no-op");
        assert_eq!(h.current(), PumpState::Faulted);
    }

    #[test]
    fn shutdown_then_fault_is_noop() {
        let (h, _rx) = PumpStateHandle::new();
        assert!(h.shutdown());
        assert_eq!(h.current(), PumpState::Shutdown);
        assert!(!h.fault());
        assert_eq!(h.current(), PumpState::Shutdown);
    }

    #[test]
    fn watchers_observe_transition() {
        let (h, mut rx) = PumpStateHandle::new();
        h.fault();
        // borrow_and_update sees the latest value even if changed before.
        assert_eq!(*rx.borrow_and_update(), PumpState::Faulted);
    }
}
