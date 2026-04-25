//! In-flight registry for pipelined pump implementations.
//!
//! Tracks pending request entries keyed by `(export_id, request_id)`, with
//! insert/take semantics for matching Responses to outstanding Requests, and a
//! `close` operation that yields all unmatched entries for cleanup on link
//! teardown.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Result, anyhow};

/// Wire-level identifier shared by Request/Response pairs.
pub(crate) type InFlightKey = (u32, u32);

pub(crate) struct InFlightRegistry<V> {
    state: Mutex<RegistryState<V>>,
}

struct RegistryState<V> {
    open: bool,
    pending: HashMap<InFlightKey, V>,
}

impl<V> InFlightRegistry<V> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RegistryState {
                open: true,
                pending: HashMap::new(),
            }),
        }
    }

    /// Register a pending entry. Fails if the registry has been closed (e.g.
    /// link is faulted) or if a duplicate key is inserted.
    pub(crate) fn insert(&self, key: InFlightKey, value: V) -> Result<()> {
        let mut state = self.state.lock().expect("registry poisoned");
        if !state.open {
            return Err(anyhow!("in-flight registry closed"));
        }
        if state.pending.insert(key, value).is_some() {
            return Err(anyhow!("duplicate in-flight key {key:?}"));
        }
        Ok(())
    }

    /// Take the entry matching `key`, if present. Returns `None` if no match
    /// (stale or unknown response) or the registry is closed.
    pub(crate) fn take(&self, key: InFlightKey) -> Option<V> {
        self.state
            .lock()
            .expect("registry poisoned")
            .pending
            .remove(&key)
    }

    /// Close the registry against further inserts and return every pending
    /// entry. Callers are responsible for any per-entry cleanup (signaling
    /// completion senders, returning checked-out buffers, etc.).
    pub(crate) fn close(&self) -> Vec<V> {
        let mut state = self.state.lock().expect("registry poisoned");
        state.open = false;
        state.pending.drain().map(|(_, v)| v).collect()
    }

    #[allow(dead_code)] // used by tests; useful for future metrics/debug
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .expect("registry poisoned")
            .pending
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_take_round_trip() {
        let reg = InFlightRegistry::<u32>::new();
        reg.insert((1, 7), 42).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.take((1, 7)), Some(42));
        assert_eq!(reg.take((1, 7)), None);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let reg = InFlightRegistry::<u32>::new();
        reg.insert((1, 7), 42).unwrap();
        let err = reg.insert((1, 7), 99).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn close_yields_all_entries_and_blocks_inserts() {
        let reg = InFlightRegistry::<&'static str>::new();
        reg.insert((1, 1), "a").unwrap();
        reg.insert((1, 2), "b").unwrap();
        reg.insert((2, 9), "c").unwrap();

        let mut drained = reg.close();
        drained.sort();
        assert_eq!(drained, vec!["a", "b", "c"]);
        assert_eq!(reg.len(), 0);

        let err = reg.insert((1, 3), "d").unwrap_err();
        assert!(err.to_string().contains("closed"), "{err}");
    }

    #[test]
    fn unmatched_take_returns_none() {
        let reg = InFlightRegistry::<()>::new();
        reg.insert((1, 1), ()).unwrap();
        assert!(reg.take((9, 9)).is_none());
        assert_eq!(reg.len(), 1);
    }
}
