#![no_std]

extern crate alloc;

pub mod block;
pub mod control;
pub mod export_id;
pub mod exports;
pub mod heartbeat;
pub mod host;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod pump;
pub mod transport;

pub use block::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceHandle, BlockSourceResult,
};
pub use export_id::{
    derive_export_id, derive_export_id_from_source, derive_export_id_with, ExportHasher32,
    ExportIdentity,
};
pub use exports::{
    register_export, register_export_with_id, ExportConfigError, ExportConfigErrorKind,
};
pub use heartbeat::heartbeat_once;
pub use host::{HostError, HostErrorKind, HostResult, SmooHost};
#[cfg(feature = "metrics")]
pub use metrics::{MetricsSnapshot, QueueSnapshot, StatSnapshot};
pub use transport::{
    ControlTransport, CountingTransport, Transport, TransportCounterSnapshot, TransportCounters,
    TransportError, TransportErrorKind, TransportResult,
};
