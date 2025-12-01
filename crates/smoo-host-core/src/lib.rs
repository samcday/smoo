#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod control;
pub mod export_id;
pub mod host;
pub mod pump;
pub mod transport;

pub use block::{
    BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceHandle, BlockSourceResult,
};
pub use export_id::{
    ExportHasher32, ExportIdentity, derive_export_id, derive_export_id_from_source,
    derive_export_id_with,
};
pub use host::{HostError, HostErrorKind, HostResult, SmooHost};
pub use pump::{HostIoPumpHandle, HostIoPumpRequestRx, HostIoPumpTask, start_host_io_pump};
pub use transport::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
