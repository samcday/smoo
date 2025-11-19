#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod control;
pub mod host;
pub mod transport;

pub use block::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
pub use control::{
    ConfigExportEntry, ConfigExportsV0Payload, StatusClient, read_ident, read_status_v0,
    send_config_exports_v0,
};
pub use host::{HostError, HostErrorKind, HostExport, HostResult, SmooHost};
pub use transport::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
