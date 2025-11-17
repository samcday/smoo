#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod host;
pub mod transport;

pub use block::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};
pub use host::{HostError, HostErrorKind, HostResult, SmooHost};
pub use transport::{Transport, TransportError, TransportErrorKind, TransportResult};
