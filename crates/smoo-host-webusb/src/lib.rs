//! WebUSB-backed smoo host transport.
//!
//! This crate provides a [`Transport`](smoo_host_core::transport::Transport) implementation
//! suitable for use from WebAssembly targets where WebUSB is available. On non-wasm targets
//! the types compile but always return `TransportErrorKind::Unsupported`.

/// Transport configuration for WebUSB.
#[derive(Clone, Copy, Debug)]
pub struct WebUsbTransportConfig {
    /// Interface number to claim before issuing transfers.
    pub interface: u8,
    /// Interrupt endpoint address used to receive Request messages (device → host).
    pub interrupt_in: u8,
    /// Interrupt endpoint address used to send Response messages (host → device).
    pub interrupt_out: u8,
    /// Bulk endpoint address used to read payloads (device → host).
    pub bulk_in: u8,
    /// Bulk endpoint address used to write payloads (host → device).
    pub bulk_out: u8,
}

impl Default for WebUsbTransportConfig {
    fn default() -> Self {
        Self {
            interface: 0,
            interrupt_in: 0x81,
            interrupt_out: 0x01,
            bulk_in: 0x82,
            bulk_out: 0x02,
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod webusb;

#[cfg(target_arch = "wasm32")]
pub use webusb::{WebUsbControl, WebUsbTransport};

#[cfg(not(target_arch = "wasm32"))]
mod unsupported;

#[cfg(not(target_arch = "wasm32"))]
pub use unsupported::{WebUsbControl, WebUsbTransport};
