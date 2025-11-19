#![cfg_attr(
    not(all(target_arch = "wasm32", web_sys_unstable_apis)),
    allow(dead_code)
)]

#[cfg(all(target_arch = "wasm32", web_sys_unstable_apis))]
mod wasm;
#[cfg(all(target_arch = "wasm32", web_sys_unstable_apis))]
pub use wasm::WebUsbTransport;

#[cfg(not(all(target_arch = "wasm32", web_sys_unstable_apis)))]
mod unsupported;
#[cfg(not(all(target_arch = "wasm32", web_sys_unstable_apis)))]
pub use unsupported::WebUsbTransport;
