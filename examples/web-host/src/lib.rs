#[cfg(not(target_arch = "wasm32"))]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(target_arch = "wasm32")]
mod wasm_host {
    use smoo_host_blocksource_http::HttpBlockSource;
    use smoo_host_core::{
        BlockSource, BlockSourceHandle, SmooHost, control::ConfigExportsV0, register_export,
        start_host_io_pump,
    };
    use smoo_host_webusb::{WebUsbTransport, WebUsbTransportConfig};
    use std::sync::Once;
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
    use tracing_wasm::WASMLayerConfigBuilder;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::spawn_local;
    use web_sys::console;

    #[wasm_bindgen]
    pub async fn start(device: web_sys::UsbDevice, backing_url: String) -> Result<(), JsValue> {
        console_error_panic_hook::set_once();
        init_tracing();

        let url = url::Url::parse(&backing_url)
            .map_err(|err| JsValue::from_str(&format!("parse backing URL: {err}")))?;
        let block_size = 512u32;
        let source = HttpBlockSource::new(url.clone(), block_size)
            .await
            .map_err(to_js_err)?;
        let total_blocks = source.total_blocks().await.map_err(to_js_err)?;
        let size_bytes = total_blocks
            .checked_mul(block_size as u64)
            .ok_or_else(|| JsValue::from_str("backing size overflow"))?;

        let mut sources = BTreeMap::new();
        let mut entries = Vec::new();
        let identity = format!("http:{url}");
        register_export(
            &mut sources,
            &mut entries,
            BlockSourceHandle::new(source, identity.clone()),
            identity,
            block_size,
            size_bytes,
        )
        .map_err(to_js_err)?;
        let payload = ConfigExportsV0::from_slice(&entries)
            .map_err(|err| JsValue::from_str(&format!("build CONFIG_EXPORTS: {err:?}")))?;

        let transport = WebUsbTransport::new(device, WebUsbTransportConfig::default())
            .await
            .map_err(to_js_err)?;
        let control = transport.control_handle();
        let (pump_handle, request_rx, pump_task) = start_host_io_pump(transport);
        spawn_local(async move {
            if let Err(err) = pump_task.await {
                log_warn(&format!("pump exited: {err}"));
            }
        });

        let mut host = SmooHost::new(pump_handle, request_rx, sources);
        let ident = host.setup(&control).await.map_err(to_js_err)?;
        log_info(&format!("IDENT {}.{}", ident.major, ident.minor));
        host.configure_exports_v0(&control, &payload)
            .await
            .map_err(to_js_err)?;

        let state = Rc::new(RefCell::new(Some(HostState { host })));
        schedule_host_loop(state)?;
        Ok(())
    }

    static TRACING_INIT: Once = Once::new();

    fn init_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_wasm::set_as_global_default_with_config(
                WASMLayerConfigBuilder::default()
                    .set_max_level(tracing::Level::DEBUG)
                    .build(),
            );
        });
    }

    struct HostState {
        host: SmooHost<BlockSourceHandle>,
    }

    fn schedule_host_loop(state: Rc<RefCell<Option<HostState>>>) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("window unavailable"))?;
        let cb_state = state.clone();
        let raf_cb: Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>> = Rc::new(RefCell::new(None));
        let raf_cb_clone = raf_cb.clone();
        *raf_cb_clone.borrow_mut() = Some(Closure::wrap(Box::new(move |_ts: f64| {
            let inner_state = cb_state.clone();
            let raf_cb_inner = raf_cb.clone();
            spawn_local(async move {
                let keep_running = {
                    let mut guard = inner_state.borrow_mut();
                    if let Some(ctx) = guard.as_mut() {
                        match ctx.host.run_once().await {
                            Ok(()) => true,
                            Err(err) => {
                                log_warn(&format!("host loop error: {err}"));
                                false
                            }
                        }
                    } else {
                        false
                    }
                };
                if keep_running {
                    if let Some(win) = web_sys::window() {
                        if let Some(cb) = raf_cb_inner.borrow().as_ref() {
                            let _ = win.request_animation_frame(cb.as_ref().unchecked_ref());
                        }
                    }
                }
            });
        }) as Box<dyn FnMut(f64)>));
        if let Some(cb) = raf_cb_clone.borrow().as_ref() {
            window
                .request_animation_frame(cb.as_ref().unchecked_ref())
                .map_err(JsValue::from)?;
        }
        Ok(())
    }

    fn log_info(msg: &str) {
        console::log_1(&JsValue::from_str(msg));
    }

    fn log_warn(msg: &str) {
        console::warn_1(&JsValue::from_str(msg));
    }

    fn to_js_err(err: impl core::fmt::Display) -> JsValue {
        JsValue::from_str(&err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_host::start;

#[cfg(not(target_arch = "wasm32"))]
#[wasm_bindgen]
pub async fn start(
    _device: wasm_bindgen::JsValue,
    _backing_url: String,
) -> Result<(), wasm_bindgen::JsValue> {
    Err(wasm_bindgen::JsValue::from_str(
        "web-host is only available for wasm32 targets",
    ))
}
