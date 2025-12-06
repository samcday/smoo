#[cfg(not(target_arch = "wasm32"))]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(target_arch = "wasm32")]
mod wasm_host {
    use futures_util::future::{AbortHandle, Abortable};
    use smoo_host_blocksource_http::HttpBlockSource;
    use smoo_host_core::{
        BlockSourceHandle, HostIoPumpHandle, SmooHost, control::ConfigExportsV0, heartbeat_once,
        register_export, start_host_io_pump,
    };
    use smoo_host_webusb::{WebUsbControl, WebUsbTransport, WebUsbTransportConfig};
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

        let transport_config = WebUsbTransportConfig::default();
        let state = Rc::new(RefCell::new(Some(
            start_session(
                device.clone(),
                transport_config,
                sources.clone(),
                payload.clone(),
            )
            .await?,
        )));
        let restart_in_progress = Rc::new(RefCell::new(false));
        let next_restart_ms = Rc::new(RefCell::new(0.0));
        schedule_host_loop(
            state,
            device,
            sources,
            payload,
            transport_config,
            restart_in_progress,
            next_restart_ms,
        )?;
        Ok(())
    }

    static TRACING_INIT: Once = Once::new();

    fn init_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_wasm::set_as_global_default_with_config(
                WASMLayerConfigBuilder::default()
                    .set_max_level(tracing::Level::INFO)
                    .build(),
            );
        });
    }

    struct HostState {
        host: SmooHost<BlockSourceHandle>,
        control: WebUsbControl,
        pump_handle: HostIoPumpHandle,
        pump_abort: AbortHandle,
        session_id: u64,
        last_heartbeat_ms: f64,
    }

    async fn start_session(
        device: web_sys::UsbDevice,
        transport_config: WebUsbTransportConfig,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
    ) -> Result<HostState, JsValue> {
        let transport = WebUsbTransport::new(device, transport_config)
            .await
            .map_err(to_js_err)?;
        let control = transport.control_handle();
        let (pump_handle, request_rx, pump_task) = start_host_io_pump(transport);
        let (abort_handle, abort_reg) = AbortHandle::new_pair();
        let pump_abort = abort_handle.clone();
        let pump_future = Abortable::new(pump_task, abort_reg);
        spawn_local(async move {
            match pump_future.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    log_warn(&format!("pump exited: {err}"));
                }
                Err(_) => {
                    log_info("pump task aborted");
                }
            }
        });

        let mut host = SmooHost::new(pump_handle.clone(), request_rx, sources);
        let ident = host.setup(&control).await.map_err(to_js_err)?;
        log_info(&format!("IDENT {}.{}", ident.major, ident.minor));
        host.configure_exports_v0(&control, &payload)
            .await
            .map_err(to_js_err)?;

        let status = heartbeat_once(&control)
            .await
            .map_err(|err| JsValue::from_str(&format!("initial heartbeat failed: {err}")))?;
        log_info(&format!(
            "SMOO_STATUS session=0x{:016x} exports={}",
            status.session_id, status.export_count
        ));

        Ok(HostState {
            host,
            control,
            pump_handle,
            pump_abort,
            session_id: status.session_id,
            last_heartbeat_ms: now_ms().unwrap_or(0.0),
        })
    }

    fn teardown_state(state: &mut Option<HostState>) {
        if let Some(ctx) = state.take() {
            let pump = ctx.pump_handle.clone();
            let abort = ctx.pump_abort;
            spawn_local(async move {
                let _ = pump.shutdown().await;
            });
            abort.abort();
        }
    }

    fn spawn_session_restart(
        state: Rc<RefCell<Option<HostState>>>,
        restart_flag: Rc<RefCell<bool>>,
        next_restart_ms: Rc<RefCell<f64>>,
        device: web_sys::UsbDevice,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
        transport_config: WebUsbTransportConfig,
    ) {
        if *restart_flag.borrow() {
            return;
        }
        *restart_flag.borrow_mut() = true;
        if let Some(now) = now_ms() {
            *next_restart_ms.borrow_mut() = now + 1000.0;
        }
        let restart_flag_clone = restart_flag.clone();
        let next_restart_ms_clone = next_restart_ms.clone();
        spawn_local(async move {
            teardown_state(&mut state.borrow_mut());
            match start_session(device, transport_config, sources, payload).await {
                Ok(new_state) => {
                    state.replace(Some(new_state));
                }
                Err(err) => {
                    log_warn(&format!("session restart failed: {err:?}"));
                }
            }
            *restart_flag_clone.borrow_mut() = false;
            if state.borrow().is_none() {
                if let Some(now) = now_ms() {
                    *next_restart_ms_clone.borrow_mut() = now + 1000.0;
                }
            }
        });
    }

    fn schedule_host_loop(
        state: Rc<RefCell<Option<HostState>>>,
        device: web_sys::UsbDevice,
        sources: BTreeMap<u32, BlockSourceHandle>,
        payload: ConfigExportsV0,
        transport_config: WebUsbTransportConfig,
        restart_in_progress: Rc<RefCell<bool>>,
        next_restart_ms: Rc<RefCell<f64>>,
    ) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("window unavailable"))?;
        let cb_state = state.clone();
        let raf_cb: Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>> = Rc::new(RefCell::new(None));
        let raf_cb_clone = raf_cb.clone();
        *raf_cb_clone.borrow_mut() = Some(Closure::wrap(Box::new(move |_ts: f64| {
            let inner_state = cb_state.clone();
            let restart_flag = restart_in_progress.clone();
            let next_restart_ms = next_restart_ms.clone();
            let device = device.clone();
            let sources = sources.clone();
            let payload = payload.clone();
            let raf_cb_inner = raf_cb.clone();
            spawn_local(async move {
                let now = now_ms();
                let mut heartbeat = None;
                let mut request_restart = false;
                {
                    let mut guard = inner_state.borrow_mut();
                    if guard.is_none() && !*restart_flag.borrow() {
                        if now.map_or(true, |ts| ts >= *next_restart_ms.borrow()) {
                            request_restart = true;
                        }
                    }
                    if let Some(ctx) = guard.as_mut() {
                        match ctx.host.run_once().await {
                            Ok(()) => {}
                            Err(err) => {
                                log_warn(&format!("host loop error: {err}"));
                            }
                        }
                        if let Some(ts) = now {
                            if ts - ctx.last_heartbeat_ms >= 1000.0 {
                                ctx.last_heartbeat_ms = ts;
                                heartbeat = Some((ctx.control.clone(), ctx.session_id));
                            }
                        }
                    }
                };
                if let Some((control, expected_session)) = heartbeat {
                    match heartbeat_once(&control).await {
                        Ok(status) => {
                            log_info(&format!(
                                "heartbeat ok session=0x{:016x} exports={}",
                                status.session_id, status.export_count
                            ));
                            if status.session_id != expected_session {
                                log_info(&format!(
                                    "session changed (0x{expected_session:016x} -> 0x{:016x}); restarting",
                                    status.session_id
                                ));
                                request_restart = true;
                            }
                        }
                        Err(err) => {
                            log_warn(&format!("heartbeat error: {err}"));
                            request_restart = true;
                        }
                    }
                }
                if request_restart {
                    spawn_session_restart(
                        inner_state.clone(),
                        restart_flag.clone(),
                        next_restart_ms.clone(),
                        device.clone(),
                        sources.clone(),
                        payload.clone(),
                        transport_config,
                    );
                }
                if let Some(win) = web_sys::window() {
                    if let Some(cb) = raf_cb_inner.borrow().as_ref() {
                        let _ = win.request_animation_frame(cb.as_ref().unchecked_ref());
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

    fn now_ms() -> Option<f64> {
        let window = web_sys::window()?;
        let perf = window.performance()?;
        Some(perf.now())
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
