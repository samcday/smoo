use crate::WebUsbTransportConfig;
use async_trait::async_trait;
use js_sys::Uint8Array;
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    UsbControlTransferParameters, UsbDevice, UsbInTransferResult, UsbOutTransferResult,
    UsbRecipient, UsbRequestType, UsbTransferStatus,
};

/// Clonable control handle for issuing vendor requests alongside the transport.
#[derive(Clone)]
pub struct WebUsbControl {
    device: UsbDevice,
    interface: u8,
}

impl WebUsbControl {
    pub fn new(device: UsbDevice, interface: u8) -> Self {
        Self { device, interface }
    }

    fn ensure_open(&self) -> TransportResult<()> {
        if !self.device.opened() {
            return Err(TransportError::new(TransportErrorKind::NotReady));
        }
        Ok(())
    }
}

/// [`Transport`] implementation backed by WebUSB.
#[derive(Clone)]
pub struct WebUsbTransport {
    device: UsbDevice,
    config: WebUsbTransportConfig,
    control: WebUsbControl,
}

impl WebUsbTransport {
    /// Construct a transport from an already obtained `UsbDevice`.
    ///
    /// This will `open()` the device and `claim_interface()` using the supplied config.
    pub async fn new(device: UsbDevice, config: WebUsbTransportConfig) -> TransportResult<Self> {
        open_and_claim(&device, config.interface).await?;
        let control = WebUsbControl::new(device.clone(), config.interface);
        Ok(Self {
            device,
            config,
            control,
        })
    }

    /// Returns a clonable control handle for issuing vendor requests alongside the transport.
    pub fn control_handle(&self) -> WebUsbControl {
        self.control.clone()
    }
}

#[async_trait]
impl ControlTransport for WebUsbControl {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.ensure_open()?;
        let params = control_params(request_type, request, self.interface);
        let promise = self
            .device
            .control_transfer_in_with_length(&params, buf.len() as u32)
            .map_err(|err| js_error("control_in", err))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error("control_in", err))?;
        let result: UsbInTransferResult = result
            .dyn_into()
            .map_err(|err| js_error("control_in cast", err))?;
        match result.status() {
            UsbTransferStatus::Ok => {
                let data = result
                    .data()
                    .ok_or_else(|| TransportError::new(TransportErrorKind::Protocol))?;
                let view = Uint8Array::new(&data);
                let read = view.length() as usize;
                let copy_len = buf.len().min(read);
                view.slice(0, copy_len as u32).copy_to(buf);
                Ok(copy_len)
            }
            status => Err(TransportError::with_message(
                map_transfer_status(status),
                format!("control_in status {:?}", status.as_string()),
            )),
        }
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.ensure_open()?;
        let params = control_params(request_type, request, self.interface);
        let payload = Uint8Array::from(data);
        let promise = self
            .device
            .control_transfer_out_with_u8_array(&params, &payload)
            .map_err(|err| js_error("control_out", err))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error("control_out", err))?;
        let result: UsbOutTransferResult = result
            .dyn_into()
            .map_err(|err| js_error("control_out cast", err))?;
        match result.status() {
            UsbTransferStatus::Ok => Ok(result.bytes_written() as usize),
            status => Err(TransportError::with_message(
                map_transfer_status(status),
                format!("control_out status {:?}", status.as_string()),
            )),
        }
    }
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn read_interrupt(&self, buf: &mut [u8]) -> TransportResult<usize> {
        transfer_in(&self.device, self.config.interrupt_in, buf).await
    }

    async fn write_interrupt(&self, buf: &[u8]) -> TransportResult<usize> {
        transfer_out(&self.device, self.config.interrupt_out, buf).await
    }

    async fn read_bulk(&self, buf: &mut [u8]) -> TransportResult<usize> {
        transfer_in(&self.device, self.config.bulk_in, buf).await
    }

    async fn write_bulk(&self, buf: &[u8]) -> TransportResult<usize> {
        transfer_out(&self.device, self.config.bulk_out, buf).await
    }
}

unsafe impl Send for WebUsbTransport {}
unsafe impl Sync for WebUsbTransport {}
unsafe impl Send for WebUsbControl {}
unsafe impl Sync for WebUsbControl {}

fn control_params(request_type: u8, request: u8, interface: u8) -> UsbControlTransferParameters {
    let params = UsbControlTransferParameters::new();
    let (req_type, recipient) = decode_request_type(request_type);
    params.set_request_type(req_type);
    params.set_recipient(recipient.unwrap_or(UsbRecipient::Interface));
    params.set_request(request);
    params.set_value(0);
    params.set_index(interface as u16);
    params
}

fn decode_request_type(bm_request_type: u8) -> (UsbRequestType, Option<UsbRecipient>) {
    let ty = match (bm_request_type >> 5) & 0x03 {
        0 => UsbRequestType::Standard,
        1 => UsbRequestType::Class,
        2 => UsbRequestType::Vendor,
        _ => UsbRequestType::Vendor,
    };
    let recipient = match bm_request_type & 0x1f {
        0 => Some(UsbRecipient::Device),
        1 => Some(UsbRecipient::Interface),
        2 => Some(UsbRecipient::Endpoint),
        3 => Some(UsbRecipient::Other),
        _ => None,
    };
    (ty, recipient)
}

async fn open_and_claim(device: &UsbDevice, interface: u8) -> TransportResult<()> {
    if !device.opened() {
        JsFuture::from(device.open().map_err(|err| js_error("open", err))?)
            .await
            .map_err(|err| js_error("open", err))?;
    }
    if device.configuration().is_none() {
        JsFuture::from(
            device
                .select_configuration(1)
                .map_err(|err| js_error("select_configuration", err))?,
        )
        .await
        .map_err(|err| js_error("select_configuration", err))?;
    }
    JsFuture::from(
        device
            .claim_interface(interface as u8)
            .map_err(|err| js_error("claim_interface", err))?,
    )
    .await
    .map_err(|err| js_error("claim_interface", err))?;
    Ok(())
}

async fn transfer_in(device: &UsbDevice, endpoint: u8, buf: &mut [u8]) -> TransportResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if !device.opened() {
        return Err(TransportError::new(TransportErrorKind::NotReady));
    }
    let promise = device
        .transfer_in(endpoint, buf.len() as u32)
        .map_err(|err| js_error("transfer_in", err))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|err| js_error("transfer_in", err))?;
    let result: UsbInTransferResult = result
        .dyn_into()
        .map_err(|err| js_error("transfer_in cast", err))?;
    match result.status() {
        UsbTransferStatus::Ok => {
            let data = result
                .data()
                .ok_or_else(|| TransportError::new(TransportErrorKind::Protocol))?;
            let view = Uint8Array::new(&data);
            let read = view.length() as usize;
            let copy_len = buf.len().min(read);
            view.slice(0, copy_len as u32).copy_to(buf);
            Ok(copy_len)
        }
        status => Err(TransportError::with_message(
            map_transfer_status(status),
            format!("transfer_in status {:?}", status.as_string()),
        )),
    }
}

async fn transfer_out(device: &UsbDevice, endpoint: u8, buf: &[u8]) -> TransportResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if !device.opened() {
        return Err(TransportError::new(TransportErrorKind::NotReady));
    }
    let payload = Uint8Array::from(buf);
    let promise = device
        .transfer_out(endpoint, &payload)
        .map_err(|err| js_error("transfer_out", err))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|err| js_error("transfer_out", err))?;
    let result: UsbOutTransferResult = result
        .dyn_into()
        .map_err(|err| js_error("transfer_out cast", err))?;
    match result.status() {
        UsbTransferStatus::Ok => Ok(result.bytes_written() as usize),
        status => Err(TransportError::with_message(
            map_transfer_status(status),
            format!("transfer_out status {:?}", status.as_string()),
        )),
    }
}

fn map_transfer_status(status: UsbTransferStatus) -> TransportErrorKind {
    match status {
        UsbTransferStatus::Ok => TransportErrorKind::Other,
        UsbTransferStatus::Stall | UsbTransferStatus::Babble => TransportErrorKind::Protocol,
        _ => TransportErrorKind::Other,
    }
}

fn js_error(op: &str, err: impl Into<wasm_bindgen::JsValue>) -> TransportError {
    let js: wasm_bindgen::JsValue = err.into();
    let msg = js_as_string(&js).unwrap_or_else(|| format!("{:?}", js));
    TransportError::with_message(TransportErrorKind::Other, format!("{op}: {msg}"))
}

fn js_as_string(js: &wasm_bindgen::JsValue) -> Option<String> {
    js.as_string().or_else(|| {
        js.dyn_ref::<js_sys::Error>()
            .and_then(|e| e.message().as_string())
    })
}
