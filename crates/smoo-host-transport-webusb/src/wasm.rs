use async_trait::async_trait;
use core::convert::TryFrom;
use js_sys::{Array, DataView, Promise, Uint8Array};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use smoo_proto::{REQUEST_LEN, RESPONSE_LEN, Request, Response};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DomException, UsbAlternateInterface, UsbConfiguration, UsbControlTransferParameters, UsbDevice,
    UsbDirection, UsbEndpoint, UsbEndpointType, UsbInTransferResult, UsbInterface,
    UsbOutTransferResult, UsbRecipient, UsbRequestType, UsbTransferStatus,
};

const SMOO_INTERFACE_CLASS: u8 = 0xFF;
const SMOO_INTERFACE_SUBCLASS: u8 = 0x53;
const SMOO_INTERFACE_PROTOCOL: u8 = 0x4D;

pub struct WebUsbTransport {
    device: UsbDevice,
    #[allow(dead_code)]
    configuration_value: u8,
    interface_number: u8,
    interrupt_in: EndpointState,
    interrupt_out: EndpointState,
    bulk_in: EndpointState,
    bulk_out: EndpointState,
}

// SAFETY: wasm targets execute on a single thread, and `UsbDevice` handles are
// only ever accessed from that thread. Marking the transport as `Send`
// satisfies the host trait bounds without introducing additional sharing.
unsafe impl Send for WebUsbTransport {}

#[derive(Clone)]
pub struct WebUsbControlHandle {
    device: UsbDevice,
    #[allow(dead_code)]
    interface_number: u8,
}

unsafe impl Send for WebUsbControlHandle {}

impl WebUsbTransport {
    pub async fn new(device: UsbDevice) -> TransportResult<Self> {
        let transport = Self::configure_device(device).await?;
        Ok(transport)
    }

    async fn configure_device(device: UsbDevice) -> TransportResult<Self> {
        if !device.opened() {
            JsFuture::from(device.open())
                .await
                .map_err(|err| js_error("open WebUSB device", err))?;
        }
        let discovered = discover_interface(&device)?;
        if device.configuration().map(|cfg| cfg.configuration_value())
            != Some(discovered.configuration_value)
        {
            let select = device.select_configuration(discovered.configuration_value);
            JsFuture::from(select)
                .await
                .map_err(|err| js_error("select WebUSB configuration", err))?;
        }
        let claim = device.claim_interface(discovered.interface_number);
        JsFuture::from(claim)
            .await
            .map_err(|err| js_error("claim WebUSB interface", err))?;
        Ok(Self {
            device,
            configuration_value: discovered.configuration_value,
            interface_number: discovered.interface_number,
            interrupt_in: EndpointState::from_descriptor(discovered.interrupt_in),
            interrupt_out: EndpointState::from_descriptor(discovered.interrupt_out),
            bulk_in: EndpointState::from_descriptor(discovered.bulk_in),
            bulk_out: EndpointState::from_descriptor(discovered.bulk_out),
        })
    }

    pub fn control_handle(&self) -> WebUsbControlHandle {
        WebUsbControlHandle {
            device: self.device.clone(),
            interface_number: self.interface_number,
        }
    }

    async fn read_exact(
        &mut self,
        endpoint: &mut EndpointState,
        len: usize,
        label: &str,
    ) -> TransportResult<Vec<u8>> {
        let transfer_len = u32_len(len, label)?;
        endpoint.drain(label).await?;
        let promise = self.device.transfer_in(endpoint.number, transfer_len);
        endpoint.track(&promise);
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error(&format!("await {label}"), err))?;
        endpoint.clear();
        let transfer: UsbInTransferResult = result
            .dyn_into()
            .map_err(|value| type_error("UsbInTransferResult", value))?;
        ensure_transfer_ok(&transfer, label)?;
        extract_transfer_bytes(&transfer, len, label)
    }

    async fn write_exact(
        &mut self,
        endpoint: &mut EndpointState,
        data: &[u8],
        label: &str,
    ) -> TransportResult<()> {
        if data.is_empty() {
            endpoint.drain(label).await?;
            return Ok(());
        }
        endpoint.drain(label).await?;
        let payload_len = u32_len(data.len(), label)?;
        let payload = Uint8Array::new_with_length(payload_len);
        payload.copy_from(data);
        let promise = self
            .device
            .transfer_out_with_u8_array(endpoint.number, &payload)
            .map_err(|err| js_error(&format!("submit {label}"), err))?;
        endpoint.track(&promise);
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error(&format!("await {label}"), err))?;
        endpoint.clear();
        let transfer: UsbOutTransferResult = result
            .dyn_into()
            .map_err(|value| type_error("UsbOutTransferResult", value))?;
        ensure_out_transfer_ok(&transfer, data.len(), label)
    }
}

#[async_trait]
impl Transport for WebUsbTransport {
    async fn read_request(&mut self) -> TransportResult<Request> {
        let bytes = self
            .read_exact(&mut self.interrupt_in, REQUEST_LEN, "interrupt-in transfer")
            .await?;
        Request::try_from(bytes.as_slice())
            .map_err(|err| protocol_error(format!("decode request: {err}")))
    }

    async fn send_response(&mut self, response: Response) -> TransportResult<()> {
        let data = response.encode();
        self.write_exact(&mut self.interrupt_out, &data, "interrupt-out transfer")
            .await
    }

    async fn read_bulk(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let bytes = self
            .read_exact(&mut self.bulk_in, buf.len(), "bulk-in transfer")
            .await?;
        if bytes.len() != buf.len() {
            return Err(protocol_error(format!(
                "bulk read truncated (expected {}, got {})",
                buf.len(),
                bytes.len()
            )));
        }
        buf.copy_from_slice(&bytes);
        Ok(())
    }

    async fn write_bulk(&mut self, buf: &[u8]) -> TransportResult<()> {
        self.write_exact(&mut self.bulk_out, buf, "bulk-out transfer")
            .await
    }
}

#[async_trait]
impl ControlTransport for WebUsbTransport {
    async fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let mut handle = self.control_handle();
        handle
            .control_in(request_type, request, value, index, buf)
            .await
    }

    async fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> TransportResult<()> {
        let mut handle = self.control_handle();
        handle
            .control_out(request_type, request, value, index, data)
            .await
    }
}

#[async_trait]
impl ControlTransport for WebUsbControlHandle {
    async fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        ensure_direction(request_type, true)?;
        let (recipient, req_type) = decode_request_type(request_type)?;
        let params = UsbControlTransferParameters::new(index, recipient, request, req_type, value);
        let promise = self
            .device
            .control_transfer_in(&params, u16_len(buf.len(), "control-in transfer")?);
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error("await control-in transfer", err))?;
        let transfer: UsbInTransferResult = result
            .dyn_into()
            .map_err(|value| type_error("UsbInTransferResult", value))?;
        ensure_transfer_ok(&transfer, "control-in transfer")?;
        let data = extract_transfer_bytes(&transfer, buf.len(), "control-in transfer")?;
        buf.copy_from_slice(&data);
        Ok(data.len())
    }

    async fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> TransportResult<()> {
        ensure_direction(request_type, false)?;
        let (recipient, req_type) = decode_request_type(request_type)?;
        let params = UsbControlTransferParameters::new(index, recipient, request, req_type, value);
        let payload_len = u32_len(data.len(), "control-out transfer")?;
        let payload = Uint8Array::new_with_length(payload_len);
        payload.copy_from(data);
        let promise = self
            .device
            .control_transfer_out_with_u8_array(&params, &payload)
            .map_err(|err| js_error("submit control-out transfer", err))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| js_error("await control-out transfer", err))?;
        let transfer: UsbOutTransferResult = result
            .dyn_into()
            .map_err(|value| type_error("UsbOutTransferResult", value))?;
        ensure_out_transfer_ok(&transfer, data.len(), "control-out transfer")
    }
}

struct EndpointState {
    number: u8,
    #[allow(dead_code)]
    max_packet_size: u32,
    inflight: Option<Promise>,
}

impl EndpointState {
    fn from_descriptor(descriptor: EndpointDescriptor) -> Self {
        Self {
            number: descriptor.number,
            max_packet_size: descriptor.max_packet_size,
            inflight: None,
        }
    }

    async fn drain(&mut self, label: &str) -> TransportResult<()> {
        if let Some(promise) = self.inflight.take() {
            JsFuture::from(promise)
                .await
                .map_err(|err| js_error(&format!("await prior {label}"), err))?;
        }
        Ok(())
    }

    fn track(&mut self, promise: &Promise) {
        self.inflight = Some(promise.clone());
    }

    fn clear(&mut self) {
        self.inflight = None;
    }
}

struct EndpointDescriptor {
    number: u8,
    #[allow(dead_code)]
    max_packet_size: u32,
}

struct DiscoveredInterface {
    configuration_value: u8,
    interface_number: u8,
    interrupt_in: EndpointDescriptor,
    interrupt_out: EndpointDescriptor,
    bulk_in: EndpointDescriptor,
    bulk_out: EndpointDescriptor,
}

fn discover_interface(device: &UsbDevice) -> TransportResult<DiscoveredInterface> {
    let configs = device.configurations();
    for cfg_value in configs.iter() {
        let config: UsbConfiguration = cfg_value
            .dyn_into()
            .map_err(|value| type_error("UsbConfiguration", value))?;
        let interfaces = config.interfaces();
        for iface_value in interfaces.iter() {
            let interface: UsbInterface = iface_value
                .dyn_into()
                .map_err(|value| type_error("UsbInterface", value))?;
            let interface_number = interface.interface_number();
            let alternates = interface.alternates();
            for alt_value in alternates.iter() {
                let alternate: UsbAlternateInterface = alt_value
                    .dyn_into()
                    .map_err(|value| type_error("UsbAlternateInterface", value))?;
                if alternate.interface_class() == SMOO_INTERFACE_CLASS
                    && alternate.interface_subclass() == SMOO_INTERFACE_SUBCLASS
                    && alternate.interface_protocol() == SMOO_INTERFACE_PROTOCOL
                {
                    if let Some(endpoints) = collect_endpoints(&alternate)? {
                        return Ok(DiscoveredInterface {
                            configuration_value: config.configuration_value(),
                            interface_number,
                            interrupt_in: endpoints.interrupt_in,
                            interrupt_out: endpoints.interrupt_out,
                            bulk_in: endpoints.bulk_in,
                            bulk_out: endpoints.bulk_out,
                        });
                    }
                }
            }
        }
    }
    Err(TransportError::with_message(
        TransportErrorKind::Unsupported,
        "No smoo-compatible WebUSB interfaces found",
    ))
}

struct EndpointSet {
    interrupt_in: EndpointDescriptor,
    interrupt_out: EndpointDescriptor,
    bulk_in: EndpointDescriptor,
    bulk_out: EndpointDescriptor,
}

fn collect_endpoints(alternate: &UsbAlternateInterface) -> TransportResult<Option<EndpointSet>> {
    let mut interrupt_in = None;
    let mut interrupt_out = None;
    let mut bulk_in = None;
    let mut bulk_out = None;
    let endpoints: Array = alternate.endpoints();
    for ep_value in endpoints.iter() {
        let endpoint: UsbEndpoint = ep_value
            .dyn_into()
            .map_err(|value| type_error("UsbEndpoint", value))?;
        match (endpoint.type_(), endpoint.direction()) {
            (UsbEndpointType::Interrupt, UsbDirection::In) if interrupt_in.is_none() => {
                interrupt_in = Some(describe_endpoint(&endpoint));
            }
            (UsbEndpointType::Interrupt, UsbDirection::Out) if interrupt_out.is_none() => {
                interrupt_out = Some(describe_endpoint(&endpoint));
            }
            (UsbEndpointType::Bulk, UsbDirection::In) if bulk_in.is_none() => {
                bulk_in = Some(describe_endpoint(&endpoint));
            }
            (UsbEndpointType::Bulk, UsbDirection::Out) if bulk_out.is_none() => {
                bulk_out = Some(describe_endpoint(&endpoint));
            }
            _ => {}
        }
    }
    match (interrupt_in, interrupt_out, bulk_in, bulk_out) {
        (Some(interrupt_in), Some(interrupt_out), Some(bulk_in), Some(bulk_out)) => {
            Ok(Some(EndpointSet {
                interrupt_in,
                interrupt_out,
                bulk_in,
                bulk_out,
            }))
        }
        _ => Ok(None),
    }
}

fn describe_endpoint(endpoint: &UsbEndpoint) -> EndpointDescriptor {
    EndpointDescriptor {
        number: endpoint.endpoint_number(),
        max_packet_size: endpoint.packet_size(),
    }
}

fn ensure_transfer_ok(result: &UsbInTransferResult, label: &str) -> TransportResult<()> {
    match result.status() {
        UsbTransferStatus::Ok => Ok(()),
        UsbTransferStatus::Stall | UsbTransferStatus::Babble => Err(protocol_error(format!(
            "{label} failed with status {:?}",
            result.status()
        ))),
    }
}

fn ensure_out_transfer_ok(
    result: &UsbOutTransferResult,
    expected: usize,
    label: &str,
) -> TransportResult<()> {
    match result.status() {
        UsbTransferStatus::Ok => {
            if result.bytes_written() as usize != expected {
                return Err(protocol_error(format!(
                    "{label} truncated (expected {expected}, wrote {})",
                    result.bytes_written()
                )));
            }
            Ok(())
        }
        UsbTransferStatus::Stall | UsbTransferStatus::Babble => Err(protocol_error(format!(
            "{label} failed with status {:?}",
            result.status()
        ))),
    }
}

fn extract_transfer_bytes(
    result: &UsbInTransferResult,
    expected_len: usize,
    label: &str,
) -> TransportResult<Vec<u8>> {
    let view: DataView = result
        .data()
        .ok_or_else(|| protocol_error(format!("{label} returned no data")))?;
    let len = view.byte_length() as usize;
    if len != expected_len {
        return Err(protocol_error(format!(
            "{label} length mismatch (expected {expected_len}, got {len})"
        )));
    }
    let offset = view.byte_offset() as u32;
    let array = Uint8Array::new(&view.buffer()).subarray(offset, offset + view.byte_length());
    let mut buf = vec![0u8; len];
    array.copy_to(&mut buf);
    Ok(buf)
}

fn ensure_direction(request_type: u8, expect_in: bool) -> TransportResult<()> {
    let is_in = (request_type & 0x80) != 0;
    if is_in == expect_in {
        Ok(())
    } else {
        Err(TransportError::with_message(
            TransportErrorKind::Unsupported,
            format!(
                "unsupported control direction (request_type={:#04x}, expected {})",
                request_type,
                if expect_in { "IN" } else { "OUT" }
            ),
        ))
    }
}

fn decode_request_type(request_type: u8) -> TransportResult<(UsbRecipient, UsbRequestType)> {
    let recipient = match request_type & 0x1F {
        1 => UsbRecipient::Interface,
        _ => {
            return Err(TransportError::with_message(
                TransportErrorKind::Unsupported,
                format!("unsupported recipient in request_type {request_type:#04x}"),
            ));
        }
    };
    let req_type = match (request_type >> 5) & 0x03 {
        2 => UsbRequestType::Vendor,
        _ => {
            return Err(TransportError::with_message(
                TransportErrorKind::Unsupported,
                format!("unsupported request type {request_type:#04x}"),
            ));
        }
    };
    Ok((recipient, req_type))
}

fn u32_len(len: usize, label: &str) -> TransportResult<u32> {
    u32::try_from(len).map_err(|_| {
        TransportError::with_message(
            TransportErrorKind::Unsupported,
            format!("{label} size {len} exceeds WebUSB limits"),
        )
    })
}

fn u16_len(len: usize, label: &str) -> TransportResult<u16> {
    u16::try_from(len).map_err(|_| {
        TransportError::with_message(
            TransportErrorKind::Unsupported,
            format!("{label} size {len} exceeds control transfer limits"),
        )
    })
}

fn js_error(context: &str, err: JsValue) -> TransportError {
    if let Some(dom) = err.dyn_ref::<DomException>() {
        let kind = match dom.name().as_str() {
            "NetworkError" => TransportErrorKind::Disconnected,
            "NotFoundError" | "InvalidAccessError" => TransportErrorKind::Unsupported,
            "TimeoutError" => TransportErrorKind::Timeout,
            _ => TransportErrorKind::Other,
        };
        return TransportError::with_message(kind, format!("{context}: {}", dom.message()));
    }
    TransportError::with_message(TransportErrorKind::Other, format!("{context}: {:?}", err))
}

fn type_error(expected: &str, value: JsValue) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Other,
        format!("type mismatch: expected {expected}, got {:?}", value),
    )
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}
