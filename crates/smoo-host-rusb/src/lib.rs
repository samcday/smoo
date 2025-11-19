use async_trait::async_trait;
use rusb::{DeviceHandle, UsbContext};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
use smoo_proto::{REQUEST_LEN, RESPONSE_LEN, Request, Response};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task;

/// Configuration for [`RusbTransport`].
#[derive(Clone, Copy, Debug)]
pub struct RusbTransportConfig {
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
    /// Timeout applied to interrupt/control transfers.
    pub timeout: Duration,
}

impl Default for RusbTransportConfig {
    fn default() -> Self {
        Self {
            interface: 0,
            interrupt_in: 0x81,
            interrupt_out: 0x01,
            bulk_in: 0x82,
            bulk_out: 0x02,
            timeout: Duration::from_secs(1),
        }
    }
}

/// [`Transport`] implementation backed by `rusb`.
pub struct RusbTransport<T: UsbContext + Send + Sync + 'static> {
    handle: Arc<Mutex<DeviceHandle<T>>>,
    config: RusbTransportConfig,
}

impl<T: UsbContext + Send + Sync + 'static> RusbTransport<T> {
    pub fn new(handle: DeviceHandle<T>, config: RusbTransportConfig) -> TransportResult<Self> {
        handle
            .claim_interface(config.interface)
            .map_err(|err| map_rusb_error("claim usb interface", err))?;
        Ok(Self {
            handle: Arc::new(Mutex::new(handle)),
            config,
        })
    }

    /// Returns a control handle that can issue vendor requests alongside the transport.
    pub fn control_handle(&self) -> RusbControlHandle<T> {
        RusbControlHandle {
            handle: self.handle.clone(),
            timeout: self.config.timeout,
        }
    }
}

#[derive(Clone)]
pub struct RusbControlHandle<T: UsbContext + Send + Sync + 'static> {
    handle: Arc<Mutex<DeviceHandle<T>>>,
    timeout: Duration,
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> ControlTransport for RusbTransport<T> {
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
impl<T: UsbContext + Send + Sync + 'static> ControlTransport for RusbControlHandle<T> {
    async fn control_in(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let handle = self.handle.clone();
        let timeout = self.timeout;
        let len = buf.len();
        let (read, data) = task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let handle = handle.lock().unwrap();
            let read =
                handle.read_control(request_type, request, value, index, &mut tmp, timeout)?;
            Ok::<_, rusb::Error>((read, tmp))
        })
        .await
        .map_err(|err| join_error("control-in transfer", err))?
        .map_err(|err| map_rusb_error("control-in transfer", err))?;
        if read > len {
            return Err(protocol_error(format!(
                "control-in transfer overran buffer (read {read}, buf len {len})"
            )));
        }
        buf[..read].copy_from_slice(&data[..read]);
        Ok(read)
    }

    async fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> TransportResult<()> {
        let handle = self.handle.clone();
        let timeout = self.timeout;
        let payload = data.to_vec();
        let written = task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_control(request_type, request, value, index, &payload, timeout)
        })
        .await
        .map_err(|err| join_error("control-out transfer", err))?
        .map_err(|err| map_rusb_error("control-out transfer", err))?;
        if written != data.len() {
            return Err(protocol_error(format!(
                "control-out transfer truncated (expected {}, wrote {written})",
                data.len()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> Transport for RusbTransport<T> {
    async fn read_request(&mut self) -> TransportResult<Request> {
        let handle = self.handle.clone();
        let endpoint = self.config.interrupt_in;
        let timeout = self.config.timeout;
        let (len, buf) = task::spawn_blocking(move || {
            let mut data = [0u8; REQUEST_LEN];
            let handle = handle.lock().unwrap();
            let read = handle.read_interrupt(endpoint, &mut data, timeout)?;
            Ok::<_, rusb::Error>((read, data))
        })
        .await
        .map_err(|err| join_error("interrupt-in read", err))?
        .map_err(|err| map_rusb_error("interrupt-in read", err))?;

        if len != REQUEST_LEN {
            return Err(protocol_error(format!(
                "request transfer truncated (expected {REQUEST_LEN}, got {len})"
            )));
        }
        Request::decode(buf).map_err(|err| protocol_error(format!("decode request: {err}")))
    }

    async fn send_response(&mut self, response: Response) -> TransportResult<()> {
        let handle = self.handle.clone();
        let endpoint = self.config.interrupt_out;
        let timeout = self.config.timeout;
        let data = response.encode();
        let written = task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_interrupt(endpoint, &data, timeout)
        })
        .await
        .map_err(|err| join_error("interrupt-out write", err))?
        .map_err(|err| map_rusb_error("interrupt-out write", err))?;

        if written != RESPONSE_LEN {
            return Err(protocol_error(format!(
                "response transfer truncated (expected {RESPONSE_LEN}, wrote {written})"
            )));
        }
        Ok(())
    }

    async fn read_bulk(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        let len = buf.len();
        if len == 0 {
            return Ok(());
        }
        let handle = self.handle.clone();
        let endpoint = self.config.bulk_in;
        let timeout = self.config.timeout;
        let (read, data) = task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let handle = handle.lock().unwrap();
            let read = handle.read_bulk(endpoint, &mut tmp, timeout)?;
            Ok::<_, rusb::Error>((read, tmp))
        })
        .await
        .map_err(|err| join_error("bulk-in read", err))?
        .map_err(|err| map_rusb_error("bulk-in read", err))?;
        if read != len {
            return Err(protocol_error(format!(
                "bulk read truncated (expected {len}, got {read})"
            )));
        }
        buf.copy_from_slice(&data[..len]);
        Ok(())
    }

    async fn write_bulk(&mut self, buf: &[u8]) -> TransportResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let data = buf.to_vec();
        let len = data.len();
        let handle = self.handle.clone();
        let endpoint = self.config.bulk_out;
        let timeout = self.config.timeout;
        let written = task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_bulk(endpoint, &data, timeout)
        })
        .await
        .map_err(|err| join_error("bulk-out write", err))?
        .map_err(|err| map_rusb_error("bulk-out write", err))?;
        if written != len {
            return Err(protocol_error(format!(
                "bulk write truncated (expected {len}, wrote {written})"
            )));
        }
        Ok(())
    }
}

fn map_rusb_error(op: &str, err: rusb::Error) -> TransportError {
    let kind = match err {
        rusb::Error::Timeout => TransportErrorKind::Timeout,
        rusb::Error::NoDevice => TransportErrorKind::Disconnected,
        rusb::Error::Pipe | rusb::Error::Overflow => TransportErrorKind::Protocol,
        rusb::Error::NotFound => TransportErrorKind::Unsupported,
        _ => TransportErrorKind::Other,
    };
    TransportError::with_message(kind, format!("{op}: {err}"))
}

fn join_error(op: &str, err: task::JoinError) -> TransportError {
    TransportError::with_message(
        TransportErrorKind::Other,
        format!("{op} task join failed: {err}"),
    )
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message.into())
}
