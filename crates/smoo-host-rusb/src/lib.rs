use async_trait::async_trait;
use rusb::{DeviceHandle, UsbContext};
use smoo_host_core::{
    ControlTransport, Transport, TransportError, TransportErrorKind, TransportResult,
};
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

#[derive(Clone)]
pub struct RusbControl<T: UsbContext + Send + Sync + 'static> {
    handle: Arc<Mutex<DeviceHandle<T>>>,
    interface: u8,
    timeout: Duration,
}

impl<T: UsbContext + Send + Sync + 'static> RusbControl<T> {
    pub fn new(handle: Arc<Mutex<DeviceHandle<T>>>, interface: u8, timeout: Duration) -> Self {
        Self {
            handle,
            interface,
            timeout,
        }
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> ControlTransport for RusbControl<T> {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        let handle = self.handle.clone();
        let interface = self.interface;
        let timeout = self.timeout;
        let len = buf.len();
        let (read, data) = task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let handle = handle.lock().unwrap();
            let read = handle.read_control(
                request_type,
                request,
                0,
                interface as u16,
                &mut tmp,
                timeout,
            )?;
            Ok::<_, rusb::Error>((read, tmp))
        })
        .await
        .map_err(|err| join_error("control-in transfer", err))?
        .map_err(|err| map_rusb_error("control-in transfer", err))?;
        buf[..read].copy_from_slice(&data[..read]);
        Ok(read)
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        let payload = data.to_vec();
        let handle = self.handle.clone();
        let interface = self.interface;
        let timeout = self.timeout;
        task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_control(
                request_type,
                request,
                0,
                interface as u16,
                &payload,
                timeout,
            )
        })
        .await
        .map_err(|err| join_error("control-out transfer", err))?
        .map_err(|err| map_rusb_error("control-out transfer", err))
    }
}

/// [`Transport`] implementation backed by `rusb`.
pub struct RusbTransport<T: UsbContext + Send + Sync + 'static> {
    control: RusbControl<T>,
    config: RusbTransportConfig,
}

impl<T: UsbContext + Send + Sync + 'static> RusbTransport<T> {
    pub fn new(handle: DeviceHandle<T>, config: RusbTransportConfig) -> TransportResult<Self> {
        handle
            .claim_interface(config.interface)
            .map_err(|err| map_rusb_error("claim usb interface", err))?;
        let control = RusbControl::new(
            Arc::new(Mutex::new(handle)),
            config.interface,
            config.timeout,
        );
        Ok(Self { control, config })
    }

    /// Returns a clonable control handle for issuing vendor requests alongside the transport.
    pub fn control_handle(&self) -> RusbControl<T> {
        self.control.clone()
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> ControlTransport for RusbTransport<T> {
    async fn control_in(
        &self,
        request_type: u8,
        request: u8,
        buf: &mut [u8],
    ) -> TransportResult<usize> {
        self.control.control_in(request_type, request, buf).await
    }

    async fn control_out(
        &self,
        request_type: u8,
        request: u8,
        data: &[u8],
    ) -> TransportResult<usize> {
        self.control.control_out(request_type, request, data).await
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> Transport for RusbTransport<T> {
    async fn read_interrupt(&mut self, buf: &mut [u8]) -> TransportResult<usize> {
        let handle = self.control.handle.clone();
        let endpoint = self.config.interrupt_in;
        let timeout = self.config.timeout;
        let len = buf.len();
        task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let handle = handle.lock().unwrap();
            let read = handle.read_interrupt(endpoint, &mut tmp, timeout)?;
            Ok::<_, rusb::Error>((read, tmp))
        })
        .await
        .map_err(|err| join_error("interrupt-in read", err))?
        .map_err(|err| map_rusb_error("interrupt-in read", err))
        .map(|(read, tmp)| {
            buf[..read].copy_from_slice(&tmp[..read]);
            read
        })
    }

    async fn write_interrupt(&mut self, buf: &[u8]) -> TransportResult<usize> {
        let payload = buf.to_vec();
        let handle = self.control.handle.clone();
        let endpoint = self.config.interrupt_out;
        let timeout = self.config.timeout;
        task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_interrupt(endpoint, &payload, timeout)
        })
        .await
        .map_err(|err| join_error("interrupt-out write", err))?
        .map_err(|err| map_rusb_error("interrupt-out write", err))
    }

    async fn read_bulk(&mut self, buf: &mut [u8]) -> TransportResult<usize> {
        let len = buf.len();
        if len == 0 {
            return Ok(0);
        }
        let handle = self.control.handle.clone();
        let endpoint = self.config.bulk_in;
        let timeout = self.config.timeout;
        task::spawn_blocking(move || {
            let mut tmp = vec![0u8; len];
            let handle = handle.lock().unwrap();
            let read = handle.read_bulk(endpoint, &mut tmp, timeout)?;
            Ok::<_, rusb::Error>((read, tmp))
        })
        .await
        .map_err(|err| join_error("bulk-in read", err))?
        .map_err(|err| map_rusb_error("bulk-in read", err))
        .map(|(read, tmp)| {
            buf[..read].copy_from_slice(&tmp[..read]);
            read
        })
    }

    async fn write_bulk(&mut self, buf: &[u8]) -> TransportResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let payload = buf.to_vec();
        let handle = self.control.handle.clone();
        let endpoint = self.config.bulk_out;
        let timeout = self.config.timeout;
        task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_bulk(endpoint, &payload, timeout)
        })
        .await
        .map_err(|err| join_error("bulk-out write", err))?
        .map_err(|err| map_rusb_error("bulk-out write", err))
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
