use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use rusb::{DeviceHandle, Direction, Recipient, RequestType, UsbContext};
use smoo_host_core::Transport;
use smoo_proto::{IDENT_LEN, IDENT_REQUEST, Ident, REQUEST_LEN, RESPONSE_LEN, Request, Response};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task;
use tracing::debug;

/// Configuration for [`RusbTransport`].
#[derive(Clone, Copy, Debug)]
pub struct RusbTransportConfig {
    /// Interface number to claim before issuing transfers.
    pub interface: u8,
    /// Interrupt endpoint address used to receive Request messages (device → host).
    pub interrupt_in: u8,
    /// Interrupt endpoint address used to send Response messages (host → device).
    pub interrupt_out: u8,
    /// Timeout applied to interrupt/control transfers.
    pub timeout: Duration,
}

impl Default for RusbTransportConfig {
    fn default() -> Self {
        Self {
            interface: 0,
            interrupt_in: 0x81,
            interrupt_out: 0x01,
            timeout: Duration::from_secs(1),
        }
    }
}

/// [`Transport`] implementation backed by `rusb`.
pub struct RusbTransport<T: UsbContext + Send + Sync + 'static> {
    handle: Arc<Mutex<DeviceHandle<T>>>,
    config: RusbTransportConfig,
    ident: Option<Ident>,
}

impl<T: UsbContext + Send + Sync + 'static> RusbTransport<T> {
    pub fn new(handle: DeviceHandle<T>, config: RusbTransportConfig) -> Result<Self> {
        handle
            .claim_interface(config.interface)
            .context("claim usb interface")?;
        Ok(Self {
            handle: Arc::new(Mutex::new(handle)),
            config,
            ident: None,
        })
    }

    fn request_type(&self) -> u8 {
        rusb::request_type(Direction::In, RequestType::Vendor, Recipient::Interface)
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> Transport for RusbTransport<T> {
    async fn setup(&mut self) -> Result<Ident> {
        if let Some(ident) = self.ident {
            return Ok(ident);
        }

        let handle = self.handle.clone();
        let request_type = self.request_type();
        let interface = self.config.interface;
        let timeout = self.config.timeout;
        let (len, buf) = task::spawn_blocking(move || {
            let mut data = [0u8; IDENT_LEN];
            let handle = handle.lock().unwrap();
            let read = handle.read_control(
                request_type,
                IDENT_REQUEST,
                0,
                interface as u16,
                &mut data,
                timeout,
            )?;
            Ok::<_, rusb::Error>((read, data))
        })
        .await
        .context("join ident control transfer")??;

        ensure!(
            len == IDENT_LEN,
            "ident control transfer truncated (expected {IDENT_LEN}, got {len})"
        );
        let ident = Ident::decode(buf).map_err(|err| anyhow!("decode ident response: {err}"))?;
        debug!(
            major = ident.major,
            minor = ident.minor,
            interface = interface,
            "ident handshake complete"
        );
        self.ident = Some(ident);
        Ok(ident)
    }

    async fn read_request(&mut self) -> Result<Request> {
        ensure!(self.ident.is_some(), "transport not set up");
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
        .context("join interrupt-in read")??;

        ensure!(
            len == REQUEST_LEN,
            "request transfer truncated (expected {REQUEST_LEN}, got {len})"
        );
        Request::decode(buf).map_err(|err| anyhow!("decode request: {err}"))
    }

    async fn send_response(&mut self, response: Response) -> Result<()> {
        ensure!(self.ident.is_some(), "transport not set up");
        let handle = self.handle.clone();
        let endpoint = self.config.interrupt_out;
        let timeout = self.config.timeout;
        let data = response.encode();
        let written = task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_interrupt(endpoint, &data, timeout)
        })
        .await
        .context("join interrupt-out write")??;

        ensure!(
            written == RESPONSE_LEN,
            "response transfer truncated (expected {RESPONSE_LEN}, wrote {written})"
        );
        Ok(())
    }
}
