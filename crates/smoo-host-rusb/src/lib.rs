use async_trait::async_trait;
use rusb::{DeviceHandle, UsbContext};
use smoo_host_core::{Transport, TransportError, TransportErrorKind, TransportResult};
use smoo_proto::{IDENT_LEN, IDENT_REQUEST, Ident, REQUEST_LEN, RESPONSE_LEN, Request, Response};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task;
use tracing::debug;

const IDENT_REQ_TYPE: u8 = 0xC1;
const CONFIG_REQ_TYPE: u8 = 0x41;
const CONFIG_EXPORTS_REQUEST: u8 = 0x02;

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
    ident: Option<Ident>,
}

impl<T: UsbContext + Send + Sync + 'static> RusbTransport<T> {
    pub fn new(handle: DeviceHandle<T>, config: RusbTransportConfig) -> TransportResult<Self> {
        handle
            .claim_interface(config.interface)
            .map_err(|err| map_rusb_error("claim usb interface", err))?;
        Ok(Self {
            handle: Arc::new(Mutex::new(handle)),
            config,
            ident: None,
        })
    }

    fn ident_request_type(&self) -> u8 {
        IDENT_REQ_TYPE
    }

    async fn perform_ident(&mut self) -> TransportResult<Ident> {
        if let Some(ident) = self.ident {
            return Ok(ident);
        }
        let handle = self.handle.clone();
        let request_type = self.ident_request_type();
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
        .map_err(|err| join_error("ident control transfer", err))?
        .map_err(|err| map_rusb_error("ident control transfer", err))?;

        if len != IDENT_LEN {
            return Err(protocol_error(format!(
                "ident control transfer truncated (expected {IDENT_LEN}, got {len})"
            )));
        }
        let ident = Ident::decode(buf)
            .map_err(|err| protocol_error(format!("decode ident response: {err}")))?;
        debug!(
            major = ident.major,
            minor = ident.minor,
            interface = interface,
            "ident handshake complete"
        );
        self.ident = Some(ident);
        Ok(ident)
    }

    pub async fn ensure_ident(&mut self) -> TransportResult<Ident> {
        self.perform_ident().await
    }

    pub async fn send_config_exports_v0(
        &mut self,
        payload: &ConfigExportsV0Payload,
    ) -> TransportResult<()> {
        let handle = self.handle.clone();
        let interface = self.config.interface;
        let timeout = self.config.timeout;
        let data = payload.encode();
        let written = task::spawn_blocking(move || {
            let handle = handle.lock().unwrap();
            handle.write_control(
                CONFIG_REQ_TYPE,
                CONFIG_EXPORTS_REQUEST,
                0,
                interface as u16,
                &data,
                timeout,
            )
        })
        .await
        .map_err(|err| join_error("CONFIG_EXPORTS control transfer", err))?
        .map_err(|err| map_rusb_error("CONFIG_EXPORTS control transfer", err))?;
        if written != ConfigExportsV0Payload::ENCODED_LEN {
            return Err(protocol_error(format!(
                "CONFIG_EXPORTS transfer truncated (expected {}, got {written})",
                ConfigExportsV0Payload::ENCODED_LEN
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl<T: UsbContext + Send + Sync + 'static> Transport for RusbTransport<T> {
    async fn setup(&mut self) -> TransportResult<Ident> {
        self.perform_ident().await
    }

    async fn read_request(&mut self) -> TransportResult<Request> {
        if self.ident.is_none() {
            return Err(not_ready());
        }
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
        if self.ident.is_none() {
            return Err(not_ready());
        }
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
        if self.ident.is_none() {
            return Err(not_ready());
        }
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
        if self.ident.is_none() {
            return Err(not_ready());
        }
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

fn not_ready() -> TransportError {
    TransportError::with_message(
        TransportErrorKind::NotReady,
        "transport not set up".to_string(),
    )
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message.into())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0Payload {
    count: u16,
    block_size: u32,
    size_bytes: u64,
}

impl ConfigExportsV0Payload {
    pub const ENCODED_LEN: usize = 28;

    pub fn zero_exports() -> Self {
        Self {
            count: 0,
            block_size: 0,
            size_bytes: 0,
        }
    }

    pub fn single_export(block_size: u32, size_bytes: u64) -> Self {
        Self {
            count: 1,
            block_size,
            size_bytes,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut buf = [0u8; Self::ENCODED_LEN];
        buf[0..2].copy_from_slice(&0u16.to_le_bytes());
        buf[2..4].copy_from_slice(&self.count.to_le_bytes());
        buf[4..8].copy_from_slice(&0u32.to_le_bytes());
        buf[8..12].copy_from_slice(&self.block_size.to_le_bytes());
        buf[12..20].copy_from_slice(&self.size_bytes.to_le_bytes());
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        buf[24..28].copy_from_slice(&0u32.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigExportsV0Payload;

    #[test]
    fn config_exports_single_encodes_fields() {
        let payload = ConfigExportsV0Payload::single_export(4096, 8192);
        let encoded = payload.encode();
        assert_eq!(encoded.len(), ConfigExportsV0Payload::ENCODED_LEN);
        assert_eq!(&encoded[2..4], &[1, 0]);
        assert_eq!(&encoded[8..12], &4096u32.to_le_bytes());
        assert_eq!(&encoded[12..20], &8192u64.to_le_bytes());
    }
}
