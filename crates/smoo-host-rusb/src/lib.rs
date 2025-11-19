use async_trait::async_trait;
use rusb::{DeviceHandle, UsbContext};
use smoo_host_core::{Transport, TransportError, TransportErrorKind, TransportResult};
use smoo_proto::{
    IDENT_LEN, IDENT_REQUEST, Ident, REQUEST_LEN, RESPONSE_LEN, Request, Response, SMOO_STATUS_LEN,
    SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST, SmooStatusV0,
};
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
        let expected_len = data.len();
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
        if written != expected_len {
            return Err(protocol_error(format!(
                "CONFIG_EXPORTS transfer truncated (expected {expected_len}, got {written})"
            )));
        }
        Ok(())
    }

    /// Returns a status client that can issue SMOO_STATUS requests alongside the transport.
    pub fn status_client(&self) -> StatusClient<T> {
        StatusClient {
            handle: self.handle.clone(),
            interface: self.config.interface,
            timeout: self.config.timeout,
        }
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

/// Helper for issuing SMOO_STATUS control transfers.
#[derive(Clone)]
pub struct StatusClient<T: UsbContext + Send + Sync + 'static> {
    handle: Arc<Mutex<DeviceHandle<T>>>,
    interface: u8,
    timeout: Duration,
}

impl<T: UsbContext + Send + Sync + 'static> StatusClient<T> {
    pub async fn read_status(&self) -> TransportResult<SmooStatusV0> {
        let handle = self.handle.clone();
        let interface = self.interface;
        let timeout = self.timeout;
        let (len, buf) = task::spawn_blocking(move || {
            let mut data = [0u8; SMOO_STATUS_LEN];
            let handle = handle.lock().unwrap();
            let read = handle.read_control(
                SMOO_STATUS_REQ_TYPE,
                SMOO_STATUS_REQUEST,
                0,
                interface as u16,
                &mut data,
                timeout,
            )?;
            Ok::<_, rusb::Error>((read, data))
        })
        .await
        .map_err(|err| join_error("SMOO_STATUS control transfer", err))?
        .map_err(|err| map_rusb_error("SMOO_STATUS control transfer", err))?;
        if len != SMOO_STATUS_LEN {
            return Err(protocol_error(format!(
                "SMOO_STATUS transfer truncated (expected {SMOO_STATUS_LEN}, got {len})"
            )));
        }
        SmooStatusV0::try_from_slice(&buf[..len])
            .map_err(|err| protocol_error(format!("decode SMOO_STATUS payload: {err}")))
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0Payload {
    entries: Vec<ConfigExportEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigExportEntry {
    pub export_id: u32,
    pub block_size: u32,
    pub size_bytes: u64,
}

impl ConfigExportsV0Payload {
    pub const HEADER_LEN: usize = 8;
    pub const ENTRY_LEN: usize = 24;
    pub const MAX_EXPORTS: usize = 32;

    pub fn new(entries: Vec<ConfigExportEntry>) -> TransportResult<Self> {
        if entries.len() > Self::MAX_EXPORTS {
            return Err(protocol_error(format!(
                "CONFIG_EXPORTS entry count {} exceeds maximum {}",
                entries.len(),
                Self::MAX_EXPORTS
            )));
        }
        Ok(Self { entries })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::HEADER_LEN + self.entries.len() * Self::ENTRY_LEN];
        buf[2..4].copy_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for (idx, entry) in self.entries.iter().enumerate() {
            let offset = Self::HEADER_LEN + idx * Self::ENTRY_LEN;
            buf[offset..offset + 4].copy_from_slice(&entry.export_id.to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&entry.block_size.to_le_bytes());
            buf[offset + 8..offset + 16].copy_from_slice(&entry.size_bytes.to_le_bytes());
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigExportEntry, ConfigExportsV0Payload};

    #[test]
    fn config_exports_single_encodes_fields() {
        let payload = ConfigExportsV0Payload::new(vec![ConfigExportEntry {
            export_id: 5,
            block_size: 4096,
            size_bytes: 8192,
        }])
        .expect("payload");
        let encoded = payload.encode();
        assert_eq!(
            encoded.len(),
            ConfigExportsV0Payload::HEADER_LEN + ConfigExportsV0Payload::ENTRY_LEN
        );
        assert_eq!(&encoded[2..4], &[1, 0]);
        assert_eq!(&encoded[8..12], &5u32.to_le_bytes());
        assert_eq!(&encoded[12..16], &4096u32.to_le_bytes());
        assert_eq!(&encoded[16..24], &8192u64.to_le_bytes());
    }
}
