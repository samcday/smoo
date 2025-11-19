use crate::{ControlTransport, TransportError, TransportErrorKind, TransportResult};
use alloc::vec::Vec;
use smoo_proto::{
    IDENT_LEN, IDENT_REQUEST, Ident, SMOO_STATUS_LEN, SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST,
    SmooStatusV0,
};

const SMOO_IDENT_REQ_TYPE: u8 = 0xC1;
const SMOO_CONFIG_REQ_TYPE: u8 = 0x41;
const CONFIG_EXPORTS_REQUEST: u8 = 0x02;

/// Execute the IDENT handshake against the gadget and decode its response.
pub async fn read_ident<T: ControlTransport>(
    control: &mut T,
    interface: u8,
) -> TransportResult<Ident> {
    let mut buf = [0u8; IDENT_LEN];
    let len = control
        .control_in(
            SMOO_IDENT_REQ_TYPE,
            IDENT_REQUEST,
            0,
            interface as u16,
            &mut buf,
        )
        .await?;
    if len != IDENT_LEN {
        return Err(protocol_error(format!(
            "IDENT transfer truncated (expected {IDENT_LEN}, got {len})"
        )));
    }
    Ident::decode(buf).map_err(|err| protocol_error(format!("decode IDENT: {err}")))
}

/// Issue CONFIG_EXPORTS with the provided payload.
pub async fn send_config_exports_v0<T: ControlTransport>(
    control: &mut T,
    interface: u8,
    payload: &ConfigExportsV0Payload,
) -> TransportResult<()> {
    let data = payload.encode();
    control
        .control_out(
            SMOO_CONFIG_REQ_TYPE,
            CONFIG_EXPORTS_REQUEST,
            0,
            interface as u16,
            &data,
        )
        .await
}

/// Read the SMOO_STATUS heartbeat payload.
pub async fn read_status_v0<T: ControlTransport>(
    control: &mut T,
    interface: u8,
) -> TransportResult<SmooStatusV0> {
    let mut buf = [0u8; SMOO_STATUS_LEN];
    let len = control
        .control_in(
            SMOO_STATUS_REQ_TYPE,
            SMOO_STATUS_REQUEST,
            0,
            interface as u16,
            &mut buf,
        )
        .await?;
    if len != SMOO_STATUS_LEN {
        return Err(protocol_error(format!(
            "SMOO_STATUS transfer truncated (expected {SMOO_STATUS_LEN}, got {len})"
        )));
    }
    SmooStatusV0::try_from_slice(&buf[..len])
        .map_err(|err| protocol_error(format!("decode SMOO_STATUS payload: {err}")))
}

/// Control-plane helper that can be cloned and driven from background tasks.
#[derive(Clone)]
pub struct StatusClient<C> {
    control: C,
    interface: u8,
}

impl<C> StatusClient<C> {
    pub fn new(control: C, interface: u8) -> Self {
        Self { control, interface }
    }

    pub fn interface(&self) -> u8 {
        self.interface
    }
}

impl<C> StatusClient<C>
where
    C: ControlTransport,
{
    pub async fn read_status(&mut self) -> TransportResult<SmooStatusV0> {
        read_status_v0(&mut self.control, self.interface).await
    }
}

/// CONFIG_EXPORTS payload describing the exports for the current session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0Payload {
    entries: Vec<ConfigExportEntry>,
}

/// Descriptor for a single export advertised to the gadget.
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

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
}
