use crate::{ControlTransport, TransportError, TransportErrorKind, TransportResult};
use smoo_proto::{
    IDENT_LEN, IDENT_REQUEST, Ident, SMOO_STATUS_LEN, SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST,
    SmooStatusV0,
};

const IDENT_REQ_TYPE: u8 = 0xC1;
const CONFIG_REQ_TYPE: u8 = 0x41;
const CONFIG_EXPORTS_REQUEST: u8 = 0x02;

/// Payload for CONFIG_EXPORTS v0 requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigExportsV0Payload {
    count: u16,
    block_size: u32,
    size_bytes: u64,
}

impl ConfigExportsV0Payload {
    /// Number of bytes in the encoded CONFIG_EXPORTS v0 payload.
    pub const ENCODED_LEN: usize = 28;

    /// Encode a payload with no exports configured.
    pub const fn zero_exports() -> Self {
        Self {
            count: 0,
            block_size: 0,
            size_bytes: 0,
        }
    }

    /// Encode a payload with a single export.
    pub const fn single_export(block_size: u32, size_bytes: u64) -> Self {
        Self {
            count: 1,
            block_size,
            size_bytes,
        }
    }

    /// Encode the payload into the protocol wire format.
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

/// Execute the IDENT control transfer and decode the gadget's response.
pub async fn fetch_ident<T: ControlTransport>(transport: &T) -> TransportResult<Ident> {
    let mut buf = [0u8; IDENT_LEN];
    let len = transport
        .control_in(IDENT_REQ_TYPE, IDENT_REQUEST, &mut buf)
        .await?;
    if len != IDENT_LEN {
        return Err(protocol_error(format!(
            "ident control transfer truncated (expected {IDENT_LEN}, got {len})"
        )));
    }
    Ident::decode(buf).map_err(|err| protocol_error(format!("decode ident response: {err}")))
}

/// Send a v0 CONFIG_EXPORTS payload to the gadget.
pub async fn send_config_exports_v0<T: ControlTransport>(
    transport: &T,
    payload: &ConfigExportsV0Payload,
) -> TransportResult<()> {
    let data = payload.encode();
    let written = transport
        .control_out(CONFIG_REQ_TYPE, CONFIG_EXPORTS_REQUEST, &data)
        .await?;
    if written != ConfigExportsV0Payload::ENCODED_LEN {
        return Err(protocol_error(format!(
            "CONFIG_EXPORTS transfer truncated (expected {}, got {written})",
            ConfigExportsV0Payload::ENCODED_LEN
        )));
    }
    Ok(())
}

/// Issue a SMOO_STATUS request and decode the response payload.
pub async fn read_status<T: ControlTransport>(transport: &T) -> TransportResult<SmooStatusV0> {
    let mut buf = [0u8; SMOO_STATUS_LEN];
    let len = transport
        .control_in(SMOO_STATUS_REQ_TYPE, SMOO_STATUS_REQUEST, &mut buf)
        .await?;
    if len != SMOO_STATUS_LEN {
        return Err(protocol_error(format!(
            "SMOO_STATUS transfer truncated (expected {SMOO_STATUS_LEN}, got {len})"
        )));
    }
    SmooStatusV0::try_from_slice(&buf[..len])
        .map_err(|err| protocol_error(format!("decode SMOO_STATUS payload: {err}")))
}

fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::with_message(TransportErrorKind::Protocol, message)
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
