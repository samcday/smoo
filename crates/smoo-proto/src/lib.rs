#![no_std]

use core::{convert::TryFrom, fmt};

/// ASCII magic prefix for Ident handshake messages.
pub const IDENT_MAGIC: [u8; 4] = *b"SMOO";
/// Number of bytes in an encoded [`Ident`] message.
pub const IDENT_LEN: usize = 8;
/// Vendor control request opcode used to fetch [`Ident`].
pub const IDENT_REQUEST: u8 = 0x01;
/// Number of bytes in an encoded [`Request`] control message.
pub const REQUEST_LEN: usize = 20;
/// Number of bytes in an encoded [`Response`] control message.
pub const RESPONSE_LEN: usize = 20;
/// Vendor control bRequest used to fetch [`SmooStatusV0`].
pub const SMOO_STATUS_REQUEST: u8 = 0x03;
/// bmRequestType for SMOO status/heartbeat (device → host, vendor, interface).
pub const SMOO_STATUS_REQ_TYPE: u8 = 0xA1;
/// Number of bytes returned by [`SmooStatusV0`].
pub const SMOO_STATUS_LEN: usize = 16;
/// Supported status payload version.
pub const SMOO_STATUS_VERSION: u16 = 0;
/// Status flag indicating an active export.
pub const SMOO_STATUS_FLAG_EXPORT_ACTIVE: u16 = 1 << 0;

/// Errors surfaced while decoding protocol messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Buffer length did not match the protocol expectation.
    InvalidLength { expected: usize, actual: usize },
    /// Incoming opcode is unsupported.
    InvalidOpcode(u8),
    /// Ident magic prefix did not match `SMOO`.
    InvalidMagic,
    /// Payload or struct version mismatch.
    InvalidVersion { expected: u16, actual: u16 },
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::InvalidLength { expected, actual } => {
                write!(f, "invalid message length {actual}, expected {expected}")
            }
            ProtoError::InvalidOpcode(op) => write!(f, "invalid opcode {op}"),
            ProtoError::InvalidMagic => write!(f, "invalid ident magic"),
            ProtoError::InvalidVersion { expected, actual } => write!(
                f,
                "unsupported payload version {actual}, expected {expected}"
            ),
        }
    }
}

/// Result alias for protocol parsing operations.
pub type Result<T> = core::result::Result<T, ProtoError>;

/// Control-plane operations issued by ublk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Read = 0,
    Write = 1,
    Flush = 2,
    Discard = 3,
}

impl TryFrom<u8> for OpCode {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Read),
            1 => Ok(Self::Write),
            2 => Ok(Self::Flush),
            3 => Ok(Self::Discard),
            other => Err(ProtoError::InvalidOpcode(other)),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(op: OpCode) -> Self {
        op as u8
    }
}

/// Ident handshake sent from the gadget to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    pub major: u16,
    pub minor: u16,
}

impl Ident {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn encode(self) -> [u8; IDENT_LEN] {
        let mut buf = [0u8; IDENT_LEN];
        buf[0..4].copy_from_slice(&IDENT_MAGIC);
        buf[4..6].copy_from_slice(&self.major.to_le_bytes());
        buf[6..8].copy_from_slice(&self.minor.to_le_bytes());
        buf
    }

    pub fn decode(bytes: [u8; IDENT_LEN]) -> Result<Self> {
        if bytes[0..4] != IDENT_MAGIC {
            return Err(ProtoError::InvalidMagic);
        }
        let major = u16::from_le_bytes([bytes[4], bytes[5]]);
        let minor = u16::from_le_bytes([bytes[6], bytes[7]]);
        Ok(Self { major, minor })
    }
}

/// Request message emitted by the gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub op: OpCode,
    pub lba: u64,
    pub byte_len: u32,
    pub flags: u32,
}

impl Request {
    pub const fn new(op: OpCode, lba: u64, byte_len: u32, flags: u32) -> Self {
        Self {
            op,
            lba,
            byte_len,
            flags,
        }
    }

    pub fn encode(self) -> [u8; REQUEST_LEN] {
        encode_common(self.op, self.lba, self.byte_len, self.flags)
    }

    pub fn decode(bytes: [u8; REQUEST_LEN]) -> Result<Self> {
        decode_common(bytes).map(|(op, lba, byte_len, flags)| Self {
            op,
            lba,
            byte_len,
            flags,
        })
    }
}

impl TryFrom<&[u8]> for Request {
    type Error = ProtoError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != REQUEST_LEN {
            return Err(ProtoError::InvalidLength {
                expected: REQUEST_LEN,
                actual: value.len(),
            });
        }
        let mut buf = [0u8; REQUEST_LEN];
        buf.copy_from_slice(value);
        Self::decode(buf)
    }
}

/// Response message sent back by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub op: OpCode,
    pub lba: u64,
    pub byte_len: u32,
    pub flags: u32,
}

impl Response {
    pub const fn new(op: OpCode, lba: u64, byte_len: u32, flags: u32) -> Self {
        Self {
            op,
            lba,
            byte_len,
            flags,
        }
    }

    pub fn encode(self) -> [u8; RESPONSE_LEN] {
        encode_common(self.op, self.lba, self.byte_len, self.flags)
    }

    pub fn decode(bytes: [u8; RESPONSE_LEN]) -> Result<Self> {
        decode_common(bytes).map(|(op, lba, byte_len, flags)| Self {
            op,
            lba,
            byte_len,
            flags,
        })
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = ProtoError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != RESPONSE_LEN {
            return Err(ProtoError::InvalidLength {
                expected: RESPONSE_LEN,
                actual: value.len(),
            });
        }
        let mut buf = [0u8; RESPONSE_LEN];
        buf.copy_from_slice(value);
        Self::decode(buf)
    }
}

fn encode_common(op: OpCode, lba: u64, byte_len: u32, flags: u32) -> [u8; REQUEST_LEN] {
    let mut buf = [0u8; REQUEST_LEN];
    buf[0] = u8::from(op);
    buf[1..4].fill(0);
    buf[4..12].copy_from_slice(&lba.to_le_bytes());
    buf[12..16].copy_from_slice(&byte_len.to_le_bytes());
    buf[16..20].copy_from_slice(&flags.to_le_bytes());
    buf
}

fn decode_common(bytes: [u8; REQUEST_LEN]) -> Result<(OpCode, u64, u32, u32)> {
    let op = OpCode::try_from(bytes[0])?;
    let mut lba_bytes = [0u8; 8];
    lba_bytes.copy_from_slice(&bytes[4..12]);
    let lba = u64::from_le_bytes(lba_bytes);

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[12..16]);
    let byte_len = u32::from_le_bytes(len_bytes);

    let mut flag_bytes = [0u8; 4];
    flag_bytes.copy_from_slice(&bytes[16..20]);
    let flags = u32::from_le_bytes(flag_bytes);

    Ok((op, lba, byte_len, flags))
}

/// Heartbeat/status payload returned by the gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmooStatusV0 {
    pub version: u16,
    pub flags: u16,
    pub export_count: u32,
    pub session_id: u64,
}

impl SmooStatusV0 {
    /// Create a v0 status payload with the provided flags/count/session.
    pub const fn new(flags: u16, export_count: u32, session_id: u64) -> Self {
        Self {
            version: SMOO_STATUS_VERSION,
            flags,
            export_count,
            session_id,
        }
    }

    /// Serialize the status payload to its on-wire representation.
    pub fn encode(self) -> [u8; SMOO_STATUS_LEN] {
        let mut buf = [0u8; SMOO_STATUS_LEN];
        buf[0..2].copy_from_slice(&self.version.to_le_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_le_bytes());
        buf[4..8].copy_from_slice(&self.export_count.to_le_bytes());
        buf[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        buf
    }

    /// Decode a status payload from a fixed-size buffer.
    pub fn decode(bytes: [u8; SMOO_STATUS_LEN]) -> Result<Self> {
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != SMOO_STATUS_VERSION {
            return Err(ProtoError::InvalidVersion {
                expected: SMOO_STATUS_VERSION,
                actual: version,
            });
        }
        let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
        let export_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let session_id = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Ok(Self {
            version,
            flags,
            export_count,
            session_id,
        })
    }

    /// Decode a status payload from a borrowed slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != SMOO_STATUS_LEN {
            return Err(ProtoError::InvalidLength {
                expected: SMOO_STATUS_LEN,
                actual: slice.len(),
            });
        }
        let mut buf = [0u8; SMOO_STATUS_LEN];
        buf.copy_from_slice(slice);
        Self::decode(buf)
    }

    /// Returns true when the export_active flag is set.
    pub fn export_active(&self) -> bool {
        (self.flags & SMOO_STATUS_FLAG_EXPORT_ACTIVE) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_round_trip() {
        let ident = Ident::new(1, 2);
        let bytes = ident.encode();
        assert_eq!(Ident::decode(bytes).unwrap(), ident);
    }

    #[test]
    fn ident_magic_guard() {
        let mut bytes = Ident::new(1, 2).encode();
        bytes[0] = b'X';
        assert!(matches!(
            Ident::decode(bytes),
            Err(ProtoError::InvalidMagic)
        ));
    }

    #[test]
    fn request_round_trip() {
        let req = Request::new(OpCode::Write, 42, 4096, 0xAA55AA55);
        let bytes = req.encode();
        assert_eq!(Request::decode(bytes).unwrap(), req);
        assert_eq!(Request::try_from(bytes.as_slice()).unwrap(), req);
    }

    #[test]
    fn response_round_trip() {
        let resp = Response::new(OpCode::Read, 9001, 512, 0);
        let bytes = resp.encode();
        assert_eq!(Response::decode(bytes).unwrap(), resp);
        assert_eq!(Response::try_from(bytes.as_slice()).unwrap(), resp);
    }

    #[test]
    fn status_round_trip() {
        let status = SmooStatusV0::new(SMOO_STATUS_FLAG_EXPORT_ACTIVE, 1, 0x0102_0304_0506_0708);
        let bytes = status.encode();
        assert_eq!(SmooStatusV0::try_from_slice(&bytes).unwrap(), status);
        assert!(SmooStatusV0::decode(bytes).unwrap().export_active());
    }

    #[test]
    fn bad_opcode() {
        let mut bytes = Request::new(OpCode::Flush, 0, 0, 0).encode();
        bytes[0] = 0xFF;
        assert!(matches!(
            Request::decode(bytes),
            Err(ProtoError::InvalidOpcode(0xFF))
        ));
    }

    #[test]
    fn invalid_len() {
        assert!(matches!(
            Request::try_from(&[0u8; 19][..]),
            Err(ProtoError::InvalidLength {
                expected: 20,
                actual: 19
            })
        ));
    }
}
