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

/// Errors surfaced while decoding protocol messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Buffer length did not match the protocol expectation.
    InvalidLength { expected: usize, actual: usize },
    /// Incoming opcode is unsupported.
    InvalidOpcode(u8),
    /// Ident magic prefix did not match `SMOO`.
    InvalidMagic,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::InvalidLength { expected, actual } => {
                write!(f, "invalid message length {actual}, expected {expected}")
            }
            ProtoError::InvalidOpcode(op) => write!(f, "invalid opcode {op}"),
            ProtoError::InvalidMagic => write!(f, "invalid ident magic"),
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
