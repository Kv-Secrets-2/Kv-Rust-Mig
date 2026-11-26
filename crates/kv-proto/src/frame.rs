//! Versioned broker IPC frame codec.
//!
//! One frame is a fixed twelve-byte header followed by one JSON payload:
//!
//! ```text
//! 0..4   magic: b"KVIP"
//! 4..6   protocol version, big-endian u16 (currently 1)
//! 6      kind: 1 = request, 2 = response
//! 7      flags: zero in version 1
//! 8..12  payload length, big-endian u32
//! ```
//!
//! The length is always validated against the direction's payload cap before a
//! stream reader allocates or reads the payload.

use serde_json::Value;
use thiserror::Error;

use crate::{MAX_AGENT_RESPONSE_BYTES, MAX_MSG, ProtocolError, python_utf8_error};

pub const IPC_FRAME_MAGIC: [u8; 4] = *b"KVIP";
pub const IPC_FRAME_VERSION: u16 = 1;
pub const IPC_FRAME_HEADER_LEN: usize = 12;

const KIND_REQUEST: u8 = 1;
const KIND_RESPONSE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Request,
    Response,
}

impl FrameKind {
    pub fn max_payload_bytes(self) -> usize {
        match self {
            Self::Request => MAX_MSG,
            Self::Response => MAX_AGENT_RESPONSE_BYTES,
        }
    }

    fn wire(self) -> u8 {
        match self {
            Self::Request => KIND_REQUEST,
            Self::Response => KIND_RESPONSE,
        }
    }

    fn from_wire(value: u8) -> Result<Self, FrameError> {
        match value {
            KIND_REQUEST => Ok(Self::Request),
            KIND_RESPONSE => Ok(Self::Response),
            other => Err(FrameError::UnsupportedKind(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    #[error("IPC frame is truncated")]
    Truncated,
    #[error("IPC frame has bad magic")]
    BadMagic,
    #[error("unsupported IPC frame version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported IPC frame kind {0}")]
    UnsupportedKind(u8),
    #[error("unsupported IPC frame flags {0}")]
    UnsupportedFlags(u8),
    #[error("IPC frame length mismatch")]
    LengthMismatch,
    #[error("IPC frame carries {actual:?}, not {expected:?}")]
    WrongKind {
        expected: FrameKind,
        actual: FrameKind,
    },
    #[error("IPC {kind:?} payload exceeds {limit} bytes ({actual} declared)")]
    PayloadTooLarge {
        kind: FrameKind,
        limit: usize,
        actual: usize,
    },
}

pub fn frame_header(
    kind: FrameKind,
    payload_len: usize,
) -> Result<[u8; IPC_FRAME_HEADER_LEN], FrameError> {
    let limit = kind.max_payload_bytes();
    if payload_len > limit {
        return Err(FrameError::PayloadTooLarge {
            kind,
            limit,
            actual: payload_len,
        });
    }
    let mut header = [0_u8; IPC_FRAME_HEADER_LEN];
    header[..4].copy_from_slice(&IPC_FRAME_MAGIC);
    header[4..6].copy_from_slice(&IPC_FRAME_VERSION.to_be_bytes());
    header[6] = kind.wire();
    header[8..12].copy_from_slice(&(payload_len as u32).to_be_bytes());
    Ok(header)
}

pub fn decode_frame_header(
    header: &[u8; IPC_FRAME_HEADER_LEN],
) -> Result<(FrameKind, usize), FrameError> {
    if header[..4] != IPC_FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != IPC_FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let kind = FrameKind::from_wire(header[6])?;
    if header[7] != 0 {
        return Err(FrameError::UnsupportedFlags(header[7]));
    }
    let payload_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let limit = kind.max_payload_bytes();
    if payload_len > limit {
        return Err(FrameError::PayloadTooLarge {
            kind,
            limit,
            actual: payload_len,
        });
    }
    Ok((kind, payload_len))
}

pub fn encode_frame(kind: FrameKind, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let header = frame_header(kind, payload.len())?;
    let mut bytes = Vec::with_capacity(IPC_FRAME_HEADER_LEN + payload.len());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameError> {
    if bytes.len() < IPC_FRAME_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    let mut header = [0_u8; IPC_FRAME_HEADER_LEN];
    header.copy_from_slice(&bytes[..IPC_FRAME_HEADER_LEN]);
    let (kind, payload_len) = decode_frame_header(&header)?;
    let end = IPC_FRAME_HEADER_LEN + payload_len;
    if bytes.len() < end {
        return Err(FrameError::Truncated);
    }
    if bytes.len() != end {
        return Err(FrameError::LengthMismatch);
    }
    Ok(Frame {
        kind,
        payload: bytes[IPC_FRAME_HEADER_LEN..end].to_vec(),
    })
}

pub(crate) fn json_payload(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    kv_store::pyjson::to_vec_python(value, false)
        .map_err(|error| ProtocolError::Message(error.to_string()))
}

pub fn encode_json_frame(kind: FrameKind, value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let payload = json_payload(value)?;
    encode_frame(kind, &payload).map_err(ProtocolError::Frame)
}

pub fn decode_json_frame(bytes: &[u8]) -> Result<(FrameKind, Value), ProtocolError> {
    let frame = decode_frame(bytes)?;
    let value = parse_json_payload(&frame.payload)?;
    Ok((frame.kind, value))
}

pub(crate) fn parse_json_payload(payload: &[u8]) -> Result<Value, ProtocolError> {
    if let Err(error) = std::str::from_utf8(payload) {
        return Err(ProtocolError::InvalidUtf8(python_utf8_error(
            payload, error,
        )));
    }
    serde_json::from_slice(payload).map_err(ProtocolError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn header_layout_is_stable() {
        let header = frame_header(FrameKind::Request, 0x0102).unwrap();
        assert_eq!(
            header,
            [b'K', b'V', b'I', b'P', 0, 1, 1, 0, 0, 0, 0x01, 0x02,]
        );
        assert_eq!(
            decode_frame_header(&header).unwrap(),
            (FrameKind::Request, 0x0102)
        );
    }

    #[test]
    fn json_frame_round_trips_with_canonical_payload() {
        let value = json!({"cmd":"status","nested":[true,null,"é"]});
        let bytes = encode_json_frame(FrameKind::Response, &value).unwrap();
        assert_eq!(&bytes[..4], b"KVIP");
        assert_eq!(
            decode_json_frame(&bytes).unwrap(),
            (FrameKind::Response, value)
        );
    }

    #[test]
    fn exact_payload_caps_are_accepted_and_one_more_byte_is_rejected() {
        for kind in [FrameKind::Request, FrameKind::Response] {
            let limit = kind.max_payload_bytes();
            assert!(encode_frame(kind, &vec![b' '; limit]).is_ok());
            assert!(matches!(
                encode_frame(kind, &vec![b' '; limit + 1]),
                Err(FrameError::PayloadTooLarge { actual, .. }) if actual == limit + 1
            ));
        }
    }

    #[test]
    fn malformed_headers_are_rejected_before_payload_decoding() {
        let valid = frame_header(FrameKind::Response, 2).unwrap();
        for (index, value, expected) in [
            (0, b'X', FrameError::BadMagic),
            (5, 2, FrameError::UnsupportedVersion(2)),
            (6, 9, FrameError::UnsupportedKind(9)),
            (7, 1, FrameError::UnsupportedFlags(1)),
        ] {
            let mut header = valid;
            header[index] = value;
            assert_eq!(decode_frame_header(&header), Err(expected));
        }
    }

    #[test]
    fn truncated_and_trailing_frames_are_rejected() {
        let bytes = encode_frame(FrameKind::Request, b"{}").unwrap();
        assert_eq!(decode_frame(&bytes[..5]), Err(FrameError::Truncated));
        assert_eq!(
            decode_frame(&bytes[..bytes.len() - 1]),
            Err(FrameError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_frame(&trailing), Err(FrameError::LengthMismatch));
    }

    #[test]
    fn oversized_declared_length_is_rejected_from_the_header_alone() {
        for (kind, limit) in [
            (FrameKind::Request, MAX_MSG),
            (FrameKind::Response, MAX_AGENT_RESPONSE_BYTES),
        ] {
            let mut header = frame_header(kind, 0).unwrap();
            header[8..12].copy_from_slice(&((limit + 1) as u32).to_be_bytes());
            assert_eq!(
                decode_frame(&header),
                Err(FrameError::PayloadTooLarge {
                    kind,
                    limit,
                    actual: limit + 1,
                })
            );
        }
    }
}
