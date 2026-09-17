//! Decoding of connection-scoped HTTP/3 metadata carried by TLS ALPS.

use std::{error::Error as StdError, fmt};

use crate::accept_ch::AcceptCh;

const ACCEPT_CH_FRAME_TYPE: u64 = 0x89;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DecodeError {
    frame_index: usize,
    offset: usize,
    kind: DecodeErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeErrorKind {
    TruncatedFrameType,
    TruncatedFrameLength,
    FrameLength,
    TruncatedFramePayload,
    TruncatedOriginLength,
    OriginLength,
    TruncatedOrigin,
    TruncatedValueLength,
    ValueLength,
    TruncatedValue,
}

impl DecodeErrorKind {
    const fn reason(self) -> &'static str {
        match self {
            Self::TruncatedFrameType => "ALPS ended inside an HTTP/3 frame type",
            Self::TruncatedFrameLength => "ALPS ended inside an HTTP/3 frame length",
            Self::FrameLength => "ALPS HTTP/3 frame length cannot be represented",
            Self::TruncatedFramePayload => "ALPS ended inside an HTTP/3 frame payload",
            Self::TruncatedOriginLength => "ACCEPT_CH ended inside an origin length",
            Self::OriginLength => "ACCEPT_CH origin length cannot be represented",
            Self::TruncatedOrigin => "ACCEPT_CH ended inside an origin",
            Self::TruncatedValueLength => "ACCEPT_CH ended inside a value length",
            Self::ValueLength => "ACCEPT_CH value length cannot be represented",
            Self::TruncatedValue => "ACCEPT_CH ended inside a value",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at ALPS frame {} byte {}",
            self.kind.reason(),
            self.frame_index,
            self.offset
        )
    }
}

impl StdError for DecodeError {}

pub(super) fn decode(encoded: &[u8]) -> Result<AcceptCh, DecodeError> {
    let mut accept_ch = AcceptCh::default();
    let mut offset = 0;
    let mut frame_index = 0;

    while offset < encoded.len() {
        let frame_offset = offset;
        let frame_type = read_varint(
            encoded,
            &mut offset,
            frame_index,
            0,
            DecodeErrorKind::TruncatedFrameType,
        )?;
        let payload_len = read_varint(
            encoded,
            &mut offset,
            frame_index,
            0,
            DecodeErrorKind::TruncatedFrameLength,
        )?;
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| error(frame_index, frame_offset, DecodeErrorKind::FrameLength))?;
        let payload_end = offset
            .checked_add(payload_len)
            .ok_or_else(|| error(frame_index, frame_offset, DecodeErrorKind::FrameLength))?;
        let payload = encoded.get(offset..payload_end).ok_or_else(|| {
            error(
                frame_index,
                frame_offset,
                DecodeErrorKind::TruncatedFramePayload,
            )
        })?;

        if frame_type == ACCEPT_CH_FRAME_TYPE {
            decode_accept_ch(payload, frame_index, offset, &mut accept_ch)?;
        }

        offset = payload_end;
        frame_index += 1;
    }

    Ok(accept_ch)
}

fn decode_accept_ch(
    payload: &[u8],
    frame_index: usize,
    payload_offset: usize,
    accept_ch: &mut AcceptCh,
) -> Result<(), DecodeError> {
    let mut offset = 0;
    while offset < payload.len() {
        let origin_len_offset = offset;
        let origin_len = read_varint(
            payload,
            &mut offset,
            frame_index,
            payload_offset,
            DecodeErrorKind::TruncatedOriginLength,
        )?;
        let origin_len = usize::try_from(origin_len).map_err(|_| {
            error(
                frame_index,
                payload_offset + origin_len_offset,
                DecodeErrorKind::OriginLength,
            )
        })?;
        let origin_end = offset.checked_add(origin_len).ok_or_else(|| {
            error(
                frame_index,
                payload_offset + origin_len_offset,
                DecodeErrorKind::OriginLength,
            )
        })?;
        let origin = payload.get(offset..origin_end).ok_or_else(|| {
            error(
                frame_index,
                payload_offset + origin_len_offset,
                DecodeErrorKind::TruncatedOrigin,
            )
        })?;
        offset = origin_end;

        let value_len_offset = offset;
        let value_len = read_varint(
            payload,
            &mut offset,
            frame_index,
            payload_offset,
            DecodeErrorKind::TruncatedValueLength,
        )?;
        let value_len = usize::try_from(value_len).map_err(|_| {
            error(
                frame_index,
                payload_offset + value_len_offset,
                DecodeErrorKind::ValueLength,
            )
        })?;
        let value_end = offset.checked_add(value_len).ok_or_else(|| {
            error(
                frame_index,
                payload_offset + value_len_offset,
                DecodeErrorKind::ValueLength,
            )
        })?;
        let value = payload.get(offset..value_end).ok_or_else(|| {
            error(
                frame_index,
                payload_offset + value_len_offset,
                DecodeErrorKind::TruncatedValue,
            )
        })?;
        offset = value_end;

        accept_ch.insert(origin, value);
    }
    Ok(())
}

fn read_varint(
    encoded: &[u8],
    offset: &mut usize,
    frame_index: usize,
    base_offset: usize,
    truncated: DecodeErrorKind,
) -> Result<u64, DecodeError> {
    let start = *offset;
    let first = *encoded
        .get(start)
        .ok_or_else(|| error(frame_index, base_offset + start, truncated))?;
    let width = 1_usize << (first >> 6);
    let end = start
        .checked_add(width)
        .ok_or_else(|| error(frame_index, base_offset + start, truncated))?;
    let bytes = encoded
        .get(start..end)
        .ok_or_else(|| error(frame_index, base_offset + start, truncated))?;

    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }

    *offset = end;
    Ok(value)
}

const fn error(frame_index: usize, offset: usize, kind: DecodeErrorKind) -> DecodeError {
    DecodeError {
        frame_index,
        offset,
        kind,
    }
}

#[cfg(test)]
mod tests;
