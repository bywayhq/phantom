use std::collections::BTreeMap;

use phantom_profile::quic::QuicVarIntWidth;
use quinn_proto::transport_parameters::TransportParameters;

use super::{QuicTransportProfileError, field_for_identifier, profile_error};

pub(super) const ENTROPY_LEN: usize = 1_024;
const MAX_VARINT: u64 = (1 << 62) - 1;

pub(super) struct ParsedTransportParameters {
    pub(super) values: BTreeMap<u64, Vec<u8>>,
}

impl ParsedTransportParameters {
    pub(super) fn new(params: &TransportParameters) -> Result<Self, QuicTransportProfileError> {
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        Self::from_encoded(&encoded)
    }

    pub(super) fn from_encoded(encoded: &[u8]) -> Result<Self, QuicTransportProfileError> {
        let mut offset = 0;
        let mut values = BTreeMap::new();
        while offset < encoded.len() {
            let (identifier, _) = decode_varint(encoded, &mut offset)?;
            let (length, _) = decode_varint(encoded, &mut offset)?;
            let length = usize::try_from(length).map_err(|_| {
                profile_error("wire_parameters", "stock parameter length is too large")
            })?;
            let end = offset.checked_add(length).ok_or_else(|| {
                profile_error("wire_parameters", "stock parameter length overflowed")
            })?;
            let value = encoded
                .get(offset..end)
                .ok_or_else(|| profile_error("wire_parameters", "stock parameter is truncated"))?;
            if values.insert(identifier, value.to_vec()).is_some() {
                return Err(profile_error(
                    "wire_parameters",
                    "stock parameters contain a duplicate identifier",
                ));
            }
            offset = end;
        }
        Ok(Self { values })
    }

    pub(super) fn value(&self, identifier: u64) -> Result<&[u8], QuicTransportProfileError> {
        self.values
            .get(&identifier)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                profile_error(
                    field_for_identifier(identifier),
                    "Quinn omitted a profile-required parameter",
                )
            })
    }

    pub(super) fn scalar(&self, identifier: u64) -> Result<u64, QuicTransportProfileError> {
        let value = self.value(identifier)?;
        let mut offset = 0;
        let (decoded, _) = decode_varint(value, &mut offset)?;
        if offset != value.len() {
            return Err(profile_error(
                field_for_identifier(identifier),
                "Quinn encoded a malformed scalar parameter",
            ));
        }
        Ok(decoded)
    }
}

pub(super) struct WireEntropy {
    bytes: [u8; ENTROPY_LEN],
    offset: usize,
}

impl WireEntropy {
    pub(super) fn random() -> Result<Self, QuicTransportProfileError> {
        let mut bytes = [0; ENTROPY_LEN];
        btls::rand::rand_bytes(&mut bytes).map_err(|_| {
            profile_error(
                "entropy",
                "BoringSSL could not generate transport-parameter entropy",
            )
        })?;
        Ok(Self { bytes, offset: 0 })
    }

    #[cfg(test)]
    pub(super) const fn from_bytes(bytes: [u8; ENTROPY_LEN]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn shuffle<T>(&mut self, values: &mut [T]) -> Result<(), QuicTransportProfileError> {
        for index in (1..values.len()).rev() {
            let selected = self.uniform(index + 1)?;
            values.swap(index, selected);
        }
        Ok(())
    }

    fn uniform(&mut self, upper_exclusive: usize) -> Result<usize, QuicTransportProfileError> {
        if upper_exclusive == 0 || upper_exclusive > 256 {
            return Err(profile_error(
                "entropy",
                "uniform range is outside the supported bound",
            ));
        }
        let zone = 256 - (256 % upper_exclusive);
        loop {
            let candidate = usize::from(self.take(1)?[0]);
            if candidate < zone {
                return Ok(candidate % upper_exclusive);
            }
        }
    }

    pub(super) fn uniform_inclusive(
        &mut self,
        minimum: u8,
        maximum: u8,
    ) -> Result<u8, QuicTransportProfileError> {
        let width = usize::from(maximum - minimum) + 1;
        let offset = u8::try_from(self.uniform(width)?)
            .map_err(|_| profile_error("entropy", "uniform result cannot be represented"))?;
        minimum
            .checked_add(offset)
            .ok_or_else(|| profile_error("entropy", "uniform result overflowed"))
    }

    pub(super) fn reserved_transport_parameter_id(
        &mut self,
    ) -> Result<u64, QuicTransportProfileError> {
        let maximum_n = (MAX_VARINT - 27) / 31;
        loop {
            let candidate = u64::from_be_bytes(self.take_array()?) & ((1 << 58) - 1);
            if candidate <= maximum_n {
                return Ok(31 * candidate + 27);
            }
        }
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&[u8], QuicTransportProfileError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| profile_error("entropy", "entropy cursor overflowed"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| profile_error("entropy", "transport-parameter entropy was exhausted"))?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn take_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], QuicTransportProfileError> {
        self.take(N)?
            .try_into()
            .map_err(|_| profile_error("entropy", "entropy slice has the wrong length"))
    }
}

pub(super) fn encode_varint(
    value: u64,
    width: QuicVarIntWidth,
    output: &mut Vec<u8>,
) -> Result<(), QuicTransportProfileError> {
    if !width.can_encode(value) {
        return Err(profile_error(
            "wire_parameters",
            "value does not fit its configured QUIC varint width",
        ));
    }
    match width {
        QuicVarIntWidth::One => output.push(value as u8),
        QuicVarIntWidth::Two => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        QuicVarIntWidth::Four => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        }
        QuicVarIntWidth::Eight => {
            output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
        }
        _ => {
            return Err(profile_error(
                "wire_parameters",
                "provider does not support this QUIC varint width",
            ));
        }
    }
    Ok(())
}

pub(super) fn decode_varint(
    input: &[u8],
    offset: &mut usize,
) -> Result<(u64, QuicVarIntWidth), QuicTransportProfileError> {
    let first = *input
        .get(*offset)
        .ok_or_else(|| profile_error("wire_parameters", "QUIC varint is truncated"))?;
    let width = match first >> 6 {
        0 => QuicVarIntWidth::One,
        1 => QuicVarIntWidth::Two,
        2 => QuicVarIntWidth::Four,
        3 => QuicVarIntWidth::Eight,
        _ => {
            return Err(profile_error(
                "wire_parameters",
                "invalid QUIC varint prefix",
            ));
        }
    };
    let end = offset
        .checked_add(width.encoded_len())
        .ok_or_else(|| profile_error("wire_parameters", "QUIC varint length overflowed"))?;
    let bytes = input
        .get(*offset..end)
        .ok_or_else(|| profile_error("wire_parameters", "QUIC varint is truncated"))?;
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    padded[8 - bytes.len()] &= 0x3f;
    *offset = end;
    Ok((u64::from_be_bytes(padded), width))
}

pub(super) fn is_reserved_transport_parameter(identifier: u64) -> bool {
    identifier >= 27 && identifier % 31 == 27
}
