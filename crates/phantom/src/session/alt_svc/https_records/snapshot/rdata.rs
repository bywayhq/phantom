//! Bounded canonical encoding of the parsed HTTPS record representation.

use phantom_net::dns::{HttpsRecord, TargetName};

use super::{Kind, MAX_RDATA, SessionSnapshotError};

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SessionSnapshotError> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > MAX_RDATA)
    {
        return Err(SessionSnapshotError::new(Kind::TooLarge));
    }
    out.try_reserve(bytes.len())
        .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn parameter(out: &mut Vec<u8>, key: u16, value: &[u8]) -> Result<(), SessionSnapshotError> {
    let length =
        u16::try_from(value.len()).map_err(|_| SessionSnapshotError::new(Kind::TooLarge))?;
    put(out, &key.to_be_bytes())?;
    put(out, &length.to_be_bytes())?;
    put(out, value)
}

pub(crate) fn encode_record(record: &HttpsRecord) -> Result<Vec<u8>, SessionSnapshotError> {
    let mut out = Vec::new();
    put(&mut out, &record.priority().to_be_bytes())?;
    match record.target() {
        TargetName::Owner => {}
        TargetName::Name(name) => {
            for label in name.split('.') {
                let length = u8::try_from(label.len())
                    .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
                put(&mut out, &[length])?;
                put(&mut out, label.as_bytes())?;
            }
        }
        _ => return Err(SessionSnapshotError::new(Kind::Unsupported)),
    }
    put(&mut out, &[0])?;
    match record {
        HttpsRecord::Alias(_) => {}
        HttpsRecord::Service(service) => {
            if !service.mandatory().is_empty() {
                let mut value = Vec::new();
                for key in service.mandatory() {
                    put(&mut value, &key.to_be_bytes())?;
                }
                parameter(&mut out, 0, &value)?;
            }
            if !service.alpn().is_empty() {
                let mut value = Vec::new();
                for id in service.alpn() {
                    let length = u8::try_from(id.len())
                        .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
                    put(&mut value, &[length])?;
                    put(&mut value, id)?;
                }
                parameter(&mut out, 1, &value)?;
            }
            if service.no_default_alpn() {
                parameter(&mut out, 2, &[])?;
            }
            if let Some(port) = service.port() {
                parameter(&mut out, 3, &port.to_be_bytes())?;
            }
            if !service.ipv4_hint().is_empty() {
                let mut value = Vec::new();
                for address in service.ipv4_hint() {
                    put(&mut value, &address.octets())?;
                }
                parameter(&mut out, 4, &value)?;
            }
            if let Some(ech) = service.ech() {
                parameter(&mut out, 5, ech.as_bytes())?;
            }
            if !service.ipv6_hint().is_empty() {
                let mut value = Vec::new();
                for address in service.ipv6_hint() {
                    put(&mut value, &address.octets())?;
                }
                parameter(&mut out, 6, &value)?;
            }
            for other in service.other_params() {
                parameter(&mut out, other.key(), other.value())?;
            }
        }
        _ => return Err(SessionSnapshotError::new(Kind::Unsupported)),
    }
    // Reuse the native parser for all DNS syntax, without interpreting ECH bytes.
    if HttpsRecord::from_rdata(&out)
        .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?
        != *record
    {
        return Err(SessionSnapshotError::new(Kind::Unsupported));
    }
    Ok(out)
}
