//! Version-2 completed HTTPS answers inside the authenticated envelope.

use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer};

use super::{Kind, Reader, SessionSnapshotError, Writer};
use crate::session::alt_svc::https_record_snapshot::{
    Entry, HttpsRecordSnapshot, MAX_ENTRIES, MAX_RDATA, MAX_RECORDS, encode_record,
};

pub(super) fn write(
    writer: &mut Writer,
    snapshot: Option<&HttpsRecordSnapshot>,
) -> Result<(), SessionSnapshotError> {
    writer.byte(u8::from(snapshot.is_some()))?;
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    writer.field(snapshot.namespace.as_bytes(), 256)?;
    writer.count(snapshot.entries.len(), MAX_ENTRIES)?;
    for entry in &snapshot.entries {
        writer.text(&entry.host)?;
        writer.raw(&entry.port.to_be_bytes())?;
        writer.time(entry.expires_at)?;
        writer.byte(u8::from(entry.negative_ttl.is_some()))?;
        if let Some(ttl) = entry.negative_ttl {
            writer.raw(&ttl.to_be_bytes())?;
        }
        writer.count(entry.answers.len(), MAX_RECORDS)?;
        for answer in &entry.answers {
            writer.text(answer.owner())?;
            writer.raw(&answer.ttl().to_be_bytes())?;
            writer.field(&encode_record(answer.record())?, MAX_RDATA)?;
        }
    }
    Ok(())
}

pub(super) fn read(reader: &mut Reader<'_>) -> Result<HttpsRecordSnapshot, SessionSnapshotError> {
    let namespace = std::str::from_utf8(reader.field(256)?)
        .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
    if namespace.is_empty() || namespace.chars().any(char::is_control) {
        return Err(SessionSnapshotError::new(Kind::InvalidSnapshot));
    }
    let namespace = namespace.into();
    let count = reader.count(MAX_ENTRIES)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
    for _ in 0..count {
        let host = reader.text()?;
        let port = u16::from_be_bytes(
            reader
                .raw(2)?
                .try_into()
                .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
        );
        let expires_at = reader.time()?;
        let negative_ttl = if reader.boolean()? {
            Some(u32::from_be_bytes(reader.raw(4)?.try_into().map_err(
                |_| SessionSnapshotError::new(Kind::InvalidSnapshot),
            )?))
        } else {
            None
        };
        let count = reader.count(MAX_RECORDS)?;
        let mut answers = Vec::new();
        answers
            .try_reserve_exact(count)
            .map_err(|_| SessionSnapshotError::new(Kind::Allocation))?;
        for _ in 0..count {
            let owner = reader.text()?;
            let ttl = u32::from_be_bytes(
                reader
                    .raw(4)?
                    .try_into()
                    .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?,
            );
            let record = HttpsRecord::from_rdata(reader.field(MAX_RDATA)?)
                .map_err(|_| SessionSnapshotError::new(Kind::InvalidSnapshot))?;
            answers.push(HttpsRecordAnswer::new(owner, ttl, record));
        }
        entries.push(Entry {
            host,
            port,
            expires_at,
            negative_ttl,
            answers,
        });
    }
    Ok(HttpsRecordSnapshot { namespace, entries })
}
