//! Closed TCP storage metadata and opaque native-backed transfer values.

use std::{fmt, sync::Arc};

use btls::ssl::{AuthenticatedSessionRecord, PendingSessionExport, SessionTransferError};
use zeroize::Zeroizing;

use crate::tls::{PreparedTlsSessionReplacement, RetiredTlsSessionReplacements};

pub(crate) const MAX_OWNERS: usize = 256;
pub(crate) const MAX_RECORDS: usize = 2560;
const MAX_METADATA: usize = 128 * 1024;
const HEADER_LEN: usize = 22;
const MAGIC: &[u8; 8] = b"PHTCP001";

/// A strictly parsed storage manifest. Parsing does not authenticate it.
///
/// The facade must authenticate this header and its record-slot mapping,
/// including the intent to replace a store with zero records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSessionStoreHeader {
    pub(crate) order: u8,
    pub(crate) per_hostname: u8,
    pub(crate) physical: u8,
    pub(crate) records: u8,
    pub(crate) next_batch: u64,
}

impl TcpSessionStoreHeader {
    /// Parse one complete fixed-size manifest without accepting trailing bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, SessionTransferError> {
        if bytes.len() != HEADER_LEN || &bytes[..8] != MAGIC || bytes[8..10] != [0, 1] {
            return Err(SessionTransferError::Malformed);
        }
        let header = Self {
            order: bytes[10],
            per_hostname: bytes[11],
            physical: bytes[12],
            records: bytes[13],
            next_batch: u64::from_be_bytes(
                bytes[14..22]
                    .try_into()
                    .map_err(|_| SessionTransferError::Malformed)?,
            ),
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn validate(self) -> Result<(), SessionTransferError> {
        if self.order > 2
            || !(1..=10).contains(&self.per_hostname)
            || self.physical > self.per_hostname
            || self.records > self.physical
            || (self.physical != 0 && self.next_batch == 0)
        {
            return Err(SessionTransferError::Malformed);
        }
        Ok(())
    }

    /// Encode the complete manifest in its canonical fixed-width form.
    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[9] = 1;
        bytes[10] = self.order;
        bytes[11] = self.per_hostname;
        bytes[12] = self.physical;
        bytes[13] = self.records;
        bytes[14..].copy_from_slice(&self.next_batch.to_be_bytes());
        bytes
    }

    /// Number of declared records, excluding slots already expired at capture.
    #[must_use]
    pub fn record_count(self) -> usize {
        usize::from(self.records)
    }
    /// Number of physical slots excluded as expired when the store was captured.
    #[must_use]
    pub fn excluded_expired_count(self) -> usize {
        usize::from(self.physical - self.records)
    }
}

/// Borrowed storage fields from authenticated native owner metadata.
///
/// A parsed value grants no authority. Native authorization and the facade's
/// typed source-witness validation must precede preparation.
pub struct TcpSessionRecordMetadata<'a> {
    pub(crate) header: TcpSessionStoreHeader,
    pub(crate) ordinal: u8,
    pub(crate) batch: u64,
    pub(crate) sequence: u32,
    pub(crate) hostname: &'a str,
    pub(crate) payload: &'a [u8],
}

impl<'a> TcpSessionRecordMetadata<'a> {
    /// Parse one bounded owner-metadata frame without accepting trailing bytes.
    /// Parsing does not authenticate the bytes or grant import authority.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, SessionTransferError> {
        if bytes.len() > MAX_METADATA {
            return Err(SessionTransferError::TooLarge);
        }
        let mut reader = Reader(bytes);
        let header = TcpSessionStoreHeader::parse(reader.take(HEADER_LEN)?)?;
        let ordinal = reader.take(1)?[0];
        let batch = u64::from_be_bytes(
            reader
                .take(8)?
                .try_into()
                .map_err(|_| SessionTransferError::Malformed)?,
        );
        let sequence = u32::from_be_bytes(
            reader
                .take(4)?
                .try_into()
                .map_err(|_| SessionTransferError::Malformed)?,
        );
        if reader.take(1)? != [0] {
            return Err(SessionTransferError::Malformed);
        }
        let name_len = u16::from_be_bytes(
            reader
                .take(2)?
                .try_into()
                .map_err(|_| SessionTransferError::Malformed)?,
        ) as usize;
        let hostname = std::str::from_utf8(reader.take(name_len)?)
            .map_err(|_| SessionTransferError::Malformed)?;
        validate_hostname(hostname)?;
        let payload_len = u32::from_be_bytes(
            reader
                .take(4)?
                .try_into()
                .map_err(|_| SessionTransferError::Malformed)?,
        ) as usize;
        let payload = reader.take(payload_len)?;
        if !reader.0.is_empty()
            || header.records == 0
            || ordinal >= header.physical
            || batch >= header.next_batch
        {
            return Err(SessionTransferError::Malformed);
        }
        Ok(Self {
            header,
            ordinal,
            batch,
            sequence,
            hostname,
            payload,
        })
    }

    /// Return the complete storage header carried by this owner metadata.
    #[must_use]
    pub fn header(&self) -> TcpSessionStoreHeader {
        self.header
    }
    /// Borrow the facade payload from the authenticated owner metadata.
    /// This payload contains metadata, never serialized native session bytes.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Borrow the exact source hostname carried by this owner metadata.
    #[must_use]
    pub fn hostname(&self) -> &'a str {
        self.hostname
    }
    /// Return the original physical slot, preserving gaps from expired tickets.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        usize::from(self.ordinal)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SessionTransferError> {
        let (value, remaining) = self
            .0
            .split_at_checked(count)
            .ok_or(SessionTransferError::Malformed)?;
        self.0 = remaining;
        Ok(value)
    }
}

pub(crate) fn validate_hostname(hostname: &str) -> Result<(), SessionTransferError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.is_ascii()
        || hostname.as_bytes().contains(&0)
    {
        return Err(SessionTransferError::Malformed);
    }
    Ok(())
}

pub(crate) fn reserved<T>(count: usize) -> Result<Vec<T>, SessionTransferError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SessionTransferError::Allocation)?;
    Ok(values)
}

/// A native-proven pending export with its original physical slot and arrival.
/// It has no attachable session accessor and cannot be cloned.
pub struct TcpSessionExportRecord {
    pub(crate) pending: PendingSessionExport,
    pub(crate) header: TcpSessionStoreHeader,
    pub(crate) ordinal: u8,
    pub(crate) batch: u64,
    pub(crate) sequence: u32,
    pub(crate) hostname: Arc<str>,
}

impl TcpSessionExportRecord {
    /// Original physical source slot, retained even when earlier tickets expired.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        usize::from(self.ordinal)
    }

    /// Seal after all stores are unlocked. Expiry fails the attempted snapshot.
    pub fn seal(
        self,
        payload: &[u8],
        key: &[u8; 32],
    ) -> Result<AuthenticatedSessionRecord, SessionTransferError> {
        let size = 42usize
            .checked_add(self.hostname.len())
            .and_then(|n| n.checked_add(payload.len()))
            .filter(|n| *n <= MAX_METADATA)
            .ok_or(SessionTransferError::TooLarge)?;
        let mut bytes = Zeroizing::new(reserved(size)?);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.push(self.ordinal);
        bytes.extend_from_slice(&self.batch.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(self.hostname.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.hostname.as_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        self.pending.seal(&bytes, key)
    }
}

/// Complete captured store fields, including explicit expired exclusions.
pub struct TcpSessionStoreExport {
    pub(crate) header: TcpSessionStoreHeader,
    pub(crate) records: Vec<TcpSessionExportRecord>,
}
impl TcpSessionStoreExport {
    /// Return the captured storage header, including expired-slot exclusions.
    #[must_use]
    pub fn header(&self) -> TcpSessionStoreHeader {
        self.header
    }
    /// Consume the capture and return its native-proven pending records.
    /// Original physical slots retain gaps left by excluded expired tickets.
    /// Seal these records only after every store guard has been released.
    #[must_use]
    pub fn into_records(self) -> Vec<TcpSessionExportRecord> {
        self.records
    }
}

/// Private staged sessions. Only genuine native permits can create this value.
pub struct PreparedTcpSessionReplacement(pub(crate) PreparedTlsSessionReplacement);

/// Old sessions and callback states retained until every transaction lock drops.
pub struct RetiredTcpSessionReplacements(pub(crate) RetiredTlsSessionReplacements);
impl RetiredTcpSessionReplacements {
    /// Release old sessions and retire pending callback publications.
    /// Call only after all transaction guards have been released.
    /// Return the number of removed stored and pending ticket entries.
    #[must_use]
    pub fn finish(self) -> usize {
        self.0.finish()
    }
}

macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => { $(impl fmt::Debug for $kind {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct(stringify!($kind)).finish_non_exhaustive()
        }
    })+ };
}
redacted_debug!(
    TcpSessionRecordMetadata<'_>,
    TcpSessionExportRecord,
    TcpSessionStoreExport,
    PreparedTcpSessionReplacement,
    RetiredTcpSessionReplacements
);

#[cfg(test)]
mod tests;
