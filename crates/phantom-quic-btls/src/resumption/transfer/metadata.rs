//! Closed QUIC cache metadata. Framing is neither authentication nor TP validation.

use std::{fmt, time::Duration};

use btls::ssl::SessionTransferError;
use zeroize::Zeroizing;

use crate::{
    QuicVersion,
    resumption::{MAX_APPLICATION_STATE_LEN, MAX_SESSIONS},
};

const MAGIC: &[u8; 8] = b"PHQUIC01";
const HEADER_LEN: usize = 26;
const RECORD_FIXED_LEN: usize = HEADER_LEN + 20;
const MAX_METADATA: usize = 128 * 1024;
const MAX_PEER_TRANSPORT_PARAMETERS: usize = u16::MAX as usize;

/// Physical queue shape and the cache's latest RTT for its bound server name.
/// The facade must authenticate even a zero-record replacement intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicSessionStoreHeader {
    physical: u8,
    records: u8,
    round_trip_time: Option<Duration>,
}

impl QuicSessionStoreHeader {
    pub(super) fn new(
        physical: usize,
        records: usize,
        round_trip_time: Option<Duration>,
    ) -> Result<Self, SessionTransferError> {
        if physical > MAX_SESSIONS || records > physical {
            return Err(SessionTransferError::Malformed);
        }
        Ok(Self {
            physical: physical as u8,
            records: records as u8,
            round_trip_time,
        })
    }

    /// Parse one complete canonical storage header. This does not authenticate it.
    pub fn parse(bytes: &[u8]) -> Result<Self, SessionTransferError> {
        if bytes.len() != HEADER_LEN
            || &bytes[..8] != MAGIC
            || bytes[8..10] != [0, 1]
            || bytes[12] > 1
            || bytes[13] != 0
        {
            return Err(SessionTransferError::Malformed);
        }
        let mut reader = Reader(&bytes[14..]);
        let seconds = u64::from_be_bytes(reader.array()?);
        let nanos = u32::from_be_bytes(reader.array()?);
        if nanos >= 1_000_000_000 || (bytes[12] == 0 && (seconds != 0 || nanos != 0)) {
            return Err(SessionTransferError::Malformed);
        }
        Self::new(
            usize::from(bytes[10]),
            usize::from(bytes[11]),
            (bytes[12] == 1).then(|| Duration::new(seconds, nanos)),
        )
    }

    #[must_use]
    /// Encode the complete canonical storage header.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[9] = 1;
        bytes[10] = self.physical;
        bytes[11] = self.records;
        if let Some(rtt) = self.round_trip_time {
            bytes[12] = 1;
            bytes[14..22].copy_from_slice(&rtt.as_secs().to_be_bytes());
            bytes[22..26].copy_from_slice(&rtt.subsec_nanos().to_be_bytes());
        }
        bytes
    }

    #[must_use]
    /// Number of retained, nonexpired records.
    pub fn record_count(self) -> usize {
        usize::from(self.records)
    }

    #[must_use]
    /// Physical source slots excluded as expired at capture.
    pub fn excluded_expired_count(self) -> usize {
        usize::from(self.physical - self.records)
    }

    #[must_use]
    /// Latest optional cache-owned RTT for the bound server name.
    pub fn round_trip_time(self) -> Option<Duration> {
        self.round_trip_time
    }
}

/// Borrowed fields only: no DER, source key, native session or import authority.
/// Every present TP block needs strict protocol validation before replacement.
/// Application-state validation belongs to its actual consumer as well.
pub struct QuicSessionRecordMetadata<'a> {
    pub(super) header: QuicSessionStoreHeader,
    pub(super) ordinal: u8,
    pub(super) hostname: &'a str,
    /// The connection that received the ticket, not a configured preference.
    pub(super) version: QuicVersion,
    pub(super) peer_transport_parameters: Option<&'a [u8]>,
    pub(super) application_state: Option<&'a [u8]>,
    pub(super) payload: &'a [u8],
}

impl<'a> QuicSessionRecordMetadata<'a> {
    pub(super) fn new(
        header: QuicSessionStoreHeader,
        ordinal: usize,
        hostname: &'a str,
        version: QuicVersion,
        peer_transport_parameters: Option<&'a [u8]>,
        application_state: Option<&'a [u8]>,
        payload: &'a [u8],
    ) -> Result<Self, SessionTransferError> {
        if header.records == 0 || ordinal >= usize::from(header.physical) {
            return Err(SessionTransferError::Malformed);
        }
        let value = Self {
            header,
            ordinal: ordinal as u8,
            hostname,
            version,
            peer_transport_parameters,
            application_state,
            payload,
        };
        value.encoded_len()?;
        Ok(value)
    }

    /// Parse one bounded complete frame without granting native import authority.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, SessionTransferError> {
        if bytes.len() > MAX_METADATA {
            return Err(SessionTransferError::TooLarge);
        }
        let mut reader = Reader(bytes);
        let header = QuicSessionStoreHeader::parse(reader.take(HEADER_LEN)?)?;
        let ordinal = usize::from(reader.array::<1>()?[0]);
        let flags = reader.array::<1>()?[0];
        if flags & !3 != 0 {
            return Err(SessionTransferError::Malformed);
        }
        let version = QuicVersion::from_wire(u32::from_be_bytes(reader.array()?))
            .ok_or(SessionTransferError::Malformed)?;
        let name_len = usize::from(u16::from_be_bytes(reader.array()?));
        let tp_len = reader.length()?;
        let application_len = reader.length()?;
        let payload_len = reader.length()?;
        if tp_len > MAX_PEER_TRANSPORT_PARAMETERS || application_len > MAX_APPLICATION_STATE_LEN {
            return Err(SessionTransferError::TooLarge);
        }
        if (flags & 1 == 0 && tp_len != 0) || (flags & 2 == 0 && application_len != 0) {
            return Err(SessionTransferError::Malformed);
        }
        let hostname = std::str::from_utf8(reader.take(name_len)?)
            .map_err(|_| SessionTransferError::Malformed)?;
        let tp = reader.take(tp_len)?;
        let application = reader.take(application_len)?;
        let payload = reader.take(payload_len)?;
        if !reader.0.is_empty() {
            return Err(SessionTransferError::Malformed);
        }
        Self::new(
            header,
            ordinal,
            hostname,
            version,
            (flags & 1 != 0).then_some(tp),
            (flags & 2 != 0).then_some(application),
            payload,
        )
    }

    pub(super) fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, SessionTransferError> {
        let len = self.encoded_len()?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(len)
            .map_err(|_| SessionTransferError::Allocation)?;
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.push(self.ordinal);
        bytes.push(
            u8::from(self.peer_transport_parameters.is_some())
                | (u8::from(self.application_state.is_some()) << 1),
        );
        bytes.extend_from_slice(&self.version.wire().to_be_bytes());
        bytes.extend_from_slice(&(self.hostname.len() as u16).to_be_bytes());
        bytes.extend_from_slice(
            &(self.peer_transport_parameters.map_or(0, <[u8]>::len) as u32).to_be_bytes(),
        );
        bytes.extend_from_slice(
            &(self.application_state.map_or(0, <[u8]>::len) as u32).to_be_bytes(),
        );
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.hostname.as_bytes());
        if let Some(parameters) = self.peer_transport_parameters {
            bytes.extend_from_slice(parameters);
        }
        if let Some(state) = self.application_state {
            bytes.extend_from_slice(state);
        }
        bytes.extend_from_slice(self.payload);
        Ok(bytes)
    }

    /// Return the complete header authenticated alongside this record.
    #[must_use]
    pub fn header(&self) -> QuicSessionStoreHeader {
        self.header
    }
    /// Return the original physical slot, including gaps from expired tickets.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        usize::from(self.ordinal)
    }
    /// Borrow the exact authenticated source hostname.
    #[must_use]
    pub fn hostname(&self) -> &'a str {
        self.hostname
    }
    /// Borrow the facade's authenticated source-witness payload.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Borrow application bytes for the actual protocol consumer's validation.
    #[must_use]
    pub fn application_state(&self) -> Option<&'a [u8]> {
        self.application_state
    }
    /// Validate every present remembered-server TP value for its actual version.
    /// Absence remains valid unless the intended use separately requires a value.
    pub fn validate_transport_parameters(&self) -> Result<(), SessionTransferError> {
        super::validate_parameters(self.version, self.peer_transport_parameters)
    }

    fn encoded_len(&self) -> Result<usize, SessionTransferError> {
        if self.header.records == 0
            || self.ordinal >= self.header.physical
            || self.hostname.is_empty()
            || self.hostname.len() > 253
            || !self.hostname.is_ascii()
            || self.hostname.as_bytes().contains(&0)
        {
            return Err(SessionTransferError::Malformed);
        }
        let tp_len = self.peer_transport_parameters.map_or(0, <[u8]>::len);
        let application_len = self.application_state.map_or(0, <[u8]>::len);
        if tp_len > MAX_PEER_TRANSPORT_PARAMETERS || application_len > MAX_APPLICATION_STATE_LEN {
            return Err(SessionTransferError::TooLarge);
        }
        RECORD_FIXED_LEN
            .checked_add(self.hostname.len())
            .and_then(|n| n.checked_add(tp_len))
            .and_then(|n| n.checked_add(application_len))
            .and_then(|n| n.checked_add(self.payload.len()))
            .filter(|n| *n <= MAX_METADATA)
            .ok_or(SessionTransferError::TooLarge)
    }
}

impl fmt::Debug for QuicSessionRecordMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicSessionRecordMetadata")
            .field("header", &self.header)
            .field("ordinal", &self.ordinal)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Validate the complete retained sequence, never compacting expired ordinals.
/// Native permit and facade witness checks remain separate prerequisites.
pub(super) fn validate_store(
    header: QuicSessionStoreHeader,
    hostname: &str,
    records: &[QuicSessionRecordMetadata<'_>],
) -> Result<(), SessionTransferError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.is_ascii()
        || hostname.as_bytes().contains(&0)
        || records.len() != header.record_count()
    {
        return Err(SessionTransferError::Malformed);
    }
    let mut previous = None;
    for record in records {
        record.encoded_len()?;
        if record.header != header
            || record.hostname != hostname
            || previous.is_some_and(|ordinal| record.ordinal <= ordinal)
        {
            return Err(SessionTransferError::Malformed);
        }
        previous = Some(record.ordinal);
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SessionTransferError> {
        let (value, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(SessionTransferError::Malformed)?;
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], SessionTransferError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SessionTransferError::Malformed)
    }
    fn length(&mut self) -> Result<usize, SessionTransferError> {
        usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| SessionTransferError::TooLarge)
    }
}

#[cfg(test)]
mod tests;
