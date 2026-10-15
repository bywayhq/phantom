//! Authenticated owner manifests. Parsed metadata grants no native authority.

use std::{fmt, ops::Range};

use btls::{
    aead::ConcurrentAeadCtx,
    hash::{Hasher, MessageDigest, hash, hmac_sha256},
    ssl::SessionTransferEnvelope,
};
use phantom_net::TcpSessionStoreHeader;
use zeroize::Zeroizing;

use super::binding::{TicketCacheLeg, TicketCacheProtocol};
use crate::authority::Endpoint;

const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
const MAX_OWNERS: usize = 256;
const MAX_RECORDS: usize = 2560;
const MAX_POLICY: usize = 1024 * 1024;
const MAX_NAME: usize = 253;
const MAX_AUTHORITY: usize = 1024;
const MAGIC: &[u8; 8] = b"PHOWN002";
const HEADER: usize = 90;
const TAG: usize = 16;
const STORE_HEADER: usize = 22;
const NATIVE_HEADER: usize = 56;
const NATIVE_MAGIC: &[u8; 8] = b"PHTKT001";
const FORMAT: &[u8] = concat!(env!("CARGO_PKG_VERSION"), ":owner-manifest2:tcp-store1").as_bytes();
const KEY_DOMAIN: &[u8] = b"phantom-ticket-facade-owner-envelope-v2";

#[derive(Debug)]
pub(super) enum EnvelopeError {
    TooLarge,
    Allocation,
    Malformed,
    Authentication,
    IncompatibleFormat,
    UnsupportedEmptyCredentials,
    UnsupportedProtocol,
    Backend(btls::error::ErrorStack),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "ticket manifest exceeds its resource bound",
            Self::Allocation => "ticket manifest allocation failed",
            Self::Malformed => "invalid ticket manifest framing",
            Self::Authentication => "ticket manifest authentication failed",
            Self::IncompatibleFormat => "incompatible ticket manifest format",
            Self::UnsupportedEmptyCredentials => {
                "empty credentialed ticket transfer is unsupported"
            }
            Self::UnsupportedProtocol => "ticket manifest requires a TCP store",
            Self::Backend(_) => "ticket manifest backend failed",
        })
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            _ => None,
        }
    }
}

impl From<btls::error::ErrorStack> for EnvelopeError {
    fn from(error: btls::error::ErrorStack) -> Self {
        Self::Backend(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecordSlot {
    pub(super) native_slot: u16,
    pub(super) physical_ordinal: u8,
}

/// Inputs supplied only by the actual source registry and captured TCP stores.
pub(super) struct OwnerInput<'a> {
    pub(super) record_owner_index: u16,
    pub(super) origin: &'a Endpoint,
    pub(super) server_name: &'a str,
    pub(super) leg: TicketCacheLeg,
    pub(super) protocol: TicketCacheProtocol,
    pub(super) policy: &'a [u8],
    pub(super) source_witness: &'a [u8],
    pub(super) has_credentials: bool,
    pub(super) header: TcpSessionStoreHeader,
    pub(super) slots: &'a [RecordSlot],
}

pub(super) struct SealedManifest(Zeroizing<Vec<u8>>);

impl SealedManifest {
    pub(super) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Borrows authenticated source metadata; none of these fields grants a permit.
pub(super) struct OwnerView<'a> {
    pub(super) index: u16,
    pub(super) record_owner_index: u16,
    pub(super) origin_authority: &'a str,
    pub(super) origin_host: &'a str,
    pub(super) origin_port: u16,
    pub(super) server_name: &'a str,
    pub(super) leg: TicketCacheLeg,
    pub(super) protocol: TicketCacheProtocol,
    pub(super) policy: &'a [u8],
    pub(super) source_witness: &'a [u8],
    pub(super) has_credentials: bool,
    pub(super) header: TcpSessionStoreHeader,
    slots: &'a [u8],
}

impl OwnerView<'_> {
    pub(super) fn slots(&self) -> impl ExactSizeIterator<Item = RecordSlot> + '_ {
        self.slots
            .as_chunks::<3>()
            .0
            .iter()
            .map(|bytes| RecordSlot {
                native_slot: u16::from_be_bytes([bytes[0], bytes[1]]),
                physical_ordinal: bytes[2],
            })
    }
}

/// Owns zeroized authenticated plaintext without copied owners or native sessions.
pub(super) struct OpenedManifest {
    plaintext: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    backend: [u8; 32],
    owner_count: u16,
    record_count: u16,
    native_range: Range<usize>,
}

impl OpenedManifest {
    pub(super) fn owner_count(&self) -> usize {
        usize::from(self.owner_count)
    }

    pub(super) fn record_count(&self) -> usize {
        usize::from(self.record_count)
    }

    /// Public native-envelope framing identity, not a current-backend approval.
    #[cfg(test)]
    pub(super) fn native_backend(&self) -> &[u8; 32] {
        &self.backend
    }

    /// Returns nested encrypted envelope bytes, never serialized native sessions.
    pub(super) fn native_ciphertext(&self) -> &[u8] {
        &self.plaintext[self.native_range.clone()]
    }

    pub(super) fn owners(&self) -> Owners<'_> {
        Owners {
            reader: Reader(&self.plaintext[4..]),
            next: 0,
            count: self.owner_count,
        }
    }
}

pub(super) struct Owners<'a> {
    reader: Reader<'a>,
    next: u16,
    count: u16,
}

impl<'a> Iterator for Owners<'a> {
    type Item = Result<OwnerView<'a>, EnvelopeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.count {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(parse_owner(&mut self.reader, index))
    }
}

fn format_identity() -> Result<[u8; 32], EnvelopeError> {
    hash(MessageDigest::sha256(), FORMAT)?
        .as_ref()
        .try_into()
        .map_err(|_| EnvelopeError::Malformed)
}

fn key(
    snapshot_key: &[u8; 32],
    format: &[u8; 32],
    backend: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let mut input = Writer::new(KEY_DOMAIN.len() + 64)?;
    input.raw(KEY_DOMAIN)?;
    input.raw(format)?;
    input.raw(backend)?;
    Ok(Zeroizing::new(hmac_sha256(snapshot_key, &input.bytes)?))
}

fn native_backend(bytes: &[u8]) -> Result<&[u8; 32], EnvelopeError> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(EnvelopeError::TooLarge);
    }
    if bytes.len() < NATIVE_HEADER + TAG + 4 || &bytes[..8] != NATIVE_MAGIC {
        return Err(EnvelopeError::Malformed);
    }
    let length = u32::from_be_bytes(
        bytes[52..56]
            .try_into()
            .map_err(|_| EnvelopeError::Malformed)?,
    ) as usize;
    if length != bytes.len() - NATIVE_HEADER - TAG {
        return Err(EnvelopeError::Malformed);
    }
    bytes[8..40]
        .try_into()
        .map_err(|_| EnvelopeError::Malformed)
}

pub(super) fn seal_manifest(
    snapshot_key: &[u8; 32],
    owners: &[OwnerInput<'_>],
    native: &SessionTransferEnvelope,
) -> Result<SealedManifest, EnvelopeError> {
    if owners.len() > MAX_OWNERS {
        return Err(EnvelopeError::TooLarge);
    }
    let records = owners.iter().try_fold(0_usize, |count, owner| {
        count
            .checked_add(owner.slots.len())
            .filter(|n| *n <= MAX_RECORDS)
            .ok_or(EnvelopeError::TooLarge)
    })?;
    let mut validation = Validation::new(records);
    let mut size = 4_usize;
    for owner in owners {
        if usize::from(owner.record_owner_index) >= MAX_OWNERS {
            return Err(EnvelopeError::Malformed);
        }
        validation.owner(
            owner.origin.authority().as_str(),
            owner.origin.host(),
            owner.origin.port(),
            owner.server_name,
            owner.leg,
            owner.protocol,
            owner.policy,
            owner.source_witness,
            owner.has_credentials,
            owner.header,
            owner.slots.iter().copied(),
        )?;
        size = size
            .checked_add(2 + 2 + 2 + 1 + 1 + 1 + STORE_HEADER + 1 + 20)
            .and_then(|n| n.checked_add(owner.origin.authority().as_str().len()))
            .and_then(|n| n.checked_add(owner.origin.host().len()))
            .and_then(|n| n.checked_add(owner.server_name.len()))
            .and_then(|n| n.checked_add(owner.policy.len()))
            .and_then(|n| n.checked_add(owner.source_witness.len()))
            .and_then(|n| n.checked_add(owner.slots.len() * 3))
            .ok_or(EnvelopeError::TooLarge)?;
    }
    validation.finish()?;
    let backend = native_backend(native.as_bytes())?;
    size = size
        .checked_add(4)
        .and_then(|n| n.checked_add(native.as_bytes().len()))
        .ok_or(EnvelopeError::TooLarge)?;
    let total = size
        .checked_add(HEADER + TAG)
        .filter(|n| *n <= MAX_ENVELOPE)
        .ok_or(EnvelopeError::TooLarge)?;
    let mut plaintext = Writer::new(size)?;
    plaintext.u16(owners.len() as u16)?;
    plaintext.u16(records as u16)?;
    for (index, owner) in owners.iter().enumerate() {
        plaintext.u16(index as u16)?;
        plaintext.u16(owner.record_owner_index)?;
        plaintext.field(owner.origin.authority().as_str().as_bytes())?;
        plaintext.field(owner.origin.host().as_bytes())?;
        plaintext.u16(owner.origin.port())?;
        plaintext.field(owner.server_name.as_bytes())?;
        plaintext.raw(&[
            leg_tag(owner.leg),
            protocol_tag(owner.protocol),
            u8::from(owner.has_credentials),
        ])?;
        plaintext.field(owner.policy)?;
        plaintext.field(owner.source_witness)?;
        plaintext.raw(&owner.header.to_bytes())?;
        plaintext.raw(&[owner.slots.len() as u8])?;
        for slot in owner.slots {
            plaintext.u16(slot.native_slot)?;
            plaintext.raw(&[slot.physical_ordinal])?;
        }
    }
    plaintext.field(native.as_bytes())?;
    if plaintext.bytes.len() != size {
        return Err(EnvelopeError::Malformed);
    }
    let format = format_identity()?;
    let mut output = Writer::new(total)?;
    output.raw(MAGIC)?;
    output.u16(2)?;
    output.raw(&format)?;
    output.raw(backend)?;
    let mut nonce = [0; 12];
    btls::rand::rand_bytes(&mut nonce)?;
    output.raw(&nonce)?;
    output.raw(&(size as u32).to_be_bytes())?;
    let cipher = ConcurrentAeadCtx::aes_256_gcm(&*key(snapshot_key, &format, backend)?)?;
    let mut tag = [0; TAG];
    cipher.seal_in_place(&nonce, &mut plaintext.bytes, &mut tag, &output.bytes)?;
    output.raw(&plaintext.bytes)?;
    output.raw(&tag)?;
    Ok(SealedManifest(output.bytes))
}

pub(super) fn open_manifest(
    snapshot: &[u8],
    snapshot_key: &[u8; 32],
) -> Result<OpenedManifest, EnvelopeError> {
    if snapshot.len() > MAX_ENVELOPE {
        return Err(EnvelopeError::TooLarge);
    }
    if snapshot.len() < HEADER + TAG || &snapshot[..8] != MAGIC || snapshot[8..10] != [0, 2] {
        return Err(EnvelopeError::Malformed);
    }
    let format: &[u8; 32] = snapshot[10..42]
        .try_into()
        .map_err(|_| EnvelopeError::Malformed)?;
    if *format != format_identity()? {
        return Err(EnvelopeError::IncompatibleFormat);
    }
    let backend: &[u8; 32] = snapshot[42..74]
        .try_into()
        .map_err(|_| EnvelopeError::Malformed)?;
    let size = u32::from_be_bytes(
        snapshot[86..90]
            .try_into()
            .map_err(|_| EnvelopeError::Malformed)?,
    ) as usize;
    if size != snapshot.len() - HEADER - TAG {
        return Err(EnvelopeError::Malformed);
    }
    let mut plaintext = Writer::new(size)?;
    plaintext.raw(&snapshot[HEADER..HEADER + size])?;
    let cipher = ConcurrentAeadCtx::aes_256_gcm(&*key(snapshot_key, format, backend)?)?;
    cipher
        .open_in_place(
            &snapshot[74..86],
            &mut plaintext.bytes,
            &snapshot[HEADER + size..],
            &snapshot[..HEADER],
        )
        .map_err(|_| EnvelopeError::Authentication)?;
    let (owner_count, record_count, native_range) = validate_plaintext(&plaintext.bytes, backend)?;
    Ok(OpenedManifest {
        plaintext: plaintext.bytes,
        #[cfg(test)]
        backend: *backend,
        owner_count,
        record_count,
        native_range,
    })
}

fn validate_plaintext(
    bytes: &[u8],
    backend: &[u8; 32],
) -> Result<(u16, u16, Range<usize>), EnvelopeError> {
    let mut reader = Reader(bytes);
    let owners = reader.u16()?;
    let records = reader.u16()?;
    if usize::from(owners) > MAX_OWNERS || usize::from(records) > MAX_RECORDS {
        return Err(EnvelopeError::TooLarge);
    }
    let mut validation = Validation::new(usize::from(records));
    for index in 0..owners {
        let owner = parse_owner(&mut reader, index)?;
        validation.owner(
            owner.origin_authority,
            owner.origin_host,
            owner.origin_port,
            owner.server_name,
            owner.leg,
            owner.protocol,
            owner.policy,
            owner.source_witness,
            owner.has_credentials,
            owner.header,
            owner.slots(),
        )?;
    }
    validation.finish()?;
    let native = reader.field(MAX_ENVELOPE)?;
    let native_start = bytes.len() - reader.0.len() - native.len();
    if !reader.0.is_empty() || native_backend(native)? != backend {
        return Err(EnvelopeError::Malformed);
    }
    Ok((owners, records, native_start..native_start + native.len()))
}

fn parse_owner<'a>(reader: &mut Reader<'a>, expected: u16) -> Result<OwnerView<'a>, EnvelopeError> {
    let index = reader.u16()?;
    if index != expected {
        return Err(EnvelopeError::Malformed);
    }
    let record_owner_index = reader.u16()?;
    if usize::from(record_owner_index) >= MAX_OWNERS {
        return Err(EnvelopeError::Malformed);
    }
    let origin_authority = reader.authority()?;
    let origin_host = reader.name()?;
    let origin_port = reader.u16()?;
    let server_name = reader.name()?;
    let leg = match reader.u8()? {
        0 => TicketCacheLeg::Origin,
        1 => TicketCacheLeg::HttpProxy,
        2 => TicketCacheLeg::ConnectUdp,
        _ => return Err(EnvelopeError::Malformed),
    };
    let protocol = match reader.u8()? {
        0 => TicketCacheProtocol::Http1,
        1 => TicketCacheProtocol::Http2,
        2 => TicketCacheProtocol::Negotiated,
        3 => return Err(EnvelopeError::UnsupportedProtocol),
        _ => return Err(EnvelopeError::Malformed),
    };
    let has_credentials = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(EnvelopeError::Malformed),
    };
    let policy = reader.field(MAX_POLICY)?;
    let source_witness = reader.field(MAX_POLICY)?;
    let header = TcpSessionStoreHeader::parse(reader.take(STORE_HEADER)?)
        .map_err(|_| EnvelopeError::Malformed)?;
    let count = usize::from(reader.u8()?);
    if count != header.record_count() {
        return Err(EnvelopeError::Malformed);
    }
    let slots = reader.take(count * 3)?;
    Ok(OwnerView {
        index,
        record_owner_index,
        origin_authority,
        origin_host,
        origin_port,
        server_name,
        leg,
        protocol,
        policy,
        source_witness,
        has_credentials,
        header,
        slots,
    })
}

fn leg_tag(leg: TicketCacheLeg) -> u8 {
    match leg {
        TicketCacheLeg::Origin => 0,
        TicketCacheLeg::HttpProxy => 1,
        TicketCacheLeg::ConnectUdp => 2,
    }
}

fn protocol_tag(protocol: TicketCacheProtocol) -> u8 {
    match protocol {
        TicketCacheProtocol::Http1 => 0,
        TicketCacheProtocol::Http2 => 1,
        TicketCacheProtocol::Negotiated => 2,
        TicketCacheProtocol::Http3 => 3,
    }
}

fn name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.is_ascii() && !name.as_bytes().contains(&0)
}

fn authority_valid(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= MAX_AUTHORITY
        && authority.is_ascii()
        && !authority
            .bytes()
            .any(|byte| byte == b'@' || byte.is_ascii_control() || byte.is_ascii_whitespace())
}

struct Validation {
    records: usize,
    seen_records: usize,
    slots: [u64; MAX_RECORDS.div_ceil(64)],
    owners: [[u8; 32]; MAX_OWNERS],
    owner_count: usize,
}

impl Validation {
    fn new(records: usize) -> Self {
        Self {
            records,
            seen_records: 0,
            slots: [0; MAX_RECORDS.div_ceil(64)],
            owners: [[0; 32]; MAX_OWNERS],
            owner_count: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn owner(
        &mut self,
        authority: &str,
        host: &str,
        port: u16,
        server_name: &str,
        leg: TicketCacheLeg,
        protocol: TicketCacheProtocol,
        policy: &[u8],
        witness: &[u8],
        has_credentials: bool,
        header: TcpSessionStoreHeader,
        slots: impl ExactSizeIterator<Item = RecordSlot>,
    ) -> Result<(), EnvelopeError> {
        if !authority_valid(authority)
            || !name_valid(host)
            || !name_valid(server_name)
            || policy.is_empty()
        {
            return Err(EnvelopeError::Malformed);
        }
        if policy.len() > MAX_POLICY || witness.len() > MAX_POLICY || self.owner_count == MAX_OWNERS
        {
            return Err(EnvelopeError::TooLarge);
        }
        if matches!(protocol, TicketCacheProtocol::Http3) {
            return Err(EnvelopeError::UnsupportedProtocol);
        }
        if header.record_count() != slots.len() {
            return Err(EnvelopeError::Malformed);
        }
        if has_credentials && slots.len() == 0 {
            return Err(EnvelopeError::UnsupportedEmptyCredentials);
        }
        let mut digest = Hasher::new(MessageDigest::sha256())?;
        digest.update(b"phantom-ticket-owner-identity-v1")?;
        for field in [
            authority.as_bytes(),
            host.as_bytes(),
            &port.to_be_bytes(),
            server_name.as_bytes(),
            &[leg_tag(leg), protocol_tag(protocol)],
            policy,
        ] {
            digest.update(&(field.len() as u32).to_be_bytes())?;
            digest.update(field)?;
        }
        let identity: [u8; 32] = digest
            .finish()?
            .as_ref()
            .try_into()
            .map_err(|_| EnvelopeError::Malformed)?;
        if self.owners[..self.owner_count].contains(&identity) {
            return Err(EnvelopeError::Malformed);
        }
        self.owners[self.owner_count] = identity;
        self.owner_count += 1;
        let physical = header.to_bytes()[12];
        let mut previous = None;
        for slot in slots {
            let index = usize::from(slot.native_slot);
            if index >= self.records
                || slot.physical_ordinal >= physical
                || previous.is_some_and(|value| slot.physical_ordinal <= value)
            {
                return Err(EnvelopeError::Malformed);
            }
            previous = Some(slot.physical_ordinal);
            let bit = 1_u64 << (index % 64);
            if self.slots[index / 64] & bit != 0 {
                return Err(EnvelopeError::Malformed);
            }
            self.slots[index / 64] |= bit;
            self.seen_records += 1;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), EnvelopeError> {
        if self.seen_records != self.records {
            Err(EnvelopeError::Malformed)
        } else {
            Ok(())
        }
    }
}

struct Writer {
    bytes: Zeroizing<Vec<u8>>,
    bound: usize,
}

impl Writer {
    fn new(bound: usize) -> Result<Self, EnvelopeError> {
        if bound > MAX_ENVELOPE {
            return Err(EnvelopeError::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(bound)
            .map_err(|_| EnvelopeError::Allocation)?;
        Ok(Self { bytes, bound })
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), EnvelopeError> {
        self.bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.bound)
            .ok_or(EnvelopeError::TooLarge)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn u16(&mut self, value: u16) -> Result<(), EnvelopeError> {
        self.raw(&value.to_be_bytes())
    }

    fn field(&mut self, bytes: &[u8]) -> Result<(), EnvelopeError> {
        let length = u32::try_from(bytes.len()).map_err(|_| EnvelopeError::TooLarge)?;
        self.raw(&length.to_be_bytes())?;
        self.raw(bytes)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], EnvelopeError> {
        let bytes = self.0.get(..count).ok_or(EnvelopeError::Malformed)?;
        self.0 = &self.0[count..];
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, EnvelopeError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| EnvelopeError::Malformed)?,
        ))
    }

    fn field(&mut self, bound: usize) -> Result<&'a [u8], EnvelopeError> {
        let length = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| EnvelopeError::Malformed)?,
        ) as usize;
        if length > bound {
            return Err(EnvelopeError::TooLarge);
        }
        self.take(length)
    }

    fn name(&mut self) -> Result<&'a str, EnvelopeError> {
        let name =
            std::str::from_utf8(self.field(MAX_NAME)?).map_err(|_| EnvelopeError::Malformed)?;
        if !name_valid(name) {
            return Err(EnvelopeError::Malformed);
        }
        Ok(name)
    }

    fn authority(&mut self) -> Result<&'a str, EnvelopeError> {
        let authority = std::str::from_utf8(self.field(MAX_AUTHORITY)?)
            .map_err(|_| EnvelopeError::Malformed)?;
        if !authority_valid(authority) {
            return Err(EnvelopeError::Malformed);
        }
        Ok(authority)
    }
}

#[cfg(test)]
mod tests;
