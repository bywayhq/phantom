//! Opaque cold TCP and QUIC custody. This module never grants recipient authority.
//!
//! Capture requires the caller to validate configured route, policy, credentials
//! and allowed source witnesses, and to open `native` from this exact manifest.
//! The caller must also validate H3 application state with its actual consumer.
//! Whole-owner consumption is private preparation, never a published partial state.

use std::fmt;

use btls::ssl::{
    AuthenticatedSessionRecord, SessionTransferError, SslContextRef, VerifiedSessionEnvelope,
};
use phantom_net::{QuicSessionRecordMetadata, SessionTicketStoreHeader, TcpSessionRecordMetadata};
use zeroize::Zeroizing;

use super::{
    binding::{TicketCacheLeg, TicketCacheProtocol},
    envelope::{self, EnvelopeError, OpenedManifest, OwnerInput, OwnerView, RecordSlot},
};
use crate::authority::Endpoint;

const MAX_OWNERS: usize = 256;
const MAX_RECORDS: usize = 2560;
const MAX_ENVELOPE: usize = 16 * 1024 * 1024;
const MAX_POLICY: usize = 1024 * 1024;
// PHOWN003 header/tag, owner/count framing, nested native header/count/tag.
const ENVELOPE_FRAME: usize = 90 + 16 + 4 + 4 + 56 + 16 + 4;
const OWNER_FRAME: usize = 2 + 2 + 2 + 1 + 1 + 1 + 1 + 4 + 1 + 20;
const NATIVE_FRAME: usize = 56 + 16 + 4;

#[derive(Debug)]
pub(super) enum ColdError {
    Allocation,
    TooLarge,
    Mapping,
    UnsupportedOwner,
    Manifest(EnvelopeError),
    Native(SessionTransferError),
}

impl fmt::Display for ColdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "cold ticket custody allocation failed",
            Self::TooLarge => "cold ticket custody exceeds its resource bound",
            Self::Mapping => "cold ticket owner mapping is inconsistent",
            Self::UnsupportedOwner => "cold ticket owner shape is unsupported",
            Self::Manifest(_) => "cold ticket manifest failed validation",
            Self::Native(_) => "cold native ticket validation failed",
        })
    }
}

impl std::error::Error for ColdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EnvelopeError> for ColdError {
    fn from(error: EnvelopeError) -> Self {
        Self::Manifest(error)
    }
}

impl From<SessionTransferError> for ColdError {
    fn from(error: SessionTransferError) -> Self {
        Self::Native(error)
    }
}

/// Metadata remains separate from the native envelope's attachment authority.
/// Policy, witness and copied server-name storage are zeroized on drop.
pub(super) struct ColdOwner {
    pub(super) origin: Endpoint,
    pub(super) server_name: Zeroizing<String>,
    pub(super) leg: TicketCacheLeg,
    pub(super) protocol: TicketCacheProtocol,
    pub(super) policy: Zeroizing<Vec<u8>>,
    pub(super) source_witness: Zeroizing<Vec<u8>>,
    pub(super) has_credentials: bool,
    pub(super) record_owner_index: u16,
    pub(super) header: SessionTicketStoreHeader,
    pub(super) slots: Vec<RecordSlot>,
}

impl ColdOwner {
    pub(super) fn input(&self) -> OwnerInput<'_> {
        OwnerInput {
            record_owner_index: self.record_owner_index,
            origin: &self.origin,
            server_name: &self.server_name,
            leg: self.leg,
            protocol: self.protocol,
            policy: &self.policy,
            source_witness: &self.source_witness,
            has_credentials: self.has_credentials,
            header: self.header,
            slots: &self.slots,
        }
    }

    fn capture(view: OwnerView<'_>) -> Result<Self, ColdError> {
        let origin = endpoint(view.origin_authority, view.origin_host, view.origin_port)?;
        let mut slots = reserved(view.slots().len())?;
        slots.extend(view.slots());
        Ok(Self {
            origin,
            server_name: copy_name(view.server_name)?,
            leg: view.leg,
            protocol: view.protocol,
            policy: copy_bytes(view.policy)?,
            source_witness: copy_bytes(view.source_witness)?,
            has_credentials: view.has_credentials,
            record_owner_index: view.record_owner_index,
            header: view.header,
            slots,
        })
    }

    fn copy_remapped(&self, map: &[Option<u16>]) -> Result<Self, ColdError> {
        let mut slots = reserved(self.slots.len())?;
        for slot in &self.slots {
            let native_slot = map
                .get(usize::from(slot.native_slot))
                .copied()
                .flatten()
                .ok_or(ColdError::Mapping)?;
            slots.push(RecordSlot {
                native_slot,
                physical_ordinal: slot.physical_ordinal,
            });
        }
        Ok(Self {
            origin: endpoint(
                self.origin.authority().as_str(),
                self.origin.host(),
                self.origin.port(),
            )?,
            server_name: copy_name(&self.server_name)?,
            leg: self.leg,
            protocol: self.protocol,
            policy: copy_bytes(&self.policy)?,
            source_witness: copy_bytes(&self.source_witness)?,
            has_credentials: self.has_credentials,
            record_owner_index: self.record_owner_index,
            header: self.header,
            slots,
        })
    }
}

/// Root serializes mutation with its registry and consumes only whole owners.
/// This value retains no caller encryption key and has no infallible Clone.
pub(super) struct ColdState {
    pub(super) owners: Vec<ColdOwner>,
    pub(super) native: VerifiedSessionEnvelope,
    // Cloning/removing whole owners can only shrink this original byte bound.
    encoded_records_bound: usize,
}

/// Opaque records are rekeyed under the caller's key; owner slots address this
/// vector densely. Root must offset slots when combining with live exports.
pub(super) struct ColdExport {
    pub(super) owners: Vec<ColdOwner>,
    pub(super) records: Vec<AuthenticatedSessionRecord>,
}

impl ColdState {
    /// The caller supplies paired, authenticated inputs after configured-policy
    /// validation. Parsing and metadata checks here provide no native permit.
    pub(super) fn capture(
        manifest: &OpenedManifest,
        native: VerifiedSessionEnvelope,
    ) -> Result<Self, ColdError> {
        if manifest.owner_count() > MAX_OWNERS || native.record_count() > MAX_RECORDS {
            return Err(ColdError::TooLarge);
        }
        if manifest.record_count() != native.record_count() {
            return Err(ColdError::Mapping);
        }
        let encoded_records_bound = manifest
            .native_ciphertext()
            .len()
            .checked_sub(NATIVE_FRAME)
            .ok_or(ColdError::Mapping)?;
        // Check the complete framing budget before allocating copied metadata.
        let mut framing = ENVELOPE_FRAME;
        for owner in manifest.owners() {
            let owner = owner?;
            framing = add_owner_size(
                framing,
                [
                    owner.origin_authority.len(),
                    owner.origin_host.len(),
                    owner.server_name.len(),
                    owner.policy.len(),
                    owner.source_witness.len(),
                ],
                owner.slots().len(),
                owner.header,
            )?;
        }
        bounded_add(framing, encoded_records_bound, MAX_ENVELOPE)?;
        let mut owners = reserved(manifest.owner_count())?;
        for owner in manifest.owners() {
            owners.push(ColdOwner::capture(owner?)?);
        }
        let state = Self {
            owners,
            native,
            encoded_records_bound,
        };
        let (_, remaining) = state.compact_owners()?;
        if remaining != state.native.record_count() {
            return Err(ColdError::Mapping);
        }
        Ok(state)
    }

    /// Only wholly consumed owners disappear. Empty owners retain their clear
    /// intent. A partial owner is a failed preparation, never a new cold state.
    pub(super) fn try_clone_remaining(&self) -> Result<Self, ColdError> {
        let (owners, count) = self.compact_owners()?;
        let native = self.native.try_clone_remaining()?;
        if native.record_count() != count {
            return Err(ColdError::Mapping);
        }
        bounded_add(
            owner_framing(&owners)?,
            self.encoded_records_bound,
            MAX_ENVELOPE,
        )?;
        Ok(Self {
            owners,
            native,
            encoded_records_bound: self.encoded_records_bound,
        })
    }

    /// The budget covers the complete facade manifest plus native envelope, not
    /// merely native record bytes. No key, permit or raw session is retained.
    pub(super) fn prepare_export(
        &self,
        new_key: &[u8; 32],
        budget: usize,
    ) -> Result<ColdExport, ColdError> {
        let (owners, count) = self.compact_owners()?;
        let budget = budget.min(MAX_ENVELOPE);
        let framing = owner_framing(&owners)?;
        let available = budget.checked_sub(framing).ok_or(ColdError::TooLarge)?;
        let records = self.native.prepare_remaining_records(new_key, available)?;
        if records.len() != count {
            return Err(ColdError::Mapping);
        }
        let total = records.iter().try_fold(framing, |size, record| {
            bounded_add(size, record.encoded_len(), budget)
        })?;
        if total > budget {
            return Err(ColdError::TooLarge);
        }
        Ok(ColdExport { owners, records })
    }

    /// Prepare cold custody before any live-store commit. `replacements` must
    /// contain the full original incoming manifest, including owners already
    /// consumed into live stores. Root validates configured policies, allowed
    /// source witnesses and direct routes before calling. No authority follows
    /// from these metadata views. The caller validates actual configured routes
    /// and native credential policy before preparing this union.
    ///
    /// Already-applied empty owners must be removed from `incoming.owners` by
    /// the caller; a remaining empty owner is explicit pending clear intent.
    pub(super) fn prepare_union(
        &self,
        incoming: &Self,
        replacements: &[OwnerView<'_>],
        decoding_context: &SslContextRef,
    ) -> Result<Self, ColdError> {
        validate_replacements(replacements)?;
        for owner in &incoming.owners {
            let source = replacements
                .iter()
                .find(|view| same_view(owner, view))
                .ok_or(ColdError::Mapping)?;
            if owner.record_owner_index != source.record_owner_index
                || owner.header != source.header
                || owner.has_credentials != source.has_credentials
                || owner.source_witness.as_slice() != source.source_witness
                || !owner
                    .slots
                    .iter()
                    .map(|slot| slot.physical_ordinal)
                    .eq(source.slots().map(|slot| slot.physical_ordinal))
            {
                return Err(ColdError::Mapping);
            }
        }
        let old = self.select_owners(replacements)?;
        let mut fresh = incoming.select_owners(&[])?;
        let owner_count = bounded_add(old.owners.len(), fresh.owners.len(), MAX_OWNERS)?;
        let record_count = bounded_add(old.indices.len(), fresh.indices.len(), MAX_RECORDS)?;
        // Count full owner and native framing before copying owner metadata or
        // native bodies. Each selected native group checks its byte total before
        // that group's copies; exact combined bytes are known after the first.
        let framing =
            old.owners
                .iter()
                .chain(&fresh.owners)
                .try_fold(ENVELOPE_FRAME, |size, owner| {
                    add_owner_size(
                        size,
                        [
                            owner.origin.authority().as_str().len(),
                            owner.origin.host().len(),
                            owner.server_name.len(),
                            owner.policy.len(),
                            owner.source_witness.len(),
                        ],
                        owner.slots.len(),
                        owner.header,
                    )
                })?;
        let available = MAX_ENVELOPE
            .checked_sub(framing)
            .ok_or(ColdError::TooLarge)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        btls::rand::rand_bytes(&mut *key).map_err(SessionTransferError::from)?;
        let mut records = self
            .native
            .prepare_selected_records(&old.indices, &key, available)?;
        let old_bytes = record_bytes(&records, available)?;
        let remaining = available
            .checked_sub(old_bytes)
            .ok_or(ColdError::TooLarge)?;
        // Joining the second group needs no later allocation. Earlier failures
        // drop private preparation only and leave both sources untouched.
        records
            .try_reserve_exact(fresh.indices.len())
            .map_err(|_| ColdError::Allocation)?;
        let new_records =
            incoming
                .native
                .prepare_selected_records(&fresh.indices, &key, remaining)?;
        record_bytes(&new_records, remaining)?;
        records.extend(new_records);
        if records.len() != record_count {
            return Err(ColdError::Mapping);
        }
        let offset = u16::try_from(old.indices.len()).map_err(|_| ColdError::TooLarge)?;
        for slot in fresh.map.iter_mut().flatten() {
            *slot = slot.checked_add(offset).ok_or(ColdError::TooLarge)?;
        }
        let mut owners = reserved(owner_count)?;
        for owner in &old.owners {
            owners.push(owner.copy_remapped(&old.map)?);
        }
        for owner in &fresh.owners {
            owners.push(owner.copy_remapped(&fresh.map)?);
        }
        let mut inputs = reserved(owner_count)?;
        inputs.extend(owners.iter().map(ColdOwner::input));
        let sealed_native = btls::ssl::seal_envelope(&records, &key)?;
        let sealed_manifest = envelope::seal_manifest(&key, &inputs, &sealed_native)?;
        let manifest = envelope::open_manifest(sealed_manifest.as_bytes(), &key)?;
        let native =
            btls::ssl::open_envelope(manifest.native_ciphertext(), &key, decoding_context)?;
        // This pair was created and opened under this temporary key. No source
        // key or fabricated record crosses the boundary; capture checks maps.
        Self::capture(&manifest, native)
    }

    fn select_owners<'a>(
        &'a self,
        excluded: &[OwnerView<'_>],
    ) -> Result<OwnerSelection<'a>, ColdError> {
        let count = self.native.record_count();
        if count > MAX_RECORDS || self.owners.len() > MAX_OWNERS {
            return Err(ColdError::TooLarge);
        }
        let mut seen = [false; MAX_RECORDS];
        let mut selected = [false; MAX_RECORDS];
        let mut owners = reserved(self.owners.len())?;
        for (owner_index, owner) in self.owners.iter().enumerate() {
            owner_shape(
                owner.leg,
                owner.protocol,
                owner.has_credentials,
                owner.header,
            )?;
            let (records, physical) = store_shape(owner.protocol, owner.header)?;
            if self.owners[..owner_index]
                .iter()
                .any(|old| same_owner(old, owner))
                || records != owner.slots.len()
                || usize::from(owner.record_owner_index) >= MAX_OWNERS
            {
                return Err(ColdError::Mapping);
            }
            let replaced = excluded.iter().any(|view| same_view(owner, view));
            let mut live = 0;
            let mut previous = None;
            for slot in &owner.slots {
                let index = usize::from(slot.native_slot);
                if index >= count
                    || seen[index]
                    || usize::from(slot.physical_ordinal) >= physical
                    || previous.is_some_and(|old| slot.physical_ordinal <= old)
                {
                    return Err(ColdError::Mapping);
                }
                previous = Some(slot.physical_ordinal);
                seen[index] = true;
                // Explicit replacement never reads an old owner's native body
                // or checks its expiry, including when all old slots expired.
                if replaced {
                    continue;
                }
                match self.native.owner_metadata(index) {
                    Ok(_) => {
                        validate_record(&self.native, owner, *slot)?;
                        selected[index] = true;
                        live += 1;
                    }
                    Err(SessionTransferError::Consumed) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !replaced {
                if live != 0 && live != owner.slots.len() {
                    return Err(ColdError::Mapping);
                }
                if live != 0 || owner.slots.is_empty() {
                    owners.push(owner);
                }
            }
        }
        if seen[..count].iter().any(|value| !value) {
            return Err(ColdError::Mapping);
        }
        let mut indices = reserved(selected[..count].iter().filter(|value| **value).count())?;
        let mut map = [None; MAX_RECORDS];
        for (index, keep) in selected[..count].iter().copied().enumerate() {
            if keep {
                map[index] = Some(u16::try_from(indices.len()).map_err(|_| ColdError::TooLarge)?);
                indices.push(index);
            }
        }
        Ok(OwnerSelection {
            owners,
            indices,
            map,
        })
    }

    fn compact_owners(&self) -> Result<(Vec<ColdOwner>, usize), ColdError> {
        let count = self.native.record_count();
        if count > MAX_RECORDS || self.owners.len() > MAX_OWNERS {
            return Err(ColdError::TooLarge);
        }
        let mut map = [None; MAX_RECORDS];
        let mut remaining = 0_u16;
        for (index, target) in map[..count].iter_mut().enumerate() {
            match self.native.owner_metadata(index) {
                Ok(_) => {
                    *target = Some(remaining);
                    remaining += 1;
                }
                Err(SessionTransferError::Consumed) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut seen = [false; MAX_RECORDS];
        let mut owners = reserved(self.owners.len())?;
        for owner in &self.owners {
            let (records, physical) = store_shape(owner.protocol, owner.header)?;
            if records != owner.slots.len() || usize::from(owner.record_owner_index) >= MAX_OWNERS {
                return Err(ColdError::Mapping);
            }
            let mut live = 0;
            let mut previous = None;
            for slot in &owner.slots {
                let index = usize::from(slot.native_slot);
                if index >= count
                    || seen[index]
                    || usize::from(slot.physical_ordinal) >= physical
                    || previous.is_some_and(|value| slot.physical_ordinal <= value)
                {
                    return Err(ColdError::Mapping);
                }
                previous = Some(slot.physical_ordinal);
                seen[index] = true;
                if map[index].is_some() {
                    validate_record(&self.native, owner, *slot)?;
                    live += 1;
                }
            }
            if live != 0 && live != owner.slots.len() {
                return Err(ColdError::Mapping);
            }
            if owner.slots.is_empty() || live != 0 {
                owners.push(owner.copy_remapped(&map[..count])?);
            }
        }
        if seen[..count].iter().any(|seen| !seen) {
            return Err(ColdError::Mapping);
        }
        Ok((owners, usize::from(remaining)))
    }
}

fn validate_record(
    native: &VerifiedSessionEnvelope,
    owner: &ColdOwner,
    slot: RecordSlot,
) -> Result<(), ColdError> {
    let index = usize::from(slot.native_slot);
    validate_metadata(
        owner.header,
        &owner.server_name,
        &owner.source_witness,
        owner.record_owner_index,
        slot,
        native.owner_metadata(index)?,
        native.source_witness(index)?,
    )
}

// Structural validation only. Neither parsing nor this function grants a permit.
fn validate_metadata(
    header: SessionTicketStoreHeader,
    server_name: &str,
    source_witness: &[u8],
    record_owner_index: u16,
    slot: RecordSlot,
    bytes: &[u8],
    native_witness: &[u8],
) -> Result<(), ColdError> {
    let (actual_header, hostname, ordinal, payload) = match header {
        SessionTicketStoreHeader::Tcp(_) => {
            let metadata = TcpSessionRecordMetadata::parse(bytes)?;
            (
                SessionTicketStoreHeader::Tcp(metadata.header()),
                metadata.hostname(),
                metadata.ordinal(),
                metadata.payload(),
            )
        }
        SessionTicketStoreHeader::Quic(_) => {
            let metadata = QuicSessionRecordMetadata::parse(bytes)?;
            metadata.validate_transport_parameters()?;
            // H3 application-state semantics are validated by the caller.
            (
                SessionTicketStoreHeader::Quic(metadata.header()),
                metadata.hostname(),
                metadata.ordinal(),
                metadata.payload(),
            )
        }
    };
    if native_witness != source_witness
        || actual_header != header
        || hostname != server_name
        || ordinal != usize::from(slot.physical_ordinal)
        || payload.len() != 12
        || payload[..8] != *b"PHTOW001"
        || payload[8..10] != 1_u16.to_be_bytes()
        || payload[10..12] != record_owner_index.to_be_bytes()
    {
        return Err(ColdError::Mapping);
    }
    Ok(())
}

fn owner_framing(owners: &[ColdOwner]) -> Result<usize, ColdError> {
    owners.iter().try_fold(ENVELOPE_FRAME, |size, owner| {
        add_owner_size(
            size,
            [
                owner.origin.authority().as_str().len(),
                owner.origin.host().len(),
                owner.server_name.len(),
                owner.policy.len(),
                owner.source_witness.len(),
            ],
            owner.slots.len(),
            owner.header,
        )
    })
}

fn add_owner_size(
    size: usize,
    fields: [usize; 5],
    slots: usize,
    header: SessionTicketStoreHeader,
) -> Result<usize, ColdError> {
    let size = bounded_add(size, OWNER_FRAME, MAX_ENVELOPE)?;
    let header_len = match header {
        SessionTicketStoreHeader::Tcp(header) => header.to_bytes().len(),
        SessionTicketStoreHeader::Quic(header) => header.to_bytes().len(),
    };
    let size = bounded_add(size, header_len, MAX_ENVELOPE)?;
    let size = fields
        .into_iter()
        .try_fold(size, |size, field| bounded_add(size, field, MAX_ENVELOPE))?;
    bounded_add(
        size,
        slots.checked_mul(3).ok_or(ColdError::TooLarge)?,
        MAX_ENVELOPE,
    )
}

fn bounded_add(left: usize, right: usize, bound: usize) -> Result<usize, ColdError> {
    left.checked_add(right)
        .filter(|size| *size <= bound)
        .ok_or(ColdError::TooLarge)
}

fn reserved<T>(count: usize) -> Result<Vec<T>, ColdError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ColdError::Allocation)?;
    Ok(values)
}

fn copy_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ColdError> {
    if bytes.len() > MAX_POLICY {
        return Err(ColdError::TooLarge);
    }
    let mut copied = Zeroizing::new(reserved(bytes.len())?);
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn copy_name(name: &str) -> Result<Zeroizing<String>, ColdError> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() || name.as_bytes().contains(&0) {
        return Err(ColdError::Mapping);
    }
    let mut copied = Zeroizing::new(String::new());
    copied
        .try_reserve_exact(name.len())
        .map_err(|_| ColdError::Allocation)?;
    copied.push_str(name);
    Ok(copied)
}

fn endpoint(authority: &str, host: &str, port: u16) -> Result<Endpoint, ColdError> {
    if authority.len() > 1024 || host.len() > 253 {
        return Err(ColdError::TooLarge);
    }
    let parsed = authority.parse().map_err(|_| ColdError::Mapping)?;
    let endpoint = Endpoint::new(parsed, port).map_err(|_| ColdError::Mapping)?;
    if endpoint.authority().as_str() != authority
        || endpoint.host() != host
        || endpoint.port() != port
    {
        return Err(ColdError::Mapping);
    }
    Ok(endpoint)
}

// Metadata remains borrowed until the complete union framing/count check.
// Map keys are original slots; values are compact combined native positions.
struct OwnerSelection<'a> {
    owners: Vec<&'a ColdOwner>,
    indices: Vec<usize>,
    map: [Option<u16>; MAX_RECORDS],
}

fn owner_shape(
    leg: TicketCacheLeg,
    protocol: TicketCacheProtocol,
    credentials: bool,
    header: SessionTicketStoreHeader,
) -> Result<(), ColdError> {
    let (records, _) = store_shape(protocol, header)?;
    if (credentials && records == 0)
        || (leg == TicketCacheLeg::HttpProxy && protocol == TicketCacheProtocol::Http3)
        || (leg == TicketCacheLeg::ConnectUdp && protocol == TicketCacheProtocol::Negotiated)
    {
        return Err(ColdError::UnsupportedOwner);
    }
    Ok(())
}

fn store_shape(
    protocol: TicketCacheProtocol,
    header: SessionTicketStoreHeader,
) -> Result<(usize, usize), ColdError> {
    match (protocol, header) {
        (
            TicketCacheProtocol::Http1
            | TicketCacheProtocol::Http2
            | TicketCacheProtocol::Negotiated,
            SessionTicketStoreHeader::Tcp(header),
        ) => Ok((
            header.record_count(),
            header.record_count() + header.excluded_expired_count(),
        )),
        (TicketCacheProtocol::Http3, SessionTicketStoreHeader::Quic(header)) => Ok((
            header.record_count(),
            header.record_count() + header.excluded_expired_count(),
        )),
        _ => Err(ColdError::Mapping),
    }
}

fn same_owner(left: &ColdOwner, right: &ColdOwner) -> bool {
    left.origin.authority().as_str() == right.origin.authority().as_str()
        && left.origin.host() == right.origin.host()
        && left.origin.port() == right.origin.port()
        && left.server_name.as_str() == right.server_name.as_str()
        && left.leg == right.leg
        && left.protocol == right.protocol
        && left.policy.as_slice() == right.policy.as_slice()
}

fn same_view(owner: &ColdOwner, view: &OwnerView<'_>) -> bool {
    owner.origin.authority().as_str() == view.origin_authority
        && owner.origin.host() == view.origin_host
        && owner.origin.port() == view.origin_port
        && owner.server_name.as_str() == view.server_name
        && owner.leg == view.leg
        && owner.protocol == view.protocol
        && owner.policy.as_slice() == view.policy
}

fn same_views(left: &OwnerView<'_>, right: &OwnerView<'_>) -> bool {
    left.origin_authority == right.origin_authority
        && left.origin_host == right.origin_host
        && left.origin_port == right.origin_port
        && left.server_name == right.server_name
        && left.leg == right.leg
        && left.protocol == right.protocol
        && left.policy == right.policy
}

fn validate_replacements(replacements: &[OwnerView<'_>]) -> Result<(), ColdError> {
    if replacements.len() > MAX_OWNERS {
        return Err(ColdError::TooLarge);
    }
    for (index, owner) in replacements.iter().enumerate() {
        owner_shape(
            owner.leg,
            owner.protocol,
            owner.has_credentials,
            owner.header,
        )?;
        if usize::from(owner.index) != index
            || replacements[..index]
                .iter()
                .any(|old| same_views(old, owner))
        {
            return Err(ColdError::Mapping);
        }
    }
    Ok(())
}

fn record_bytes(records: &[AuthenticatedSessionRecord], budget: usize) -> Result<usize, ColdError> {
    records.iter().try_fold(0_usize, |size, record| {
        bounded_add(size, record.encoded_len(), budget)
    })
}

#[cfg(test)]
mod tests;
