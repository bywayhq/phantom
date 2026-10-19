//! Export complete TCP and QUIC owners without changing their ticket stores.

use std::fmt;

use btls::ssl::{PreparedSessionPolicyFreeze, SessionPolicyBinding, SessionTransferError};
use phantom_net::{SessionTicketCacheOwner, SessionTicketStoreExport, SessionTicketStoreHeader};

use super::{
    RegisteredBinding, RegisteredCache, TicketCacheProtocol, TicketOwner,
    binding::PreparationError,
    envelope::{self, OwnerInput, RecordSlot, SealedManifest},
};

#[cfg(test)]
use super::TicketCacheLeg;

const MAX_FRAME: usize = 16 * 1024 * 1024;
// Closed PHOWN003 and PHTKT001 framing: outer header/tag, counts, native
// field prefix, and native header/tag/count. Record framing comes from native.
const BASE_FRAME: usize = 90 + 16 + 4 + 4 + 56 + 16 + 4;
const OWNER_FRAME: usize = 2 + 2 + 2 + 1 + 1 + 1 + 1 + 4 + 1 + 20;
const MAX_OWNERS: usize = 256;
const MAX_RECORDS: usize = 2560;
const MAX_STORE_RECORDS: usize = 10;
const PAYLOAD_MAGIC: &[u8; 8] = b"PHTOW001";

pub(super) enum ExportError {
    Allocation,
    TooLarge,
    RegistryPoisoned,
    ConflictingOwner,
    AmbiguousSharing,
    InvalidCapture,
    Cold(super::staging::ColdError),
    Preparation(PreparationError),
    Native(SessionTransferError),
    Envelope(envelope::EnvelopeError),
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "ticket export allocation failed",
            Self::TooLarge => "ticket export exceeds its resource bound",
            Self::RegistryPoisoned => "ticket export registry is poisoned",
            Self::AmbiguousSharing => {
                "ticket sharing retains several live stores for one portable owner"
            }
            Self::ConflictingOwner => "ticket export has conflicting cache owners",
            Self::InvalidCapture => "ticket export has invalid storage metadata",
            Self::Cold(_) => "cold ticket export failed validation",
            Self::Preparation(_) => "ticket export configuration is unsupported",
            Self::Native(_) => "ticket export native validation failed",
            Self::Envelope(_) => "ticket export envelope failed",
        })
    }
}

impl fmt::Debug for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cold(error) => Some(error),
            Self::Preparation(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Envelope(error) => Some(error),
            _ => None,
        }
    }
}

impl From<super::staging::ColdError> for ExportError {
    fn from(error: super::staging::ColdError) -> Self {
        Self::Cold(error)
    }
}

impl From<PreparationError> for ExportError {
    fn from(error: PreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<SessionTransferError> for ExportError {
    fn from(error: SessionTransferError) -> Self {
        Self::Native(error)
    }
}

impl From<envelope::EnvelopeError> for ExportError {
    fn from(error: envelope::EnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

struct LiveOwner<'a> {
    cache: SessionTicketCacheOwner,
    registration: &'a RegisteredBinding,
    native_binding: &'a SessionPolicyBinding,
}

impl TicketOwner {
    /// Authenticate every supported live owner while preserving its source store.
    /// Any unsupported or conflicting live registration rejects the whole attempt.
    pub(super) fn export(&self, key: &[u8; 32]) -> Result<SealedManifest, ExportError> {
        let preparation = self
            .preparation
            .as_ref()
            .ok_or(PreparationError::Unsupported("missing client preparation"))?
            .as_ref()
            .map_err(|error| *error)?;
        // Callbacks never take this lock. Keep register and clear serialized
        // through capture and both native and facade envelope sealing.
        let registry = self
            .registry
            .lock()
            .map_err(|_| ExportError::RegistryPoisoned)?;
        let caches = &registry.caches;
        let mut owners: Vec<LiveOwner<'_>> = reserved(caches.len().min(MAX_OWNERS))?;
        for registered in caches.iter() {
            let Some(cache) = registered.cache.upgrade() else {
                continue;
            };
            let registration = registered.binding.as_ref().map_err(|error| *error)?;
            let native_binding = registered.native_binding.as_ref().map_err(|error| *error)?;
            preparation.validate_source_witness(registration.descriptor.source_witness())?;
            let mut alias = false;
            for existing in &owners {
                if existing.cache.same_cache(&cache) {
                    if !same_registration(existing.registration, registration) {
                        return Err(ExportError::ConflictingOwner);
                    }
                    alias = true;
                } else if same_manifest_owner(existing.registration, registration) {
                    // Two physical counters cannot be merged into one logical owner.
                    return Err(if self.sharing_enabled() {
                        ExportError::AmbiguousSharing
                    } else {
                        ExportError::ConflictingOwner
                    });
                }
            }
            if alias {
                continue;
            }
            if owners.len() == MAX_OWNERS {
                return Err(ExportError::TooLarge);
            }
            owners.push(LiveOwner {
                cache,
                registration,
                native_binding,
            });
        }
        // Count all configured owner bytes before capture or record retention.
        let mut budget = owner_frame_budget(&owners)?;
        // Stored cold custody is whole-owner state. Count it before retaining
        // any additional opaque bodies; capture callbacks never take this lock.
        let cold = if let Some(cold) = &registry.cold {
            if owners
                .len()
                .checked_add(cold.owners.len())
                .is_none_or(|n| n > MAX_OWNERS)
            {
                return Err(ExportError::TooLarge);
            }
            for retained in &cold.owners {
                if owners.iter().any(|live| {
                    let binding = live.registration;
                    retained.origin.authority().as_str() == binding.origin.authority().as_str()
                        && retained.origin.host() == binding.origin.host()
                        && retained.origin.port() == binding.origin.port()
                        && retained.server_name.as_str() == binding.server_name
                        && retained.leg == binding.leg
                        && retained.protocol == binding.protocol
                        && retained.policy.as_slice() == binding.descriptor.policy()
                }) {
                    return Err(ExportError::ConflictingOwner);
                }
            }
            let available = MAX_FRAME
                .checked_sub(budget - BASE_FRAME)
                .ok_or(ExportError::TooLarge)?;
            let export = cold.prepare_export(key, available)?;
            for retained in &export.owners {
                for size in [
                    owner_frame(match retained.header {
                        SessionTicketStoreHeader::Tcp(_) => StoreKind::Tcp,
                        SessionTicketStoreHeader::Quic(_) => StoreKind::Quic,
                    }),
                    retained.origin.authority().as_str().len(),
                    retained.origin.host().len(),
                    retained.server_name.len(),
                    retained.policy.len(),
                    retained.source_witness.len(),
                    retained
                        .slots
                        .len()
                        .checked_mul(3)
                        .ok_or(ExportError::TooLarge)?,
                ] {
                    charge_frame(&mut budget, size)?;
                }
            }
            for record in &export.records {
                charge_frame(&mut budget, record.encoded_len())?;
            }
            Some(export)
        } else {
            None
        };
        let cold_owner_count = cold.as_ref().map_or(0, |cold| cold.owners.len());
        let cold_record_count = cold.as_ref().map_or(0, |cold| cold.records.len());
        let mut capture_inputs = reserved(owners.len())?;
        let mut native_bindings = reserved(owners.len())?;
        let mut slots = reserved(owners.len())?;
        let mut headers: Vec<SessionTicketStoreHeader> = reserved(owners.len())?;
        let mut manifest_owners = reserved(owners.len() + cold_owner_count)?;
        let mut records = reserved(MAX_RECORDS)?;
        for owner in &owners {
            capture_inputs.push((&owner.cache, owner.registration.server_name.as_str()));
            native_bindings.push(owner.native_binding);
            slots.push(reserved(MAX_STORE_RECORDS)?);
        }
        // This helper releases every native guard before capture locks stores.
        validate_bindings(caches, &native_bindings)?;
        let exports = SessionTicketCacheOwner::capture_stores(&capture_inputs)?;
        if exports.len() != owners.len() {
            return Err(ExportError::InvalidCapture);
        }
        let total = exports.iter().try_fold(0_usize, |count, store| {
            count
                .checked_add(record_count(store_header(store)))
                .filter(|value| *value <= MAX_RECORDS)
                .ok_or(ExportError::TooLarge)
        })?;
        if total
            .checked_add(cold_record_count)
            .is_none_or(|n| n > MAX_RECORDS)
        {
            return Err(ExportError::TooLarge);
        }
        charge_frame(
            &mut budget,
            total.checked_mul(3).ok_or(ExportError::TooLarge)?,
        )?;
        for (index, store) in exports.into_iter().enumerate() {
            let header = store_header(&store);
            if record_count(header) > MAX_STORE_RECORDS {
                return Err(ExportError::InvalidCapture);
            }
            headers.push(header);
            let payload = owner_payload(index as u16);
            let mut retain_record = |ordinal: usize,
                                     sealed: btls::ssl::AuthenticatedSessionRecord|
             -> Result<(), ExportError> {
                if records.len() == MAX_RECORDS {
                    return Err(ExportError::TooLarge);
                }
                let ordinal = u8::try_from(ordinal).map_err(|_| ExportError::InvalidCapture)?;
                let slot = RecordSlot {
                    native_slot: records.len() as u16,
                    physical_ordinal: ordinal,
                };
                charge_frame(&mut budget, sealed.encoded_len())?;
                records.push(sealed);
                slots[index].push(slot);
                Ok(())
            };
            // Native sealing happens after capture releases every store guard.
            // Each original live proof and expiry is checked again by seal.
            match store {
                SessionTicketStoreExport::Tcp(store) => {
                    for record in store.into_records() {
                        let ordinal = record.ordinal();
                        retain_record(ordinal, record.seal(&payload, key)?)?;
                    }
                }
                SessionTicketStoreExport::Quic(store) => {
                    for record in store.into_records() {
                        let ordinal = record.ordinal();
                        retain_record(ordinal, record.seal(&payload, key)?)?;
                    }
                }
            }
            if slots[index].len() != record_count(header) {
                return Err(ExportError::InvalidCapture);
            }
        }
        if records.len() != total {
            return Err(ExportError::InvalidCapture);
        }
        for (index, owner) in owners.iter().enumerate() {
            let registration = owner.registration;
            manifest_owners.push(OwnerInput {
                record_owner_index: index as u16,
                origin: &registration.origin,
                server_name: &registration.server_name,
                leg: registration.leg,
                protocol: registration.protocol,
                policy: registration.descriptor.policy(),
                source_witness: registration.descriptor.source_witness(),
                has_credentials: registration.route.credential()?.is_some(),
                header: headers[index],
                slots: &slots[index],
            });
        }
        let mut cold = cold;
        if let Some(cold) = &mut cold {
            let offset = u16::try_from(records.len()).map_err(|_| ExportError::TooLarge)?;
            for owner in &mut cold.owners {
                for slot in &mut owner.slots {
                    slot.native_slot = slot
                        .native_slot
                        .checked_add(offset)
                        .ok_or(ExportError::TooLarge)?;
                }
            }
            manifest_owners.extend(cold.owners.iter().map(super::staging::ColdOwner::input));
            records.append(&mut cold.records);
        }
        let native = btls::ssl::seal_envelope(&records, key)?;
        let sealed = envelope::seal_manifest(key, &manifest_owners, &native)?;
        if sealed.as_bytes().len() != budget {
            return Err(ExportError::InvalidCapture);
        }
        // Check all original registrations, including equal aliases, after
        // serialization. Guard membership uses actual installed identity.
        validate_bindings(caches, &native_bindings)?;
        Ok(sealed)
    }
}

#[derive(Clone, Copy)]
enum StoreKind {
    Tcp,
    Quic,
}

fn owner_frame(kind: StoreKind) -> usize {
    OWNER_FRAME
        + match kind {
            StoreKind::Tcp => 22,
            StoreKind::Quic => 26,
        }
}

fn store_header(store: &SessionTicketStoreExport) -> SessionTicketStoreHeader {
    match store {
        SessionTicketStoreExport::Tcp(store) => SessionTicketStoreHeader::Tcp(store.header()),
        SessionTicketStoreExport::Quic(store) => SessionTicketStoreHeader::Quic(store.header()),
    }
}

fn record_count(header: SessionTicketStoreHeader) -> usize {
    match header {
        SessionTicketStoreHeader::Tcp(header) => header.record_count(),
        SessionTicketStoreHeader::Quic(header) => header.record_count(),
    }
}

fn same_registration(left: &RegisteredBinding, right: &RegisteredBinding) -> bool {
    left.origin == right.origin
        && left.origin.authority().as_str() == right.origin.authority().as_str()
        && left.server_name == right.server_name
        && left.leg == right.leg
        && left.protocol == right.protocol
        && left.route == right.route
        && left.descriptor == right.descriptor
}

fn same_manifest_owner(left: &RegisteredBinding, right: &RegisteredBinding) -> bool {
    left.origin.authority().as_str() == right.origin.authority().as_str()
        && left.origin.host() == right.origin.host()
        && left.origin.port() == right.origin.port()
        && left.server_name == right.server_name
        && left.leg == right.leg
        && left.protocol == right.protocol
        && left.descriptor.policy() == right.descriptor.policy()
}

fn owner_frame_budget(owners: &[LiveOwner<'_>]) -> Result<usize, ExportError> {
    let mut budget = BASE_FRAME;
    for owner in owners {
        let registration = owner.registration;
        for length in [
            owner_frame(match owner.registration.protocol {
                TicketCacheProtocol::Http3 => StoreKind::Quic,
                _ => StoreKind::Tcp,
            }),
            registration.origin.authority().as_str().len(),
            registration.origin.host().len(),
            registration.server_name.len(),
            registration.descriptor.policy().len(),
            registration.descriptor.source_witness().len(),
        ] {
            charge_frame(&mut budget, length)?;
        }
    }
    Ok(budget)
}

fn charge_frame(budget: &mut usize, length: usize) -> Result<(), ExportError> {
    let next = budget
        .checked_add(length)
        .filter(|value| *value <= MAX_FRAME)
        .ok_or(ExportError::TooLarge)?;
    *budget = next;
    Ok(())
}

fn owner_payload(index: u16) -> [u8; 12] {
    let mut payload = [0; 12];
    payload[..8].copy_from_slice(PAYLOAD_MAGIC);
    payload[9] = 1;
    payload[10..].copy_from_slice(&index.to_be_bytes());
    payload
}

fn validate_bindings(
    registry: &[RegisteredCache],
    bindings: &[&SessionPolicyBinding],
) -> Result<(), ExportError> {
    let frozen = PreparedSessionPolicyFreeze::new(bindings)?.try_freeze()?;
    for registered in registry.iter().filter(|entry| entry.cache.is_live()) {
        let binding = registered.native_binding.as_ref().map_err(|error| *error)?;
        let registration = registered.binding.as_ref().map_err(|error| *error)?;
        frozen.validate_binding(binding, &registration.server_name)?;
    }
    Ok(())
}

fn reserved<T>(count: usize) -> Result<Vec<T>, ExportError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ExportError::Allocation)?;
    Ok(values)
}

#[cfg(test)]
mod tests;
