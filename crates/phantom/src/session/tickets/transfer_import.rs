//! Direct TCP replacement and cold custody. Parsing grants no recipient authority.

use std::{fmt, sync::Arc};

use btls::ssl::{SessionTransferError, SslContextRef};
use phantom_net::{SessionTicketCacheOwner, TcpSessionRecordMetadata};

use super::{
    RegisteredBinding, TicketOwner,
    binding::{PreparationError, TicketCacheLeg, TicketCacheProtocol},
    envelope::{self, EnvelopeError, OwnerView},
    staging::{ColdError, ColdState},
};
use crate::{Route, authority::Endpoint};

const MAX_OWNERS: usize = 256;
const MAX_RECORDS: usize = 2560;
const MAX_ENVELOPE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub(super) enum ImportError {
    Allocation,
    RegistryPoisoned,
    TooLarge,
    OwnerMapping,
    UnsupportedRoute,
    EmptyCredentials,
    Preparation(PreparationError),
    Manifest(EnvelopeError),
    Native(SessionTransferError),
    Cold(ColdError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegistryPoisoned => "ticket recipient registry is poisoned",
            Self::Allocation => "ticket import allocation failed",
            Self::TooLarge => "ticket import exceeds its resource bound",
            Self::OwnerMapping => "ticket owners do not match recipient configuration",
            Self::UnsupportedRoute => "ticket import requires direct TCP origins",
            Self::EmptyCredentials => "empty credentialed ticket import is unsupported",
            Self::Preparation(_) => "ticket recipient preparation failed",
            Self::Manifest(_) => "ticket owner manifest failed validation",
            Self::Native(_) => "native ticket import failed validation",
            Self::Cold(_) => "cold ticket custody preparation failed",
        })
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preparation(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Cold(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PreparationError> for ImportError {
    fn from(error: PreparationError) -> Self {
        Self::Preparation(error)
    }
}
impl From<EnvelopeError> for ImportError {
    fn from(error: EnvelopeError) -> Self {
        Self::Manifest(error)
    }
}
impl From<SessionTransferError> for ImportError {
    fn from(error: SessionTransferError) -> Self {
        Self::Native(error)
    }
}

impl From<ColdError> for ImportError {
    fn from(error: ColdError) -> Self {
        Self::Cold(error)
    }
}

fn reserved<T>(count: usize) -> Result<Vec<T>, ImportError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ImportError::Allocation)?;
    Ok(values)
}

fn same_registration(left: &RegisteredBinding, right: &RegisteredBinding) -> bool {
    left.origin == right.origin
        && left.origin.authority() == right.origin.authority()
        && left.server_name == right.server_name
        && left.leg == right.leg
        && left.protocol == right.protocol
        && left.route == right.route
        && left.descriptor == right.descriptor
}

fn matches_owner(source: &OwnerView<'_>, recipient: &RegisteredBinding) -> bool {
    source.origin_authority == recipient.origin.authority().as_str()
        && source.origin_host == recipient.origin.host()
        && source.origin_port == recipient.origin.port()
        && source.server_name == recipient.server_name
        && source.leg == recipient.leg
        && source.protocol == recipient.protocol
}

fn validate_record(
    source: &OwnerView<'_>,
    ordinal: u8,
    witness: &[u8],
    metadata: &[u8],
) -> Result<(), ImportError> {
    let record = TcpSessionRecordMetadata::parse(metadata)?;
    let payload = record.payload();
    if witness != source.source_witness
        || record.header() != source.header
        || record.hostname() != source.server_name
        || record.ordinal() != usize::from(ordinal)
        || payload.len() != 12
        || payload[..8] != *b"PHTOW001"
        || payload[8..10] != 1_u16.to_be_bytes()
        || payload[10..12] != source.record_owner_index.to_be_bytes()
    {
        return Err(ImportError::OwnerMapping);
    }
    Ok(())
}

enum ImportConfiguration<'a> {
    Client(&'a crate::client::ClientInner),
    #[cfg(test)]
    Fixture,
}

impl ImportConfiguration<'_> {
    fn validate(
        &self,
        origin: &Endpoint,
        protocol: TicketCacheProtocol,
    ) -> Result<(), ImportError> {
        match self {
            Self::Client(client) => {
                if !matches!(client.selected_route(None, "https", origin), Route::Direct) {
                    return Err(ImportError::UnsupportedRoute);
                }
                let connectors = client.connectors_for(origin);
                let available = match protocol {
                    TicketCacheProtocol::Http1 => connectors.http1.is_some(),
                    TicketCacheProtocol::Http2 => connectors.http2.is_some(),
                    TicketCacheProtocol::Negotiated => connectors.http1_or_2.is_some(),
                    TicketCacheProtocol::Http3 => false,
                };
                if !available {
                    return Err(ImportError::OwnerMapping);
                }
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture => Ok(()),
        }
    }
}

impl TicketOwner {
    pub(super) fn import_tcp_for_client(
        &self,
        snapshot: &[u8],
        key: &[u8; 32],
        decoding_context: &SslContextRef,
        client: &crate::client::ClientInner,
    ) -> Result<usize, ImportError> {
        self.import_tcp_configured(
            snapshot,
            key,
            decoding_context,
            ImportConfiguration::Client(client),
        )
    }

    #[cfg(test)]
    fn import_tcp(
        &self,
        snapshot: &[u8],
        key: &[u8; 32],
        decoding_context: &SslContextRef,
    ) -> Result<usize, ImportError> {
        self.import_tcp_configured(
            snapshot,
            key,
            decoding_context,
            ImportConfiguration::Fixture,
        )
    }

    /// The caller supplies a compatible decoding context, never recipient proof.
    /// A zero-owner envelope is an authenticated no-op. Matched owners replace
    /// only their live stores; unmatched direct TCP owners retain cold custody.
    fn import_tcp_configured(
        &self,
        snapshot: &[u8],
        key: &[u8; 32],
        decoding_context: &SslContextRef,
        configuration: ImportConfiguration<'_>,
    ) -> Result<usize, ImportError> {
        if snapshot.len() > MAX_ENVELOPE {
            return Err(ImportError::TooLarge);
        }
        let manifest = envelope::open_manifest(snapshot, key)?;
        let native = btls::ssl::open_envelope(manifest.native_ciphertext(), key, decoding_context)?;
        if native.record_count() != manifest.record_count()
            || manifest.owner_count() > MAX_OWNERS
            || native.record_count() > MAX_RECORDS
        {
            return Err(ImportError::OwnerMapping);
        }
        if manifest.owner_count() == 0 {
            return Ok(0);
        }
        let preparation = self
            .preparation
            .as_ref()
            .ok_or(ImportError::OwnerMapping)?
            .as_ref()
            .map_err(|error| *error)?;
        // Keep the complete original views, including owners consumed into live
        // stores below. They also replace matching old cold owner identities.
        let mut sources = reserved(manifest.owner_count())?;
        for source in manifest.owners() {
            sources.push(source?);
        }
        // Registration and clear cannot change mappings or cold custody during
        // preparation and commit. No callbacks acquire this registry lock.
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| ImportError::RegistryPoisoned)?;
        let caches = &registry.caches;
        let mut owners: Vec<(SessionTicketCacheOwner, usize)> = reserved(MAX_OWNERS)?;
        for (index, registration) in caches.iter().enumerate() {
            let Some(owner) = registration.cache.upgrade() else {
                continue;
            };
            let binding = registration.binding.as_ref().map_err(|error| *error)?;
            if !sources.iter().any(|source| matches_owner(source, binding)) {
                continue;
            }
            if let Some((_, old)) = owners.iter().find(|(other, _)| owner.same_cache(other)) {
                let old_binding = caches[*old].binding.as_ref().map_err(|error| *error)?;
                if !same_registration(binding, old_binding) {
                    return Err(ImportError::OwnerMapping);
                }
                // A failed duplicate installation cannot hide behind an eligible copy.
                registration
                    .native_binding
                    .as_ref()
                    .map_err(|error| *error)?;
                continue;
            }
            if owners.len() == MAX_OWNERS {
                return Err(ImportError::TooLarge);
            }
            owners.push((owner, index));
        }
        let mut used = [false; MAX_OWNERS];
        let mut matches = reserved(sources.len())?;
        // Validate every owner and every native record before authorizing any
        // slot. Metadata, descriptors and configured policy grant no permit.
        for source in &sources {
            let mut matched = None;
            for (position, (_, index)) in owners.iter().enumerate() {
                let binding = caches[*index].binding.as_ref().map_err(|error| *error)?;
                if matches_owner(source, binding) && matched.replace(position).is_some() {
                    return Err(ImportError::OwnerMapping);
                }
            }
            if let Some(position) = matched {
                if std::mem::replace(&mut used[position], true) {
                    return Err(ImportError::OwnerMapping);
                }
                let registration = &caches[owners[position].1];
                let binding = registration.binding.as_ref().map_err(|error| *error)?;
                let has_credentials = crate::route::transfer_credential(&binding.route)?.is_some();
                if source.header.record_count() == 0 && has_credentials {
                    return Err(ImportError::EmptyCredentials);
                }
                if !matches!(binding.route, Route::Direct)
                    || binding.leg != TicketCacheLeg::Origin
                    || !matches!(
                        binding.protocol,
                        TicketCacheProtocol::Http1
                            | TicketCacheProtocol::Http2
                            | TicketCacheProtocol::Negotiated
                    )
                {
                    return Err(ImportError::UnsupportedRoute);
                }
                if source.policy != binding.descriptor.policy()
                    || source.has_credentials != has_credentials
                {
                    return Err(ImportError::OwnerMapping);
                }
                registration
                    .native_binding
                    .as_ref()
                    .map_err(|error| *error)?;
            }
            if source.has_credentials
                || source.leg != TicketCacheLeg::Origin
                || !matches!(
                    source.protocol,
                    TicketCacheProtocol::Http1
                        | TicketCacheProtocol::Http2
                        | TicketCacheProtocol::Negotiated
                )
            {
                return Err(ImportError::UnsupportedRoute);
            }
            let authority = source
                .origin_authority
                .parse()
                .map_err(|_| ImportError::OwnerMapping)?;
            let origin = Endpoint::new(authority, source.origin_port)
                .map_err(|_| ImportError::OwnerMapping)?;
            if origin.authority().as_str() != source.origin_authority
                || origin.host() != source.origin_host
                || origin.port() != source.origin_port
            {
                return Err(ImportError::OwnerMapping);
            }
            configuration.validate(&origin, source.protocol)?;
            let descriptor = preparation.prepare_cache_descriptor(
                &origin,
                source.server_name,
                source.leg,
                source.protocol,
                &Route::Direct,
            )?;
            if source.policy != descriptor.policy() {
                return Err(ImportError::OwnerMapping);
            }
            preparation.validate_source_witness(source.source_witness)?;
            let configured = preparation.configured_direct_tcp_policy(
                &descriptor,
                source.leg,
                source.protocol,
                &Route::Direct,
            )?;
            for slot in source.slots() {
                let index = usize::from(slot.native_slot);
                validate_record(
                    source,
                    slot.physical_ordinal,
                    native.source_witness(index)?,
                    native.owner_metadata(index)?,
                )?;
                preparation.validate_configured_direct_tcp_record(
                    &native,
                    index,
                    &configured,
                    source.server_name,
                )?;
            }
            matches.push(matched);
        }
        let mut incoming = ColdState::capture(&manifest, native)?;
        let mut replacements = reserved(owners.len())?;
        for (source, matched) in sources.iter().zip(&matches) {
            let Some(position) = *matched else {
                continue;
            };
            let (owner, index) = &owners[position];
            let registration = &caches[*index];
            let recipient = registration
                .native_binding
                .as_ref()
                .map_err(|error| *error)?;
            let mut permits = reserved(source.header.record_count())?;
            for slot in source.slots() {
                // Only an actual installed recipient binding mints a permit.
                // Failed preparation consumes private incoming custody only.
                permits.push(
                    incoming
                        .native
                        .authorize_record(usize::from(slot.native_slot), recipient)?,
                );
            }
            replacements.push(owner.prepare_tcp_replacement(
                Arc::from(source.server_name),
                source.header,
                permits,
            )?);
        }
        // Empty owners have no consumed slots to mark successful application.
        // Remove only matched empty intent; retain unmatched empty cold owners.
        let mut index = 0;
        incoming.owners.retain(|owner| {
            let applied = matches[index].is_some();
            index += 1;
            !applied || !owner.slots.is_empty()
        });
        let next_cold = match registry.cold.as_ref() {
            Some(old) => old.prepare_union(&incoming, &sources, decoding_context)?,
            None => incoming.try_clone_remaining()?,
        };
        let next_cold = if next_cold.owners.is_empty() {
            None
        } else {
            Some(next_cold)
        };
        // All cold allocation, native rekeying and sealing precede mutation.
        // The lower transaction validates every store before any live swap.
        let retired = SessionTicketCacheOwner::replace_tcp_stores(replacements)?;
        let old_cold = std::mem::replace(&mut registry.cold, next_cold);
        drop(registry);
        drop(old_cold);
        Ok(retired.finish())
    }
}

#[cfg(test)]
mod tests;
