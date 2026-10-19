//! TCP and QUIC replacement and cold custody. Parsing grants no authority.

use std::{fmt, sync::Arc};

use btls::ssl::{SessionTransferError, SslContextRef};
use phantom_net::{
    QuicSessionRecordMetadata, SessionTicketCacheOwner, SessionTicketStoreHeader,
    TcpSessionRecordMetadata,
};

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
    AmbiguousSharing,
    EmptyCredentials,
    Preparation(PreparationError),
    Manifest(EnvelopeError),
    Native(SessionTransferError),
    Cold(ColdError),
    Application(phantom_net::http3::Http3Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RegistryPoisoned => "ticket recipient registry is poisoned",
            Self::Allocation => "ticket import allocation failed",
            Self::TooLarge => "ticket import exceeds its resource bound",
            Self::OwnerMapping => "ticket owners do not match recipient configuration",
            Self::AmbiguousSharing => {
                "ticket sharing retains several live stores for one portable owner"
            }
            Self::UnsupportedRoute => "ticket import route or protocol is unsupported",
            Self::EmptyCredentials => "empty credentialed ticket import is unsupported",
            Self::Preparation(_) => "ticket recipient preparation failed",
            Self::Manifest(_) => "ticket owner manifest failed validation",
            Self::Native(_) => "native ticket import failed validation",
            Self::Cold(_) => "cold ticket custody preparation failed",
            Self::Application(_) => "remembered HTTP/3 settings are invalid",
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
            Self::Application(error) => Some(error),
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
        && source.policy == recipient.descriptor.policy()
}

fn validate_record(
    source: &OwnerView<'_>,
    ordinal: u8,
    witness: &[u8],
    metadata: &[u8],
) -> Result<(), ImportError> {
    let (header, hostname, actual_ordinal, payload) = match source.header {
        SessionTicketStoreHeader::Tcp(_) => {
            let record = TcpSessionRecordMetadata::parse(metadata)?;
            (
                SessionTicketStoreHeader::Tcp(record.header()),
                record.hostname(),
                record.ordinal(),
                record.payload(),
            )
        }
        SessionTicketStoreHeader::Quic(_) => {
            let record = QuicSessionRecordMetadata::parse(metadata)?;
            record.validate_transport_parameters()?;
            if let Some(settings) = record.application_state() {
                phantom_net::http3::validate_remembered_peer_settings(settings)
                    .map_err(ImportError::Application)?;
            }
            (
                SessionTicketStoreHeader::Quic(record.header()),
                record.hostname(),
                record.ordinal(),
                record.payload(),
            )
        }
    };
    if witness != source.source_witness
        || header != source.header
        || hostname != source.server_name
        || actual_ordinal != usize::from(ordinal)
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
    Client {
        client: &'a crate::client::ClientInner,
        routes: &'a [Route],
    },
    #[cfg(test)]
    Fixture,
}

impl ImportConfiguration<'_> {
    fn resolve_route(
        &self,
        preparation: &super::binding::PreparedTicketPolicy,
        source: &OwnerView<'_>,
        origin: &Endpoint,
        native: &btls::ssl::VerifiedSessionEnvelope,
    ) -> Result<Route, ImportError> {
        let mut candidates = reserved(MAX_OWNERS + 1)?;
        match self {
            Self::Client { client, routes } => {
                let shared = source.leg == TicketCacheLeg::ConnectUdp
                    && matches!(
                        source.protocol,
                        TicketCacheProtocol::Http2 | TicketCacheProtocol::Http3
                    );
                if let Some(route) = client.ticket_import_route(origin, shared) {
                    candidates.push(route);
                }
                for route in *routes {
                    if !candidates.contains(route) {
                        candidates.push(route.clone());
                    }
                }
            }
            #[cfg(test)]
            Self::Fixture => candidates.push(Route::Direct),
        }
        let mut credential_mismatch = false;
        for route in candidates {
            if !self.supports_route(source, origin, &route) {
                continue;
            }
            let descriptor = preparation.prepare_cache_descriptor(
                origin,
                source.server_name,
                source.leg,
                source.protocol,
                &route,
            )?;
            if source.policy != descriptor.policy()
                || source.has_credentials != crate::route::transfer_credential(&route)?.is_some()
            {
                continue;
            }
            let configured =
                preparation.configured_policy(&descriptor, source.leg, source.protocol, &route)?;
            // QUIC retains early-data metadata even when its offer is disabled.
            // The native check compares retention mode; policy binds the offer.
            let keep_early_data = match source.header {
                SessionTicketStoreHeader::Tcp(_) => {
                    preparation.allows_early_data(source.leg, source.protocol, &route)?
                }
                SessionTicketStoreHeader::Quic(_) => true,
            };
            let validation = source.slots().try_for_each(|slot| {
                native.validate_record_policy(
                    usize::from(slot.native_slot),
                    &configured,
                    source.server_name,
                    keep_early_data,
                )
            });
            match validation {
                Ok(()) => return Ok(route),
                // Credential values are deliberately absent from public policy
                // bytes. An earlier candidate must not hide a later exact match.
                Err(SessionTransferError::Credentials) => credential_mismatch = true,
                Err(error) => return Err(error.into()),
            }
        }
        if credential_mismatch {
            Err(SessionTransferError::Credentials.into())
        } else {
            Err(ImportError::OwnerMapping)
        }
    }

    fn supports_route(&self, source: &OwnerView<'_>, origin: &Endpoint, route: &Route) -> bool {
        self.supports_ticket_route(source, origin, &super::TicketRoute::capture(route))
    }

    fn supports_ticket_route(
        &self,
        source: &OwnerView<'_>,
        origin: &Endpoint,
        route: &super::TicketRoute,
    ) -> bool {
        let client = match self {
            Self::Client { client, .. } => client,
            #[cfg(test)]
            Self::Fixture => return matches!(route.ordinary(), Some(Route::Direct)),
        };
        let connectors = client.connectors_for(origin);
        match source.leg {
            TicketCacheLeg::Origin => {
                if source.server_name != origin.host() {
                    return false;
                }
                match source.protocol {
                    TicketCacheProtocol::Http1 => {
                        connectors.http1.is_some()
                            && route
                                .ordinary()
                                .is_some_and(Route::carries_origin_tls_for_alpn)
                    }
                    TicketCacheProtocol::Http2 => {
                        connectors.http2.is_some()
                            && route
                                .ordinary()
                                .is_some_and(Route::carries_origin_tls_for_alpn)
                    }
                    TicketCacheProtocol::Negotiated => {
                        connectors.http1_or_2.is_some()
                            && route
                                .ordinary()
                                .is_some_and(Route::carries_origin_tls_for_alpn)
                    }
                    TicketCacheProtocol::Http3 => {
                        connectors.http3.is_some()
                            && (matches!(route.ordinary(), Some(Route::Direct | Route::Socks5(_)))
                                || route.connect_udp().is_some())
                    }
                }
            }
            TicketCacheLeg::HttpProxy => {
                let Some(Route::HttpProxy(proxy)) = route.ordinary() else {
                    return false;
                };
                proxy.uses_tls()
                    && client.https_proxy.is_some()
                    && source.server_name == proxy.host()
                    && source.protocol
                        == if proxy.uses_http2() {
                            TicketCacheProtocol::Http2
                        } else {
                            TicketCacheProtocol::Http1
                        }
            }
            TicketCacheLeg::ConnectUdp => {
                let Some(proxy) = route.connect_udp() else {
                    return false;
                };
                let Some(outer) = &client.connect_udp_proxy else {
                    return false;
                };
                let supported = match (source.protocol, proxy.tcp_protocol()) {
                    (
                        TicketCacheProtocol::Http1,
                        Some(phantom_net::proxy::HttpsProxyProtocol::Http1),
                    ) => outer.tcp.is_some() && connectors.http3.is_some(),
                    (
                        TicketCacheProtocol::Http2,
                        Some(phantom_net::proxy::HttpsProxyProtocol::Http2),
                    ) => outer.tcp.is_some(),
                    (TicketCacheProtocol::Http3, None) => outer.http3.is_some(),
                    _ => false,
                };
                supported
                    && source.server_name == proxy.host()
                    && (source.protocol == TicketCacheProtocol::Http1
                        || (origin.host() == proxy.host()
                            && origin.port() == proxy.port()
                            && origin.authority().as_str() == proxy.authority()))
            }
        }
    }
}

impl TicketOwner {
    pub(super) fn import_for_client(
        &self,
        snapshot: &[u8],
        key: &[u8; 32],
        decoding_context: &SslContextRef,
        client: &crate::client::ClientInner,
        receiving_routes: &[Route],
    ) -> Result<usize, ImportError> {
        if receiving_routes.len() > MAX_OWNERS {
            return Err(ImportError::TooLarge);
        }
        self.import_configured(
            snapshot,
            key,
            decoding_context,
            ImportConfiguration::Client {
                client,
                routes: receiving_routes,
            },
        )
    }

    #[cfg(test)]
    fn import_tcp(
        &self,
        snapshot: &[u8],
        key: &[u8; 32],
        decoding_context: &SslContextRef,
    ) -> Result<usize, ImportError> {
        self.import_configured(
            snapshot,
            key,
            decoding_context,
            ImportConfiguration::Fixture,
        )
    }

    /// The caller supplies a compatible decoding context, never recipient proof.
    /// A zero-owner envelope is an authenticated no-op. Matched owners replace
    /// only their live stores; unmatched owners retain validated cold custody.
    fn import_configured(
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
                    return Err(if self.sharing_enabled() {
                        ImportError::AmbiguousSharing
                    } else {
                        ImportError::OwnerMapping
                    });
                }
            }
            if let Some(position) = matched {
                if std::mem::replace(&mut used[position], true) {
                    return Err(ImportError::OwnerMapping);
                }
                let registration = &caches[owners[position].1];
                let binding = registration.binding.as_ref().map_err(|error| *error)?;
                let has_credentials = binding.route.credential()?.is_some();
                if envelope::store_counts(source.header).0 == 0 && has_credentials {
                    return Err(ImportError::EmptyCredentials);
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
            if source.slots().len() == 0 && source.has_credentials {
                return Err(ImportError::EmptyCredentials);
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
            let live_route = matched
                .map(|position| caches[owners[position].1].binding.as_ref())
                .transpose()
                .map_err(|error| *error)?;
            preparation.validate_source_witness(source.source_witness)?;
            for slot in source.slots() {
                let index = usize::from(slot.native_slot);
                validate_record(
                    source,
                    slot.physical_ordinal,
                    native.source_witness(index)?,
                    native.owner_metadata(index)?,
                )?;
            }
            if let Some(binding) = live_route {
                if !configuration.supports_ticket_route(source, &origin, &binding.route) {
                    return Err(ImportError::OwnerMapping);
                }
                let configured = preparation.configured_registered_policy(binding)?;
                let keep_early_data = matches!(source.header, SessionTicketStoreHeader::Quic(_))
                    || binding.keep_early_data;
                for slot in source.slots() {
                    native.validate_record_policy(
                        usize::from(slot.native_slot),
                        &configured,
                        source.server_name,
                        keep_early_data,
                    )?;
                }
            } else {
                configuration.resolve_route(preparation, source, &origin, &native)?;
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
            let mut permits = reserved(envelope::store_counts(source.header).0)?;
            for slot in source.slots() {
                // Only an actual installed recipient binding mints a permit.
                // Failed preparation consumes private incoming custody only.
                permits.push(
                    incoming
                        .native
                        .authorize_record(usize::from(slot.native_slot), recipient)?,
                );
            }
            replacements.push(owner.prepare_replacement(
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
        let retired = SessionTicketCacheOwner::replace_stores(replacements)?;
        let old_cold = std::mem::replace(&mut registry.cold, next_cold);
        drop(registry);
        drop(old_cold);
        Ok(retired.finish())
    }
}

#[cfg(test)]
mod tests;
