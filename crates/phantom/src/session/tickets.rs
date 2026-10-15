//! Controls every TLS and QUIC cache owned by one client.

use std::sync::Mutex;
#[cfg(test)]
use std::sync::{MutexGuard, PoisonError};

use phantom_net::proxy::HttpsProxyProtocol;
use phantom_net::{SessionTicketCache, SessionTicketCacheOwner};

use crate::{Route, authority::Endpoint};

use binding::{PreparationError, PreparedCacheDescriptor, TicketCacheLeg, TicketCacheProtocol};

mod api;
pub(super) mod binding;
mod envelope;
mod staging;
mod transfer;
mod transfer_import;

pub use api::{SessionTicketError, SessionTicketErrorKind, SessionTicketSnapshot};

#[derive(Clone, Copy)]
pub(super) struct TicketCacheBinding<'a> {
    pub(super) origin: &'a Endpoint,
    pub(super) server_name: &'a str,
    pub(super) leg: TicketCacheLeg,
    pub(super) protocol: Result<TicketCacheProtocol, PreparationError>,
    pub(super) route: &'a Route,
}

impl TicketCacheBinding<'_> {
    pub(super) fn proxy_protocol(
        protocol: HttpsProxyProtocol,
    ) -> Result<TicketCacheProtocol, PreparationError> {
        match protocol {
            HttpsProxyProtocol::Http1 => Ok(TicketCacheProtocol::Http1),
            HttpsProxyProtocol::Http2 => Ok(TicketCacheProtocol::Http2),
            _ => Err(PreparationError::Unsupported("HttpsProxyProtocol")),
        }
    }
}

struct RegisteredCache {
    cache: SessionTicketCache,
    binding: Result<RegisteredBinding, PreparationError>,
    native_binding: Result<btls::ssl::SessionPolicyBinding, PreparationError>,
}

/// Retains typed inputs for stable policy and local same-cache conflict checks.
/// Neither the descriptor nor these inputs authorize native session attachment.
struct RegisteredBinding {
    descriptor: PreparedCacheDescriptor,
    origin: Endpoint,
    server_name: String,
    leg: TicketCacheLeg,
    protocol: TicketCacheProtocol,
    route: Route,
}

#[derive(Default)]
struct TicketRegistry {
    caches: Vec<RegisteredCache>,
    cold: Option<staging::ColdState>,
}

#[derive(Debug)]
pub(super) struct TicketUseError(transfer_import::ImportError);

impl std::fmt::Display for TicketUseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for TicketUseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Registered caches remain weak so evicted entries can release their tickets.
/// Dead registrations are removed on every registration and clear. The live
/// set follows pool entries plus evicted entries still used by a connection
/// or setup. No connection or setup is retained by this registry.
#[derive(Default)]
pub(super) struct TicketOwner {
    preparation:
        Option<Result<std::sync::Arc<binding::PreparedTicketPolicy>, binding::PreparationError>>,
    registry: Mutex<TicketRegistry>,
}

impl TicketOwner {
    pub(super) fn with_preparation(
        preparation: Result<
            std::sync::Arc<binding::PreparedTicketPolicy>,
            binding::PreparationError,
        >,
    ) -> Self {
        Self {
            preparation: Some(preparation),
            registry: Mutex::default(),
        }
    }

    /// Register before the connector is used. The registry lock serializes
    /// this with clear, so a new cache is either cleared or starts empty after
    /// it. Cache callbacks never acquire the owner lock.
    #[cfg(test)]
    pub(super) fn register(
        &self,
        cache: Option<SessionTicketCache>,
        input: TicketCacheBinding<'_>,
    ) {
        let Some(cache) = cache else {
            return;
        };
        let mut registry = self.registry();
        self.register_locked(
            &mut registry.caches,
            cache,
            self.prepare_registration(input),
        );
    }

    /// Register the pinned shared outer owner and apply matching cold intent.
    pub(super) fn register_shared_outer_before_use(
        &self,
        cache: Option<SessionTicketCache>,
        input: TicketCacheBinding<'_>,
    ) -> Result<(), TicketUseError> {
        let supported = input.leg == TicketCacheLeg::ConnectUdp
            && matches!(
                input.protocol,
                Ok(TicketCacheProtocol::Http2 | TicketCacheProtocol::Http3)
            )
            && matches!(input.route, Route::ConnectUdp(_));
        let registered = self.register_before_use(cache, input);
        if !supported {
            return Err(TicketUseError(
                transfer_import::ImportError::UnsupportedRoute,
            ));
        }
        registered
    }

    fn register_locked(
        &self,
        caches: &mut Vec<RegisteredCache>,
        cache: SessionTicketCache,
        mut binding: Result<RegisteredBinding, PreparationError>,
    ) {
        caches.retain(|registered| registered.cache.is_live());
        let mut native_binding = Err(PreparationError::Unsupported("dead cache"));
        if let Some(owner) = cache.upgrade() {
            let mut duplicate = None;
            let mut conflict = binding.as_ref().err().copied();
            for existing in &*caches {
                if existing
                    .cache
                    .upgrade()
                    .is_some_and(|other| owner.same_cache(&other))
                {
                    match (&existing.binding, &binding) {
                        (Ok(existing_binding), Ok(new_binding))
                            if existing_binding.descriptor != new_binding.descriptor
                                || existing_binding.route != new_binding.route =>
                        {
                            conflict = Some(PreparationError::Unsupported(
                                "conflicting cache descriptors",
                            ));
                        }
                        (Ok(_), Ok(_)) => duplicate = Some(existing.native_binding.clone()),
                        (Err(error), _) => conflict = Some(*error),
                        _ => {}
                    }
                }
            }
            if let Some(error) = conflict {
                binding = Err(error);
                native_binding = Err(error);
                for existing in &mut *caches {
                    if existing
                        .cache
                        .upgrade()
                        .is_some_and(|other| owner.same_cache(&other))
                    {
                        existing.binding = Err(error);
                        existing.native_binding = Err(error);
                    }
                }
            } else {
                native_binding = duplicate.unwrap_or_else(|| {
                    let prepared = self
                        .preparation
                        .as_ref()
                        .ok_or(PreparationError::Unsupported("missing client preparation"))?
                        .as_ref()
                        .map_err(|error| *error)?;
                    let registration = binding.as_ref().map_err(|error| *error)?;
                    prepared.bind_transfer_policy(
                        &owner,
                        &registration.descriptor,
                        &registration.server_name,
                        registration.leg,
                        registration.protocol,
                        &registration.route,
                    )
                });
            }
        }
        caches.push(RegisteredCache {
            cache,
            binding,
            native_binding,
        });
    }

    /// Apply matching cold custody before a connector's next TCP or QUIC TLS use.
    /// Registration and replacement share one registry order with import/clear.
    pub(super) fn register_before_use(
        &self,
        cache: Option<SessionTicketCache>,
        input: TicketCacheBinding<'_>,
    ) -> Result<(), TicketUseError> {
        self.prepare_before_use(cache, input)
            .map_err(TicketUseError)
    }

    fn prepare_before_use(
        &self,
        cache: Option<SessionTicketCache>,
        input: TicketCacheBinding<'_>,
    ) -> Result<(), transfer_import::ImportError> {
        use transfer_import::ImportError;

        let Some(cache) = cache else {
            return Ok(());
        };
        let Some(owner) = cache.upgrade() else {
            return Ok(());
        };
        let origin = input.origin;
        let server_name = input.server_name;
        let leg = input.leg;
        let protocol = input.protocol;
        let route = input.route;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| ImportError::RegistryPoisoned)?;
        registry
            .caches
            .retain(|registered| registered.cache.is_live());
        let index = registry.caches.iter().position(|registered| {
            registered
                .cache
                .upgrade()
                .is_some_and(|other| owner.same_cache(&other))
        });
        let index = match index {
            Some(index) => {
                let prepared = self.prepare_registration(input);
                let previous = &mut registry.caches[index];
                let conflict = match (&previous.binding, prepared) {
                    (Ok(old), Ok(new))
                        if old.descriptor != new.descriptor || old.route != new.route =>
                    {
                        Some(PreparationError::Unsupported(
                            "conflicting cache descriptors",
                        ))
                    }
                    (_, Err(error)) => Some(error),
                    _ => None,
                };
                if let Some(error) = conflict {
                    previous.binding = Err(error);
                    previous.native_binding = Err(error);
                }
                index
            }
            None => {
                let index = registry.caches.len();
                self.register_locked(
                    &mut registry.caches,
                    cache,
                    self.prepare_registration(input),
                );
                index
            }
        };
        let Some(cold) = registry.cold.as_ref() else {
            return Ok(());
        };
        let registration = &registry.caches[index];
        let candidate = cold.owners.iter().any(|staged| {
            staged.origin.host().eq_ignore_ascii_case(origin.host())
                && staged.origin.port() == origin.port()
                && staged.leg == leg
                && Ok(staged.protocol) == protocol
        });
        if !candidate {
            return Ok(());
        }
        let binding = registration.binding.as_ref().map_err(|error| *error)?;
        let same_identity = |staged: &staging::ColdOwner| {
            staged.origin.authority().as_str() == origin.authority().as_str()
                && staged.server_name.as_str() == server_name
                && staged.leg == leg
                && Ok(staged.protocol) == protocol
        };
        if !cold.owners.iter().any(same_identity) {
            return Err(ImportError::OwnerMapping);
        }
        let mut matching = cold.owners.iter().enumerate().filter(|(_, staged)| {
            same_identity(staged) && staged.policy.as_slice() == binding.descriptor.policy()
        });
        let Some((position, _)) = matching.next() else {
            return Ok(());
        };
        if matching.next().is_some()
            || binding.route != *route
            || binding.leg != leg
            || Ok(binding.protocol) != protocol
        {
            return Err(ImportError::OwnerMapping);
        }
        // Only the private clone is consumed. Every failure retains published
        // native custody, metadata and live store contents unchanged.
        let mut working = cold.try_clone_remaining()?;
        if matches!(
            registration.native_binding,
            Err(PreparationError::Backend | PreparationError::Allocation)
        ) {
            let preparation = self
                .preparation
                .as_ref()
                .ok_or(PreparationError::Unsupported("missing client preparation"))?
                .as_ref()
                .map_err(|error| *error)?;
            let retried = preparation.bind_transfer_policy(
                &owner,
                &binding.descriptor,
                &binding.server_name,
                binding.leg,
                binding.protocol,
                &binding.route,
            );
            registry.caches[index].native_binding = retried;
        }
        let recipient = registry.caches[index]
            .native_binding
            .as_ref()
            .map_err(|error| *error)?;
        let staged = &working.owners[position];
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(staged.slots.len())
            .map_err(|_| ImportError::Allocation)?;
        for slot in &staged.slots {
            permits.push(
                working
                    .native
                    .authorize_record(usize::from(slot.native_slot), recipient)?,
            );
        }
        let replacement = owner.prepare_replacement(
            std::sync::Arc::from(staged.server_name.as_str()),
            staged.header,
            permits,
        )?;
        // Empty intent has no consumed native slot. Remove it explicitly.
        if staged.slots.is_empty() {
            working.owners.remove(position);
        }
        let next = working.try_clone_remaining()?;
        let next = (!next.owners.is_empty()).then_some(next);
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(1)
            .map_err(|_| ImportError::Allocation)?;
        replacements.push(replacement);
        let retired = SessionTicketCacheOwner::replace_stores(replacements)?;
        let old = std::mem::replace(&mut registry.cold, next);
        drop(registry);
        drop(old);
        let _ = retired.finish();
        Ok(())
    }

    fn prepare_registration(
        &self,
        input: TicketCacheBinding<'_>,
    ) -> Result<RegisteredBinding, PreparationError> {
        let preparation = self
            .preparation
            .as_ref()
            .ok_or(PreparationError::Unsupported("missing client preparation"))?
            .as_ref()
            .map_err(|error| *error)?;
        let protocol = input.protocol?;
        let descriptor = preparation.prepare_cache_descriptor(
            input.origin,
            input.server_name,
            input.leg,
            protocol,
            input.route,
        )?;
        let mut server_name = String::new();
        server_name
            .try_reserve_exact(input.server_name.len())
            .map_err(|_| PreparationError::Allocation)?;
        server_name.push_str(input.server_name);
        Ok(RegisteredBinding {
            descriptor,
            origin: input.origin.clone(),
            server_name,
            leg: input.leg,
            protocol,
            route: input.route.clone(),
        })
    }

    pub(super) fn clear(&self) -> Result<usize, SessionTicketError> {
        let mut registry = self.registry.lock().map_err(|_| {
            SessionTicketError::with_source(transfer_import::ImportError::RegistryPoisoned)
        })?;
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(registry.caches.len())
            .map_err(|_| {
                SessionTicketError::with_source(btls::ssl::SessionTransferError::Allocation)
            })?;
        owners.extend(
            registry
                .caches
                .iter()
                .filter_map(|registered| registered.cache.upgrade()),
        );
        // Clear and lower-level transfer acquire actual stores in the same order.
        // Cold custody remains published until every live store can be cleared.
        let live_count = SessionTicketCacheOwner::clear_stores(&owners)
            .map_err(SessionTicketError::with_source)?;
        let cold = registry.cold.take();
        // Captured cold state has already validated every present native slot.
        // Metadata access counts present records without rejecting expired ones.
        let cold_count = cold.as_ref().map_or(0, |cold| {
            (0..cold.native.record_count())
                .filter(|index| cold.native.owner_metadata(*index).is_ok())
                .count()
        });
        registry
            .caches
            .retain(|registered| registered.cache.is_live());
        drop(cold);
        Ok(cold_count + live_count)
    }

    #[cfg(test)]
    fn registry(&self) -> MutexGuard<'_, TicketRegistry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
