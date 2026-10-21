//! Per-Env cleanup and registration of independent native client owners.

use std::sync::Arc;

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer},
};
use napi_derive::napi;

use super::{
    buffer::{checkpoint_bytes, checkpoint_key, copy_buffer},
    certificates::client_certificates,
    client::NativeClient,
    options::{ClientOptions, SessionRouteOptions, SessionSharingOptions},
    profile::NativeProfile,
};
use crate::{
    client::{ClientState, Environment},
    error::failure,
    profile::ProfileState,
    session,
};

/// Private module environment owner; the facade creates one per Worker.
#[derive(Debug)]
#[napi]
pub struct NativeEnvironment {
    state: Arc<Environment>,
}

#[napi]
impl NativeEnvironment {
    /// Registers native-only environment cleanup.
    #[napi(constructor)]
    pub fn new(env: Env) -> Result<Self> {
        let state = Arc::new(Environment::default());
        env.add_env_cleanup_hook(Arc::clone(&state), |state| state.close())?;
        Ok(Self { state })
    }
    /// Constructs a reusable client without caching this Env.
    #[napi]
    pub fn client(
        &self,
        env: Env,
        mut options: ClientOptions,
        profile: Option<&NativeProfile>,
    ) -> Result<NativeClient> {
        let profile = match (options.profile.take(), profile) {
            (Some(identifier), None) => ProfileState::catalog(&identifier, None)?,
            (None, Some(profile)) => Arc::clone(&profile.state),
            _ => {
                return Err(failure(
                    "InvalidProfile",
                    "choose an exact identifier or a Profile",
                ));
            }
        };
        let copy_roots = |roots: Option<Vec<Buffer>>| {
            let roots = roots.unwrap_or_default();
            if roots.len() > 16 {
                return Err(failure("InputLimit", "too many additional trust roots"));
            }
            roots
                .into_iter()
                .map(|root| copy_buffer(&env, root, 1024 * 1024))
                .collect::<Result<Vec<_>>>()
        };
        let roots = copy_roots(options.additional_roots.take())?;
        let proxy_roots = copy_roots(options.additional_proxy_roots.take())?;
        let copy_pins = |input: Option<Vec<Buffer>>, field| {
            input
                .map(|input| {
                    crate::tls::count(input.len(), field)?;
                    let copied = input
                        .into_iter()
                        .map(|pin| {
                            copy_buffer(&env, pin, 32).map_err(|error| {
                                if error.reason.starts_with("PHANTOM:InputLimit:") {
                                    crate::tls::digest_length(field)
                                } else {
                                    error
                                }
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    crate::tls::pins(copied, field)
                })
                .transpose()
        };
        let pins = crate::tls::ServerPins {
            origin: copy_pins(options.server_spki_pins.take(), "serverSpkiPins")?,
            proxy: copy_pins(options.proxy_server_spki_pins.take(), "proxyServerSpkiPins")?,
        };
        let certificates = client_certificates(&mut options)?;
        ClientState::build(
            options,
            profile,
            roots,
            proxy_roots,
            pins,
            certificates,
            &self.state,
        )
        .map(|state| NativeClient { state })
    }

    /// Registers an independent client with explicitly selected native state.
    #[napi]
    pub fn fork(
        &self,
        source: &NativeClient,
        sharing: SessionSharingOptions,
    ) -> Result<NativeClient> {
        let sharing = phantom::SessionSharing::none()
            .cookies(sharing.cookies.unwrap_or(false))
            .dns(sharing.dns.unwrap_or(false))
            .client_hints(sharing.client_hints.unwrap_or(false))
            .discovery(sharing.discovery.unwrap_or(false))
            .tickets(sharing.tickets.unwrap_or(false));
        source
            .state
            .fork(sharing, &self.state)
            .map(|state| NativeClient { state })
    }

    /// Restores CPU-owned checkpoint bytes and registers a fresh client owner.
    #[napi]
    pub fn restore_session(
        &self,
        env: Env,
        source: &NativeClient,
        snapshot: Buffer,
        secret: Buffer,
        routes: Vec<SessionRouteOptions>,
    ) -> Result<AsyncBlock<NativeClient>> {
        let key = checkpoint_key(&env, secret)?;
        let bytes = checkpoint_bytes(&env, snapshot, session::MAXIMUM_BYTES)?;
        if routes.len() > session::MAXIMUM_ROUTES {
            return Err(session::failure("too_large"));
        }
        let routes = routes
            .into_iter()
            .map(|route| {
                crate::client::route(
                    &route.route,
                    route.proxy.as_deref(),
                    route.proxy_username.as_deref(),
                    route.proxy_password.as_deref(),
                    route.proxy_user_id.as_deref(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let owner = Arc::clone(&source.state);
        let environment = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            let core = session::restore(owner.core.clone(), bytes, key, routes).await?;
            owner
                .with_core(core, &environment)
                .map(|state| NativeClient { state })
        })
        .build(&env)
    }
}
