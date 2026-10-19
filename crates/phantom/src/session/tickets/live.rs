//! Local cache selection never authorizes portable ticket transfer.

use std::{collections::VecDeque, sync::OnceLock};

use phantom_net::{
    SessionTicketCache, SessionTicketCacheOwner, http1::Http1TlsConnector,
    http1_or_2::Http1Or2TlsConnector, http2::Http2TlsConnector, http3::Http3Connector,
    proxy::HttpsProxyConnector,
};

use super::{TicketCacheBinding, TicketOwner, TicketUseError, binding::PreparationError};
use crate::{Route, route::ConnectUdpTicketRoute};

#[derive(Clone, Eq, PartialEq)]
pub(super) enum TicketRoute {
    Ordinary(Route),
    ConnectUdp(ConnectUdpTicketRoute),
}

impl TicketRoute {
    pub(super) fn ordinary(&self) -> Option<&Route> {
        match self {
            Self::Ordinary(route) => Some(route),
            Self::ConnectUdp(_) => None,
        }
    }

    pub(super) fn connect_udp(&self) -> Option<&ConnectUdpTicketRoute> {
        match self {
            Self::ConnectUdp(route) => Some(route),
            _ => None,
        }
    }

    pub(super) fn supported(
        &self,
        leg: super::TicketCacheLeg,
        protocol: super::TicketCacheProtocol,
    ) -> bool {
        use super::{TicketCacheLeg as Leg, TicketCacheProtocol as Protocol};
        match self {
            Self::ConnectUdp(_) => matches!(
                (leg, protocol),
                (Leg::Origin, Protocol::Http3)
                    | (
                        Leg::ConnectUdp,
                        Protocol::Http1 | Protocol::Http2 | Protocol::Http3
                    )
            ),
            Self::Ordinary(route) => matches!(
                (leg, protocol, route),
                (
                    Leg::Origin,
                    Protocol::Http3,
                    Route::Direct | Route::Socks5(_)
                ) | (
                    Leg::Origin,
                    Protocol::Http1 | Protocol::Http2 | Protocol::Negotiated,
                    Route::Direct | Route::HttpProxy(_) | Route::Socks4(_) | Route::Socks5(_)
                ) | (
                    Leg::HttpProxy,
                    Protocol::Http1 | Protocol::Http2,
                    Route::HttpProxy(_)
                )
            ),
        }
    }
    pub(super) fn capture(route: &Route) -> Self {
        match route {
            Route::ConnectUdp(proxy) => Self::ConnectUdp(proxy.ticket_route()),
            route => Self::Ordinary(route.clone()),
        }
    }

    pub(super) fn credential(
        &self,
    ) -> Result<Option<btls::ssl::SessionTransferCredential>, PreparationError> {
        match self {
            Self::Ordinary(route) => crate::route::transfer_credential(route),
            Self::ConnectUdp(route) => route.transfer_credential(),
        }
    }
}

impl PartialEq<Route> for TicketRoute {
    fn eq(&self, other: &Route) -> bool {
        match (self, other) {
            (Self::Ordinary(left), right) => left == right,
            (Self::ConnectUdp(left), Route::ConnectUdp(right)) => left.matches(right),
            _ => false,
        }
    }
}

impl std::fmt::Debug for TicketRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ordinary(_) => "TicketRoute",
            Self::ConnectUdp(_) => "ConnectUdpTicketRoute",
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct LiveBinding {
    origin: crate::authority::Endpoint,
    server_name: String,
    leg: super::TicketCacheLeg,
    protocol: Result<super::TicketCacheProtocol, PreparationError>,
    route: TicketRoute,
}

impl LiveBinding {
    pub(super) fn capture(input: TicketCacheBinding<'_>) -> Self {
        Self {
            origin: input.origin.clone(),
            server_name: input.server_name.into(),
            leg: input.leg,
            protocol: input.protocol,
            route: TicketRoute::capture(input.route),
        }
    }
}

pub(super) struct SharedCaches {
    capacity: usize,
    entries: VecDeque<(LiveBinding, SessionTicketCacheOwner)>,
}

impl SharedCaches {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::new(),
        }
    }

    pub(super) fn retain(&mut self, live: LiveBinding, owner: SessionTicketCacheOwner) {
        if let Some(position) = self.entries.iter().position(|(key, _)| *key == live) {
            if let Some(current) = self.entries.remove(position) {
                self.entries.push_back(current);
            }
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((live, owner));
    }
}

/// Ordinary connectors remain valid for work selected before sharing starts.
/// The selected connector retains the canonical store for the entry's lifetime.
pub(in crate::session) struct TicketConnector<C> {
    ordinary: OnceLock<C>,
    selected: OnceLock<C>,
}

impl<C> Default for TicketConnector<C> {
    fn default() -> Self {
        Self {
            ordinary: OnceLock::new(),
            selected: OnceLock::new(),
        }
    }
}

impl<C> TicketConnector<C> {
    #[cfg(test)]
    pub(in crate::session) fn set(&self, connector: C) -> Result<(), C> {
        self.ordinary.set(connector)
    }

    pub(in crate::session) fn get(&self) -> Option<&C> {
        self.selected.get().or_else(|| self.ordinary.get())
    }

    pub(in crate::session) fn get_or_init(&self, initialize: impl FnOnce() -> C) -> &C {
        self.ordinary.get_or_init(initialize)
    }
}

pub(in crate::session) trait NativeTicketConnector: Sized {
    fn cache(&self) -> Option<SessionTicketCache>;
    fn attach(&self, owner: &SessionTicketCacheOwner) -> Result<Self, PreparationError>;
}

macro_rules! connector {
    ($($ty:ty),+ $(,)?) => {$(
        impl NativeTicketConnector for $ty {
            fn cache(&self) -> Option<SessionTicketCache> { self.session_ticket_cache() }
            fn attach(&self, owner: &SessionTicketCacheOwner) -> Result<Self, PreparationError> {
                self.with_session_ticket_cache(owner).map_err(|_| {
                    PreparationError::Unsupported("incompatible native ticket store")
                })
            }
        }
    )+};
}

connector!(
    Http1TlsConnector,
    Http1Or2TlsConnector,
    Http2TlsConnector,
    HttpsProxyConnector,
    Http3Connector
);

impl<C: NativeTicketConnector> TicketConnector<C> {
    pub(in crate::session) fn prepare<'a>(
        &'a self,
        owner: &TicketOwner,
        ordinary: &'a C,
        input: TicketCacheBinding<'_>,
    ) -> Result<&'a C, TicketUseError> {
        if !owner.sharing_enabled() {
            return Ok(ordinary);
        }
        if let Some(selected) = self.selected.get() {
            return Ok(selected);
        }
        let Some(canonical) = owner.select_store(ordinary.cache(), input)? else {
            return Ok(ordinary);
        };
        let selected = ordinary.attach(&canonical).map_err(|error| {
            TicketUseError(super::transfer_import::ImportError::Preparation(error))
        })?;
        let _ = self.selected.set(selected);
        self.selected
            .get()
            .ok_or_else(|| TicketUseError(super::transfer_import::ImportError::RegistryPoisoned))
    }
}
