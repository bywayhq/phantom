use std::sync::Arc;

#[cfg(feature = "websocket")]
use phantom_profile::WebSocketSettings;
use phantom_profile::{ClientHintSettings, CookiePlacement, ProxyConnectTemplate};

use crate::{PreparedRequestTemplate, Route, authority::Endpoint};

/// Request defaults fixed when the client is built.
#[derive(Clone, Debug)]
pub(crate) struct RequestDefaults {
    pub(crate) base_url: Option<crate::base_url::BaseUrl>,
    pub(crate) header_hooks: Vec<crate::header_hook::HeaderHook>,
    pub(crate) request_hooks: Option<crate::request_hook::SharedRequestHooks>,
    pub(crate) client_hints: Option<ClientHintSettings>,
    /// The profile's template, validated once when the client is built.
    pub(crate) request_template: Option<PreparedRequestTemplate>,
    /// Profile position of caller and jar `Cookie` fields.
    pub(crate) cookie_placement: CookiePlacement,
    pub(super) route: Option<Route>,
    pub(super) environment_proxies: Option<crate::EnvironmentProxies>,
    /// Profile CONNECT fields for HTTP proxy routes that set none.
    pub(crate) proxy_connect: Option<Arc<ProxyConnectTemplate>>,
    /// Profile WebSocket templates and connection policy.
    #[cfg(feature = "websocket")]
    pub(crate) websocket: Option<WebSocketSettings>,
}

impl RequestDefaults {
    pub(crate) fn default_connect_udp_pool(
        &self,
    ) -> Option<&phantom_net::proxy::ConnectUdpProxyPool> {
        match &self.route {
            Some(Route::ConnectUdp(proxy)) => Some(proxy.pool()),
            _ => None,
        }
    }

    pub(crate) fn selected_route(
        &self,
        request_route: Option<&Route>,
        scheme: &str,
        endpoint: &crate::authority::Endpoint,
    ) -> Route {
        if let Some(route) = request_route {
            return route.clone();
        }

        if let Some(route) = &self.route {
            return route.clone();
        }

        self.environment_proxies.as_ref().map_or_else(
            || Route::Direct,
            |proxies| proxies.route_for(scheme, endpoint),
        )
    }

    #[cfg(feature = "session-snapshot")]
    pub(crate) fn session_snapshot_route(&self) -> Result<Route, crate::session::PreparationError> {
        if self.environment_proxies.is_some() {
            return Err(crate::session::PreparationError::Unsupported(
                "session checkpoints with environment proxy routing",
            ));
        }
        Ok(self.route.clone().unwrap_or(Route::Direct))
    }

    /// Shared outer owners use the configured proxy route, not NO_PROXY for
    /// the proxy's own address. Request-only routes are supplied at import.
    pub(crate) fn ticket_import_route(
        &self,
        endpoint: &Endpoint,
        shared_outer: bool,
    ) -> Option<Route> {
        if shared_outer {
            self.route
                .as_ref()
                .filter(|route| matches!(route, Route::ConnectUdp(_)))
                .cloned()
        } else {
            Some(self.selected_route(None, "https", endpoint))
        }
    }
}
