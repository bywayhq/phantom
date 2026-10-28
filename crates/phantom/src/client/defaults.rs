use std::sync::{Arc, OnceLock};

#[cfg(feature = "websocket")]
use phantom_profile::WebSocketSettings;
use phantom_profile::{
    ClientHintSettings, ClientProfile, CookiePlacement, InvalidRequestTemplate,
    ProxyConnectTemplate, RequestTemplate,
    catalog::{self, CatalogError, ProfileId, RequestTemplateKind},
};

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
    pub(super) request_contexts: Option<Arc<RequestContexts>>,
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

/// Lazy templates shared by requests and forks of the same configured client.
#[derive(Debug)]
pub(super) struct RequestContexts {
    source: ContextSource,
    templates: [OnceLock<Result<PreparedRequestTemplate, ContextError>>; 8],
}

#[derive(Debug)]
enum ContextSource {
    Catalog(ProfileId),
    Owned(Box<[(RequestTemplateKind, Arc<RequestTemplate>)]>),
}

#[derive(Clone, Debug)]
enum ContextError {
    Unavailable,
    Catalog(CatalogError),
    Template(InvalidRequestTemplate),
}

impl RequestContexts {
    pub(super) fn from_profile(profile: &ClientProfile) -> Option<Self> {
        let source = if let Some(id) = profile.request_context_profile() {
            ContextSource::Catalog(id)
        } else {
            let templates: Vec<_> = profile.request_contexts().collect();
            if templates.is_empty() {
                return None;
            }
            ContextSource::Owned(templates.into_boxed_slice())
        };
        Some(Self {
            source,
            templates: std::array::from_fn(|_| OnceLock::new()),
        })
    }

    fn template(
        &self,
        kind: RequestTemplateKind,
    ) -> Result<PreparedRequestTemplate, crate::RequestError> {
        let index = match kind {
            RequestTemplateKind::Navigation => 0,
            RequestTemplateKind::FetchNoStore => 1,
            RequestTemplateKind::Fetch => 2,
            RequestTemplateKind::FetchUpload => 3,
            RequestTemplateKind::Script => 4,
            RequestTemplateKind::Stylesheet => 5,
            RequestTemplateKind::Image => 6,
            RequestTemplateKind::Font => 7,
            _ => return Err(crate::RequestError::request_context_unavailable()),
        };
        match self.templates[index].get_or_init(|| {
            let template = match &self.source {
                ContextSource::Catalog(profile) => catalog::profile(profile.as_str())
                    .map_err(ContextError::Catalog)?
                    .request_template(kind)
                    .map_err(ContextError::Catalog)?,
                ContextSource::Owned(templates) => templates
                    .iter()
                    .find(|(context, _)| *context == kind)
                    .map(|(_, template)| template.as_ref().clone())
                    .ok_or(ContextError::Unavailable)?,
            };
            PreparedRequestTemplate::new(template).map_err(ContextError::Template)
        }) {
            Ok(template) => Ok(template.clone()),
            Err(ContextError::Unavailable) => {
                Err(crate::RequestError::request_context_unavailable())
            }
            Err(ContextError::Catalog(error)) => Err(crate::RequestError::request_context(*error)),
            Err(ContextError::Template(error)) => {
                Err(crate::RequestError::request_context(error.clone()))
            }
        }
    }
}

impl RequestDefaults {
    pub(crate) fn context_template(
        &self,
        kind: RequestTemplateKind,
    ) -> Result<PreparedRequestTemplate, crate::RequestError> {
        self.request_contexts
            .as_ref()
            .ok_or_else(crate::RequestError::request_context_unavailable)?
            .template(kind)
    }

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
