use crate::error::Failure;
use phantom::{
    Client, HttpAttemptBudget, HttpProtocol, Method, RequestBuilder, RequestHeader, Route,
};
use phantom_profile::catalog::{self, RequestTemplateKind};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    profile: String,
    protocol: String,
    context: Option<String>,
    proxy: Option<String>,
    cookies: bool,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub(super) name: String,
    pub(super) value: Vec<u8>,
}

pub(super) struct NativeClient {
    pub(super) client: Client,
    protocol: String,
    pub(super) closing: bool,
}

pub(super) fn protocol_name(protocol: HttpProtocol) -> &'static str {
    match protocol {
        HttpProtocol::Http1 => "h1",
        HttpProtocol::Http2 => "h2",
        HttpProtocol::Http3 => "h3",
        _ => "unknown",
    }
}

fn route(uri: Option<&str>) -> Result<Route, Failure> {
    let Some(uri) = uri else {
        return Ok(Route::direct());
    };
    match uri.split_once("://").map(|(scheme, _)| scheme) {
        Some("http" | "https") => phantom::HttpProxy::new(uri)
            .map(Route::http_proxy)
            .map_err(|_| Failure::new("invalid_http_proxy")),
        Some("socks4" | "socks4a") => phantom::Socks4Proxy::new(uri)
            .map(Route::socks4)
            .map_err(|_| Failure::new("invalid_socks4_proxy")),
        Some("socks5" | "socks5h") => phantom::Socks5Proxy::new(uri)
            .map(Route::socks5)
            .map_err(|_| Failure::new("invalid_socks5_proxy")),
        _ => Err(Failure::new("invalid_proxy_scheme")),
    }
}

impl NativeClient {
    pub(super) fn new(config: Config) -> Result<Self, Failure> {
        if !matches!(config.protocol.as_str(), "h1" | "h2" | "h3" | "negotiated") {
            return Err(Failure::new("invalid_protocol"));
        }
        let definition =
            catalog::profile(&config.profile).map_err(|_| Failure::new("unknown_profile"))?;
        let mut profile = definition
            .instantiate(&[])
            .map_err(|_| Failure::new("invalid_profile"))?
            .without_request_template();
        if let Some(context) = config.context {
            let context = match context.as_str() {
                "navigation" => RequestTemplateKind::Navigation,
                "fetch" => RequestTemplateKind::Fetch,
                _ => return Err(Failure::new("invalid_context")),
            };
            profile = profile.with_request_template(
                definition
                    .request_template(context)
                    .map_err(|_| Failure::new("context_unavailable"))?,
            );
        }
        let mut builder = Client::builder(profile).route(route(config.proxy.as_deref())?);
        if config.cookies {
            builder = builder.cookies();
        }
        if let Some(timeout) = config.timeout_ms {
            builder = builder.request_timeouts(
                phantom::RequestTimeouts::new().total(Duration::from_millis(timeout)),
            );
        }
        let client = builder
            .build()
            .map_err(|_| Failure::new("invalid_client_configuration"))?;
        Ok(Self {
            client,
            protocol: config.protocol,
            closing: false,
        })
    }

    pub(super) fn request(
        &self,
        method: &str,
        url: &str,
        headers: Vec<Header>,
        budget: Option<HttpAttemptBudget>,
        timeout_ms: Option<u64>,
    ) -> Result<RequestBuilder, Failure> {
        if self.closing {
            return Err(Failure::new("client_closed"));
        }
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|_| Failure::new("invalid_method"))?;
        let request = match self.protocol.as_str() {
            "h1" => self.client.request(HttpProtocol::Http1, method, url),
            "h2" => self.client.request(HttpProtocol::Http2, method, url),
            "h3" => self.client.request(HttpProtocol::Http3, method, url),
            "negotiated" => self.client.request_negotiated(method, url),
            _ => return Err(Failure::new("invalid_protocol")),
        };
        let mut request = request.map_err(Failure::from)?.headers(
            headers
                .into_iter()
                .map(|header| RequestHeader::new(header.name, header.value))
                .collect(),
        );
        if let Some(budget) = budget {
            request = request.attempt_budget(budget);
        }
        if let Some(timeout) = timeout_ms {
            request = request.timeouts(phantom::RequestTimeoutOverrides::new().total(
                phantom::TimeoutOverride::Limit(Duration::from_millis(timeout)),
            ));
        }
        Ok(request)
    }
}
