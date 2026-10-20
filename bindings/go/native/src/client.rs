use crate::error::Failure;
use crate::policy::{RedirectPolicy, RequestPolicy};
use crate::timeouts::Timeouts;
use phantom::{
    Client, HttpAttemptBudget, HttpProtocol, Method, RequestBuilder, RequestHeader, Route,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    profile: String,
    profile_settings: Option<u64>,
    protocol: String,
    context: Option<String>,
    proxy: Option<String>,
    base_url: Option<String>,
    proxy_credentials: Option<ProxyCredentials>,
    #[serde(default)]
    additional_roots_der: Vec<Vec<u8>>,
    #[serde(default)]
    proxy_additional_roots_der: Vec<Vec<u8>>,
    cookies: bool,
    #[serde(default)]
    timeouts: Timeouts,
    #[serde(default)]
    redirect_policy: RedirectPolicy,
    #[serde(default)]
    retry_policy: crate::retry::RetryPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyCredentials {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub(super) name: String,
    pub(super) value: Vec<u8>,
    #[serde(default)]
    pub(super) sensitive: bool,
}

pub(super) struct NativeClient {
    pub(super) client: Client,
    protocol: String,
    pub(super) closing: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct SessionSharing {
    cookies: bool,
    dns: bool,
    client_hints: bool,
    discovery: bool,
    tickets: bool,
}

impl SessionSharing {
    fn core(self) -> phantom::SessionSharing {
        phantom::SessionSharing::none()
            .cookies(self.cookies)
            .dns(self.dns)
            .client_hints(self.client_hints)
            .discovery(self.discovery)
            .tickets(self.tickets)
    }
}

pub(super) fn protocol_name(protocol: HttpProtocol) -> &'static str {
    match protocol {
        HttpProtocol::Http1 => "h1",
        HttpProtocol::Http2 => "h2",
        HttpProtocol::Http3 => "h3",
        _ => "unknown",
    }
}

fn route(uri: Option<&str>, credentials: Option<ProxyCredentials>) -> Result<Route, Failure> {
    let Some(uri) = uri else {
        if credentials.is_some() {
            return Err(Failure::new("invalid_proxy_credentials"));
        }
        return Ok(Route::direct());
    };
    match uri.split_once("://").map(|(scheme, _)| scheme) {
        Some("http" | "https") => {
            let mut proxy =
                phantom::HttpProxy::new(uri).map_err(|_| Failure::new("invalid_http_proxy"))?;
            if let Some(credentials) = credentials {
                proxy = proxy
                    .with_basic_auth(credentials.username, credentials.password)
                    .map_err(|_| Failure::new("invalid_proxy_credentials"))?;
            }
            Ok(Route::http_proxy(proxy))
        }
        Some("socks4" | "socks4a") => {
            if credentials.is_some() {
                return Err(Failure::new("invalid_proxy_credentials"));
            }
            phantom::Socks4Proxy::new(uri)
                .map(Route::socks4)
                .map_err(|_| Failure::new("invalid_socks4_proxy"))
        }
        Some("socks5" | "socks5h") => {
            let mut proxy =
                phantom::Socks5Proxy::new(uri).map_err(|_| Failure::new("invalid_socks5_proxy"))?;
            if let Some(credentials) = credentials {
                proxy = proxy
                    .with_username_password(credentials.username, credentials.password)
                    .map_err(|_| Failure::new("invalid_proxy_credentials"))?;
            }
            Ok(Route::socks5(proxy))
        }
        _ => Err(Failure::new("invalid_proxy_scheme")),
    }
}

impl NativeClient {
    pub(super) fn fork(&self, sharing: SessionSharing) -> Self {
        Self {
            client: self.client.fork(sharing.core()),
            protocol: self.protocol.clone(),
            closing: false,
        }
    }

    pub(super) fn new(config: Config) -> Result<Self, Failure> {
        if !matches!(config.protocol.as_str(), "h1" | "h2" | "h3" | "negotiated") {
            return Err(Failure::new("invalid_protocol"));
        }
        let owner = match (config.profile.is_empty(), config.profile_settings) {
            (true, Some(id)) => Some(crate::profile::get(id)?),
            (false, None) => None,
            _ => return Err(Failure::new("invalid_profile_selection")),
        };
        let profile = match owner.as_deref() {
            Some(owner) => owner.selected(config.context.as_deref())?,
            None => crate::profile::named(&config.profile, config.context.as_deref())?,
        };
        let mut builder = Client::builder(profile)
            .route(route(config.proxy.as_deref(), config.proxy_credentials)?);
        if let Some(base_url) = config.base_url {
            builder = builder.base_url(&base_url).map_err(Failure::from)?;
        }
        for root in config.additional_roots_der {
            builder = builder.add_root_certificate_der(root);
        }
        for root in config.proxy_additional_roots_der {
            builder = builder.add_proxy_root_certificate_der(root);
        }
        if config.cookies {
            builder = builder.cookies();
        }
        builder = builder
            .request_timeouts(config.timeouts.defaults())
            .retry_policy(config.retry_policy.core()?)
            .redirect_policy(config.redirect_policy.core()?);
        let client = builder.build().map_err(Failure::from)?;
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
        policy: RequestPolicy,
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
                .map(|header| {
                    let field = RequestHeader::new(header.name, header.value);
                    if header.sensitive {
                        field.sensitive()
                    } else {
                        field
                    }
                })
                .collect(),
        );
        if let Some(budget) = budget {
            request = request.attempt_budget(budget);
        }
        policy.apply(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_flags_match_core_and_reject_unknown_fields() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::from_str::<SessionSharing>("{}")?.core(),
            phantom::SessionSharing::none()
        );
        let sharing = serde_json::from_str::<SessionSharing>(
            r#"{"cookies":true,"dns":true,"client_hints":true,"discovery":true,"tickets":true}"#,
        )?;
        assert_eq!(
            sharing.core(),
            phantom::SessionSharing::none()
                .cookies(true)
                .dns(true)
                .client_hints(true)
                .discovery(true)
                .tickets(true)
        );
        assert!(serde_json::from_str::<SessionSharing>(r#"{"extra":false}"#).is_err());
        Ok(())
    }
}
