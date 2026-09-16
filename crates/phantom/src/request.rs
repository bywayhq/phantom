use std::fmt;

use http::{Response, Uri};
use phantom_net::{http1::OriginForm, request::RequestHeader};
use tracing::{Instrument, debug_span, field};

use crate::{
    Client, HttpProtocol, RequestError, ResponseBody, Route, Session, authority::Endpoint,
};

/// Builder for one exact-protocol, empty-body GET request.
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder {
    context: RequestContext,
    request: ResolvedRequest,
    protocol: HttpProtocol,
    headers: Vec<RequestHeader>,
    route: Option<Route>,
}

impl fmt::Debug for RequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol", &self.protocol)
            .field("header_count", &self.headers.len())
            .field("route_override", &self.route.is_some())
            .field("session", &self.context.session().is_some())
            .finish_non_exhaustive()
    }
}

impl RequestBuilder {
    pub(crate) fn new_client(
        client: Client,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(RequestContext::Client(client), protocol, uri)
    }

    pub(crate) fn new_session(
        session: Session,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        Self::new(RequestContext::Session(session), protocol, uri)
    }

    fn new(
        context: RequestContext,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
        let client = context.client();
        match protocol {
            HttpProtocol::Http1 if client.inner.http1.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http1));
            }
            HttpProtocol::Http2 if client.inner.http2.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http2));
            }
            HttpProtocol::Http3 if client.inner.http3.is_none() => {
                return Err(RequestError::unsupported_protocol(HttpProtocol::Http3));
            }
            HttpProtocol::Http1 | HttpProtocol::Http2 | HttpProtocol::Http3 => {}
        }
        let uri = uri.parse::<Uri>().map_err(RequestError::invalid_uri)?;
        Ok(Self {
            context,
            request: ResolvedRequest::new(&uri)?,
            protocol,
            headers: Vec::new(),
            route: None,
        })
    }

    /// Appends one ordered request field.
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.headers.push(header);
        self
    }

    /// Replaces the complete ordered request-field list.
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.headers = headers;
        self
    }

    /// Overrides the client's route for this request.
    pub fn route(mut self, route: Route) -> Self {
        self.route = Some(route);
        self
    }

    /// Sends the request using the selected route and owner.
    ///
    /// A session may reuse compatible HTTP/1.1, HTTP/2, and direct HTTP/3
    /// connections. A bare client remains one-shot. Dropping this future
    /// cancels the in-flight operation; returned bodies retain protocol
    /// cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for invalid ordered fields, a missing or
    /// I/O-disabled Tokio runtime, connection or TLS failure, and protocol
    /// failure. Inspect
    /// [`RequestError::kind`](crate::RequestError::kind) for the stable
    /// category.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use phantom::{Client, HttpProtocol, RequestError};
    /// # async fn example(client: &Client) -> Result<(), RequestError> {
    /// let response = client
    ///     .get(HttpProtocol::Http2, "https://example.com/")?
    ///     .send()
    ///     .await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send(self) -> Result<Response<ResponseBody>, RequestError> {
        let route = self
            .route
            .as_ref()
            .unwrap_or(&self.context.client().inner.route);
        let span = debug_span!(
            "client.request",
            method = "GET",
            protocol = self.protocol.trace_name(),
            route = route.trace_name(),
            outcome = field::Empty,
        );
        let outcome = RequestOutcome::new(&span);
        let result = self.send_inner().instrument(span.clone()).await;
        outcome.finish(if result.is_ok() { "ok" } else { "error" });
        result
    }

    async fn send_inner(self) -> Result<Response<ResponseBody>, RequestError> {
        if self
            .headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("host"))
        {
            return Err(RequestError::authority_header());
        }

        let Self {
            context,
            request,
            protocol,
            headers: request_headers,
            route,
        } = self;
        #[cfg(feature = "cookies")]
        let mut request_headers = request_headers;
        let client = context.client();
        let session = context.session();
        let route = route.as_ref().unwrap_or(&client.inner.route);
        ensure_route_supported(protocol, route)?;

        let ResolvedRequest {
            endpoint,
            target,
            #[cfg(feature = "cookies")]
            cookie_uri,
        } = request;
        #[cfg(feature = "cookies")]
        let cookie_jar = session.and_then(|session| session.state.cookies.as_deref());
        #[cfg(feature = "cookies")]
        let cookie_url = parse_cookie_url_if_enabled(cookie_jar.is_some(), &cookie_uri)?;
        #[cfg(feature = "cookies")]
        if let (Some(jar), Some(cookie_url)) = (cookie_jar, cookie_url.as_ref()) {
            let caller_supplied_cookie = request_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("cookie"));
            if !caller_supplied_cookie {
                if let Some(value) = jar.request_value_for_url(cookie_url) {
                    let name = match protocol {
                        HttpProtocol::Http1 => "Cookie",
                        HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
                    };
                    request_headers.push(RequestHeader::new(name, value).sensitive());
                }
            }
        }

        let response =
            match protocol {
                HttpProtocol::Http1 => {
                    let connector =
                        client.inner.http1.as_ref().ok_or_else(|| {
                            RequestError::unsupported_protocol(HttpProtocol::Http1)
                        })?;
                    let mut headers = Vec::with_capacity(request_headers.len() + 1);
                    headers.push(RequestHeader::new(
                        "Host",
                        endpoint.authority().as_str().as_bytes(),
                    ));
                    headers.extend(request_headers);
                    if let Some(session) = session {
                        session
                            .state
                            .http1
                            .send_get(connector, &endpoint, route, target, headers)
                            .await
                    } else {
                        let response = match route {
                            Route::Direct => {
                                connector
                                    .send_get_direct(
                                        endpoint.host(),
                                        endpoint.port(),
                                        endpoint.host(),
                                        target,
                                        headers,
                                    )
                                    .await
                            }
                            Route::HttpConnect(proxy) => {
                                let connect_authority = endpoint.tunnel_authority();
                                connector
                                    .send_get_http_connect(
                                        proxy.host(),
                                        proxy.port(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                        target,
                                        headers,
                                    )
                                    .await
                            }
                            Route::Socks5(proxy) => match proxy.dns_mode() {
                                crate::Socks5DnsMode::Local => {
                                    connector
                                        .send_get_socks5_local(
                                            proxy.host(),
                                            proxy.port(),
                                            endpoint.host(),
                                            endpoint.port(),
                                            endpoint.host(),
                                            target,
                                            headers,
                                        )
                                        .await
                                }
                                crate::Socks5DnsMode::Remote => {
                                    connector
                                        .send_get_socks5_remote(
                                            proxy.host(),
                                            proxy.port(),
                                            endpoint.host(),
                                            endpoint.port(),
                                            endpoint.host(),
                                            target,
                                            headers,
                                        )
                                        .await
                                }
                            },
                        }
                        .map_err(RequestError::http1)?;
                        let (parts, body) = response.into_parts();
                        Ok(Response::from_parts(parts, ResponseBody::http1(body)))
                    }
                }
                HttpProtocol::Http2 => {
                    let connector =
                        client.inner.http2.as_ref().ok_or_else(|| {
                            RequestError::unsupported_protocol(HttpProtocol::Http2)
                        })?;
                    if let Some(session) = session {
                        session
                            .state
                            .http2
                            .send_get(
                                connector,
                                &endpoint,
                                route,
                                endpoint.authority().as_str(),
                                target,
                                request_headers,
                            )
                            .await
                    } else {
                        let response = match route {
                            Route::Direct => {
                                connector
                                    .send_get_direct(
                                        endpoint.host(),
                                        endpoint.port(),
                                        endpoint.host(),
                                        endpoint.authority().as_str(),
                                        target,
                                        request_headers,
                                    )
                                    .await
                            }
                            Route::HttpConnect(proxy) => {
                                let connect_authority = endpoint.tunnel_authority();
                                connector
                                    .send_get_http_connect(
                                        proxy.host(),
                                        proxy.port(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                        endpoint.authority().as_str(),
                                        target,
                                        request_headers,
                                    )
                                    .await
                            }
                            Route::Socks5(proxy) => match proxy.dns_mode() {
                                crate::Socks5DnsMode::Local => {
                                    connector
                                        .send_get_socks5_local(
                                            proxy.host(),
                                            proxy.port(),
                                            endpoint.host(),
                                            endpoint.port(),
                                            endpoint.host(),
                                            endpoint.authority().as_str(),
                                            target,
                                            request_headers,
                                        )
                                        .await
                                }
                                crate::Socks5DnsMode::Remote => {
                                    connector
                                        .send_get_socks5_remote(
                                            proxy.host(),
                                            proxy.port(),
                                            endpoint.host(),
                                            endpoint.port(),
                                            endpoint.host(),
                                            endpoint.authority().as_str(),
                                            target,
                                            request_headers,
                                        )
                                        .await
                                }
                            },
                        }
                        .map_err(RequestError::http2)?;
                        let (parts, body) = response.into_parts();
                        Ok(Response::from_parts(parts, ResponseBody::http2(body)))
                    }
                }
                HttpProtocol::Http3 => {
                    let connector =
                        client.inner.http3.as_ref().ok_or_else(|| {
                            RequestError::unsupported_protocol(HttpProtocol::Http3)
                        })?;
                    if let Some(session) = session {
                        session
                            .state
                            .http3
                            .send_get(
                                connector,
                                &endpoint,
                                route,
                                endpoint.authority().as_str(),
                                target,
                                request_headers,
                            )
                            .await
                    } else {
                        let response = connector
                            .send_get_direct(
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                                endpoint.authority().as_str(),
                                target,
                                request_headers,
                            )
                            .await
                            .map_err(RequestError::http3)?;
                        let (parts, body) = response.into_parts();
                        Ok(Response::from_parts(parts, ResponseBody::http3(body)))
                    }
                }
            }?;

        #[cfg(feature = "cookies")]
        if let (Some(jar), Some(cookie_url)) = (cookie_jar, cookie_url.as_ref()) {
            jar.store_response_headers(cookie_url, response.headers());
        }
        Ok(response)
    }
}

enum RequestContext {
    Client(Client),
    Session(Session),
}

impl RequestContext {
    fn client(&self) -> &Client {
        match self {
            Self::Client(client) => client,
            Self::Session(session) => &session.client,
        }
    }

    fn session(&self) -> Option<&Session> {
        match self {
            Self::Client(_) => None,
            Self::Session(session) => Some(session),
        }
    }
}

fn ensure_route_supported(protocol: HttpProtocol, route: &Route) -> Result<(), RequestError> {
    if protocol == HttpProtocol::Http3 && !matches!(route, Route::Direct) {
        return Err(RequestError::unsupported_route(protocol));
    }
    Ok(())
}

#[derive(Debug)]
struct ResolvedRequest {
    endpoint: Endpoint,
    target: OriginForm,
    #[cfg(feature = "cookies")]
    cookie_uri: Uri,
}

impl ResolvedRequest {
    fn new(uri: &Uri) -> Result<Self, RequestError> {
        if uri.scheme_str() != Some("https") {
            return Err(RequestError::unsupported_scheme());
        }
        let authority = uri.authority().cloned().ok_or_else(|| {
            RequestError::invalid_authority("request URI must include an authority")
        })?;
        let endpoint = Endpoint::new(authority, 443)
            .map_err(|error| RequestError::invalid_authority(error.message()))?;
        let target = OriginForm::parse(uri.path_and_query().map_or("/", |value| value.as_str()))
            .map_err(RequestError::invalid_target)?;

        Ok(Self {
            endpoint,
            target,
            #[cfg(feature = "cookies")]
            cookie_uri: uri.clone(),
        })
    }
}

#[cfg(feature = "cookies")]
fn parse_cookie_url_if_enabled(enabled: bool, uri: &Uri) -> Result<Option<url::Url>, RequestError> {
    if !enabled {
        return Ok(None);
    }
    url::Url::parse(&uri.to_string())
        .map(Some)
        .map_err(RequestError::invalid_cookie_url)
}

struct RequestOutcome {
    span: tracing::Span,
    recorded: bool,
}

impl RequestOutcome {
    fn new(span: &tracing::Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for RequestOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_route_supported;
    use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route, Socks5Proxy};

    #[test]
    fn tcp_proxy_routes_reject_http3_without_network_io() -> Result<(), Box<dyn std::error::Error>>
    {
        let routes = [
            Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?),
            Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:9")?),
        ];

        for route in routes {
            let error = match ensure_route_supported(HttpProtocol::Http3, &route) {
                Ok(()) => panic!("TCP-only proxy route accepted HTTP/3"),
                Err(error) => error,
            };

            assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
            assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        }
        Ok(())
    }

    #[test]
    fn direct_route_accepts_each_supported_protocol() {
        for protocol in [
            HttpProtocol::Http1,
            HttpProtocol::Http2,
            HttpProtocol::Http3,
        ] {
            assert!(ensure_route_supported(protocol, &Route::Direct).is_ok());
        }
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn disabled_cookie_state_does_not_apply_whatwg_url_parsing() {
        let relative = http::Uri::from_static("/relative-only");

        assert!(
            super::parse_cookie_url_if_enabled(false, &relative).is_ok_and(|url| url.is_none())
        );
        assert!(super::parse_cookie_url_if_enabled(true, &relative).is_err());
    }
}
