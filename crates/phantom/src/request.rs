use std::fmt;

use http::{Response, Uri};
use phantom_net::{http1::OriginForm, request::RequestHeader};
use tracing::{Instrument, debug_span, field};

use crate::{Client, HttpProtocol, RequestError, ResponseBody, Route, authority::Endpoint};

/// Builder for one exact-protocol, empty-body GET request.
#[must_use = "request builders do nothing until send is awaited"]
pub struct RequestBuilder<'a> {
    client: &'a Client,
    request: ResolvedRequest,
    protocol: HttpProtocol,
    headers: Vec<RequestHeader>,
    route: Option<Route>,
}

impl fmt::Debug for RequestBuilder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBuilder")
            .field("protocol", &self.protocol)
            .field("header_count", &self.headers.len())
            .field("route_override", &self.route.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(
        client: &'a Client,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<Self, RequestError> {
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
            client,
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

    /// Sends the request over a new connection using the selected route.
    ///
    /// Dropping this future cancels the in-flight operation. After response
    /// headers arrive, the returned body owns protocol cancellation and
    /// connection shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for invalid ordered fields, a missing Tokio
    /// runtime, connection or TLS failure, and protocol failure. Inspect
    /// [`RequestError::kind`](crate::RequestError::kind) for the stable
    /// category.
    ///
    /// # Panics
    ///
    /// Tokio may panic if the current runtime was built without network I/O
    /// enabled.
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
        let route = self.route.as_ref().unwrap_or(&self.client.inner.route);
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
            client,
            request,
            protocol,
            headers: request_headers,
            route,
        } = self;
        let route = route.as_ref().unwrap_or(&client.inner.route);
        ensure_route_supported(protocol, route)?;

        match protocol {
            HttpProtocol::Http1 => {
                let connector = client
                    .inner
                    .http1
                    .as_ref()
                    .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http1))?;
                let mut headers = Vec::with_capacity(request_headers.len() + 1);
                headers.push(RequestHeader::new(
                    "Host",
                    request.endpoint.authority().as_str().as_bytes(),
                ));
                headers.extend(request_headers);
                let response = match route {
                    Route::Direct => {
                        connector
                            .send_get_direct(
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.endpoint.host(),
                                request.target,
                                headers,
                            )
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = request.endpoint.tunnel_authority();
                        connector
                            .send_get_http_connect(
                                proxy.host(),
                                proxy.port(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                request.endpoint.host(),
                                request.target,
                                headers,
                            )
                            .await
                    }
                }
                .map_err(RequestError::http1)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http1(body)))
            }
            HttpProtocol::Http2 => {
                let connector = client
                    .inner
                    .http2
                    .as_ref()
                    .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http2))?;
                let response = match route {
                    Route::Direct => {
                        connector
                            .send_get_direct(
                                request.endpoint.host(),
                                request.endpoint.port(),
                                request.endpoint.host(),
                                request.endpoint.authority().as_str(),
                                request.target,
                                request_headers,
                            )
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = request.endpoint.tunnel_authority();
                        connector
                            .send_get_http_connect(
                                proxy.host(),
                                proxy.port(),
                                &connect_authority,
                                proxy.ordered_connect_headers(),
                                request.endpoint.host(),
                                request.endpoint.authority().as_str(),
                                request.target,
                                request_headers,
                            )
                            .await
                    }
                }
                .map_err(RequestError::http2)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http2(body)))
            }
            HttpProtocol::Http3 => {
                let connector = client
                    .inner
                    .http3
                    .as_ref()
                    .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
                let response = connector
                    .send_get_direct(
                        request.endpoint.host(),
                        request.endpoint.port(),
                        request.endpoint.host(),
                        request.endpoint.authority().as_str(),
                        request.target,
                        request_headers,
                    )
                    .await
                    .map_err(RequestError::http3)?;
                let (parts, body) = response.into_parts();
                Ok(Response::from_parts(parts, ResponseBody::http3(body)))
            }
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

        Ok(Self { endpoint, target })
    }
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
    use crate::{HttpProtocol, HttpProxy, RequestErrorKind, Route};

    #[test]
    fn http_connect_route_rejects_http3_without_network_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let route = Route::http_connect(HttpProxy::new("http://127.0.0.1:9")?);

        let error = match ensure_route_supported(HttpProtocol::Http3, &route) {
            Ok(()) => panic!("HTTP CONNECT accepted HTTP/3"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
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
}
