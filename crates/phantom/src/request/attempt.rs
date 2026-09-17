use bytes::Bytes;
use http::{Method, Response};
use phantom_net::{http1_or_2::Http1Or2Connection, request::RequestHeader};
use tracing::Span;

use crate::{HttpProtocol, RequestError, ResponseBody, Route};

use super::{ProtocolSelection, RequestContext, ResolvedRequest};
use crate::session::client_hints::ClientHintContext;

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_once(
    context: &RequestContext,
    request: &ResolvedRequest,
    selection: ProtocolSelection,
    method: Method,
    request_headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: &Route,
    request_span: &Span,
) -> Result<AttemptOutcome, RequestError> {
    match selection {
        ProtocolSelection::Exact(protocol) => {
            send_once_exact(
                context,
                request,
                protocol,
                method,
                request_headers,
                body,
                route,
            )
            .await
        }
        ProtocolSelection::Http1Or2 => {
            send_once_negotiated(
                context,
                request,
                method,
                request_headers,
                body,
                route,
                request_span,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_once_exact(
    context: &RequestContext,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    method: Method,
    request_headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: &Route,
) -> Result<AttemptOutcome, RequestError> {
    let client = context.client();
    let session = context.session();
    let endpoint = &request.endpoint;
    #[cfg(feature = "cookies")]
    let cookie_jar = session.and_then(|session| session.state.cookies.as_deref());
    let mut retried_critical_hints = false;
    let client_hint_origin = client
        .inner
        .client_hints
        .as_ref()
        .map(|_| request.url.origin().ascii_serialization());

    loop {
        let prepared_headers = request_headers.clone();
        #[cfg(feature = "cookies")]
        let mut prepared_headers = prepared_headers;
        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            let caller_supplied_cookie = prepared_headers
                .iter()
                .any(|header| header.name().eq_ignore_ascii_case("cookie"));
            if !caller_supplied_cookie {
                if let Some(value) = jar.request_value_for_url(&request.url) {
                    let name = match protocol {
                        HttpProtocol::Http1 => "Cookie",
                        HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
                    };
                    prepared_headers.push(RequestHeader::new(name, value).sensitive());
                }
            }
        }

        let client_hints = client
            .inner
            .client_hints
            .as_ref()
            .zip(client_hint_origin.as_deref())
            .map(|(settings, origin)| {
                session.map_or_else(
                    || ClientHintContext::stateless(endpoint, origin, settings),
                    |session| session.client_hint_context(endpoint, origin, settings),
                )
            });
        let dispatched = dispatch(
            context,
            request,
            protocol,
            method.clone(),
            prepared_headers,
            client_hints,
            body.clone(),
            route,
        )
        .await?;
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            jar.store_response_headers(&request.url, response.headers());
        }

        let critical_retry_requested = session.is_some_and(|session| {
            client.inner.client_hints.as_ref().is_some_and(|settings| {
                session.learn_client_hints_and_should_retry(
                    endpoint,
                    settings,
                    response.headers(),
                    &sent_headers,
                )
            })
        });
        let should_retry = !retried_critical_hints
            && critical_retry_requested
            && critical_hint_retry_eligible(&method);
        if should_retry {
            retried_critical_hints = true;
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying request with negotiated client hints"
            );
            drop(response);
            continue;
        }
        return Ok(AttemptOutcome { response, protocol });
    }
}

async fn send_once_negotiated(
    context: &RequestContext,
    request: &ResolvedRequest,
    method: Method,
    request_headers: Vec<RequestHeader>,
    body: Option<Bytes>,
    route: &Route,
    request_span: &Span,
) -> Result<AttemptOutcome, RequestError> {
    if !matches!(route, Route::Direct) {
        return Err(RequestError::unsupported_negotiated_route());
    }
    let client = context.client();
    let connector = client
        .inner
        .http1_or_2
        .as_ref()
        .ok_or_else(RequestError::unsupported_negotiation)?;
    let endpoint = &request.endpoint;
    let client_hint_origin = client
        .inner
        .client_hints
        .as_ref()
        .map(|_| request.url.origin().ascii_serialization());
    let client_hints = client
        .inner
        .client_hints
        .as_ref()
        .zip(client_hint_origin.as_deref())
        .map(|(settings, origin)| ClientHintContext::stateless(endpoint, origin, settings));

    let validation_headers = prepare_headers(client_hints, request_headers.clone(), None);
    let mut http1_headers = Vec::with_capacity(validation_headers.len() + 1);
    http1_headers.push(RequestHeader::new(
        "Host",
        endpoint.authority().as_str().as_bytes(),
    ));
    http1_headers.extend(validation_headers.clone());
    phantom_net::http1::validate_request(&method, &request.target, &http1_headers, body.as_ref())
        .map_err(RequestError::negotiated_http1_validation)?;
    phantom_net::http2::validate_request(
        &method,
        endpoint.authority().as_str(),
        &request.target,
        &validation_headers,
        body.as_ref(),
    )
    .map_err(RequestError::negotiated_http2_validation)?;

    let connection = connector
        .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
        .await
        .map_err(RequestError::http1_or_2)?;
    match connection {
        Http1Or2Connection::Http1(connection) => {
            request_span.record("selected_protocol", HttpProtocol::Http1.trace_name());
            let response = connection
                .send_request(method, request.target.clone(), http1_headers, body)
                .await
                .map_err(|error| RequestError::http1(error.into()))?;
            let (parts, body) = response.into_parts();
            Ok(AttemptOutcome {
                response: Response::from_parts(parts, ResponseBody::http1(body)),
                protocol: HttpProtocol::Http1,
            })
        }
        Http1Or2Connection::Http2(connection) => {
            request_span.record("selected_protocol", HttpProtocol::Http2.trace_name());
            let sent_headers = prepare_headers(
                client_hints,
                request_headers,
                client_hints.and_then(|context| connection.accept_ch_for_origin(context.origin())),
            );
            let response = connection
                .send_request(
                    method,
                    endpoint.authority().as_str(),
                    request.target.clone(),
                    sent_headers,
                    body,
                )
                .await
                .map_err(|error| RequestError::http2(error.into()))?;
            let (parts, body) = response.into_parts();
            Ok(AttemptOutcome {
                response: Response::from_parts(parts, ResponseBody::http2(body)),
                protocol: HttpProtocol::Http2,
            })
        }
    }
}

fn critical_hint_retry_eligible(method: &Method) -> bool {
    method.is_safe()
}

struct DispatchOutcome {
    response: Response<ResponseBody>,
    sent_headers: Vec<RequestHeader>,
}

pub(super) struct AttemptOutcome {
    pub(super) response: Response<ResponseBody>,
    pub(super) protocol: HttpProtocol,
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    context: &RequestContext,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    method: Method,
    request_headers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<Bytes>,
    route: &Route,
) -> Result<DispatchOutcome, RequestError> {
    let client = context.client();
    let session = context.session();
    let endpoint = &request.endpoint;
    let target = request.target.clone();
    match protocol {
        HttpProtocol::Http1 => {
            let connector = client
                .inner
                .http1
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http1))?;
            let sent_headers = prepare_headers(client_hints, request_headers, None);
            let mut headers = Vec::with_capacity(sent_headers.len() + 1);
            headers.push(RequestHeader::new(
                "Host",
                endpoint.authority().as_str().as_bytes(),
            ));
            headers.extend(sent_headers.clone());
            let response = if let Some(session) = session {
                session
                    .state
                    .http1
                    .send_request(
                        connector,
                        client.inner.https_proxy.as_ref(),
                        endpoint,
                        route,
                        method,
                        target,
                        headers,
                        body,
                    )
                    .await?
            } else {
                let response = match route {
                    Route::Direct => {
                        connector
                            .send_request_direct(
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                                method,
                                target,
                                headers,
                                body,
                            )
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        if proxy.uses_tls() {
                            let proxy_connector =
                                client.inner.https_proxy.as_ref().ok_or_else(|| {
                                    RequestError::unsupported_route(HttpProtocol::Http1)
                                })?;
                            if let Some(credentials) = proxy.basic_credentials() {
                                // Bound the challenge/retry future on the heap;
                                // direct request stack size must not depend on it.
                                Box::pin(connector.send_request_https_connect_with_basic_auth(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                ))
                                .await
                            } else {
                                connector
                                    .send_request_https_connect(
                                        proxy_connector,
                                        proxy.host(),
                                        proxy.port(),
                                        proxy.host(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                        method,
                                        target,
                                        headers,
                                        body,
                                    )
                                    .await
                            }
                        } else {
                            if let Some(credentials) = proxy.basic_credentials() {
                                Box::pin(connector.send_request_http_connect_with_basic_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                ))
                                .await
                            } else {
                                connector
                                    .send_request_http_connect(
                                        proxy.host(),
                                        proxy.port(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                        method,
                                        target,
                                        headers,
                                        body,
                                    )
                                    .await
                            }
                        }
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => {
                            connector
                                .send_request_socks5_local_with_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.auth(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                )
                                .await
                        }
                        crate::Socks5DnsMode::Remote => {
                            connector
                                .send_request_socks5_remote_with_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.auth(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                    method,
                                    target,
                                    headers,
                                    body,
                                )
                                .await
                        }
                    },
                }
                .map_err(RequestError::http1)?;
                let (parts, body) = response.into_parts();
                Response::from_parts(parts, ResponseBody::http1(body))
            };
            Ok(DispatchOutcome {
                response,
                sent_headers,
            })
        }
        HttpProtocol::Http2 => {
            let connector = client
                .inner
                .http2
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http2))?;
            if let Some(session) = session {
                session
                    .state
                    .http2
                    .send_request(
                        connector,
                        client.inner.https_proxy.as_ref(),
                        endpoint,
                        route,
                        method,
                        endpoint.authority().as_str(),
                        target,
                        request_headers,
                        client_hints,
                        body,
                    )
                    .await
                    .map(|(response, sent_headers)| DispatchOutcome {
                        response,
                        sent_headers,
                    })
            } else {
                let prepared_validation_headers =
                    client_hints.map(|context| context.prepare(request_headers.clone(), None));
                let validation_headers = prepared_validation_headers
                    .as_deref()
                    .unwrap_or(&request_headers);
                phantom_net::http2::validate_request(
                    &method,
                    endpoint.authority().as_str(),
                    &target,
                    validation_headers,
                    body.as_ref(),
                )
                .map_err(phantom_net::http2::Http2TlsError::from)
                .map_err(RequestError::http2)?;
                let connection = match route {
                    Route::Direct => {
                        connector
                            .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                            .await
                    }
                    Route::HttpConnect(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        if proxy.uses_tls() {
                            let proxy_connector =
                                client.inner.https_proxy.as_ref().ok_or_else(|| {
                                    RequestError::unsupported_route(HttpProtocol::Http2)
                                })?;
                            if let Some(credentials) = proxy.basic_credentials() {
                                // Keep the retry state machine out of the
                                // ordinary request future's stack frame.
                                Box::pin(connector.connect_https_connect_with_basic_auth(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                ))
                                .await
                            } else {
                                connector
                                    .connect_https_connect(
                                        proxy_connector,
                                        proxy.host(),
                                        proxy.port(),
                                        proxy.host(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                    )
                                    .await
                            }
                        } else {
                            if let Some(credentials) = proxy.basic_credentials() {
                                Box::pin(connector.connect_http_connect_with_basic_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                ))
                                .await
                            } else {
                                connector
                                    .connect_http_connect(
                                        proxy.host(),
                                        proxy.port(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                    )
                                    .await
                            }
                        }
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => {
                            connector
                                .connect_socks5_local_with_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.auth(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                )
                                .await
                        }
                        crate::Socks5DnsMode::Remote => {
                            connector
                                .connect_socks5_remote_with_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.auth(),
                                    endpoint.host(),
                                    endpoint.port(),
                                    endpoint.host(),
                                )
                                .await
                        }
                    },
                }
                .map_err(RequestError::http2)?;
                let sent_headers = prepare_headers(
                    client_hints,
                    request_headers,
                    client_hints
                        .and_then(|context| connection.accept_ch_for_origin(context.origin())),
                );
                let response = connection
                    .send_request(
                        method,
                        endpoint.authority().as_str(),
                        target,
                        sent_headers.clone(),
                        body,
                    )
                    .await
                    .map_err(|error| RequestError::http2(error.into()))?;
                let (parts, body) = response.into_parts();
                Ok(DispatchOutcome {
                    response: Response::from_parts(parts, ResponseBody::http2(body)),
                    sent_headers,
                })
            }
        }
        HttpProtocol::Http3 => {
            let connector = client
                .inner
                .http3
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
            if let Some(session) = session {
                session
                    .state
                    .http3
                    .send_request(
                        connector,
                        endpoint,
                        route,
                        method,
                        endpoint.authority().as_str(),
                        target,
                        request_headers,
                        client_hints,
                        body,
                    )
                    .await
                    .map(|(response, sent_headers)| DispatchOutcome {
                        response,
                        sent_headers,
                    })
            } else {
                if !matches!(route, Route::Direct) {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http3));
                }
                let prepared_validation_headers =
                    client_hints.map(|context| context.prepare(request_headers.clone(), None));
                let validation_headers = prepared_validation_headers
                    .as_deref()
                    .unwrap_or(&request_headers);
                connector
                    .validate_request(
                        method.clone(),
                        endpoint.authority().as_str(),
                        &target,
                        validation_headers,
                        body.as_ref(),
                    )
                    .map_err(RequestError::http3)?;
                let connection = connector
                    .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                    .await
                    .map_err(RequestError::http3)?;
                let sent_headers = prepare_headers(
                    client_hints,
                    request_headers,
                    client_hints
                        .and_then(|context| connection.accept_ch_for_origin(context.origin())),
                );
                let response = connector
                    .send_request_on(
                        &connection,
                        method,
                        endpoint.authority().as_str(),
                        target,
                        sent_headers.clone(),
                        body,
                    )
                    .await
                    .map_err(RequestError::http3)?;
                let (parts, body) = response.into_parts();
                Ok(DispatchOutcome {
                    response: Response::from_parts(parts, ResponseBody::http3(body)),
                    sent_headers,
                })
            }
        }
    }
}

fn prepare_headers(
    client_hints: Option<ClientHintContext<'_>>,
    headers: Vec<RequestHeader>,
    connection_accept_ch: Option<&[u8]>,
) -> Vec<RequestHeader> {
    match client_hints {
        Some(context) => context.prepare(headers, connection_accept_ch),
        None => headers,
    }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::critical_hint_retry_eligible;

    #[test]
    fn critical_hint_replay_requires_a_safe_method() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(critical_hint_retry_eligible(&method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!critical_hint_retry_eligible(&method));
        }
    }
}
