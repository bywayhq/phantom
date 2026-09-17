use bytes::Bytes;
use http::{Method, Response};
use phantom_net::{http1_or_2::Http1Or2Connection, request::RequestHeader};
use tracing::Span;

use crate::timeout::{TimeoutBudget, TimeoutPhase};
use crate::{Client, HttpProtocol, RequestError, ResponseBody, Route};

use super::{ProtocolSelection, ResolvedRequest};
use crate::session::client_hints::ClientHintContext;

pub(super) struct AttemptRequest {
    pub(super) method: Method,
    pub(super) headers: Vec<RequestHeader>,
    pub(super) body: Option<Bytes>,
}

pub(super) async fn send_once(
    client: &Client,
    request: &ResolvedRequest,
    selection: ProtocolSelection,
    attempt: AttemptRequest,
    route: &Route,
    request_span: &Span,
    timeout_budget: TimeoutBudget,
) -> Result<AttemptOutcome, RequestError> {
    match selection {
        ProtocolSelection::Exact(protocol) => {
            send_once_exact(client, request, protocol, attempt, route, timeout_budget).await
        }
        ProtocolSelection::Http1Or2 => {
            send_once_negotiated(
                client,
                request,
                attempt,
                route,
                request_span,
                timeout_budget,
            )
            .await
        }
    }
}

async fn send_once_exact(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    attempt: AttemptRequest,
    route: &Route,
    timeout_budget: TimeoutBudget,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptRequest {
        method,
        headers: request_headers,
        body,
    } = attempt;
    let endpoint = &request.endpoint;
    #[cfg(feature = "cookies")]
    let cookie_jar = client.state.cookies.as_deref();
    let mut retried_critical_hints = false;
    let client_hint_origin = client
        .inner
        .client_hints
        .as_ref()
        .filter(|_| request.uri.scheme_str() == Some("https"))
        .map(|_| request.url.origin().ascii_serialization());

    loop {
        let mut prepared_headers = request_headers.clone();
        inject_cookie(client, request, protocol, &mut prepared_headers);

        let client_hints = client
            .inner
            .client_hints
            .as_ref()
            .filter(|_| request.uri.scheme_str() == Some("https"))
            .zip(client_hint_origin.as_deref())
            .map(|(settings, origin)| client.client_hint_context(endpoint, origin, settings));
        let dispatched = dispatch(
            client,
            request,
            protocol,
            method.clone(),
            prepared_headers,
            client_hints,
            body.clone(),
            route,
            timeout_budget,
        )
        .await?;
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            jar.store_response_headers(&request.url, response.headers());
        }

        let critical_retry_requested = request.uri.scheme_str() == Some("https")
            && client.inner.client_hints.as_ref().is_some_and(|settings| {
                client.learn_client_hints_and_should_retry(
                    endpoint,
                    settings,
                    response.headers(),
                    &sent_headers,
                )
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
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest,
    route: &Route,
    request_span: &Span,
    timeout_budget: TimeoutBudget,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptRequest {
        method,
        headers: request_headers,
        body,
    } = attempt;
    if !matches!(route, Route::Direct) {
        return Err(RequestError::unsupported_negotiated_route());
    }
    let connector = client
        .inner
        .http1_or_2
        .as_ref()
        .ok_or_else(RequestError::unsupported_negotiation)?;
    let endpoint = &request.endpoint;
    #[cfg(feature = "cookies")]
    let cookie_jar = client.state.cookies.as_deref();
    let client_hint_origin = client
        .inner
        .client_hints
        .as_ref()
        .filter(|_| request.uri.scheme_str() == Some("https"))
        .map(|_| request.url.origin().ascii_serialization());
    let mut retried_critical_hints = false;

    loop {
        let mut http1_request_headers = request_headers.clone();
        inject_cookie(
            client,
            request,
            HttpProtocol::Http1,
            &mut http1_request_headers,
        );
        let mut http2_request_headers = request_headers.clone();
        inject_cookie(
            client,
            request,
            HttpProtocol::Http2,
            &mut http2_request_headers,
        );
        let client_hints = client
            .inner
            .client_hints
            .as_ref()
            .zip(client_hint_origin.as_deref())
            .map(|(settings, origin)| client.client_hint_context(endpoint, origin, settings));
        let http1_sent_headers = prepare_headers(client_hints, http1_request_headers, None);
        let http2_validation_headers =
            prepare_headers(client_hints, http2_request_headers.clone(), None);
        let mut http1_headers = Vec::with_capacity(http1_sent_headers.len() + 1);
        http1_headers.push(RequestHeader::new(
            "Host",
            endpoint.authority().as_str().as_bytes(),
        ));
        http1_headers.extend(http1_sent_headers.clone());
        phantom_net::http1::validate_request(
            &method,
            &request.target,
            &http1_headers,
            body.as_ref(),
        )
        .map_err(RequestError::negotiated_http1_validation)?;
        phantom_net::http2::validate_request(
            &method,
            endpoint.authority().as_str(),
            &request.target,
            &http2_validation_headers,
            body.as_ref(),
        )
        .map_err(RequestError::negotiated_http2_validation)?;

        let connection = timeout_budget
            .run(TimeoutPhase::Connect, None, async {
                connector
                    .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                    .await
                    .map_err(RequestError::http1_or_2)
            })
            .await?;
        let (response, protocol, sent_headers) = match connection {
            Http1Or2Connection::Http1(connection) => {
                request_span.record("selected_protocol", HttpProtocol::Http1.trace_name());
                let response = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http1),
                        async {
                            connection
                                .send_request(
                                    method.clone(),
                                    request.target.clone(),
                                    http1_headers,
                                    body.clone(),
                                )
                                .await
                                .map_err(|error| RequestError::http1(error.into()))
                        },
                    )
                    .await?;
                let (parts, body) = response.into_parts();
                (
                    Response::from_parts(parts, ResponseBody::http1(body)),
                    HttpProtocol::Http1,
                    http1_sent_headers,
                )
            }
            Http1Or2Connection::Http2(connection) => {
                request_span.record("selected_protocol", HttpProtocol::Http2.trace_name());
                let sent_headers = prepare_headers(
                    client_hints,
                    http2_request_headers,
                    client_hints
                        .and_then(|context| connection.accept_ch_for_origin(context.origin())),
                );
                let response = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http2),
                        async {
                            connection
                                .send_request(
                                    method.clone(),
                                    endpoint.authority().as_str(),
                                    request.target.clone(),
                                    sent_headers.clone(),
                                    body.clone(),
                                )
                                .await
                                .map_err(|error| RequestError::http2(error.into()))
                        },
                    )
                    .await?;
                let (parts, body) = response.into_parts();
                (
                    Response::from_parts(parts, ResponseBody::http2(body)),
                    HttpProtocol::Http2,
                    sent_headers,
                )
            }
        };

        #[cfg(feature = "cookies")]
        if let Some(jar) = cookie_jar {
            jar.store_response_headers(&request.url, response.headers());
        }

        let critical_retry_requested = request.uri.scheme_str() == Some("https")
            && client.inner.client_hints.as_ref().is_some_and(|settings| {
                client.learn_client_hints_and_should_retry(
                    endpoint,
                    settings,
                    response.headers(),
                    &sent_headers,
                )
            });
        if !retried_critical_hints
            && critical_retry_requested
            && critical_hint_retry_eligible(&method)
        {
            retried_critical_hints = true;
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying negotiated request with client hints"
            );
            drop(response);
            continue;
        }
        return Ok(AttemptOutcome { response, protocol });
    }
}

fn inject_cookie(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    headers: &mut Vec<RequestHeader>,
) {
    #[cfg(feature = "cookies")]
    if let Some(jar) = client.state.cookies.as_deref() {
        let caller_supplied = headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("cookie"));
        if !caller_supplied {
            if let Some(value) = jar.request_value_for_url(&request.url) {
                let name = match protocol {
                    HttpProtocol::Http1 => "Cookie",
                    HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
                };
                headers.push(RequestHeader::new(name, value).sensitive());
            }
        }
    }

    #[cfg(not(feature = "cookies"))]
    let _ = (client, request, protocol, headers);
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
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    method: Method,
    request_headers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<Bytes>,
    route: &Route,
    timeout_budget: TimeoutBudget,
) -> Result<DispatchOutcome, RequestError> {
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
            let response = client
                .state
                .http1
                .send_request(
                    connector,
                    client.inner.https_proxy.as_ref(),
                    endpoint,
                    route,
                    request.uri.scheme_str() == Some("http"),
                    method,
                    target,
                    request.absolute_target.clone(),
                    headers,
                    body,
                    timeout_budget,
                )
                .await?;
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
            client
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
                    timeout_budget,
                )
                .await
                .map(|(response, sent_headers)| DispatchOutcome {
                    response,
                    sent_headers,
                })
        }
        HttpProtocol::Http3 => {
            let connector = client
                .inner
                .http3
                .as_ref()
                .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
            client
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
                    timeout_budget,
                )
                .await
                .map(|(response, sent_headers)| DispatchOutcome {
                    response,
                    sent_headers,
                })
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
