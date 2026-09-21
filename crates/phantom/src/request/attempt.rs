use http::{Method, Response};
use phantom_net::{
    http1::Http1TlsError,
    proxy::{HttpConnectError, validate_basic_proxy_challenge},
    request::{RequestBody, RequestHeader},
};
use tracing::Span;

use crate::timeout::TimeoutBudget;
use crate::{
    Client, HttpProtocol, RequestError, ResponseBody, RetryPolicy, Route,
    retry::ConnectionSetupRetryState,
};

use super::{ProtocolSelection, RequestBodySource, ResolvedRequest};
use crate::session::{
    client_hints::ClientHintContext, http1_pool::Http1ConnectionMode,
    http3_pool::Http3TransportTarget,
};

pub(super) struct AttemptRequest<'a> {
    pub(super) method: Method,
    pub(super) headers: Vec<RequestHeader>,
    pub(super) trailers: Vec<RequestHeader>,
    pub(super) body: &'a mut RequestBodySource,
}

pub(super) struct AttemptLifecycle<'a> {
    pub(super) request_span: &'a Span,
    pub(super) timeout_budget: TimeoutBudget,
    pub(super) retries: &'a mut ConnectionSetupRetryState,
}

pub(super) async fn send_once(
    client: &Client,
    request: &ResolvedRequest,
    selection: ProtocolSelection,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
) -> Result<AttemptOutcome, RequestError> {
    match selection {
        ProtocolSelection::Exact(protocol) => {
            send_once_exact(client, request, protocol, attempt, route, lifecycle).await
        }
        ProtocolSelection::Http1Or2 => {
            send_once_negotiated(
                client,
                request,
                attempt,
                route,
                lifecycle.request_span,
                lifecycle.timeout_budget,
            )
            .await
        }
    }
}

async fn send_once_exact(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
    } = lifecycle;
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let mut retried_critical_hints = false;
    let has_forward_credentials = protocol == HttpProtocol::Http1
        && request.uri.scheme_str() == Some("http")
        && route
            .as_http_proxy()
            .and_then(crate::HttpProxy::basic_credentials)
            .is_some();
    let mut retried_proxy_authentication = false;
    if has_forward_credentials {
        request_span.record("proxy_authentication_retry", false);
        request_span.record("proxy_attempts", 1_u64);
    }
    let client_hint_origin = client_hint_origin(client, request);

    loop {
        let prepared_headers = attempt_headers(client, request, protocol, &request_headers);
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        if retried_proxy_authentication {
            request_span.record("proxy_authentication_retry", true);
            request_span.record("proxy_attempts", 2_u64);
        }
        let dispatched = dispatch(
            client,
            request,
            protocol,
            method.clone(),
            prepared_headers,
            request_trailers.clone(),
            prepared.client_hints,
            prepared.body,
            route,
            None,
            retried_proxy_authentication,
            timeout_budget,
            retries,
        )
        .await?;
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if has_forward_credentials
            && response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
        {
            if retried_proxy_authentication {
                drop(response);
                return Err(proxy_authentication_error(
                    HttpConnectError::AuthenticationRejected,
                ));
            }
            validate_basic_proxy_challenge(response.headers())
                .map_err(proxy_authentication_error)?;
            retried_proxy_authentication = true;
            tracing::debug!(
                retry = 1,
                reason = "proxy_authentication",
                "retrying forward request with proxy credentials"
            );
            drop(response);
            continue;
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            &response,
            &sent_headers,
            AttemptPath::Exact,
        );
        if !retried_critical_hints
            && critical_retry_requested
            && critical_hint_retry_eligible(&method)
        {
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
    attempt: AttemptRequest<'_>,
    route: &Route,
    request_span: &Span,
    timeout_budget: TimeoutBudget,
) -> Result<AttemptOutcome, RequestError> {
    if !matches!(route, Route::Direct) {
        return Err(RequestError::unsupported_negotiated_route());
    }
    let endpoint = &request.endpoint;
    if let Some((host, port, authority, generation)) = client.alt_svc_location(endpoint) {
        return send_once_alt_svc(
            client,
            request,
            attempt,
            route,
            request_span,
            timeout_budget,
            host,
            port,
            authority,
            generation,
        )
        .await;
    }
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let connector = client
        .inner
        .http1_or_2
        .as_ref()
        .ok_or_else(RequestError::unsupported_negotiation)?;
    let client_hint_origin = client_hint_origin(client, request);
    let mut retried_critical_hints = false;

    loop {
        let http1_request_headers =
            attempt_headers(client, request, HttpProtocol::Http1, &request_headers);
        let http2_request_headers =
            attempt_headers(client, request, HttpProtocol::Http2, &request_headers);
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        let (response, protocol, sent_headers) = client
            .state
            .http1_or_2
            .send_request(
                connector,
                endpoint,
                request_span,
                method.clone(),
                request.target.clone(),
                http1_request_headers,
                http2_request_headers,
                request_trailers.clone(),
                prepared.client_hints,
                prepared.body,
                timeout_budget,
            )
            .await?;

        let critical_retry_requested = observe_response(
            client,
            request,
            &response,
            &sent_headers,
            AttemptPath::Negotiated,
        );
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

#[allow(clippy::too_many_arguments)]
async fn send_once_alt_svc(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    request_span: &Span,
    timeout_budget: TimeoutBudget,
    alternative_host: Box<str>,
    alternative_port: u16,
    alternative_authority: Box<str>,
    alternative_generation: u64,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let endpoint = &request.endpoint;
    let transport = Http3TransportTarget::new(&alternative_host, alternative_port);
    let client_hint_origin = client_hint_origin(client, request);
    let mut retried_critical_hints = false;

    loop {
        let mut prepared_headers =
            attempt_headers(client, request, HttpProtocol::Http3, &request_headers);
        prepared_headers.push(RequestHeader::new(
            "alt-used",
            alternative_authority.as_bytes(),
        ));
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), request_span.clone());
        let dispatched = dispatch(
            client,
            request,
            HttpProtocol::Http3,
            method.clone(),
            prepared_headers,
            request_trailers.clone(),
            prepared.client_hints,
            prepared.body,
            route,
            Some(transport),
            false,
            timeout_budget,
            &mut retries,
        )
        .await;
        let dispatched = match dispatched {
            Ok(dispatched) => dispatched,
            Err(error) => {
                if error.invalidates_alt_svc() {
                    client.remove_alt_svc_if_current(endpoint, alternative_generation);
                }
                return Err(error);
            }
        };
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
            store_cookies(client, request, &response);
            client.remove_alt_svc_if_current(endpoint, alternative_generation);
            return Ok(AttemptOutcome {
                response,
                protocol: HttpProtocol::Http3,
            });
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            &response,
            &sent_headers,
            AttemptPath::Alternative,
        );
        if !retried_critical_hints
            && critical_retry_requested
            && critical_hint_retry_eligible(&method)
        {
            retried_critical_hints = true;
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying alternative-service request with client hints"
            );
            drop(response);
            continue;
        }
        return Ok(AttemptOutcome {
            response,
            protocol: HttpProtocol::Http3,
        });
    }
}

/// Response bookkeeping that differs by attempt path.
#[derive(Clone, Copy)]
enum AttemptPath {
    Exact,
    Negotiated,
    Alternative,
}

impl AttemptPath {
    const fn learns_alt_svc(self) -> bool {
        matches!(self, Self::Negotiated | Self::Alternative)
    }

    const fn requires_https_for_client_hints(self) -> bool {
        matches!(self, Self::Exact | Self::Negotiated)
    }
}

struct PreparedAttempt<'a> {
    client_hints: Option<ClientHintContext<'a>>,
    body: Option<RequestBody>,
}

fn client_hint_origin(client: &Client, request: &ResolvedRequest) -> Option<String> {
    client
        .inner
        .client_hints
        .as_ref()
        .filter(|_| request.uri.scheme_str() == Some("https"))
        .map(|_| request.url.origin().ascii_serialization())
}

fn attempt_headers(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    request_headers: &[RequestHeader],
) -> Vec<RequestHeader> {
    let mut headers = request_headers.to_vec();
    inject_cookie(client, request, protocol, &mut headers);
    headers
}

fn prepare_attempt<'a>(
    client: &'a Client,
    request: &'a ResolvedRequest,
    client_hint_origin: Option<&'a str>,
    body: &mut RequestBodySource,
) -> Result<PreparedAttempt<'a>, RequestError> {
    let client_hints = client
        .inner
        .client_hints
        .as_ref()
        .zip(client_hint_origin)
        .map(|(settings, origin)| client.client_hint_context(&request.endpoint, origin, settings));
    let body = body.next_attempt()?;
    Ok(PreparedAttempt { client_hints, body })
}

/// Stores response state and returns whether it requested a Critical-CH retry.
fn observe_response(
    client: &Client,
    request: &ResolvedRequest,
    response: &Response<ResponseBody>,
    sent_headers: &[RequestHeader],
    path: AttemptPath,
) -> bool {
    store_cookies(client, request, response);
    if path.learns_alt_svc() {
        client.learn_alt_svc(&request.endpoint, response);
    }
    (!path.requires_https_for_client_hints() || request.uri.scheme_str() == Some("https"))
        && client.inner.client_hints.as_ref().is_some_and(|settings| {
            client.learn_client_hints_and_should_retry(
                &request.endpoint,
                settings,
                response.headers(),
                sent_headers,
            )
        })
}

fn store_cookies(client: &Client, request: &ResolvedRequest, response: &Response<ResponseBody>) {
    #[cfg(feature = "cookies")]
    if let Some(jar) = client.state.cookies.as_deref() {
        jar.store_response_headers(&request.url, response.headers());
    }

    #[cfg(not(feature = "cookies"))]
    let _ = (client, request, response);
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
    request_trailers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<RequestBody>,
    route: &Route,
    http3_transport: Option<Http3TransportTarget<'_>>,
    forward_authorization: bool,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
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
            let mode = match (request.uri.scheme_str(), route) {
                (Some("http"), Route::Direct) => Http1ConnectionMode::PlaintextOrigin,
                (Some("http"), Route::HttpProxy(_)) => Http1ConnectionMode::Forward,
                _ => Http1ConnectionMode::TlsOrigin,
            };
            let response = client
                .state
                .http1
                .send_request(
                    connector,
                    client.inner.https_proxy.as_ref(),
                    endpoint,
                    route,
                    mode,
                    method,
                    target,
                    request.absolute_target.clone(),
                    headers,
                    request_trailers,
                    body,
                    forward_authorization,
                    timeout_budget,
                    retries,
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
                    request_trailers,
                    client_hints,
                    body,
                    timeout_budget,
                    retries,
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
                    http3_transport,
                    method,
                    endpoint.authority().as_str(),
                    target,
                    request_headers,
                    request_trailers,
                    client_hints,
                    body,
                    timeout_budget,
                    retries,
                )
                .await
                .map(|(response, sent_headers)| DispatchOutcome {
                    response,
                    sent_headers,
                })
        }
    }
}

fn proxy_authentication_error(error: HttpConnectError) -> RequestError {
    RequestError::http1(Http1TlsError::Proxy(error))
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
