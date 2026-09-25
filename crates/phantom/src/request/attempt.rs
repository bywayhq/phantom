use std::time::Duration;

use http::{Method, Response};
use phantom_net::{
    http1::Http1TlsError,
    http2::Http2TlsError,
    proxy::{
        HttpBasicCredentials, HttpConnectError, ProxyCredentialCache, ProxyScheme,
        validate_basic_proxy_challenge,
    },
    request::{RequestBody, RequestHeader},
};
use phantom_profile::{Http2Priority, ProxyAuthorizationAttempt};
use tracing::Span;

use crate::timeout::TimeoutBudget;
use crate::{
    Client, HttpProtocol, RequestError, ResponseBody, Route, retry::ConnectionSetupRetryState,
};

use super::{
    PreparedRequestTemplate, ProtocolSelection, RequestBodySource, ResolvedRequest,
    alt_svc_attempt::{NegotiatedPlan, plan, send_once_alt_svc, send_once_raced},
    replay::{ReplayClass, ReplayState},
    secure_context::is_potentially_trustworthy,
    template::{ForwardedCredentials, Forwarding},
};
use crate::session::{
    client_hints::ClientHintContext, http1_or_2_pool::NegotiatedLease,
    http1_pool::Http1ConnectionMode, http2_pool::Http2ConnectionMode,
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
    pub(super) replays: &'a mut ReplayState,
}

pub(super) async fn send_once(
    client: &Client,
    request: &ResolvedRequest,
    selection: ProtocolSelection,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
) -> Result<AttemptOutcome, RequestError> {
    lifecycle.replays.start_hop();
    match selection {
        ProtocolSelection::Exact(protocol) => {
            send_once_exact(client, request, protocol, attempt, route, lifecycle).await
        }
        // Cleartext has no ALPN and browsers do not use h2c, so an `http://`
        // origin uses HTTP/1.1, except through an HTTP/2 proxy, where
        // browsers forward it as an HTTP/2 request. The choice follows the
        // route before any I/O, and nothing is learned from Alt-Svc.
        ProtocolSelection::Http1Or2 if request.uri.scheme_str() == Some("http") => {
            let protocol = if route.forwards_plaintext_over_http2() {
                HttpProtocol::Http2
            } else {
                HttpProtocol::Http1
            };
            lifecycle
                .request_span
                .record("selected_protocol", protocol.trace_name());
            send_once_exact(client, request, protocol, attempt, route, lifecycle).await
        }
        ProtocolSelection::Http1Or2 => {
            send_once_negotiated(client, request, attempt, route, lifecycle).await
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
        replays,
    } = lifecycle;
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let forward_authentication = ForwardAuthentication::new(client, request, protocol, route);
    if let Some(authentication) = &forward_authentication {
        request_span.record(
            "proxy_authentication_preemptive",
            authentication.remembered(),
        );
        request_span.record("proxy_authentication_retry", false);
        request_span.record("proxy_attempts", 1_u64);
    }
    let client_hint_origin = client_hint_origin(client, request);
    let mut fresh_connection = false;
    let forwarded = route.forwards(&request.uri);
    let credentials_field = forward_authentication
        .as_ref()
        .map(|authentication| authentication.field(protocol));

    loop {
        let challenged = replays.performed(ReplayClass::ProxyAuthentication);
        // The retry after a challenge carries the credentials, and so does
        // every request to a proxy that accepted them before.
        let sends_forward_credentials = forward_authentication
            .as_ref()
            .is_some_and(|authentication| challenged || authentication.remembered());
        let forwarding = Forwarding {
            forwarded,
            credentials: credentials_field
                .as_ref()
                .filter(|_| sends_forward_credentials)
                .map(|field| ForwardedCredentials {
                    field,
                    attempt: if challenged {
                        ProxyAuthorizationAttempt::Replay
                    } else {
                        ProxyAuthorizationAttempt::Preemptive
                    },
                }),
        };
        let prepared_headers =
            route_attempt_headers(client, request, protocol, &request_headers, forwarding);
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        if challenged {
            request_span.record("proxy_authentication_retry", true);
            request_span.record("proxy_attempts", 2_u64);
        }
        let dispatched = dispatch_attempt(
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
            Http1Connect {
                forward_authorization: sends_forward_credentials,
                // The single retry after an H1 forwarding challenge opens a
                // new proxy connection; a request that sends remembered
                // credentials first reuses a pooled one.
                fresh_connection: std::mem::take(&mut fresh_connection) || challenged,
            },
            timeout_budget,
            retries,
        )
        .await;
        let dispatched = match dispatched {
            Ok(dispatched) => dispatched,
            Err(error) => {
                if begin_reused_connection_replay(&error, &method, body, retries, replays) {
                    fresh_connection = true;
                    continue;
                }
                // The pool already retired the connection that refused it.
                if begin_unprocessed_replay(&error, &method, body, retries, replays) {
                    continue;
                }
                return Err(error);
            }
        };
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if let Some(authentication) = &forward_authentication {
            if response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                if sends_forward_credentials {
                    authentication.forget();
                }
                if !replays.try_begin(ReplayClass::ProxyAuthentication, &method) {
                    drop(response);
                    return Err(proxy_authentication_error(
                        protocol,
                        HttpConnectError::AuthenticationRejected,
                    ));
                }
                validate_basic_proxy_challenge(response.headers())
                    .map_err(|error| proxy_authentication_error(protocol, error))?;
                tracing::debug!(
                    retry = 1,
                    reason = "proxy_authentication",
                    "retrying forward request with proxy credentials"
                );
                drop(response);
                continue;
            }
            if sends_forward_credentials {
                authentication.accepted();
            }
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            route,
            &response,
            &sent_headers,
            AttemptPath::Exact,
        );
        if critical_retry_requested && replays.try_begin(ReplayClass::CriticalClientHints, &method)
        {
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying request with negotiated client hints"
            );
            drop(response);
            continue;
        }
        if let Some(delay) =
            begin_status_retry(&response, &method, body, timeout_budget, retries, replays)
        {
            drop(response);
            timeout_budget.delay(delay, Some(protocol)).await?;
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
    lifecycle: AttemptLifecycle<'_>,
) -> Result<AttemptOutcome, RequestError> {
    if !route.carries_origin_tls_for_alpn() {
        return Err(RequestError::unsupported_negotiated_route());
    }
    match plan(client, request, route) {
        NegotiatedPlan::Alternative(alternative) => {
            send_once_alt_svc(client, request, attempt, route, lifecycle, alternative).await
        }
        NegotiatedPlan::Race(alternative, race, lookup) => {
            send_once_raced(
                client,
                request,
                attempt,
                route,
                lifecycle,
                alternative,
                race,
                lookup,
            )
            .await
        }
        NegotiatedPlan::Origin => {
            send_once_origin(client, request, attempt, route, lifecycle, None).await
        }
    }
}

/// Sends a negotiated request to the origin over H1 or H2.
///
/// `leased` is a connection a race already admitted and established; the
/// first attempt uses it, and later attempts acquire from the pool.
pub(super) async fn send_once_origin(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    mut leased: Option<NegotiatedLease>,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
        replays,
    } = lifecycle;
    let endpoint = &request.endpoint;
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
    let mut fresh_http1_connection = false;

    loop {
        let http1_request_headers =
            attempt_headers(client, request, HttpProtocol::Http1, &request_headers);
        let http2_request_headers =
            attempt_headers(client, request, HttpProtocol::Http2, &request_headers);
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        let sent = client
            .state
            .http1_or_2
            .send_request(
                connector,
                client.inner.https_proxy.as_ref(),
                endpoint,
                route,
                request_span,
                method.clone(),
                request.target.clone(),
                http1_request_headers,
                http2_request_headers,
                request_trailers.clone(),
                prepared.client_hints,
                prepared.body,
                http2_priority(request),
                std::mem::take(&mut fresh_http1_connection),
                leased.take(),
                timeout_budget,
                retries,
            )
            .await;
        let (response, protocol, sent_headers) = match sent {
            Ok(sent) => sent,
            Err(error) => {
                if begin_reused_connection_replay(&error, &method, body, retries, replays) {
                    fresh_http1_connection = true;
                    continue;
                }
                // The pool already retired the connection that refused it; the
                // replacement is negotiated under the same selection rule.
                if begin_unprocessed_replay(&error, &method, body, retries, replays) {
                    continue;
                }
                return Err(error);
            }
        };

        let critical_retry_requested = observe_response(
            client,
            request,
            route,
            &response,
            &sent_headers,
            AttemptPath::Negotiated,
        );
        if critical_retry_requested && replays.try_begin(ReplayClass::CriticalClientHints, &method)
        {
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying negotiated request with client hints"
            );
            drop(response);
            continue;
        }
        if let Some(delay) =
            begin_status_retry(&response, &method, body, timeout_budget, retries, replays)
        {
            drop(response);
            timeout_budget.delay(delay, Some(protocol)).await?;
            continue;
        }
        return Ok(AttemptOutcome { response, protocol });
    }
}

/// Starts the one replay after a reused HTTP/1.1 connection closed before
/// any response byte, when policy, method, and body permit it.
///
/// A one-shot streaming body was moved into the failed attempt, so it is
/// never replayed and the original error is returned instead.
fn begin_reused_connection_replay(
    error: &RequestError,
    method: &Method,
    body: &RequestBodySource,
    retries: &mut ConnectionSetupRetryState,
    replays: &mut ReplayState,
) -> bool {
    if !retries.replays_reused_connections()
        || !error.is_reused_connection_close()
        || !matches!(
            body,
            RequestBodySource::Absent | RequestBodySource::Bytes(_)
        )
        || !replays.try_begin(ReplayClass::ReusedConnection, method)
    {
        return false;
    }
    retries.record_reused_connection_replay();
    true
}

/// Starts one replay after the HTTP/2 or HTTP/3 peer reported that it did not
/// process the request, when policy, remaining request-scoped budget, and body
/// permit it. Any method is eligible.
///
/// A one-shot streaming body was moved into the refused attempt, so it is
/// never replayed and the original error is returned before another
/// connection is opened.
pub(super) fn begin_unprocessed_replay(
    error: &RequestError,
    method: &Method,
    body: &RequestBodySource,
    retries: &mut ConnectionSetupRetryState,
    replays: &mut ReplayState,
) -> bool {
    if !error.is_unprocessed_request()
        || !retries.unprocessed_replay_available()
        || !matches!(
            body,
            RequestBodySource::Absent | RequestBodySource::Bytes(_)
        )
        || !replays.try_begin(ReplayClass::Unprocessed, method)
    {
        return false;
    }
    retries.record_unprocessed_replay(error.protocol());
    true
}

/// Starts one status retry after `response` was observed, returning the delay
/// to wait before the next attempt, when policy, status, `Retry-After`,
/// remaining retry budget, method, and body all permit it and the delay can
/// finish before the total deadline. Otherwise `response` is returned as is.
///
/// The caller drops the intermediate response body unread: an incomplete
/// HTTP/1.1 body retires its connection, and an H2 or H3 body cancels its
/// stream. A one-shot streaming body was moved into the first attempt, so the
/// response is returned instead.
pub(super) fn begin_status_retry(
    response: &Response<ResponseBody>,
    method: &Method,
    body: &RequestBodySource,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    replays: &mut ReplayState,
) -> Option<Duration> {
    let status = response.status();
    let delay = retries.status_retry_delay(status, response.headers())?;
    // A delay that cannot finish before the total deadline would only turn
    // this usable response into a timeout.
    if timeout_budget
        .remaining_total()
        .is_some_and(|remaining| delay >= remaining)
    {
        return None;
    }
    if !matches!(
        body,
        RequestBodySource::Absent | RequestBodySource::Bytes(_)
    ) || !replays.try_begin(ReplayClass::Status, method)
    {
        return None;
    }
    retries.record_status_retry(status, delay);
    Some(delay)
}

/// Response bookkeeping that differs by attempt path.
#[derive(Clone, Copy)]
pub(super) enum AttemptPath {
    Exact,
    Negotiated,
    Alternative,
}

impl AttemptPath {
    const fn learns_alt_svc(self) -> bool {
        matches!(self, Self::Negotiated | Self::Alternative)
    }

    const fn requires_trustworthy_origin_for_client_hints(self) -> bool {
        matches!(self, Self::Exact | Self::Negotiated)
    }
}

pub(super) struct PreparedAttempt<'a> {
    pub(super) client_hints: Option<ClientHintContext<'a>>,
    pub(super) body: Option<RequestBody>,
}

/// Returns the client-hint origin of `request`, or `None` when the client
/// sends no automatic hints to it.
///
/// Chromium sends and learns client hints only for a potentially
/// trustworthy origin: `IsValidURLForClientHints` gates both
/// `ShouldAddClientHints` and `ParseAndPersistAcceptCHForNavigation`
/// (`content/browser/client_hints/client_hints.cc` lines 501-503, 787-804,
/// and 1004 at tag `154.0.8037.58`). The retained Chrome and Edge captures
/// carry hints to `http://127.0.0.1` and none to `http://origin.phantom.test`.
pub(super) fn client_hint_origin(client: &Client, request: &ResolvedRequest) -> Option<String> {
    client
        .inner
        .client_hints
        .as_ref()
        .filter(|_| is_potentially_trustworthy(&request.url))
        .map(|_| request.url.origin().ascii_serialization())
}

/// Returns the fields of one attempt that no HTTP proxy forwards.
pub(super) fn attempt_headers(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    request_headers: &[RequestHeader],
) -> Vec<RequestHeader> {
    route_attempt_headers(
        client,
        request,
        protocol,
        request_headers,
        Forwarding::default(),
    )
}

/// Returns the fields of one attempt, with the template's route-dependent
/// entries chosen for `forwarding`.
///
/// Generated proxy credentials take the template's slot for the attempt, or
/// follow every other field, cookies included, when it has none.
fn route_attempt_headers(
    client: &Client,
    request: &ResolvedRequest,
    protocol: HttpProtocol,
    request_headers: &[RequestHeader],
    forwarding: Forwarding<'_>,
) -> Vec<RequestHeader> {
    let fields = request
        .template
        .as_ref()
        .and_then(|template| template.fields_for(protocol));
    // `send` rejects a template without a list for any protocol the request
    // may use, so a missing list never reaches this point with a template.
    let (mut headers, placed) = match fields {
        Some(fields) => super::template::expand_on_route(
            fields,
            request_headers,
            client.inner.client_hints.as_ref(),
            is_potentially_trustworthy(&request.url),
            forwarding,
        ),
        None => (request_headers.to_vec(), false),
    };
    inject_cookie(client, request, protocol, &mut headers);
    if !placed && let Some(credentials) = forwarding.credentials {
        headers.push(credentials.field.clone());
    }
    headers
}

pub(super) fn prepare_attempt<'a>(
    client: &'a Client,
    request: &'a ResolvedRequest,
    client_hint_origin: Option<&'a str>,
    body: &mut RequestBodySource,
) -> Result<PreparedAttempt<'a>, RequestError> {
    let client_hints = attempt_client_hints(client, request, client_hint_origin);
    let body = body.next_attempt()?;
    Ok(PreparedAttempt { client_hints, body })
}

/// Returns the client-hint context of one attempt, which places automatic
/// hints at the request template's slots.
///
/// Validation before I/O and the attempt itself use this one context, so a
/// template's hint placement and requested-hint refusal apply to both.
pub(super) fn attempt_client_hints<'a>(
    client: &'a Client,
    request: &'a ResolvedRequest,
    client_hint_origin: Option<&'a str>,
) -> Option<ClientHintContext<'a>> {
    client
        .inner
        .client_hints
        .as_ref()
        .zip(client_hint_origin)
        .map(|(settings, origin)| {
            client
                .client_hint_context(&request.endpoint, origin, settings)
                .with_template(request.template.as_ref())
        })
}

/// Stores response state and returns whether it requested a Critical-CH retry.
pub(super) fn observe_response(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    response: &Response<ResponseBody>,
    sent_headers: &[RequestHeader],
    path: AttemptPath,
) -> bool {
    store_cookies(client, request, response);
    if path.learns_alt_svc() {
        client.learn_alt_svc(&request.endpoint, route, response);
    }
    (!path.requires_trustworthy_origin_for_client_hints()
        || is_potentially_trustworthy(&request.url))
        && client.inner.client_hints.as_ref().is_some_and(|settings| {
            client.learn_client_hints_and_should_retry(
                &request.endpoint,
                request.uri.scheme_str() == Some("https"),
                settings,
                response.headers(),
                sent_headers,
            )
        })
}

pub(super) fn store_cookies(
    client: &Client,
    request: &ResolvedRequest,
    response: &Response<ResponseBody>,
) {
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
        if !caller_supplied && let Some(value) = jar.request_value_for_url(&request.url) {
            let name = match protocol {
                HttpProtocol::Http1 => "Cookie",
                HttpProtocol::Http2 | HttpProtocol::Http3 => "cookie",
            };
            let index = client
                .inner
                .cookie_placement
                .insertion_index(headers.iter().map(RequestHeader::name))
                .unwrap_or(headers.len());
            headers.insert(index, RequestHeader::new(name, value).sensitive());
        }
    }

    #[cfg(not(feature = "cookies"))]
    let _ = (client, request, protocol, headers);
}

pub(super) struct DispatchOutcome {
    pub(super) response: Response<ResponseBody>,
    pub(super) sent_headers: Vec<RequestHeader>,
}

pub(super) struct AttemptOutcome {
    pub(super) response: Response<ResponseBody>,
    pub(super) protocol: HttpProtocol,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
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
    dispatch_attempt(
        client,
        request,
        protocol,
        method,
        request_headers,
        request_trailers,
        client_hints,
        body,
        route,
        http3_transport,
        Http1Connect {
            forward_authorization,
            fresh_connection: false,
        },
        timeout_budget,
        retries,
    )
    .await
}

/// HTTP/1 pool connection choices for one attempt; H3 ignores them.
#[derive(Clone, Copy)]
struct Http1Connect {
    /// Whether the forwarded fields already carry the route's credentials;
    /// otherwise the pool checks the authenticated replay before I/O.
    forward_authorization: bool,
    /// Retires the pooled connection and opens a new one.
    fresh_connection: bool,
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_attempt(
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
    http1_connect: Http1Connect,
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
            let sent_headers = prepare_headers(client_hints, request_headers, None)?;
            let mut headers = Vec::with_capacity(sent_headers.len() + 1);
            headers.push(RequestHeader::new(
                "Host",
                endpoint.authority().as_str().as_bytes(),
            ));
            headers.extend(sent_headers.clone());
            let mode = match (request.uri.scheme_str(), route) {
                (Some("http"), Route::Direct | Route::Socks5(_)) => {
                    Http1ConnectionMode::PlaintextOrigin
                }
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
                    http1_connect.forward_authorization,
                    http1_connect.fresh_connection,
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
                    if request.uri.scheme_str() == Some("http") {
                        Http2ConnectionMode::Forward
                    } else {
                        Http2ConnectionMode::TlsOrigin
                    },
                    method,
                    endpoint.authority().as_str(),
                    target,
                    request_headers,
                    request_trailers,
                    client_hints,
                    body,
                    http2_priority(request),
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
                    client.inner.connect_udp_proxy.as_deref(),
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

/// Returns the template's HTTP/2 HEADERS priority for this request, if any.
fn http2_priority(request: &ResolvedRequest) -> Option<Http2Priority> {
    request
        .template
        .as_ref()
        .and_then(PreparedRequestTemplate::http2_priority)
}

fn proxy_authentication_error(protocol: HttpProtocol, error: HttpConnectError) -> RequestError {
    match protocol {
        HttpProtocol::Http2 => RequestError::http2(Http2TlsError::Proxy(error)),
        HttpProtocol::Http1 | HttpProtocol::Http3 => {
            RequestError::http1(Http1TlsError::Proxy(error))
        }
    }
}

/// Basic credentials for an `http://` request that an HTTP proxy forwards.
///
/// The client's credential record decides whether the first attempt carries
/// them. Only the route's own credentials are ever sent, and only to its
/// proxy.
struct ForwardAuthentication<'a> {
    proxy: &'a crate::HttpProxy,
    credentials: &'a HttpBasicCredentials,
    cache: Option<&'a ProxyCredentialCache>,
}

impl<'a> ForwardAuthentication<'a> {
    fn new(
        client: &'a Client,
        request: &ResolvedRequest,
        protocol: HttpProtocol,
        route: &'a Route,
    ) -> Option<Self> {
        if request.uri.scheme_str() != Some("http") {
            return None;
        }
        let forwards = match protocol {
            HttpProtocol::Http1 => !route.forwards_plaintext_over_http2(),
            HttpProtocol::Http2 => route.forwards_plaintext_over_http2(),
            HttpProtocol::Http3 => false,
        };
        let proxy = route.as_http_proxy().filter(|_| forwards)?;
        Some(Self {
            proxy,
            credentials: proxy.basic_credentials()?,
            cache: client.inner.proxy_credentials.as_ref(),
        })
    }

    /// Returns the generated field under the name `protocol` sends.
    fn field(&self, protocol: HttpProtocol) -> RequestHeader {
        let generated = self.credentials.proxy_authorization_header();
        match protocol {
            HttpProtocol::Http1 => generated,
            // HTTP/2 requires lowercase names.
            HttpProtocol::Http2 | HttpProtocol::Http3 => {
                RequestHeader::new("proxy-authorization", generated.value()).sensitive()
            }
        }
    }

    fn scheme(&self) -> ProxyScheme {
        if self.proxy.uses_tls() {
            ProxyScheme::Https
        } else {
            ProxyScheme::Http
        }
    }

    /// Whether the proxy accepted these credentials after an earlier
    /// challenge.
    fn remembered(&self) -> bool {
        self.cache.is_some_and(|cache| {
            cache.contains(
                self.scheme(),
                self.proxy.host(),
                self.proxy.port(),
                self.credentials,
            )
        })
    }

    fn accepted(&self) {
        if let Some(cache) = self.cache {
            cache.insert(
                self.scheme(),
                self.proxy.host(),
                self.proxy.port(),
                self.credentials,
            );
        }
    }

    fn forget(&self) {
        if let Some(cache) = self.cache {
            cache.remove(
                self.scheme(),
                self.proxy.host(),
                self.proxy.port(),
                self.credentials,
            );
        }
    }
}
fn prepare_headers(
    client_hints: Option<ClientHintContext<'_>>,
    headers: Vec<RequestHeader>,
    connection_accept_ch: Option<&[u8]>,
) -> Result<Vec<RequestHeader>, RequestError> {
    match client_hints {
        Some(context) => context.prepare(headers, connection_accept_ch),
        None => Ok(headers),
    }
}
