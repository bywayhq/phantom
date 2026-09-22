use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use super::{
    RequestBodySource, ResolvedRequest,
    attempt::{
        AttemptLifecycle, AttemptOutcome, AttemptPath, AttemptRequest, DispatchOutcome,
        attempt_headers, begin_status_retry, begin_unprocessed_replay, client_hint_origin,
        dispatch, observe_response, prepare_attempt, send_once_origin, store_cookies,
    },
    replay::ReplayClass,
};
use crate::{
    AltSvcRace, Client, HttpProtocol, RequestError, Route,
    session::{
        alt_svc::{AlternativeTarget, invalidates_alternative},
        http1_or_2_pool,
        http3_pool::{self, Http3Lease, Http3SetupControl, Http3TransportTarget},
    },
    timeout::TimeoutBudget,
};
use phantom_net::request::{RequestBody, RequestHeader};
use tracing::{Instrument, instrument::WithSubscriber};

pub(super) enum NegotiatedPlan {
    Origin,
    Alternative(AlternativeTarget),
    Race(AlternativeTarget, AltSvcRace),
}

pub(super) fn plan(client: &Client, request: &ResolvedRequest) -> NegotiatedPlan {
    let Some(alternative) = client.alt_svc_location(&request.endpoint) else {
        return NegotiatedPlan::Origin;
    };
    match client.alt_svc_policy().race_settings() {
        None => NegotiatedPlan::Alternative(alternative),
        // A broken alternative is not raced until its broken period ends.
        Some(_) if alternative.is_broken() => NegotiatedPlan::Origin,
        Some(race) => NegotiatedPlan::Race(alternative, race),
    }
}

pub(super) async fn send_once_alt_svc(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: AlternativeTarget,
) -> Result<AttemptOutcome, RequestError> {
    send_on_alternative(
        client,
        request,
        attempt,
        route,
        lifecycle,
        &alternative,
        None,
    )
    .await
}

/// Races alternative QUIC setup against delayed origin H1/H2 setup, then
/// sends the request once, on the winner.
///
/// Both candidates keep the request's origin identity and route. Both request
/// representations are validated before either candidate performs I/O, and
/// the request body is prepared only for the winner.
pub(super) async fn send_once_raced(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: AlternativeTarget,
    race: AltSvcRace,
) -> Result<AttemptOutcome, RequestError> {
    validate_both(client, request, &attempt, route, &alternative)?;
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
        replays,
    } = lifecycle;
    let negotiated = client
        .inner
        .http1_or_2
        .as_ref()
        .ok_or_else(RequestError::unsupported_negotiation)?;

    let connecting = Arc::new(AtomicBool::new(false));
    let alternative_setup = Box::pin(alternative_setup(
        client.clone(),
        request.endpoint.clone(),
        route.clone(),
        alternative.clone(),
        timeout_budget,
        retries.for_alternative_setup(),
        Arc::clone(&connecting),
    ));
    // Like Chromium's main job, the origin does not wait when an HTTP/2
    // connection to it is already available.
    let origin_delay = if client
        .state
        .http1_or_2
        .has_available_http2(&request.endpoint)
        .await
    {
        Duration::ZERO
    } else {
        race.origin_delay()
    };
    let outcome = race_setup(
        alternative_setup,
        || {
            client.state.http1_or_2.acquire_lease(
                negotiated,
                &request.endpoint,
                request_span,
                timeout_budget,
                retries,
            )
        },
        origin_delay,
        timeout_budget,
    )
    .await?;
    let lifecycle = AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
        replays,
    };
    match outcome {
        RaceOutcome::Alternative(leased) => {
            tracing::debug!(
                outcome = "alternative",
                "Alt-Svc race chose the alternative"
            );
            client.confirm_alt_svc(&request.endpoint, &alternative);
            send_on_alternative(
                client,
                request,
                attempt,
                route,
                lifecycle,
                &alternative,
                Some(leased),
            )
            .await
        }
        RaceOutcome::Origin { leased, loser } => {
            tracing::debug!(outcome = "origin", "Alt-Svc race chose the origin");
            match loser {
                Candidate::Failed(error) if invalidates_alternative(&error) => {
                    client.mark_alt_svc_broken(
                        &request.endpoint,
                        &alternative,
                        race.broken_backoff(),
                    );
                }
                Candidate::Failed(_) | Candidate::Taken => {}
                // A setup still waiting for admission or for its location's
                // connect turn has done no network work, so it is cancelled
                // rather than orphaned.
                Candidate::Pending(setup) if connecting.load(Ordering::Acquire) => {
                    continue_alternative(
                        client.clone(),
                        request.endpoint.clone(),
                        alternative,
                        race,
                        setup,
                    );
                }
                Candidate::Pending(_) => {}
            }
            send_once_origin(client, request, attempt, lifecycle, Some(leased)).await
        }
    }
}

/// Admits and connects one alternative lease with owned state, so an
/// unfinished setup can outlive the request that started it.
///
/// `connecting` is set once the setup holds its location's connect turn. The
/// attempt is limited to [`ALTERNATIVE_SETUP_LIMIT`] from then on, and the
/// request's own connect and total deadlines still apply when shorter.
async fn alternative_setup(
    client: Client,
    endpoint: crate::authority::Endpoint,
    route: Route,
    alternative: AlternativeTarget,
    timeout_budget: TimeoutBudget,
    mut retries: crate::retry::ConnectionSetupRetryState,
    connecting: Arc<AtomicBool>,
) -> Result<Http3Lease, RequestError> {
    let connector = client
        .inner
        .http3
        .as_ref()
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    let admission = client
        .state
        .http3
        .admit(&endpoint, &route, timeout_budget)
        .await?;
    admission
        .connect(
            connector,
            client.inner.connect_udp_proxy.as_ref(),
            &endpoint,
            &route,
            Http3TransportTarget::new(alternative.host(), alternative.port()),
            timeout_budget,
            &mut retries,
            Http3SetupControl {
                connecting: Some(&connecting),
                attempt_limit: Some(ALTERNATIVE_SETUP_LIMIT),
            },
        )
        .await
}

/// Longest time one alternative connection attempt may run once it holds
/// its location's connect turn: Chromium's client QUIC idle timeout before
/// the handshake completes.
///
/// At 153.0.8010.48, `QuicParams::max_idle_time_before_crypto_handshake` is
/// `quic::kInitialIdleTimeoutSecs` (`net/quic/quic_context.h` line 172), 5
/// seconds at the pinned quiche revision 2c4a1246
/// (`quiche/quic/core/quic_constants.h` line 159), and quiche shortens a
/// client's idle timeout by one second (`QuicConnection::SetNetworkTimeouts`,
/// `quic_connection.cc` lines 4983-4984). The `udp-blackhole` capture shows
/// the orphaned QUIC job failing with `ERR_QUIC_HANDSHAKE_FAILED` 4002-4016
/// ms after it started.
///
/// Chromium restarts that timer on every received packet and lets a
/// responsive handshake run for up to 10 seconds
/// (`kMaxTimeForCryptoHandshakeSecs`). Phantom cannot observe handshake
/// packets at this layer, so it bounds the whole attempt instead, including
/// name resolution and proxy setup that Chromium's timer does not cover.
pub(super) const ALTERNATIVE_SETUP_LIMIT: Duration = Duration::from_secs(4);

/// Lets an alternative that lost to the origin while connecting finish.
///
/// Like Chromium's orphaned alternative job, a finished connection stays
/// pooled for later requests and clears the alternative's failure history,
/// while a failure, including reaching [`ALTERNATIVE_SETUP_LIMIT`], marks it
/// broken. Without a Tokio runtime handle the setup is dropped instead:
/// nothing is pooled or marked, and the alternative is raced again.
fn continue_alternative<F>(
    client: Client,
    endpoint: crate::authority::Endpoint,
    alternative: AlternativeTarget,
    race: AltSvcRace,
    setup: Pin<Box<F>>,
) where
    F: Future<Output = Result<Http3Lease, RequestError>> + Send + 'static,
{
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let span = tracing::debug_span!("alt_svc.orphaned_alternative");
    drop(
        runtime.spawn(
            async move {
                match setup.await {
                    Ok(leased) => {
                        drop(leased);
                        client.confirm_alt_svc(&endpoint, &alternative);
                        tracing::debug!(outcome = "connected", "orphaned alternative connected");
                    }
                    Err(error) if invalidates_alternative(&error) => {
                        tracing::debug!(outcome = "failed", "orphaned alternative failed");
                        client.mark_alt_svc_broken(&endpoint, &alternative, race.broken_backoff());
                    }
                    Err(_) => {}
                }
            }
            .instrument(span)
            .with_current_subscriber(),
        ),
    );
}

/// Checks the H3 and H1/H2 representations of the first attempt before
/// either candidate performs I/O.
fn validate_both(
    client: &Client,
    request: &ResolvedRequest,
    attempt: &AttemptRequest<'_>,
    route: &Route,
    alternative: &AlternativeTarget,
) -> Result<(), RequestError> {
    let http3 = client
        .inner
        .http3
        .as_ref()
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    let owned_body;
    let body = match &*attempt.body {
        RequestBodySource::Absent => None,
        RequestBodySource::Bytes(bytes) => {
            owned_body = RequestBody::from_bytes(bytes.clone());
            Some(&owned_body)
        }
        RequestBodySource::Streaming(Some(body)) => Some(body),
        RequestBodySource::Streaming(None) => {
            return Err(RequestError::request_body_not_replayable());
        }
    };
    let hint_origin = client_hint_origin(client, request);
    let client_hints = client
        .inner
        .client_hints
        .as_ref()
        .zip(hint_origin.as_deref())
        .map(|(settings, origin)| client.client_hint_context(&request.endpoint, origin, settings));
    let mut http3_headers = attempt_headers(client, request, HttpProtocol::Http3, &attempt.headers);
    http3_headers.push(RequestHeader::new(
        "alt-used",
        alternative.authority().as_bytes(),
    ));
    http3_pool::validate_request(
        http3,
        client.inner.connect_udp_proxy.as_ref(),
        route,
        Http3TransportTarget::new(alternative.host(), alternative.port()),
        &attempt.method,
        request.endpoint.authority().as_str(),
        &request.target,
        &http3_headers,
        &attempt.trailers,
        client_hints,
        body,
    )?;
    http1_or_2_pool::validate_request(
        &request.endpoint,
        &attempt.method,
        &request.target,
        attempt_headers(client, request, HttpProtocol::Http1, &attempt.headers),
        &attempt_headers(client, request, HttpProtocol::Http2, &attempt.headers),
        &attempt.trailers,
        client_hints,
        body,
    )?;
    Ok(())
}

/// Sends a request to a learned alternative.
///
/// `leased` is a connection a race already admitted and established; the
/// first attempt uses it. Later attempts, such as status retries, stay on
/// this alternative and acquire from the pool.
async fn send_on_alternative(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: &AlternativeTarget,
    mut leased: Option<Http3Lease>,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptLifecycle {
        request_span: _,
        timeout_budget,
        retries: request_retries,
        replays,
    } = lifecycle;
    let AttemptRequest {
        method,
        headers: request_headers,
        trailers: request_trailers,
        body,
    } = attempt;
    let endpoint = &request.endpoint;
    let transport = Http3TransportTarget::new(alternative.host(), alternative.port());
    let client_hint_origin = client_hint_origin(client, request);

    loop {
        let mut prepared_headers =
            attempt_headers(client, request, HttpProtocol::Http3, &request_headers);
        prepared_headers.push(RequestHeader::new(
            "alt-used",
            alternative.authority().as_bytes(),
        ));
        let prepared = prepare_attempt(client, request, client_hint_origin.as_deref(), body)?;
        // Alternative setup failures evict the advertisement instead of retrying.
        let mut setup_retries = request_retries.for_alternative_setup();
        let dispatched = match leased.take() {
            Some(leased) => {
                dispatch_on_lease(
                    client,
                    request,
                    leased,
                    method.clone(),
                    prepared_headers,
                    request_trailers.clone(),
                    prepared.client_hints,
                    prepared.body,
                    timeout_budget,
                    &mut setup_retries,
                )
                .await
            }
            None => {
                dispatch(
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
                    &mut setup_retries,
                )
                .await
            }
        };
        let dispatched = match dispatched {
            Ok(dispatched) => dispatched,
            Err(error) => {
                // An unprocessed replay stays on this alternative and keeps it.
                if begin_unprocessed_replay(&error, &method, body, request_retries, replays) {
                    continue;
                }
                if invalidates_alternative(&error) {
                    client.remove_alt_svc_if_current(endpoint, alternative.generation());
                }
                return Err(error);
            }
        };
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
            store_cookies(client, request, &response);
            client.remove_alt_svc_if_current(endpoint, alternative.generation());
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
        if critical_retry_requested && replays.try_begin(ReplayClass::CriticalClientHints, &method)
        {
            tracing::debug!(
                retry = 1,
                reason = "critical_client_hints",
                "retrying alternative-service request with client hints"
            );
            drop(response);
            continue;
        }
        // A status retry stays on this alternative; it never falls back.
        if let Some(delay) = begin_status_retry(
            &response,
            &method,
            body,
            timeout_budget,
            request_retries,
            replays,
        ) {
            drop(response);
            timeout_budget
                .delay(delay, Some(HttpProtocol::Http3))
                .await?;
            continue;
        }
        return Ok(AttemptOutcome {
            response,
            protocol: HttpProtocol::Http3,
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_on_lease(
    client: &Client,
    request: &ResolvedRequest,
    leased: Http3Lease,
    method: http::Method,
    headers: Vec<RequestHeader>,
    trailers: Vec<RequestHeader>,
    client_hints: Option<crate::session::client_hints::ClientHintContext<'_>>,
    body: Option<RequestBody>,
    timeout_budget: TimeoutBudget,
    retries: &mut crate::retry::ConnectionSetupRetryState,
) -> Result<DispatchOutcome, RequestError> {
    let connector = client
        .inner
        .http3
        .as_ref()
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    client
        .state
        .http3
        .send_request_on_lease(
            leased,
            connector,
            method,
            request.endpoint.authority().as_str(),
            request.target.clone(),
            headers,
            trailers,
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

/// The candidate that finished setup first. When the origin wins, `loser`
/// holds the alternative's failure or its unfinished setup.
pub(super) enum RaceOutcome<A, O, F> {
    Alternative(A),
    Origin { leased: O, loser: Candidate<F> },
}

/// Races `alternative` setup against origin setup started by `start_origin`.
///
/// The alternative is polled first. The origin starts after `origin_delay`,
/// or at once when the alternative fails first, so at most one setup attempt
/// per candidate exists. The first success wins and the other candidate is
/// cancelled, except that an unfinished alternative is returned to the caller
/// when the origin wins. An origin failure waits for the alternative. When
/// both fail, the origin's error is returned. Dropping the returned future
/// cancels both candidates.
pub(super) async fn race_setup<A, O, F, S, G>(
    alternative: Pin<Box<F>>,
    start_origin: S,
    origin_delay: Duration,
    timeout_budget: TimeoutBudget,
) -> Result<RaceOutcome<A, O, F>, RequestError>
where
    F: Future<Output = Result<A, RequestError>>,
    S: FnOnce() -> G,
    G: Future<Output = Result<O, RequestError>>,
{
    let mut alternative = Candidate::Pending(alternative);
    let mut start_origin = Some(start_origin);
    let mut origin: Option<Pin<Box<G>>> = None;
    let mut origin_error = None;
    let mut delay = Some(Box::pin(timeout_budget.delay(origin_delay, None)));

    poll_fn(|context| {
        if let Candidate::Pending(setup) = &mut alternative
            && let Poll::Ready(result) = setup.as_mut().poll(context)
        {
            match result {
                Ok(leased) => return Poll::Ready(Ok(RaceOutcome::Alternative(leased))),
                Err(error) => {
                    alternative = Candidate::Failed(error);
                    // The origin no longer waits for its delay.
                    delay = None;
                    if let Some(start) = start_origin.take() {
                        origin = Some(Box::pin(start()));
                    }
                }
            }
        }
        if let Some(timer) = delay.as_mut()
            && let Poll::Ready(result) = timer.as_mut().poll(context)
        {
            delay = None;
            if let Err(error) = result {
                return Poll::Ready(Err(error));
            }
            if let Some(start) = start_origin.take() {
                origin = Some(Box::pin(start()));
            }
        }
        if let Some(setup) = origin.as_mut()
            && let Poll::Ready(result) = setup.as_mut().poll(context)
        {
            origin = None;
            match result {
                Ok(leased) => {
                    let loser = std::mem::replace(&mut alternative, Candidate::Taken);
                    return Poll::Ready(Ok(RaceOutcome::Origin { leased, loser }));
                }
                Err(error) => origin_error = Some(error),
            }
        }
        if matches!(alternative, Candidate::Failed(_)) && origin.is_none() {
            // Both failed; nothing is marked broken, because Chromium reports
            // brokenness only when the origin succeeds.
            if let Some(error) = origin_error.take() {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Pending
    })
    .await
}

/// The alternative candidate's state; `Taken` only after the race returned.
pub(super) enum Candidate<F> {
    Pending(Pin<Box<F>>),
    Failed(RequestError),
    Taken,
}

#[cfg(test)]
mod tests;
