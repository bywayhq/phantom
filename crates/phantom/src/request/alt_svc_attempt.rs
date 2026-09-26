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
        attempt_client_hints, attempt_headers, begin_status_retry, begin_unprocessed_replay,
        client_hint_origin, dispatch, observe_response, prepare_attempt, send_once_origin,
        store_cookies,
    },
    replay::ReplayClass,
};
use crate::{
    AltSvcRace, Client, HttpProtocol, RequestError, Route, TimeoutPhase,
    session::{
        alt_svc::{AlternativeTarget, PendingLookup, invalidates_alternative},
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
    /// Race the alternative against the origin. With a pending HTTPS-record
    /// lookup, alternative setup starts only if the lookup advertises `h3`.
    Race(AlternativeTarget, AltSvcRace, Option<PendingLookup>),
}

/// Chooses how one negotiated request uses this route's learned alternative,
/// or else the origin's HTTPS records.
///
/// The store is keyed by origin and route, so only an alternative learned on
/// `route` can be selected here, and it is reached over `route` as well. A
/// route that cannot carry QUIC never stores an alternative, so it always
/// plans the origin; see `Client::learn_alt_svc`.
///
/// A learned Alt-Svc alternative takes precedence over HTTPS records, since
/// Phantom races one alternative at a time. Chromium drops its
/// `DNS_ALPN_H3` job only when the Alt-Svc alternative is the same location
/// and otherwise runs both (`JobController::ClearInappropriateJobs`,
/// `net/http/http_stream_factory_job_controller.cc` lines 1125-1133 at
/// 154.0.8037.58).
///
/// An HTTPS-record lookup does not hold back the origin request; only the
/// TLS handshake of a profile that offers ECH from HTTPS records waits for
/// it, for at most 50 ms after address resolution. While one is in flight,
/// the sequential policy sends the request to the origin and leaves the
/// result for later requests; the racing policy starts origin setup at once
/// and alternative setup when the lookup advertises `h3`.
pub(super) fn plan(client: &Client, request: &ResolvedRequest, route: &Route) -> NegotiatedPlan {
    let race = client.alt_svc_policy().race_settings();
    let alternative = match client.alt_svc_location(&request.endpoint, route) {
        Some(alternative) => alternative,
        None => match https_record_plan(client, request, route, race) {
            Ok(alternative) => alternative,
            Err(plan) => return *plan,
        },
    };
    match race {
        None => NegotiatedPlan::Alternative(alternative),
        // A broken alternative is not raced until its broken period ends.
        Some(_) if alternative.is_broken() => NegotiatedPlan::Origin,
        Some(race) => NegotiatedPlan::Race(alternative, race, None),
    }
}

/// Returns the origin's own location when its cached HTTPS records advertise
/// `h3`, or the plan for a request whose records say otherwise or are still
/// being looked up.
#[cfg(feature = "https-records")]
fn https_record_plan(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    race: Option<AltSvcRace>,
) -> Result<AlternativeTarget, Box<NegotiatedPlan>> {
    use crate::session::alt_svc::Discovery;

    match client.https_record_alternative(&request.endpoint, route) {
        Some((alternative, Discovery::Advertised)) => {
            tracing::debug!(outcome = "advertised", "HTTPS records advertise h3");
            Ok(alternative)
        }
        Some((alternative, Discovery::Pending(lookup))) => {
            tracing::debug!(outcome = "pending", "HTTPS record lookup in flight");
            Err(Box::new(match race {
                Some(race) => NegotiatedPlan::Race(alternative, race, Some(lookup)),
                None => NegotiatedPlan::Origin,
            }))
        }
        Some((_, Discovery::NotAdvertised)) | None => Err(Box::new(NegotiatedPlan::Origin)),
    }
}

/// Without the `https-records` feature there are no HTTPS records to consult.
#[cfg(not(feature = "https-records"))]
fn https_record_plan(
    _client: &Client,
    _request: &ResolvedRequest,
    _route: &Route,
    _race: Option<AltSvcRace>,
) -> Result<AlternativeTarget, Box<NegotiatedPlan>> {
    Err(Box::new(NegotiatedPlan::Origin))
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
///
/// With a pending HTTPS-record `lookup`, the origin does not wait at all and
/// alternative setup begins only once the lookup advertises `h3`; a lookup
/// that fails or advertises nothing leaves the origin as the only candidate
/// and marks nothing broken.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_once_raced(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: AlternativeTarget,
    race: AltSvcRace,
    lookup: Option<PendingLookup>,
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
    let awaits_lookup = lookup.is_some();
    let alternative_setup = Box::pin(alternative_setup(
        client.clone(),
        request.endpoint.clone(),
        route.clone(),
        alternative.clone(),
        timeout_budget,
        retries.for_alternative_setup(),
        Arc::clone(&connecting),
        lookup,
        race.alternative_setup_limit(),
    ));
    // Like Chromium's main job, the origin does not wait when an HTTP/2
    // connection to it is already available. It never waits for a DNS
    // lookup, which would add a DNS round trip to a first request.
    let origin_delay = if awaits_lookup
        || client
            .state
            .http1_or_2
            .has_available_http2(&request.endpoint, route)
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
                client.inner.https_proxy.as_ref(),
                &request.endpoint,
                route,
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
            let connection = leased.connection().clone();
            // A setup that resumed with early data wins before its handshake
            // completes, so it is confirmed only once the handshake has.
            if !connection.early_data_pending() {
                client.confirm_alt_svc(&request.endpoint, route, &alternative);
                return send_on_alternative(
                    client,
                    request,
                    attempt,
                    route,
                    lifecycle,
                    &alternative,
                    Some(leased),
                )
                .await;
            }
            // Boxed: this path holds two request futures and a retry, which
            // would otherwise enlarge every poll frame of this function, and
            // a debug build on Windows then overflows a test thread's stack.
            Box::pin(send_after_early_win(
                client,
                request,
                attempt,
                route,
                lifecycle,
                alternative,
                race,
                leased,
                connection,
            ))
            .await
        }
        RaceOutcome::Origin { leased, loser } => {
            tracing::debug!(outcome = "origin", "Alt-Svc race chose the origin");
            match loser {
                Candidate::Failed(error) if invalidates_alternative(&error) => {
                    client.mark_alt_svc_broken(
                        &request.endpoint,
                        route,
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
                        route.clone(),
                        alternative,
                        race,
                        setup,
                    );
                }
                Candidate::Pending(_) => {}
            }
            send_once_origin(client, request, attempt, route, lifecycle, Some(leased)).await
        }
    }
}

/// Sends the request on a raced alternative that won while its handshake,
/// resumed with early data, was still running; then confirms the
/// alternative, marks QUIC to the origin recently broken, or races again,
/// as `after_early_win` decides.
#[allow(clippy::too_many_arguments)]
async fn send_after_early_win(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: AlternativeTarget,
    race: AltSvcRace,
    leased: Http3Lease,
    connection: phantom_net::http3::Http3Connection,
) -> Result<AttemptOutcome, RequestError> {
    let AttemptRequest {
        method,
        headers,
        trailers,
        body,
    } = attempt;
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
        replays,
    } = lifecycle;
    let result = send_on_alternative(
        client,
        request,
        AttemptRequest {
            method: method.clone(),
            headers: headers.clone(),
            trailers: trailers.clone(),
            body: &mut *body,
        },
        route,
        AttemptLifecycle {
            request_span,
            timeout_budget,
            retries: &mut *retries,
            replays: &mut *replays,
        },
        &alternative,
        Some(leased),
    )
    .await;
    // A response head arrives only after the handshake completed, so
    // the answer is settled for a response; after a failure it is
    // usually settled too. The wait stays within the request's
    // deadlines, and an unknown answer is not a failed handshake.
    let handshake_failed = timeout_budget
        .run(TimeoutPhase::Connect, Some(HttpProtocol::Http3), async {
            Ok(connection.early_data_handshake_failed().await)
        })
        .await;
    let replayable = matches!(
        &*body,
        RequestBodySource::Absent | RequestBodySource::Bytes(_)
    );
    match after_early_win(
        handshake_failed.ok(),
        result.is_ok(),
        alternative.allows_early_data(),
        replayable,
    ) {
        EarlyWinStep::Return => return result,
        EarlyWinStep::Confirm => {
            client.confirm_alt_svc(&request.endpoint, route, &alternative);
            return result;
        }
        EarlyWinStep::MarkRecentlyBroken => {
            client.mark_origin_quic_recently_broken(&request.endpoint, route);
            return result;
        }
        EarlyWinStep::RaceAgain => {
            client.mark_origin_quic_recently_broken(&request.endpoint, route);
        }
    }
    tracing::debug!(
        outcome = "handshake_failed",
        "raced alternative failed its handshake after early data; racing again"
    );
    Box::pin(send_once_raced(
        client,
        request,
        AttemptRequest {
            method,
            headers,
            trailers,
            body,
        },
        route,
        AttemptLifecycle {
            request_span,
            timeout_budget,
            retries,
            replays,
        },
        alternative.without_early_data(),
        race,
        None,
    ))
    .await
}

/// Returns whether an orphaned alternative setup that returned a connection
/// confirms the alternative.
///
/// A setup that resumed with early data returns its connection before its
/// handshake completes. When that handshake then fails, nothing is marked:
/// the orphaned connection carried no request, and Chromium's
/// `QuicSessionPool::ProcessGoingAwaySession` returns without marking QUIC
/// broken or recently broken for a session that was never active
/// (`net/quic/quic_session_pool.cc` lines 2714-2716 at 154.0.8037.58), while
/// its job had already completed and so reports no failure. Nor is the
/// alternative confirmed, since no handshake completed.
const fn confirms_orphan(handshake_failed: bool) -> bool {
    !handshake_failed
}

/// What follows a request on a raced alternative that won on early data.
#[derive(Debug, Eq, PartialEq)]
enum EarlyWinStep {
    /// The answer is unknown within the deadlines: return the result as it is.
    Return,
    /// The handshake completed: confirm the alternative.
    Confirm,
    /// The handshake failed: mark QUIC to the origin recently broken and
    /// return the result.
    MarkRecentlyBroken,
    /// The handshake failed and the request may be raced once more: mark QUIC
    /// to the origin recently broken and race again without early data.
    RaceAgain,
}

/// Decides [`EarlyWinStep`] from whether the handshake failed (`None` when
/// the answer did not arrive within the deadlines), whether the request got
/// a response, whether its race allowed early data, and whether its body can
/// be sent again.
///
/// Chromium fails the requests of a session whose handshake failed with
/// `ERR_QUIC_HANDSHAKE_FAILED` and marks QUIC to the origin recently broken;
/// `HttpNetworkTransaction::HandleIOError` then restarts the transaction,
/// which races again without early data (`RetryReason::kQuicHandshakeFailed`,
/// `net/http/http_network_transaction.cc` lines 2077-2078 and 2222-2233 at
/// 154.0.8037.58). A response already received is not sent again.
const fn after_early_win(
    handshake_failed: Option<bool>,
    responded: bool,
    allowed_early_data: bool,
    replayable: bool,
) -> EarlyWinStep {
    match handshake_failed {
        None => EarlyWinStep::Return,
        Some(false) => EarlyWinStep::Confirm,
        Some(true) if !responded && races_again(allowed_early_data, replayable) => {
            EarlyWinStep::RaceAgain
        }
        Some(true) => EarlyWinStep::MarkRecentlyBroken,
    }
}

/// Returns whether a request whose raced alternative failed its handshake
/// after early data is raced once more.
///
/// Only a race that allowed early data is retried, and the retry allows
/// none, so a request is raced again at most once, even when the retry wins
/// on a pooled connection whose own early data is still unanswered. The body
/// must be replayable: absent or owned bytes.
const fn races_again(allowed_early_data: bool, replayable: bool) -> bool {
    allowed_early_data && replayable
}

/// Admits and connects one alternative lease with owned state, so an
/// unfinished setup can outlive the request that started it.
///
/// `connecting` is set once the setup holds its location's connect turn. The
/// attempt is limited to the race's alternative setup limit from then on,
/// and the request's own connect and total deadlines still apply when
/// shorter.
///
/// With a pending HTTPS-record `lookup`, setup first waits for it and fails
/// without I/O when the records do not advertise `h3`. The race never
/// returns that failure: the origin's result decides the request.
#[allow(clippy::too_many_arguments)]
async fn alternative_setup(
    client: Client,
    endpoint: crate::authority::Endpoint,
    route: Route,
    alternative: AlternativeTarget,
    timeout_budget: TimeoutBudget,
    mut retries: crate::retry::ConnectionSetupRetryState,
    connecting: Arc<AtomicBool>,
    lookup: Option<PendingLookup>,
    setup_limit: Duration,
) -> Result<Http3Lease, RequestError> {
    if let Some(lookup) = lookup
        && !lookup.advertises_h3().await
    {
        // `invalidates_alternative` rejects this kind, so nothing is marked
        // broken.
        return Err(RequestError::unsupported_protocol(HttpProtocol::Http3));
    }
    let connector = client
        .inner
        .http3
        .as_ref()
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    // Like Chromium's QUIC job, the setup offers early data unless QUIC to
    // the origin was recently broken; a resumed connection is then ready
    // before its handshake completes.
    let early_data = connector.sends_early_data() && alternative.allows_early_data();
    let admission = client
        .state
        .http3
        .admit(&endpoint, &route, timeout_budget)
        .await?;
    admission
        .connect(
            connector,
            client.inner.connect_udp_proxy.as_deref(),
            &endpoint,
            &route,
            Http3TransportTarget::new(alternative.host(), alternative.port()),
            timeout_budget,
            &mut retries,
            Http3SetupControl {
                connecting: Some(&connecting),
                attempt_limit: Some(setup_limit),
                early_data,
            },
        )
        .await
}

/// Lets an alternative that lost to the origin while connecting finish.
///
/// Like Chromium's orphaned alternative job, a finished connection stays
/// pooled for later requests and clears the alternative's failure history,
/// while a failure, including reaching the race's setup limit, marks it
/// broken. Without a Tokio runtime handle the setup is dropped instead:
/// nothing is pooled or marked, and the alternative is raced again.
fn continue_alternative<F>(
    client: Client,
    endpoint: crate::authority::Endpoint,
    route: Route,
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
                        let connection = leased.connection().clone();
                        drop(leased);
                        // A setup that resumed with early data connected
                        // before its handshake completed.
                        let handshake_failed = connection.early_data_handshake_failed().await;
                        if confirms_orphan(handshake_failed) {
                            client.confirm_alt_svc(&endpoint, &route, &alternative);
                            tracing::debug!(
                                outcome = "connected",
                                "orphaned alternative connected"
                            );
                        } else {
                            tracing::debug!(
                                outcome = "handshake_failed",
                                "orphaned alternative failed its handshake after early data"
                            );
                        }
                    }
                    Err(error) if invalidates_alternative(&error) => {
                        tracing::debug!(outcome = "failed", "orphaned alternative failed");
                        client.mark_alt_svc_broken(
                            &endpoint,
                            &route,
                            &alternative,
                            race.broken_backoff(),
                        );
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
    let client_hints = attempt_client_hints(client, request, hint_origin.as_deref());
    let mut http3_headers = attempt_headers(client, request, HttpProtocol::Http3, &attempt.headers);
    if let Some(alt_used) = alternative.alt_used() {
        http3_headers.push(RequestHeader::new("alt-used", alt_used.as_bytes()));
    }
    http3_pool::validate_request(
        http3,
        client.inner.connect_udp_proxy.as_deref(),
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
        if let Some(alt_used) = alternative.alt_used() {
            prepared_headers.push(RequestHeader::new("alt-used", alt_used.as_bytes()));
        }
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
                    client.invalidate_alternative(endpoint, route, alternative);
                }
                return Err(error);
            }
        };
        let response = dispatched.response;
        let sent_headers = dispatched.sent_headers;

        if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
            store_cookies(client, request, &response);
            client.invalidate_alternative(endpoint, route, alternative);
            return Ok(AttemptOutcome {
                response,
                protocol: HttpProtocol::Http3,
            });
        }

        let critical_retry_requested = observe_response(
            client,
            request,
            route,
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
