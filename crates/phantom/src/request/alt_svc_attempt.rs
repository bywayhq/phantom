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
    ResolvedRequest,
    attempt::{
        AttemptLifecycle, AttemptOutcome, AttemptPath, AttemptRequest, DispatchOutcome,
        begin_accept_ch_restart, begin_status_retry, begin_unprocessed_replay, client_hint_origin,
        may_replay_unanswered, observe_response, prepare_attempt, send_once_origin, store_cookies,
    },
    field_lists::{self, AttemptFields, RacedFields},
    replay::ReplayClass,
};
use crate::{
    AltSvcRace, Client, HttpProtocol, RequestError, Route, TimeoutPhase,
    session::{
        SendBox,
        alt_svc::{AlternativeTarget, PendingLookup, invalidates_alternative},
        box_send,
        client_hints::{Dispatched, RestartHints},
        http3_pool::{Http3Fields, Http3Lease, Http3SetupControl, Http3TransportTarget},
    },
    timeout::TimeoutBudget,
};
use phantom_net::request::{RequestBody, RequestHeader};
use tracing::{Instrument, instrument::WithSubscriber};

pub(super) enum NegotiatedPlan {
    Origin,
    Alternative(AlternativeTarget),
    /// Race the alternatives, in field order, against the origin. With a
    /// pending HTTPS-record lookup there is one alternative, and its setup
    /// starts only if the lookup advertises `h3`.
    Race(Vec<AlternativeTarget>, AltSvcRace, Option<PendingLookup>),
}

/// Chooses how one negotiated request uses this route's learned
/// alternatives, or else the origin's HTTPS records.
///
/// The store is keyed by origin and route, so only an alternative learned on
/// `route` can be selected here, and it is reached over `route` as well. A
/// route that cannot carry QUIC never stores an alternative, so it always
/// plans the origin; see `Client::learn_alt_svc`.
///
/// A racing policy takes up to [`AltSvcRace::max_alternatives`] learned
/// alternatives, and the sequential policy the first one. A learned Alt-Svc
/// alternative takes precedence over HTTPS records, since Phantom races
/// either the learned alternatives or the HTTPS-record location, never
/// both. Chromium drops its
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
    let max = race.map_or(1, |race| race.max_alternatives().get());
    let mut alternatives = client.alt_svc_locations(&request.endpoint, route, max);
    if alternatives.is_empty() {
        match https_record_plan(client, request, route, race) {
            Ok(alternative) => alternatives.push(alternative),
            Err(plan) => return *plan,
        }
    }
    match race {
        None => alternatives
            .into_iter()
            .next()
            .map_or(NegotiatedPlan::Origin, NegotiatedPlan::Alternative),
        // A broken alternative is not raced until its broken period ends;
        // the store returns one only when every listed alternative is broken.
        Some(_) if alternatives.iter().any(AlternativeTarget::is_broken) => NegotiatedPlan::Origin,
        Some(race) => NegotiatedPlan::Race(alternatives, race, None),
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
                Some(race) => NegotiatedPlan::Race(vec![alternative], race, Some(lookup)),
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
        None,
        &mut false,
    )
    .await
}

/// Races QUIC setup to every alternative against delayed origin H1/H2
/// setup, then sends the request once, on the winner.
///
/// Every candidate keeps the request's origin identity and route. One H3
/// list per alternative, and the H1 and H2 lists, are built and checked
/// once, before any candidate performs I/O, unless `fields` already holds
/// them; the winner sends its lists without building them again, so an
/// `Alt-Used` field, under a profile that sends one, names the alternative
/// that won. The request body is prepared only for the winner.
///
/// With a pending HTTPS-record `lookup`, the origin does not wait at all and
/// setup of the one alternative begins only once the lookup advertises `h3`;
/// a lookup that fails or advertises nothing leaves the origin as the only
/// candidate and marks nothing broken.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_once_raced(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternatives: Vec<AlternativeTarget>,
    race: AltSvcRace,
    lookup: Option<PendingLookup>,
    fields: Option<RacedFields>,
) -> Result<AttemptOutcome, RequestError> {
    let fields = match fields {
        Some(fields) => fields,
        None => field_lists::raced(client, request, &attempt, route, &alternatives)?,
    };
    let AttemptLifecycle {
        request_span,
        timeout_budget,
        retries,
        replays,
    } = lifecycle;
    let negotiated = client
        .inner
        .connectors_for(&request.endpoint)
        .http1_or_2
        .ok_or_else(RequestError::unsupported_negotiation)?;

    let connecting: Vec<_> = alternatives
        .iter()
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();
    let awaits_lookup = lookup.is_some();
    let mut lookup = lookup;
    let setups = alternatives
        .iter()
        .zip(&connecting)
        .map(|(alternative, connecting)| {
            box_send(alternative_setup(
                client.clone(),
                request.endpoint.clone(),
                route.clone(),
                alternative.clone(),
                timeout_budget,
                retries.for_alternative_setup(),
                Arc::clone(connecting),
                lookup.take(),
                race.alternative_setup_limit(),
            ))
        })
        .collect();
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
        setups,
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
        RaceOutcome::Alternative {
            index,
            leased,
            losers,
        } => {
            tracing::debug!(
                outcome = "alternative",
                alternative = index,
                "Alt-Svc race chose the alternative"
            );
            let failed = settle_losers(
                client,
                request,
                route,
                &alternatives,
                &connecting,
                race,
                losers,
            );
            let connection = leased.connection().clone();
            // A setup that resumed with early data wins before its handshake
            // completes, so it is confirmed only once the handshake has.
            if !connection.early_data_pending() {
                // `race_setup` returns the index of one of `alternatives`.
                let winner = &alternatives[index];
                client.confirm_alt_svc(&request.endpoint, route, winner);
                mark_failed_broken(client, request, route, &alternatives, &failed, race);
                let winner_fields = fields.http3.into_vec().into_iter().nth(index);
                return send_on_alternative(
                    client,
                    request,
                    attempt,
                    route,
                    lifecycle,
                    winner,
                    Some(leased),
                    winner_fields,
                    &mut false,
                )
                .await;
            }
            // Boxed: this path holds two request futures and a retry, which
            // would otherwise enlarge every poll frame of this function, and
            // a debug build on Windows then overflows a test thread's stack.
            boxed_send_after_early_win(
                client,
                request,
                attempt,
                route,
                lifecycle,
                EarlyWin {
                    alternatives,
                    failed,
                    index,
                    race,
                    leased,
                    connection,
                    fields,
                },
            )
            .await
        }
        RaceOutcome::Origin { leased, losers } => {
            tracing::debug!(outcome = "origin", "Alt-Svc race chose the origin");
            let failed = settle_losers(
                client,
                request,
                route,
                &alternatives,
                &connecting,
                race,
                losers,
            );
            mark_failed_broken(client, request, route, &alternatives, &failed, race);
            send_once_origin(
                client,
                request,
                attempt,
                route,
                lifecycle,
                Some(leased),
                Some(fields.negotiated),
            )
            .await
        }
    }
}

/// Settles the alternatives that lost a race, given in race order with
/// `connecting` set once each held its location's connect turn.
///
/// One still connecting continues in the background, and one still waiting
/// for admission or for its location's connect turn has done no network work
/// and is cancelled rather than orphaned. Returns, in race order, which ones
/// failed in a way that breaks an alternative; the caller marks them with
/// [`mark_failed_broken`] once the winner is known to work.
fn settle_losers<F>(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    alternatives: &[AlternativeTarget],
    connecting: &[Arc<AtomicBool>],
    race: AltSvcRace,
    losers: Vec<Candidate<F>>,
) -> Vec<bool>
where
    F: Future<Output = Result<Http3Lease, RequestError>> + Send + ?Sized + 'static,
{
    let mut failed = vec![false; alternatives.len()];
    for (((loser, alternative), connecting), failed) in losers
        .into_iter()
        .zip(alternatives)
        .zip(connecting)
        .zip(&mut failed)
    {
        match loser {
            Candidate::Failed(error) => *failed = invalidates_alternative(&error),
            Candidate::Taken => {}
            Candidate::Pending(setup) if connecting.load(Ordering::Acquire) => {
                continue_alternative(
                    client.clone(),
                    request.endpoint.clone(),
                    route.clone(),
                    alternative.clone(),
                    race,
                    setup,
                );
            }
            Candidate::Pending(_) => {}
        }
    }
    failed
}

/// Marks broken each of `alternatives` that `failed` names, after the
/// origin or another alternative carried the request.
///
/// Chromium marks an alternative broken when the origin wins against it. It
/// never races two alternatives, so marking a failed alternative when
/// another alternative wins is Phantom's choice for a race of several, made
/// only once the winner's handshake has completed.
fn mark_failed_broken(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    alternatives: &[AlternativeTarget],
    failed: &[bool],
    race: AltSvcRace,
) {
    for (alternative, _) in alternatives
        .iter()
        .zip(failed)
        .filter(|(_, failed)| **failed)
    {
        client.mark_alt_svc_broken(&request.endpoint, route, alternative, race.broken_backoff());
    }
}

/// Keeps the alternatives at the positions `keep` names and, when the race
/// kept its HTTP/3 lists, the list at each of those positions, so the `n`th
/// alternative still sends the `n`th list.
/// Returns, in race order, which alternatives a race started again after the
/// winner's early-data handshake failed races: the winner whatever the store
/// says, as a race of one alternative always was, and each loser that neither
/// failed nor is now broken.
fn raced_again(winner: usize, failed: &[bool], broken: &[bool]) -> Vec<bool> {
    failed
        .iter()
        .zip(broken)
        .enumerate()
        .map(|(position, (failed, broken))| position == winner || (!failed && !broken))
        .collect()
}

fn retain_raced<A, L>(
    alternatives: Vec<A>,
    lists: Option<Box<[L]>>,
    keep: &[bool],
) -> (Vec<A>, Option<Box<[L]>>) {
    let alternatives = alternatives
        .into_iter()
        .zip(keep)
        .filter_map(|(alternative, keep)| keep.then_some(alternative))
        .collect();
    let lists = lists.map(|lists| {
        lists
            .into_vec()
            .into_iter()
            .zip(keep)
            .filter_map(|(list, keep)| keep.then_some(list))
            .collect()
    });
    (alternatives, lists)
}

/// A raced alternative that won while its handshake, resumed with early
/// data, was still running.
struct EarlyWin {
    /// Every raced alternative, in race order.
    alternatives: Vec<AlternativeTarget>,
    /// Which of `alternatives` failed as losers: marked broken once the
    /// winner's handshake completes, and left out of a race started again.
    failed: Vec<bool>,
    /// The winner's position in `alternatives`.
    index: usize,
    race: AltSvcRace,
    leased: Http3Lease,
    connection: phantom_net::http3::Http3Connection,
    fields: RacedFields,
}

/// Sends the request on a raced alternative that won while its handshake,
/// resumed with early data, was still running; then confirms the
/// alternative, marks QUIC to the origin recently broken, or races the
/// alternatives again, as `after_early_win` decides.
///
/// The race's failed losers are marked broken only when the winner's
/// handshake completes. A race started again leaves them out, and any
/// alternative the store now reports broken, such as an orphaned setup that
/// failed meanwhile; with none left the origin is used alone.
///
/// A race started again sends the race's lists again when no attempt on the
/// alternative got a response. A failed handshake starts it, but an
/// unprocessed replay may have reached another connection that answered
/// with a status the retry policy repeats; that response may have stored
/// cookies or client hints, so the race then builds the lists again.
fn boxed_send_after_early_win<'a>(
    client: &'a Client,
    request: &'a ResolvedRequest,
    attempt: AttemptRequest<'a>,
    route: &'a Route,
    lifecycle: AttemptLifecycle<'a>,
    won: EarlyWin,
) -> SendBox<'a, Result<AttemptOutcome, RequestError>> {
    // A named return type, unlike an `async fn`, lets the compiler prove
    // this future `Send` inside the recursion through `send_once_raced`;
    // see `box_send`.
    box_send(send_after_early_win(
        client, request, attempt, route, lifecycle, won,
    ))
}

/// The future that [`boxed_send_after_early_win`] boxes.
async fn send_after_early_win(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    won: EarlyWin,
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
    let EarlyWin {
        alternatives,
        failed,
        index,
        race,
        leased,
        connection,
        fields: RacedFields { http3, negotiated },
    } = won;
    // `race_setup` returns the index of one of `alternatives`.
    let winner = &alternatives[index];
    let replayable = body.can_replay();
    // Only a request that may be raced again keeps its HTTP/3 lists.
    let kept_http3 = races_again(winner.allows_early_data(), replayable).then(|| http3.clone());
    let mut responded = false;
    let winner_fields = http3.into_vec().into_iter().nth(index);
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
        winner,
        Some(leased),
        winner_fields,
        &mut responded,
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
    match after_early_win(
        handshake_failed.ok(),
        result.is_ok(),
        winner.allows_early_data(),
        // A buffered body may have passed its limit during the attempt.
        replayable && body.can_replay(),
    ) {
        EarlyWinStep::Return => return result,
        EarlyWinStep::Confirm => {
            client.confirm_alt_svc(&request.endpoint, route, winner);
            mark_failed_broken(client, request, route, &alternatives, &failed, race);
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
    let broken: Vec<bool> = alternatives
        .iter()
        .map(|alternative| client.alt_svc_is_broken(&request.endpoint, route, alternative))
        .collect();
    let keep = raced_again(index, &failed, &broken);
    let (alternatives, kept_http3) =
        retain_raced(alternatives, kept_http3.filter(|_| !responded), &keep);
    let alternatives = alternatives
        .into_iter()
        .map(AlternativeTarget::without_early_data)
        .collect();
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
        alternatives,
        race,
        None,
        kept_http3.map(|http3| RacedFields { http3, negotiated }),
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
/// must be one that can be sent again.
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
    // The origin's certificate, never the alternative's: the alternative
    // serves the origin, and its connections pool under the origin's key.
    let connector = client
        .inner
        .connectors_for(&endpoint)
        .http3
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

/// Lets an alternative that lost to another candidate while connecting
/// finish.
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
    F: Future<Output = Result<Http3Lease, RequestError>> + Send + ?Sized + 'static,
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

/// Sends a request to a learned alternative.
///
/// `leased` is a connection a race already admitted and established, and
/// `fields` the H3 list the race built and checked; the first attempt uses
/// both. Later attempts, such as status retries, stay on this alternative and
/// acquire from the pool, and send the same list until a response arrives;
/// see [`field_lists`]. `responded` is set once any attempt gets a response,
/// even one a retry then repeats.
#[allow(clippy::too_many_arguments)]
async fn send_on_alternative(
    client: &Client,
    request: &ResolvedRequest,
    attempt: AttemptRequest<'_>,
    route: &Route,
    lifecycle: AttemptLifecycle<'_>,
    alternative: &AlternativeTarget,
    mut leased: Option<Http3Lease>,
    mut fields: Option<Http3Fields>,
    responded: &mut bool,
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
    let mut restart_hints = RestartHints::default();
    let keeps_fields = may_replay_unanswered(request_retries, body);

    loop {
        let prepared = prepare_attempt(
            client,
            request,
            client_hint_origin.as_deref(),
            &restart_hints,
            body,
        )?;
        let attempt_fields = match fields.take() {
            Some(fields) => fields,
            None => field_lists::alternative_fields(
                client,
                request,
                route,
                alternative,
                &AttemptFields {
                    method: &method,
                    headers: &request_headers,
                    trailers: &request_trailers,
                    client_hints: prepared.client_hints,
                    body: prepared.body.as_ref(),
                },
            )?,
        };
        // A replay after no response sends this list again.
        let kept_fields = keeps_fields.then(|| attempt_fields.clone());
        // An alternative setup failure removes the alternative from its
        // advertisement instead of retrying.
        let mut setup_retries = request_retries.for_alternative_setup();
        let dispatched = dispatch_http3(
            client,
            request,
            route,
            transport,
            leased.take(),
            method.clone(),
            attempt_fields,
            request_trailers.clone(),
            prepared.client_hints,
            prepared.body,
            timeout_budget,
            &mut setup_retries,
        )
        .await;
        let dispatched = match dispatched {
            Ok(Dispatched::Sent(dispatched)) => {
                *responded = true;
                dispatched
            }
            // The list is built again with the connection's hints.
            Ok(Dispatched::Restart(restart)) => {
                begin_accept_ch_restart(restart, &mut restart_hints, body);
                continue;
            }
            Err(error) => {
                // An unprocessed replay stays on this alternative and keeps it.
                if begin_unprocessed_replay(&error, &method, body, request_retries, replays) {
                    fields = kept_fields;
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

        // The response may store cookies and client hints, so a later
        // attempt builds its list again.
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

/// Sends one attempt to the alternative at `transport`, on `leased` when a
/// race established it.
#[allow(clippy::too_many_arguments)]
async fn dispatch_http3(
    client: &Client,
    request: &ResolvedRequest,
    route: &Route,
    transport: Http3TransportTarget<'_>,
    leased: Option<Http3Lease>,
    method: http::Method,
    fields: Http3Fields,
    trailers: Vec<RequestHeader>,
    client_hints: Option<crate::session::client_hints::ClientHintContext<'_>>,
    body: Option<RequestBody>,
    timeout_budget: TimeoutBudget,
    retries: &mut crate::retry::ConnectionSetupRetryState,
) -> Result<Dispatched<DispatchOutcome>, RequestError> {
    let connector = client
        .inner
        .connectors_for(&request.endpoint)
        .http3
        .ok_or_else(|| RequestError::unsupported_protocol(HttpProtocol::Http3))?;
    let authority = request.endpoint.authority().as_str();
    // Boxed for the reason `dispatch_attempt` boxes its HTTP/3 send: a
    // raced request holds this path and the origin's in one future.
    let sent = match leased {
        Some(leased) => {
            box_send(client.state.http3.send_request_on_lease(
                leased,
                connector,
                method,
                authority,
                request.target.clone(),
                fields,
                trailers,
                client_hints,
                body,
                timeout_budget,
                retries,
            ))
            .await
        }
        None => {
            box_send(client.state.http3.send_request(
                connector,
                client.inner.connect_udp_proxy.as_deref(),
                &request.endpoint,
                route,
                transport,
                method,
                authority,
                request.target.clone(),
                fields,
                trailers,
                client_hints,
                body,
                timeout_budget,
                retries,
                false,
            ))
            .await
        }
    };
    sent.map(|dispatched| dispatched.map(DispatchOutcome::from))
}

/// The candidate that finished setup first, with every alternative's state
/// in race order: `losers` holds each other alternative's failure or
/// unfinished setup, and [`Candidate::Taken`] in the winner's place.
pub(super) enum RaceOutcome<A, O, F: ?Sized> {
    Alternative {
        index: usize,
        leased: A,
        losers: Vec<Candidate<F>>,
    },
    Origin {
        leased: O,
        losers: Vec<Candidate<F>>,
    },
}

/// Races `alternatives` setup against origin setup started by
/// `start_origin`.
///
/// Every alternative starts at once, and they are polled in race order. The
/// origin starts after `origin_delay`, or at once when every alternative has
/// failed, so at most one setup attempt per candidate exists. The first
/// success wins: an unfinished origin is cancelled, while the other
/// alternatives' failures and unfinished setups are returned to the caller.
/// An origin failure waits for the alternatives. When every candidate fails,
/// the origin's error is returned. Dropping the returned future cancels
/// every candidate.
pub(super) async fn race_setup<A, O, F, S, G>(
    alternatives: Vec<Pin<Box<F>>>,
    start_origin: S,
    origin_delay: Duration,
    timeout_budget: TimeoutBudget,
) -> Result<RaceOutcome<A, O, F>, RequestError>
where
    F: Future<Output = Result<A, RequestError>> + ?Sized,
    S: FnOnce() -> G,
    G: Future<Output = Result<O, RequestError>>,
{
    let mut alternatives: Vec<_> = alternatives.into_iter().map(Candidate::Pending).collect();
    let mut start_origin = Some(start_origin);
    let mut origin: Option<Pin<Box<G>>> = None;
    let mut origin_error = None;
    let mut delay = Some(Box::pin(timeout_budget.delay(origin_delay, None)));

    poll_fn(|context| {
        let mut won = None;
        for (index, candidate) in alternatives.iter_mut().enumerate() {
            if let Candidate::Pending(setup) = &mut *candidate
                && let Poll::Ready(result) = setup.as_mut().poll(context)
            {
                match result {
                    Ok(leased) => {
                        *candidate = Candidate::Taken;
                        won = Some((index, leased));
                        break;
                    }
                    Err(error) => *candidate = Candidate::Failed(error),
                }
            }
        }
        if let Some((index, leased)) = won {
            return Poll::Ready(Ok(RaceOutcome::Alternative {
                index,
                leased,
                losers: std::mem::take(&mut alternatives),
            }));
        }
        let all_failed = alternatives
            .iter()
            .all(|candidate| matches!(candidate, Candidate::Failed(_)));
        if all_failed && let Some(start) = start_origin.take() {
            // The origin no longer waits for its delay.
            delay = None;
            origin = Some(Box::pin(start()));
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
                    let losers = std::mem::take(&mut alternatives);
                    return Poll::Ready(Ok(RaceOutcome::Origin { leased, losers }));
                }
                Err(error) => origin_error = Some(error),
            }
        }
        if all_failed && origin.is_none() {
            // Every candidate failed; nothing is marked broken, because
            // Chromium reports brokenness only when the origin succeeds, and
            // Phantom marks a failed alternative only once a candidate wins.
            if let Some(error) = origin_error.take() {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Pending
    })
    .await
}

/// An alternative candidate's state; `Taken` only after the race returned.
pub(super) enum Candidate<F: ?Sized> {
    Pending(Pin<Box<F>>),
    Failed(RequestError),
    Taken,
}

#[cfg(test)]
mod tests;
