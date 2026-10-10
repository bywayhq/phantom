use std::{error::Error, fmt, io, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RedirectPolicy, RequestHeader};
use tokio::{net::TcpListener, sync::oneshot, task::AbortHandle, time::timeout};

use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

use super::{H2_ALPN, TestIdentity, TestResult, cookie_client_builder, spawn_cookie_redirect_peer};

const EXCHANGE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);

#[tokio::test]
async fn actual_cookie_redirect_completes_before_healthy_driver_cleanup() -> TestResult<()> {
    redirect_case(Case::Healthy).await
}

#[tokio::test]
async fn independently_joined_redirect_drivers_retain_both_injected_typed_causes() -> TestResult<()>
{
    redirect_case(Case::DirectJoin).await
}

#[tokio::test]
async fn actual_redirect_cleanup_retains_a_completed_first_driver_failure() -> TestResult<()> {
    redirect_case(Case::FirstError).await
}

#[tokio::test]
async fn actual_redirect_cleanup_retains_a_completed_second_driver_failure() -> TestResult<()> {
    redirect_case(Case::SecondError).await
}

#[tokio::test]
async fn actual_redirect_cleanup_retains_the_primary_and_both_completed_driver_identities()
-> TestResult<()> {
    redirect_case(Case::PrimaryAndBoth).await
}

#[derive(Clone, Copy)]
enum Case {
    Healthy,
    DirectJoin,
    FirstError,
    SecondError,
    PrimaryAndBoth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DriverRole {
    First,
    Second,
}

pub(super) struct DriverGate {
    pub(super) role: DriverRole,
    pub(super) trigger: oneshot::Receiver<()>,
    pub(super) completed: oneshot::Sender<DriverRole>,
    pub(super) started: oneshot::Sender<AbortHandle>,
}

pub(super) enum DriverCleanup {
    ActualAbort,
    Observe(oneshot::Sender<[TestResult<()>; 2]>),
}

pub(super) struct RedirectPeerControl {
    pub(super) first: Option<DriverGate>,
    pub(super) second: Option<DriverGate>,
    pub(super) operation: TestResult<()>,
    pub(super) cleanup: DriverCleanup,
}

struct DriverControl {
    gate: Option<DriverGate>,
    trigger: Option<oneshot::Sender<()>>,
    completed: oneshot::Receiver<DriverRole>,
    started: oneshot::Receiver<AbortHandle>,
    backup: Option<AbortHandle>,
}

async fn redirect_case(case: Case) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let first_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let first_address = first_listener.local_addr()?;
    let second_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let second_address = second_listener.local_addr()?;
    let first_acceptor = identity.acceptor(H2_ALPN)?;
    let second_acceptor = identity.acceptor(H2_ALPN)?;
    let session = cookie_client_builder(&identity)
        .cookies()
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .build()?;
    let mut first = driver_control(DriverRole::First);
    let mut second = driver_control(DriverRole::Second);
    let (cleanup, observed) = if matches!(case, Case::DirectJoin) {
        let (sender, receiver) = oneshot::channel();
        (DriverCleanup::Observe(sender), Some(receiver))
    } else {
        (DriverCleanup::ActualAbort, None)
    };
    let operation = if matches!(case, Case::PrimaryAndBoth) {
        Err(io::Error::new(io::ErrorKind::InvalidInput, RedirectOperationFailure).into())
    } else {
        Ok(())
    };
    let (done, completed) = oneshot::channel();
    let mut peer = Some(ConnectionPeer::from_task(spawn_cookie_redirect_peer(
        first_listener,
        first_acceptor,
        second_listener,
        second_acceptor,
        second_address,
        completed,
        Some(RedirectPeerControl {
            first: first.gate.take(),
            second: second.gate.take(),
            operation,
            cleanup,
        }),
    )));
    let expected_roles: &[DriverRole] = match case {
        Case::Healthy => &[],
        Case::FirstError => &[DriverRole::First],
        Case::SecondError => &[DriverRole::Second],
        Case::DirectJoin | Case::PrimaryAndBoth => &[DriverRole::First, DriverRole::Second],
    };

    let operation = async {
        let response = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{first_address}/start"),
            )?
            .headers(vec![
                RequestHeader::new("cookie", "manual=first").sensitive(),
                RequestHeader::new("authorization", "secret").sensitive(),
                RequestHeader::new("proxy-authorization", "proxy").sensitive(),
                RequestHeader::new("cookie2", "legacy").sensitive(),
            ])
            .send()
            .await?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err("actual redirect control did not receive its final204 response".into());
        }

        if !response.into_body().collect().await?.to_bytes().is_empty() {
            return Err("actual redirect control response was not empty".into());
        }

        first.backup = Some((&mut first.started).await?);
        second.backup = Some((&mut second.started).await?);
        for &role in expected_roles {
            let control = match role {
                DriverRole::First => &mut first,
                DriverRole::Second => &mut second,
            };
            control
                .trigger
                .take()
                .ok_or("driver fault trigger missing")?
                .send(())
                .map_err(|_| "actual driver ended before the post-response fault")?;
            let completed = (&mut control.completed).await?;
            if completed != role {
                return Err(
                    "actual completed driver identity differed from the independent role".into(),
                );
            }

            let backup = control
                .backup
                .as_ref()
                .ok_or("actual driver backup missing")?;
            wait_finished(backup).await?;
        }

        let cookie_count = session.cookie_jar().ok_or("cookie jar was disabled")?.len();
        done.send(())
            .map_err(|_| "redirect peer ended before final response collection")?;

        let result = peer.as_mut().ok_or("redirect peer owner missing")?.await;
        drop(peer.take());
        let peer_outcome = result?;
        let joined = match observed {
            Some(receiver) => Some(receiver.await?),
            None => None,
        };
        Ok::<_, Box<dyn Error + Send + Sync>>((cookie_count, peer_outcome, joined))
    };
    let result = match timeout(EXCHANGE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    // Stop the actual parent first, then every worker handed off before failure.
    let peer_stop = match peer {
        Some(peer) => peer.stop().await,
        None => Ok(()),
    };
    let first_stop = stop_driver(&mut first).await;
    let second_stop = stop_driver(&mut second).await;
    let cleanup = finish_with_cleanup(peer_stop, finish_with_cleanup(first_stop, second_stop));
    let (cookie_count, outcome, joined) = finish_with_cleanup(result, cleanup)?;
    drop(session);

    assert_eq!(cookie_count, 1);

    match case {
        Case::Healthy => outcome?,
        Case::DirectJoin => {
            outcome?;
            let [first, second] = joined.ok_or("independent driver result capture missing")?;
            require_driver(
                first
                    .err()
                    .ok_or("first controlled driver unexpectedly succeeded")?
                    .as_ref(),
                DriverRole::First,
            )?;
            require_driver(
                second
                    .err()
                    .ok_or("second controlled driver unexpectedly succeeded")?
                    .as_ref(),
                DriverRole::Second,
            )?;
        }
        Case::FirstError | Case::SecondError => {
            let error = outcome
                .err()
                .ok_or("actual redirect cleanup discarded a completed driver failure")?;
            let role = if matches!(case, Case::FirstError) {
                DriverRole::First
            } else {
                DriverRole::Second
            };
            require_driver(error.as_ref(), role)?;
        }
        Case::PrimaryAndBoth => {
            let error = outcome
                .err()
                .ok_or("actual redirect operation failure was lost")?;
            assert!(contains_operation(error.as_ref()));
            let causes = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("actual redirect caller discarded both completed secondary causes")?;
            assert!(contains_operation(causes.primary.as_ref()));
            assert_eq!(
                driver_roles(causes.cleanup.as_ref()),
                [DriverRole::First, DriverRole::Second]
            );
        }
    }

    Ok(())
}

fn driver_control(role: DriverRole) -> DriverControl {
    let (trigger, receive_trigger) = oneshot::channel();
    let (completed, receive_completed) = oneshot::channel();
    let (started, receive_started) = oneshot::channel();

    DriverControl {
        gate: Some(DriverGate {
            role,
            trigger: receive_trigger,
            completed,
            started,
        }),
        trigger: Some(trigger),
        completed: receive_completed,
        started: receive_started,
        backup: None,
    }
}

async fn stop_driver(control: &mut DriverControl) -> TestResult<()> {
    if control.backup.is_none() {
        match control.started.try_recv() {
            Ok(backup) => control.backup = Some(backup),
            Err(oneshot::error::TryRecvError::Closed) => return Ok(()),
            Err(oneshot::error::TryRecvError::Empty) => {
                return Err("actual redirect parent left a worker handoff unresolved".into());
            }
        }
    }

    let backup = control
        .backup
        .as_ref()
        .ok_or("actual driver backup missing after handoff")?;
    backup.abort();
    wait_finished(backup).await
}

async fn wait_finished(backup: &AbortHandle) -> TestResult<()> {
    timeout(CLEANUP, async {
        while !backup.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    Ok(())
}

fn require_driver(error: &(dyn Error + 'static), role: DriverRole) -> TestResult<()> {
    let causes = driver_roles(error);
    assert!(
        causes.contains(&role),
        "actual redirect result omitted the controlled driver identity"
    );
    Ok(())
}

fn contains_operation(error: &(dyn Error + 'static)) -> bool {
    if error.is::<RedirectOperationFailure>() {
        return true;
    }

    if let Some(error) = error.downcast_ref::<io::Error>() {
        if error
            .get_ref()
            .is_some_and(|source| source.is::<RedirectOperationFailure>())
        {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            return true;
        }

        return error
            .get_ref()
            .is_some_and(|source| contains_operation(source));
    }

    if let Some(errors) = error.downcast_ref::<FixtureFailures>() {
        return contains_operation(errors.primary.as_ref())
            || contains_operation(errors.cleanup.as_ref());
    }

    error.source().is_some_and(contains_operation)
}

fn driver_roles(error: &(dyn Error + 'static)) -> Vec<DriverRole> {
    if let Some(error) = error.downcast_ref::<DriverFailure>() {
        return vec![error.0];
    }

    if let Some(error) = error.downcast_ref::<io::Error>() {
        if let Some(failure) = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<DriverFailure>())
        {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return vec![failure.0];
        }

        return error
            .get_ref()
            .map(|source| driver_roles(source))
            .unwrap_or_default();
    }

    if let Some(errors) = error.downcast_ref::<FixtureFailures>() {
        let mut roles = driver_roles(errors.primary.as_ref());
        roles.extend(driver_roles(errors.cleanup.as_ref()));
        return roles;
    }

    error.source().map(driver_roles).unwrap_or_default()
}

#[derive(Debug)]
pub(super) struct DriverFailure(pub(super) DriverRole);

impl fmt::Display for DriverFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "controlled {:?} cookie redirect driver failure",
            self.0
        )
    }
}

impl Error for DriverFailure {}

#[derive(Debug)]
struct RedirectOperationFailure;

impl fmt::Display for RedirectOperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled cookie redirect operation failure")
    }
}

impl Error for RedirectOperationFailure {}
