use std::{future::Future, io, task::Poll};

use phantom_net::dns::{HttpsLookupError, HttpsLookupErrorKind};
use tokio::sync::{mpsc, oneshot};

use super::super::{DestinationError, PendingLookup, TestConfiguration};
use super::{
    Arc, AtomicUsize, Discovery, Duration, ECH_A, H3, HOST, HttpsRecordAnswer,
    HttpsRecordDiscovery, HttpsRecordLookup, HttpsRecordResolver, NonZeroUsize, Ordering,
    TestResult, endpoint, rdata, record,
};

type Reply = oneshot::Sender<Result<HttpsRecordLookup, HttpsLookupError>>;

struct Controlled {
    discovery: HttpsRecordDiscovery,
    observer: Arc<TestConfiguration>,
    queries: mpsc::UnboundedReceiver<Reply>,
    calls: Arc<AtomicUsize>,
}

impl Controlled {
    fn new(capacity: usize, tracked: bool) -> TestResult<Self> {
        let observer = Arc::new(TestConfiguration::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (queries, received) = mpsc::unbounded_channel();
        let counted = Arc::clone(&calls);
        let resolver = HttpsRecordResolver::from_fn(move |_, _| {
            let (reply, result) = oneshot::channel();
            counted.fetch_add(1, Ordering::SeqCst);
            let delivered = queries.send(reply).is_ok();
            async move {
                if !delivered {
                    return Err(HttpsLookupError::other(io::Error::other(
                        "test receiver closed",
                    )));
                }
                result
                    .await
                    .map_err(|_| HttpsLookupError::other(io::Error::other("test reply closed")))?
            }
        });
        let mut discovery = HttpsRecordDiscovery::new(
            resolver,
            NonZeroUsize::new(capacity).ok_or("zero capacity")?,
        );
        discovery.configuration = tracked.then(|| Arc::clone(&observer));
        Ok(Self {
            discovery,
            observer,
            queries: received,
            calls,
        })
    }

    fn changed(&self) {
        self.observer.generation.fetch_add(1, Ordering::AcqRel);
    }

    fn terminal(&self) {
        self.observer.terminal.store(true, Ordering::Release);
    }

    fn pending(&self) -> TestResult<PendingLookup> {
        match self.discovery.discover(&endpoint(HOST)?) {
            Discovery::Pending(pending) => Ok(pending),
            _ => Err("expected a pending query".into()),
        }
    }

    async fn query(&mut self) -> TestResult<Reply> {
        tokio::time::timeout(Duration::from_secs(5), self.queries.recv())
            .await?
            .ok_or_else(|| "query source ended".into())
    }

    async fn pending_count(&self, expected: usize) -> TestResult<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.discovery.cache.lock_state().pending.len() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}

fn positive() -> TestResult<HttpsRecordLookup> {
    Ok(HttpsRecordLookup::new(
        vec![HttpsRecordAnswer::new(
            HOST,
            300,
            record(&rdata(1, &[], &[H3, ECH_A]))?,
        )],
        None,
    ))
}

fn reply(sender: Reply, value: Result<HttpsRecordLookup, HttpsLookupError>) -> TestResult<()> {
    sender
        .send(value)
        .map_err(|_| "query no longer accepts a reply".into())
}

fn configuration_failure<T>(
    result: Result<T, DestinationError>,
) -> TestResult<Arc<HttpsLookupError>> {
    match result {
        Err(DestinationError::Lookup(error))
            if error.kind() == HttpsLookupErrorKind::Configuration =>
        {
            Ok(error)
        }
        _ => Err("expected typed configuration failure".into()),
    }
}

async fn seed(
    control: &mut Controlled,
    value: Result<HttpsRecordLookup, HttpsLookupError>,
) -> TestResult<bool> {
    let pending = control.pending()?;
    reply(control.query().await?, value)?;
    Ok(tokio::time::timeout(Duration::from_secs(5), pending.advertises_h3()).await?)
}

#[tokio::test(flavor = "current_thread")]
async fn positive_result_from_old_configuration_is_queried_again() -> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    assert!(seed(&mut control, Ok(positive()?)).await?);
    assert!(matches!(
        control.discovery.discover(&endpoint(HOST)?),
        Discovery::Advertised
    ));
    control.changed();
    let pending = control.pending()?;
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    reply(
        control.query().await?,
        Ok(HttpsRecordLookup::new(Vec::new(), Some(300))),
    )?;
    assert!(!pending.advertises_h3().await);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn negative_soa_and_operational_backoff_are_configuration_scoped() -> TestResult<()> {
    for operational in [false, true] {
        let mut control = Controlled::new(1, true)?;
        let value = if operational {
            Err(HttpsLookupError::other(io::Error::other(
                "controlled operational failure",
            )))
        } else {
            Ok(HttpsRecordLookup::new(Vec::new(), Some(300)))
        };
        assert!(!seed(&mut control, value).await?);
        assert_eq!(control.discovery.cache.lock_state().ready.len(), 1);
        assert!(matches!(
            control.discovery.discover(&endpoint(HOST)?),
            Discovery::NotAdvertised
        ));
        assert_eq!(control.calls.load(Ordering::SeqCst), 1);
        control.changed();
        assert!(seed(&mut control, Ok(positive()?)).await?);
        assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn known_change_wakes_existing_waiter_without_releasing_old_work() -> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    let destination = control.discovery.destination_plan(HOST, 443);
    tokio::pin!(destination);
    std::future::poll_fn(|context| {
        assert!(matches!(destination.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    let old = control.query().await?;
    control.changed();
    assert!(matches!(
        control.discovery.discover(&endpoint("other.test")?),
        Discovery::NotAdvertised
    ));
    configuration_failure(tokio::time::timeout(Duration::from_secs(5), destination).await?)?;
    assert_eq!(control.discovery.cache.lock_state().pending.len(), 1);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    reply(old, Ok(positive()?))?;
    control.pending_count(0).await?;
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    assert!(seed(&mut control, Ok(positive()?)).await?);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn old_completion_does_not_remove_newer_ready_result() -> TestResult<()> {
    let mut control = Controlled::new(2, true)?;
    let old_waiter = control.pending()?;
    let old = control.query().await?;
    control.changed();
    let current_waiter = control.pending()?;
    let current = control.query().await?;
    assert!(!old_waiter.advertises_h3().await);
    reply(current, Ok(positive()?))?;
    assert!(current_waiter.advertises_h3().await);
    assert_eq!(control.discovery.cache.lock_state().pending.len(), 1);
    reply(old, Ok(HttpsRecordLookup::new(Vec::new(), Some(300))))?;
    control.pending_count(0).await?;
    assert!(matches!(
        control.discovery.discover(&endpoint(HOST)?),
        Discovery::Advertised
    ));
    assert_eq!(control.discovery.cache.lock_state().ready.len(), 1);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn old_completion_does_not_remove_current_pending_reservation() -> TestResult<()> {
    let mut control = Controlled::new(2, true)?;
    let old_waiter = control.pending()?;
    let old = control.query().await?;
    control.changed();
    let current_waiter = control.pending()?;
    let current = control.query().await?;
    reply(old, Ok(positive()?))?;
    control.pending_count(1).await?;
    assert!(!old_waiter.advertises_h3().await);
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    let joined = control.pending()?;
    reply(current, Ok(positive()?))?;
    assert!(current_waiter.advertises_h3().await);
    assert!(joined.advertises_h3().await);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn deferred_ready_tcp_quic_and_destination_results_recheck_configuration() -> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    assert!(seed(&mut control, Ok(positive()?)).await?);
    let origin = endpoint(HOST)?;
    let tcp = control
        .discovery
        .tcp_ech(&origin, vec![Box::from(&b"http/1.1"[..])]);
    let quic = control.discovery.quic_ech(&origin);
    let destination = control.discovery.destination_plan(HOST, 443);
    control.changed();
    assert!(tcp.await.is_none());
    assert!(quic.await.is_none());
    configuration_failure(destination.await)?;
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completed_pending_result_is_checked_when_consumed_after_change() -> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    let pending = control.pending()?;
    reply(control.query().await?, Ok(positive()?))?;
    control.pending_count(0).await?;
    control.changed();
    assert!(!pending.advertises_h3().await);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn configuration_change_before_query_start_never_invokes_callback() -> TestResult<()> {
    let control = Controlled::new(1, true)?;
    let pending = control.pending()?;
    control.changed();
    assert!(!pending.advertises_h3().await);
    control.pending_count(0).await?;
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_configuration_error_wakes_pending_and_preserves_its_cause() -> TestResult<()> {
    use std::error::Error as _;
    let mut control = Controlled::new(1, true)?;
    let destination = control.discovery.destination_plan(HOST, 443);
    tokio::pin!(destination);
    std::future::poll_fn(|context| {
        assert!(matches!(destination.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    let old = control.query().await?;
    control.terminal();
    configuration_failure(control.discovery.destination_plan("other.test", 443).await)?;
    let error =
        configuration_failure(tokio::time::timeout(Duration::from_secs(5), destination).await?)?;
    let cause = error
        .source()
        .and_then(|error| error.downcast_ref::<io::Error>())
        .ok_or("terminal I/O cause was lost")?;
    assert_eq!(cause.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(control.discovery.cache.lock_state().pending.len(), 1);
    reply(old, Ok(positive()?))?;
    control.pending_count(0).await?;
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_configuration_cannot_project_deferred_ready_metadata() -> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    assert!(seed(&mut control, Ok(positive()?)).await?);
    let origin = endpoint(HOST)?;
    let tcp = control
        .discovery
        .tcp_ech(&origin, vec![Box::from(&b"http/1.1"[..])]);
    let destination = control.discovery.destination_plan(HOST, 443);
    control.terminal();
    assert!(tcp.await.is_none());
    configuration_failure(destination.await)?;
    assert!(matches!(
        control.discovery.discover(&origin),
        Discovery::NotAdvertised
    ));
    assert!(control.discovery.quic_ech(&origin).await.is_none());
    assert!(control.discovery.cache.lock_state().ready.is_empty());
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn configuration_lookup_failures_are_not_negative_or_operational_cache_entries()
-> TestResult<()> {
    let mut control = Controlled::new(1, true)?;
    for _ in 0..2 {
        let destination = control.discovery.destination_plan(HOST, 443);
        reply(
            control.query().await?,
            Err(HttpsLookupError::configuration(io::Error::other(
                "query crossed change",
            ))),
        )?;
        configuration_failure(destination.await)?;
        assert!(control.discovery.cache.lock_state().ready.is_empty());
        assert!(control.discovery.cache.lock_state().pending.is_empty());
    }
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn untracked_explicit_callback_keeps_its_existing_cache_behavior() -> TestResult<()> {
    let mut control = Controlled::new(1, false)?;
    assert!(seed(&mut control, Ok(positive()?)).await?);
    control.changed();
    control.terminal();
    assert!(matches!(
        control.discovery.discover(&endpoint(HOST)?),
        Discovery::Advertised
    ));
    assert!(control.discovery.quic_ech(&endpoint(HOST)?).await.is_some());
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
