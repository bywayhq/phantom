use std::{
    num::NonZeroUsize,
    sync::mpsc,
    task::{Context, Waker},
    time::Duration,
};

use phantom_profile::browser::firefox;
use tokio::runtime::Builder;

use super::*;
use crate::session::alt_svc::validation::candidate_for_test;
use crate::session::alt_svc::{AltSvcStore, StoreKey};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn setup_capacity_is_shared_across_runtimes_without_a_waiting_queue() -> TestResult {
    let first = Builder::new_current_thread().build()?;
    let second = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::new(34).ok_or("zero capacity")?);
    let mut held = Vec::new();
    for index in 0..32 {
        let endpoint = endpoint(index)?;
        let publication = publication(&store, &endpoint)?;
        let runtime = if index % 2 == 0 {
            first.handle()
        } else {
            second.handle()
        };
        held.push(
            owner
                .control
                .reserve(&publication, runtime.id())
                .ok_or("setup rejected below capacity")?,
        );
    }
    let endpoint = endpoint(32)?;
    let publication = publication(&store, &endpoint)?;

    assert!(
        owner
            .control
            .reserve(&publication, first.handle().id())
            .is_none()
    );
    assert_eq!(owner.control.lock().pending.len(), 32);
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));

    drop(held.pop());
    let next = self::endpoint(33)?;
    let publication = self::publication(&store, &next)?;
    assert!(
        owner
            .control
            .reserve(&publication, first.handle().id())
            .is_some()
    );
    Ok(())
}

#[test]
fn duplicate_setup_does_not_abandon_the_live_mapping() -> TestResult {
    let runtime = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    let publication = publication(&store, &endpoint)?;
    let expires = expiry(&store, &endpoint)?;
    let guard = owner
        .control
        .reserve(&publication, runtime.handle().id())
        .ok_or("setup rejected")?;

    assert!(
        owner
            .control
            .reserve(&publication, runtime.handle().id())
            .is_none()
    );
    assert_eq!(expiry(&store, &endpoint)?, expires);
    assert_eq!(owner.control.lock().pending.len(), 1);

    drop(guard);
    assert!(owner.control.lock().pending.is_empty());
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    Ok(())
}

#[test]
fn cancelling_one_runtime_does_not_abandon_another_runtime_setup() -> TestResult {
    let first = Builder::new_current_thread().build()?;
    let second = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    let publication = publication(&store, &endpoint)?;
    let expires = expiry(&store, &endpoint)?;
    let first = owner
        .control
        .reserve(&publication, first.handle().id())
        .ok_or("first setup rejected")?;
    let second = owner
        .control
        .reserve(&publication, second.handle().id())
        .ok_or("second runtime rejected")?;

    drop(first);
    assert_eq!(expiry(&store, &endpoint)?, expires);
    assert_eq!(owner.control.lock().pending.len(), 1);

    second.complete();
    drop(second);
    assert!(owner.control.lock().pending.is_empty());
    assert_eq!(expiry(&store, &endpoint)?, expires);
    Ok(())
}

#[test]
fn completed_failure_keeps_expiry_while_unfinished_work_gets_a_retry_window() -> TestResult {
    let runtime = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::new(2).ok_or("zero capacity")?);
    let failed = endpoint(0)?;
    let unfinished = endpoint(1)?;
    let failed_publication = publication(&store, &failed)?;
    let unfinished_publication = publication(&store, &unfinished)?;
    let failed_expiry = expiry(&store, &failed)?;
    let completed = owner
        .control
        .reserve(&failed_publication, runtime.handle().id())
        .ok_or("setup rejected")?;
    let cancelled = owner
        .control
        .reserve(&unfinished_publication, runtime.handle().id())
        .ok_or("setup rejected")?;

    completed.complete();
    drop(completed);
    drop(cancelled);

    assert_eq!(expiry(&store, &failed)?, failed_expiry);
    assert!(expiry(&store, &unfinished)? <= Instant::now() + Duration::from_secs(2));
    assert!(owner.control.lock().pending.is_empty());
    Ok(())
}

#[test]
fn refresh_cancellation_reopens_enqueue_without_reviving_old_epochs() -> TestResult {
    let runtime = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::new(2).ok_or("zero capacity")?);
    let endpoint = endpoint(0)?;
    let publication = publication(&store, &endpoint)?;
    let old = owner
        .control
        .reserve(&publication, runtime.handle().id())
        .ok_or("setup rejected")?;
    assert!(old.epoch.lock_current().is_some());

    let first = owner.begin_refresh();
    let second = owner.begin_refresh();
    assert!(old.epoch.lock_current().is_none());
    assert!(
        owner
            .control
            .reserve(&publication, runtime.handle().id())
            .is_none()
    );
    drop(first);
    assert!(
        owner
            .control
            .reserve(&publication, runtime.handle().id())
            .is_none()
    );
    drop(second);
    drop(old);

    let next = self::endpoint(1)?;
    let publication = self::publication(&store, &next)?;
    let next = owner
        .control
        .reserve(&publication, runtime.handle().id())
        .ok_or("cancelled refresh left enqueue blocked")?;
    assert!(next.epoch.lock_current().is_some());
    Ok(())
}

#[test]
fn closing_owner_permanently_rejects_publication_and_new_setup() -> TestResult {
    let runtime = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    let publication = publication(&store, &endpoint)?;
    let guard = owner
        .control
        .reserve(&publication, runtime.handle().id())
        .ok_or("setup rejected")?;

    owner.close();
    assert!(guard.epoch.lock_current().is_none());
    let refresh = owner.begin_refresh();
    drop(refresh);
    assert!(
        owner
            .control
            .reserve(&publication, runtime.handle().id())
            .is_none()
    );
    drop(guard);
    assert!(
        owner
            .control
            .reserve(&publication, runtime.handle().id())
            .is_none()
    );
    Ok(())
}

#[test]
fn abandoning_old_setup_preserves_a_replacement_advertisement() -> TestResult {
    let runtime = Builder::new_current_thread().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    let original = publication(&store, &endpoint)?;
    let guard = owner
        .control
        .reserve(&original, runtime.handle().id())
        .ok_or("setup rejected")?;
    store.learn_fields_at(
        &endpoint,
        &Route::Direct,
        [("alt-svc", b"h3=\":9443\"; ma=120".as_slice())],
        Instant::now(),
    );
    let expires = expiry(&store, &endpoint)?;

    drop(guard);

    assert_eq!(expiry(&store, &endpoint)?, expires);
    assert_eq!(
        store.get_up_to(&endpoint, &Route::Direct, 1)[0].port(),
        9443
    );
    Ok(())
}

#[test]
fn shutdown_releases_a_task_cancelled_before_its_first_poll() -> TestResult {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    {
        let _entered = runtime.enter();
        assert!(owner.start(job(&store, &endpoint)?));
    }
    assert_eq!(owner.control.lock().pending.len(), 1);

    runtime.block_on(owner.shutdown());

    assert!(owner.control.lock().pending.is_empty());
    assert!(owner.lock_tasks().is_empty());
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    Ok(())
}

#[test]
fn runtime_teardown_releases_unpolled_job_without_waiting_for_owner_drop() -> TestResult {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    {
        let _entered = runtime.enter();
        assert!(owner.start(job(&store, &endpoint)?));
    }
    assert_eq!(owner.control.lock().pending.len(), 1);

    drop(runtime);

    assert!(owner.control.lock().pending.is_empty());
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    Ok(())
}

#[test]
fn dropping_owner_cancels_job_and_does_not_keep_a_registry_cycle() -> TestResult {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let control = Arc::downgrade(&owner.control);
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    {
        let _entered = runtime.enter();
        assert!(owner.start(job(&store, &endpoint)?));
    }

    drop(owner);
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), async {
            while control.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
    })?;

    assert!(control.upgrade().is_none());
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    Ok(())
}

#[test]
fn refresh_joins_cancelled_tasks_and_blocks_enqueue_until_guard_drop() -> TestResult {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let first_store = AltSvcStore::new(NonZeroUsize::MIN);
    let rejected_store = AltSvcStore::new(NonZeroUsize::MIN);
    let later_store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;
    let entered = runtime.enter();
    assert!(owner.start(job(&first_store, &endpoint)?));

    let mut refresh = owner.begin_refresh();
    assert!(!owner.start(job(&rejected_store, &endpoint)?));
    drop(entered);
    runtime.block_on(refresh.observe_cancelled());
    assert!(owner.control.lock().pending.is_empty());
    assert!(refresh.tasks.iter().all(JoinSet::is_empty));
    assert!(expiry(&first_store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    assert!(expiry(&rejected_store, &endpoint)? <= Instant::now() + Duration::from_secs(2));

    drop(refresh);
    {
        let _entered = runtime.enter();
        assert!(owner.start(job(&later_store, &endpoint)?));
    }
    runtime.block_on(owner.shutdown());
    Ok(())
}

#[test]
fn missing_runtime_rejects_and_releases_candidate_without_spawning() -> TestResult {
    let owner = AltSvcValidationJobs::default();
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    let endpoint = endpoint(0)?;

    assert!(!owner.start(job(&store, &endpoint)?));

    assert!(owner.control.lock().pending.is_empty());
    assert!(owner.lock_tasks().is_empty());
    assert!(expiry(&store, &endpoint)? <= Instant::now() + Duration::from_secs(2));
    Ok(())
}

#[test]
fn dropped_refresh_retains_unobserved_task_failure_for_the_owner() -> TestResult {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let (panicking, observed) = tokio::sync::oneshot::channel();
    owner.lock_tasks().active.spawn_on(
        async move {
            // The receiving test may already have failed during cleanup.
            let _ = panicking.send(());
            panic!("validation failure control");
        },
        runtime.handle(),
    );
    runtime.block_on(observed)?;

    let refresh = owner.begin_refresh();
    drop(refresh);

    let errors = owner.lock_tasks().reap();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].is_panic());
    assert!(owner.lock_tasks().is_empty());
    drop(owner.begin_refresh());
    assert!(owner.lock_tasks().retired.is_empty());
    Ok(())
}

#[test]
fn concurrent_shutdowns_wait_for_the_same_task_destruction() -> TestResult {
    let worker = Builder::new_multi_thread().worker_threads(1).build()?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let mut gate = TaskDropGate::spawn(&owner, worker.handle());

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut context = Context::from_waker(Waker::noop());
            let mut first = Box::pin(owner.shutdown());
            let first_waited = first.as_mut().poll(&mut context).is_pending();
            (&mut gate.entered).await?;
            let mut second = Box::pin(owner.shutdown());
            let second_waited = second.as_mut().poll(&mut context).is_pending();

            gate.release();
            tokio::join!(first, second);

            assert!(first_waited);
            assert!(second_waited, "second shutdown bypassed unfinished cleanup");
            gate.assert_destroyed();
            assert!(owner.lock_tasks().is_empty());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await?
    })
}

#[test]
fn shutdown_waits_for_task_destruction_and_the_outer_refresh_guard() -> TestResult {
    let worker = Builder::new_multi_thread().worker_threads(1).build()?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let mut gate = TaskDropGate::spawn(&owner, worker.handle());
    let mut refresh = owner.begin_refresh();

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut context = Context::from_waker(Waker::noop());
            let mut observing = Box::pin(refresh.observe_cancelled());
            let refresh_waited = observing.as_mut().poll(&mut context).is_pending();
            (&mut gate.entered).await?;
            let mut shutdown = Box::pin(owner.shutdown());
            let shutdown_waited = shutdown.as_mut().poll(&mut context).is_pending();

            gate.release();
            observing.as_mut().await;
            drop(observing);
            let outer_guard_waited = shutdown.as_mut().poll(&mut context).is_pending();
            drop(refresh);
            shutdown.await;

            assert!(refresh_waited);
            assert!(shutdown_waited, "shutdown bypassed refresh task cleanup");
            assert!(
                outer_guard_waited,
                "shutdown bypassed the pool refresh guard"
            );
            gate.assert_destroyed();
            assert!(owner.lock_tasks().is_empty());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await?
    })
}

#[test]
fn cancelled_shutdown_restores_tasks_before_releasing_the_cleanup_turn() -> TestResult {
    let worker = Builder::new_multi_thread().worker_threads(1).build()?;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let owner = AltSvcValidationJobs::default();
    let mut gate = TaskDropGate::spawn(&owner, worker.handle());

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut context = Context::from_waker(Waker::noop());
            let mut first = Box::pin(owner.shutdown());
            let first_waited = first.as_mut().poll(&mut context).is_pending();
            (&mut gate.entered).await?;
            drop(first);
            let mut second = Box::pin(owner.shutdown());
            let second_waited = second.as_mut().poll(&mut context).is_pending();

            gate.release();
            second.await;

            assert!(first_waited);
            assert!(second_waited, "cancelled shutdown lost its unfinished task");
            gate.assert_destroyed();
            assert!(owner.lock_tasks().is_empty());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await?
    })
}

struct TaskDropGate {
    entered: tokio::sync::oneshot::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
    destroyed: Arc<AtomicBool>,
    expired: Arc<AtomicBool>,
}

impl TaskDropGate {
    fn spawn(owner: &AltSvcValidationJobs, runtime: &Handle) -> Self {
        let (entered, receiver) = tokio::sync::oneshot::channel();
        let (release, wait) = mpsc::channel();
        let destroyed = Arc::new(AtomicBool::new(false));
        let expired = Arc::new(AtomicBool::new(false));
        let held = HeldTaskDrop {
            entered: Some(entered),
            release: wait,
            destroyed: Arc::clone(&destroyed),
            expired: Arc::clone(&expired),
        };
        owner.lock_tasks().active.spawn_on(
            async move {
                let _held = held;
                std::future::pending::<()>().await;
            },
            runtime,
        );
        Self {
            entered: receiver,
            release: Some(release),
            destroyed,
            expired,
        }
    }

    fn release(&mut self) {
        // Disconnecting also releases a destructor during an early test error.
        drop(self.release.take());
    }

    fn assert_destroyed(&self) {
        assert!(self.destroyed.load(Ordering::SeqCst));
        assert!(!self.expired.load(Ordering::SeqCst));
    }
}

struct HeldTaskDrop {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    release: mpsc::Receiver<()>,
    destroyed: Arc<AtomicBool>,
    expired: Arc<AtomicBool>,
}

impl Drop for HeldTaskDrop {
    fn drop(&mut self) {
        if let Some(entered) = self.entered.take() {
            // A cancelled test may have dropped its observation receiver.
            let _ = entered.send(());
        }
        self.expired.store(
            matches!(
                self.release.recv_timeout(Duration::from_secs(2)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            Ordering::SeqCst,
        );
        self.destroyed.store(true, Ordering::SeqCst);
    }
}

fn endpoint(index: usize) -> Result<Endpoint, Box<dyn std::error::Error>> {
    Ok(Endpoint::new(
        format!("origin-{index}.test:443").parse()?,
        443,
    )?)
}

fn job(
    store: &AltSvcStore,
    endpoint: &Endpoint,
) -> Result<AltSvcValidationJob, Box<dyn std::error::Error>> {
    let one = NonZeroUsize::MIN;
    Ok(AltSvcValidationJob {
        pool: Arc::new(Http3Pool::new(one, one, one)),
        connector: Arc::new(Http3Connector::new(
            &firefox::v157_quic_tls(),
            &firefox::v157_quic(),
            &firefox::v157_http3(),
            &firefox::v157_http3_request(),
        )?),
        connect_udp_proxy: None,
        endpoint: endpoint.clone(),
        route: Route::Direct,
        candidate: candidate_for_test(store, endpoint, b"h3=\":8443\"; ma=60")
            .ok_or("missing candidate")?,
        timeouts: RequestTimeouts::new(),
    })
}

fn publication(
    store: &AltSvcStore,
    endpoint: &Endpoint,
) -> Result<AltSvcValidationPublication, Box<dyn std::error::Error>> {
    store.learn_fields_at(
        endpoint,
        &Route::Direct,
        [("alt-svc", b"h3=\":8443\"; ma=60".as_slice())],
        Instant::now(),
    );
    store
        .get_up_to(endpoint, &Route::Direct, 1)
        .first()
        .and_then(|selection| selection.publication.clone())
        .ok_or_else(|| "missing publication".into())
}

fn expiry(store: &AltSvcStore, endpoint: &Endpoint) -> Result<Instant, Box<dyn std::error::Error>> {
    store
        .lock_entries()
        .iter()
        .find(|entry| entry.key == StoreKey::new(endpoint, &Route::Direct))
        .and_then(|entry| entry.alternatives.first())
        .map(|alternative| alternative.expires_at)
        .ok_or_else(|| "missing alternative expiry".into())
}
