mod listener_owner;

use listener_owner::ListenerWitness;
pub(super) use listener_owner::OwnedListener;

use std::{
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    task::AbortHandle,
    time::{sleep, timeout},
};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{
    TestIdentity, TestResult, chromium_profile, client, get_forwarded, get_https, observe_log,
    spawn_origin_fixture, spawn_proxy_fixture,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskRole {
    ProxyListener,
    ProxyConnection,
    OriginListener,
    OriginConnection,
    RelayDownstream,
    RelayUpstream,
    ForwardDriver,
    ConnectDriver,
    #[cfg(feature = "websocket")]
    WebSocketOrigin,
}

struct ObservedTask {
    role: TaskRole,
    abort: AbortHandle,
    alive: Arc<AtomicBool>,
}

struct Lifetime(Arc<AtomicBool>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
pub(crate) struct TaskProbe(
    Arc<Mutex<Vec<ObservedTask>>>,
    Arc<Mutex<Vec<ListenerWitness>>>,
);

impl TaskProbe {
    fn observe_listener(&self, witness: ListenerWitness) {
        self.listener_registry().push(witness);
    }

    fn listener_registry(&self) -> std::sync::MutexGuard<'_, Vec<ListenerWitness>> {
        match self.1.lock() {
            Ok(registry) => registry,
            Err(_) => panic!("listener lifetime registry poisoned"),
        }
    }

    pub(crate) fn live_listeners(&self) -> Vec<SocketAddr> {
        self.listener_registry()
            .iter()
            .filter(|listener| listener.is_live())
            .map(|listener| listener.address())
            .collect()
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Vec<ObservedTask>> {
        match self.0.lock() {
            Ok(registry) => registry,
            Err(_) => panic!("task lifetime registry poisoned"),
        }
    }

    pub(crate) fn spawn<T: Send + 'static>(
        &self,
        role: TaskRole,
        future: impl Future<Output = T> + Send + 'static,
    ) -> ConnectionPeer<T> {
        let alive = Arc::new(AtomicBool::new(true));
        let lifetime = Lifetime(Arc::clone(&alive));
        let task = tokio::spawn(async move {
            let _lifetime = lifetime;
            future.await
        });
        self.registry().push(ObservedTask {
            role,
            abort: task.abort_handle(),
            alive,
        });
        ConnectionPeer::from_task(task)
    }

    pub(crate) fn live(&self) -> Vec<TaskRole> {
        self.registry()
            .iter()
            .filter(|task| task.alive.load(Ordering::SeqCst))
            .map(|task| task.role)
            .collect()
    }

    pub(crate) async fn backup(&self) -> TestResult<()> {
        for task in self.registry().iter() {
            task.abort.abort();
        }
        timeout(Duration::from_secs(5), async {
            while !self.live().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}

enum Cancellation {
    Finish,
    Drop,
    Unpolled,
}

async fn cancellation(kind: Cancellation) -> TestResult<()> {
    let proxy_identity = TestIdentity::generate()?;
    let origin_identity = TestIdentity::generate()?;
    let proxy_probe = TaskProbe::default();
    let origin_probe = TaskProbe::default();
    let fixture = spawn_proxy_fixture(&proxy_identity, None, Some(proxy_probe.clone())).await?;
    let address = fixture.address;
    assert_eq!(proxy_probe.live_listeners(), [address]);
    let origin = spawn_origin_fixture(&origin_identity, Some(origin_probe.clone())).await?;
    let client = client(
        chromium_profile(),
        &origin_identity,
        &proxy_identity,
        fixture.address,
    )?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "forward.test:8080"),
    )
    .await??;
    timeout(Duration::from_secs(5), get_https(&client, origin.address)).await??;
    let records = observe_log(&fixture.log)?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].method, http::Method::GET);
    assert_eq!(records[1].method, http::Method::CONNECT);
    assert_eq!(records[1].authority, origin.address.to_string());
    let initial = proxy_probe.live();
    for role in [
        TaskRole::ProxyListener,
        TaskRole::ProxyConnection,
        TaskRole::RelayDownstream,
        TaskRole::RelayUpstream,
    ] {
        assert!(
            initial.contains(&role),
            "actual exchange did not leave {role:?} live"
        );
    }
    assert!(origin_probe.live().contains(&TaskRole::OriginConnection));

    match kind {
        Cancellation::Finish => fixture.finish().await?,
        Cancellation::Drop => drop(fixture),
        Cancellation::Unpolled => drop(fixture.finish()),
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = proxy_probe.live();
    let remaining_listeners = proxy_probe.live_listeners();
    // The live external client and origin precede finite backup destruction.
    let proxy_stop = proxy_probe.backup().await;
    let origin_stop = origin_probe.backup().await;
    crate::support::tunnel_proxy::finish_with_cleanup(proxy_stop, origin_stop)?;
    drop(origin);
    drop(client);

    assert!(
        remaining.is_empty(),
        "actual multiplex fixture left tasks live before backup: {remaining:?}"
    );
    assert!(
        remaining_listeners.is_empty(),
        "actual multiplex listener remained owned before backup: {remaining_listeners:?}"
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_finish_stops_actual_listener_and_relay_descendants() -> TestResult<()> {
    cancellation(Cancellation::Finish).await
}

#[tokio::test]
async fn eager_drop_stops_actual_listener_and_relay_descendants() -> TestResult<()> {
    cancellation(Cancellation::Drop).await
}

#[tokio::test]
async fn dropping_an_unpolled_finish_stops_actual_listener_and_relay_descendants() -> TestResult<()>
{
    cancellation(Cancellation::Unpolled).await
}

#[tokio::test]
async fn explicit_backup_observes_actual_fixture_destruction() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fixture = spawn_proxy_fixture(&identity, None, Some(probe.clone())).await?;
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "healthy.test:8080"),
    )
    .await??;
    assert_eq!(observe_log(&fixture.log)?.len(), 1);
    assert!(probe.live().contains(&TaskRole::ProxyConnection));
    probe.backup().await?;
    assert!(probe.live().is_empty());
    drop(fixture);
    drop(client);
    Ok(())
}

#[tokio::test]
async fn a_retained_fixture_listener_and_relay_do_not_satisfy_cleanup() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy_probe = TaskProbe::default();
    let origin_probe = TaskProbe::default();
    let proxy = spawn_proxy_fixture(&identity, None, Some(proxy_probe.clone())).await?;
    let origin = spawn_origin_fixture(&identity, Some(origin_probe.clone())).await?;
    let client = client(chromium_profile(), &identity, &identity, proxy.address)?;
    timeout(Duration::from_secs(5), get_https(&client, origin.address)).await??;
    let retained_tasks = proxy_probe.live();
    let retained_listeners = proxy_probe.live_listeners();
    for role in [TaskRole::RelayDownstream, TaskRole::RelayUpstream] {
        assert!(retained_tasks.contains(&role));
    }
    assert_eq!(retained_listeners, [proxy.address]);
    assert!(!retained_tasks.is_empty());
    assert!(!retained_listeners.is_empty());

    let proxy_stop = proxy.finish().await;
    let origin_stop = origin.finish().await;
    crate::support::tunnel_proxy::finish_with_cleanup(proxy_stop, origin_stop)?;
    assert!(proxy_probe.live().is_empty());
    assert!(proxy_probe.live_listeners().is_empty());
    assert!(origin_probe.live().is_empty());
    assert!(origin_probe.live_listeners().is_empty());
    drop(client);
    Ok(())
}

pub(super) fn poison(log: &super::ProxyLog) -> TestResult<()> {
    let actual_log = log;
    let log = Arc::clone(log);
    let poisoned = std::thread::spawn(move || {
        let Ok(_lock) = log.lock() else {
            return;
        };
        panic!("intentional proxy log poison");
    })
    .join();
    assert!(poisoned.is_err());
    assert!(actual_log.is_poisoned());
    Ok(())
}

#[tokio::test]
async fn a_poisoned_log_returns_an_error_after_a_real_forwarded_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let probe = TaskProbe::default();
    let fixture = spawn_proxy_fixture(&identity, None, Some(probe.clone())).await?;
    let client = client(chromium_profile(), &identity, &identity, fixture.address)?;
    timeout(
        Duration::from_secs(5),
        get_forwarded(&client, "poison.test:8080"),
    )
    .await??;
    assert_eq!(observe_log(&fixture.log)?.len(), 1);
    poison(&fixture.log)?;
    let observed = super::observe_log(&fixture.log);
    probe.backup().await?;
    drop(fixture);
    drop(client);

    let error = observed
        .err()
        .ok_or("poisoned actual log became an empty successful observation")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("log poison lost its typed observer cause")?
            .kind(),
        io::ErrorKind::Other
    );
    Ok(())
}

async fn origin_cancellation(kind: Cancellation) -> TestResult<()> {
    let proxy_identity = TestIdentity::generate()?;
    let origin_identity = TestIdentity::generate()?;
    let proxy_probe = TaskProbe::default();
    let origin_probe = TaskProbe::default();
    let proxy = spawn_proxy_fixture(&proxy_identity, None, Some(proxy_probe.clone())).await?;
    let origin = spawn_origin_fixture(&origin_identity, Some(origin_probe.clone())).await?;
    let address = origin.address;
    assert_eq!(origin_probe.live_listeners(), [address]);
    let client = client(
        chromium_profile(),
        &origin_identity,
        &proxy_identity,
        proxy.address,
    )?;
    timeout(Duration::from_secs(5), get_https(&client, address)).await??;
    let records = observe_log(&proxy.log)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, http::Method::CONNECT);
    assert_eq!(records[0].authority, address.to_string());
    let live = origin_probe.live();
    assert!(live.contains(&TaskRole::OriginListener));
    assert!(live.contains(&TaskRole::OriginConnection));
    match kind {
        Cancellation::Finish => origin.finish().await?,
        Cancellation::Drop => drop(origin),
        Cancellation::Unpolled => drop(origin.finish()),
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = origin_probe.live();
    let remaining_listeners = origin_probe.live_listeners();
    let origin_stop = origin_probe.backup().await;
    let proxy_stop = proxy_probe.backup().await;
    crate::support::tunnel_proxy::finish_with_cleanup(origin_stop, proxy_stop)?;
    drop(proxy);
    drop(client);
    assert!(
        remaining.is_empty(),
        "actual multiplex origin fixture left tasks live before backup: {remaining:?}"
    );
    assert!(
        remaining_listeners.is_empty(),
        "actual multiplex origin listener remained owned before backup: {remaining_listeners:?}"
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_origin_finish_stops_its_actual_listener_and_connection() -> TestResult<()> {
    origin_cancellation(Cancellation::Finish).await
}
#[tokio::test]
async fn eager_origin_drop_stops_its_actual_listener_and_connection() -> TestResult<()> {
    origin_cancellation(Cancellation::Drop).await
}
#[tokio::test]
async fn an_unpolled_origin_finish_stops_its_actual_listener_and_connection() -> TestResult<()> {
    origin_cancellation(Cancellation::Unpolled).await
}
