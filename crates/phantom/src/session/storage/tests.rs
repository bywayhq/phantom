use std::{
    collections::HashMap,
    io,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use tokio::sync::Notify;

use super::*;
use crate::{AltSvcSnapshot, AltSvcSnapshotEntry, SessionSnapshotError, SessionSnapshotErrorKind};

type TestResult = Result<(), Box<dyn StdError + Send + Sync>>;
const KEY: &[u8; 32] = &[71; 32];

#[derive(Default)]
struct MemoryStore {
    values: Mutex<HashMap<String, Vec<u8>>>,
    calls: AtomicUsize,
}

impl SessionStore for MemoryStore {
    fn load<'a>(&'a self, name: &'a str) -> SessionStoreFuture<'a, Option<SessionSnapshot>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let values = self.values.lock().map_err(|_| io::Error::other("lock"))?;
            values
                .get(name)
                .map(|bytes| SessionSnapshot::from_bytes(bytes).map_err(Into::into))
                .transpose()
        })
    }

    fn save<'a>(
        &'a self,
        name: &'a str,
        snapshot: &'a SessionSnapshot,
    ) -> SessionStoreFuture<'a, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if snapshot.as_bytes().len() > 32 * 1024 * 1024 {
                return Err(io::Error::other("object exceeds store bound").into());
            }
            self.values
                .lock()
                .map_err(|_| io::Error::other("lock"))?
                .insert(name.to_owned(), snapshot.as_bytes().to_vec());
            Ok(())
        })
    }
}

fn client() -> Result<Client, crate::BuildError> {
    Client::builder(crate::profile::browser::chrome::v154_windows())
        .alt_svc(NonZeroUsize::MIN)
        .build()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn seed(client: &Client, origin: &str) -> TestResult {
    client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        origin,
        "alt.example",
        443,
        SystemTime::now() + Duration::from_secs(600),
    )]))?;
    Ok(())
}

#[tokio::test]
async fn explicit_storage_round_trip_keeps_source_receiver_and_restored_state_independent()
-> TestResult {
    let source = client()?;
    seed(&source, "https://source.example")?;
    let receiver = client()?;
    seed(&receiver, "https://receiver.example")?;
    let store = MemoryStore::default();
    source
        .save_session(&store, "job/session", KEY, deadline())
        .await?;
    {
        let saved = store.values.lock().map_err(|_| "lock")?;
        let encrypted = saved.get("job/session").ok_or("missing bytes")?;
        assert!(encrypted.starts_with(b"PHSES001"));
        assert!(
            !encrypted
                .windows(b"source.example".len())
                .any(|part| part == b"source.example")
        );
        assert!(!encrypted.windows(KEY.len()).any(|part| part == KEY));
    }
    let restored = receiver
        .load_session(&store, "job/session", KEY, deadline(), &[])
        .await?
        .ok_or("missing checkpoint")?;
    assert!(!Arc::ptr_eq(&receiver.state, &restored.state));
    assert_eq!(
        restored.export_alt_svc().ok_or("disabled")?.entries()[0].origin(),
        "https://source.example"
    );
    restored.clear_alt_svc();
    assert_eq!(source.export_alt_svc().ok_or("disabled")?.len(), 1);
    assert_eq!(
        receiver.export_alt_svc().ok_or("disabled")?.entries()[0].origin(),
        "https://receiver.example"
    );
    assert!(
        receiver
            .load_session(&store, "missing", KEY, deadline(), &[])
            .await?
            .is_none()
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn corrupt_and_wrong_key_loads_preserve_typed_snapshot_errors_and_receiver() -> TestResult {
    let receiver = client()?;
    seed(&receiver, "https://receiver.example")?;
    let store = MemoryStore::default();
    receiver
        .save_session(&store, "valid", KEY, deadline())
        .await?;
    store
        .values
        .lock()
        .map_err(|_| "lock")?
        .insert("bad".into(), vec![0; 64]);
    for (name, key, kind) in [
        ("valid", &[72; 32], SessionSnapshotErrorKind::Authentication),
        ("bad", KEY, SessionSnapshotErrorKind::InvalidSnapshot),
    ] {
        let error = receiver
            .load_session(&store, name, key, deadline(), &[])
            .await
            .err()
            .ok_or("expected session storage rejection")?;
        assert_eq!(error.kind(), SessionStorageErrorKind::Snapshot);
        assert_eq!(
            error
                .source()
                .and_then(|error| error.downcast_ref::<SessionSnapshotError>())
                .map(SessionSnapshotError::kind),
            Some(kind)
        );
    }
    assert_eq!(receiver.export_alt_svc().ok_or("disabled")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn invalid_names_and_expired_deadlines_never_call_the_store() -> TestResult {
    let client = client()?;
    let store = MemoryStore::default();
    for name in [
        "".to_owned(),
        "control\nname".into(),
        "nul\0name".into(),
        "é".repeat(129),
    ] {
        assert_eq!(
            client
                .save_session(&store, &name, KEY, deadline())
                .await
                .err()
                .ok_or("expected session storage rejection")?
                .kind(),
            SessionStorageErrorKind::InvalidName
        );
        assert_eq!(
            client
                .load_session(&store, &name, KEY, deadline(), &[])
                .await
                .err()
                .ok_or("expected session storage rejection")?
                .kind(),
            SessionStorageErrorKind::InvalidName
        );
    }
    let expired = Instant::now();
    assert_eq!(
        client
            .save_session(&store, "valid", KEY, expired)
            .await
            .err()
            .ok_or("expected session storage rejection")?
            .kind(),
        SessionStorageErrorKind::Deadline
    );
    assert_eq!(
        client
            .load_session(&store, "valid", KEY, expired, &[])
            .await
            .err()
            .ok_or("expected session storage rejection")?
            .kind(),
        SessionStorageErrorKind::Deadline
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    client
        .save_session(&store, &"é".repeat(128), KEY, deadline())
        .await?;
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

struct FailedStore;

#[tokio::test]
async fn unsupported_checkpoint_configuration_fails_before_saving() -> TestResult {
    let client = Client::builder(crate::profile::browser::chrome::v154_windows())
        .route(Route::http_proxy(
            crate::HttpProxy::new("http://proxy.example")?.with_basic_auth("user", "secret")?,
        ))
        .build()?;
    let store = MemoryStore::default();
    let error = client
        .save_session(&store, "valid", KEY, deadline())
        .await
        .err()
        .ok_or("expected session storage rejection")?;
    assert_eq!(error.kind(), SessionStorageErrorKind::Snapshot);
    assert_eq!(
        error
            .source()
            .and_then(|error| error.downcast_ref::<SessionSnapshotError>())
            .map(SessionSnapshotError::kind),
        Some(SessionSnapshotErrorKind::Unsupported)
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

impl SessionStore for FailedStore {
    fn load<'a>(&'a self, _: &'a str) -> SessionStoreFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async { Err(io::Error::other("secret-backend-detail").into()) })
    }

    fn save<'a>(&'a self, _: &'a str, _: &'a SessionSnapshot) -> SessionStoreFuture<'a, ()> {
        Box::pin(async { Err(io::Error::other("secret-backend-detail").into()) })
    }
}

#[tokio::test]
async fn backend_errors_do_not_fall_back_and_error_formatting_omits_backend_secrets() -> TestResult
{
    let client = client()?;
    let saved = client
        .save_session(&FailedStore, "private-name", KEY, deadline())
        .await
        .err()
        .ok_or("expected session storage rejection")?;
    let loaded = client
        .load_session(&FailedStore, "private-name", KEY, deadline(), &[])
        .await
        .err()
        .ok_or("expected session storage rejection")?;
    for error in [saved, loaded] {
        assert_eq!(error.kind(), SessionStorageErrorKind::Backend);
        assert_eq!(
            error
                .source()
                .and_then(|error| error.downcast_ref::<io::Error>())
                .map(ToString::to_string),
            Some("secret-backend-detail".into())
        );
        let formatted = format!("{error:?} {error}");
        for secret in ["secret-backend-detail", "private-name", &format!("{KEY:?}")] {
            assert!(!formatted.contains(secret));
        }
    }
    Ok(())
}

#[derive(Default)]
struct PendingStore {
    entered: Notify,
    dropped: AtomicUsize,
    ordinary: MemoryStore,
}

struct Dropped<'a>(&'a AtomicUsize);

impl Drop for Dropped<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl PendingStore {
    fn pending<T: Send>(&self) -> SessionStoreFuture<'_, T> {
        Box::pin(async move {
            let _dropped = Dropped(&self.dropped);
            self.entered.notify_one();
            std::future::pending().await
        })
    }
}

impl SessionStore for PendingStore {
    fn load<'a>(&'a self, name: &'a str) -> SessionStoreFuture<'a, Option<SessionSnapshot>> {
        if name == "pending" {
            self.pending()
        } else {
            self.ordinary.load(name)
        }
    }

    fn save<'a>(
        &'a self,
        name: &'a str,
        snapshot: &'a SessionSnapshot,
    ) -> SessionStoreFuture<'a, ()> {
        if name == "pending" {
            self.pending()
        } else {
            self.ordinary.save(name, snapshot)
        }
    }
}

#[tokio::test]
async fn deadline_drops_a_pending_backend_operation() -> TestResult {
    let client = client()?;
    let store = PendingStore::default();
    let error = client
        .load_session(
            &store,
            "pending",
            KEY,
            Instant::now() + Duration::from_millis(100),
            &[],
        )
        .await
        .err()
        .ok_or("expected session storage rejection")?;
    assert_eq!(error.kind(), SessionStorageErrorKind::Deadline);
    assert_eq!(store.dropped.load(Ordering::SeqCst), 1);
    Ok(())
}

struct LateStore;

impl SessionStore for LateStore {
    fn load<'a>(&'a self, _: &'a str) -> SessionStoreFuture<'a, Option<SessionSnapshot>> {
        Box::pin(async {
            // Deliberately violate the store's yielding contract: timeout_at
            // can observe a ready result before it polls its elapsed timer.
            std::thread::sleep(Duration::from_millis(150));
            Ok(None)
        })
    }

    fn save<'a>(&'a self, _: &'a str, _: &'a SessionSnapshot) -> SessionStoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn a_backend_that_returns_after_blocking_past_the_deadline_cannot_report_success()
-> TestResult {
    let client = client()?;
    let error = client
        .load_session(
            &LateStore,
            "valid",
            KEY,
            Instant::now() + Duration::from_millis(100),
            &[],
        )
        .await
        .err()
        .ok_or("expected session storage rejection")?;
    assert_eq!(error.kind(), SessionStorageErrorKind::Deadline);
    Ok(())
}

#[tokio::test]
async fn dropping_save_or_load_drops_only_its_backend_future() -> TestResult {
    let client = client()?;
    let store = PendingStore::default();
    let mut saving = Box::pin(client.save_session(&store, "pending", KEY, deadline()));
    tokio::select! {
        result = &mut saving => panic!("pending save completed: {result:?}"),
        () = store.entered.notified() => {}
    }
    client.save_session(&store, "kept", KEY, deadline()).await?;
    drop(saving);
    assert_eq!(store.dropped.load(Ordering::SeqCst), 1);
    let mut loading = Box::pin(client.load_session(&store, "pending", KEY, deadline(), &[]));
    tokio::select! {
        result = &mut loading => panic!("pending load completed: {result:?}"),
        () = store.entered.notified() => {}
    }
    assert!(
        client
            .load_session(&store, "kept", KEY, deadline(), &[])
            .await?
            .is_some()
    );
    drop(loading);
    assert_eq!(store.dropped.load(Ordering::SeqCst), 2);
    assert!(
        client
            .load_session(&store, "kept", KEY, deadline(), &[])
            .await?
            .is_some()
    );
    Ok(())
}
