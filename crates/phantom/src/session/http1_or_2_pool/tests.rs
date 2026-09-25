use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use phantom_net::{http1::Http1Connection, http2::Http2Connection};
use phantom_profile::chromium;
use tokio::{
    io::{DuplexStream, duplex},
    time::timeout,
};

use super::{
    Acquired, BeforeAdmission, Checkout, EntryConnections, Http1Or2Pool, Http2Keys, MAX_HTTP2_KEYS,
    PoolKey, PooledConnection, Reservation,
};
use crate::{HttpProtocol, HttpProxy, Route, Socks5Proxy, authority::Endpoint};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bound(value: usize) -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
    NonZeroUsize::new(value).ok_or_else(|| "zero bound".into())
}

/// Opens an HTTP/1.1 connection over an in-memory stream.
///
/// The returned peer half must outlive the connection, or its driver sees the
/// close and the connection stops being reusable.
async fn http1() -> Result<(PooledConnection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, server) = duplex(1024);
    Ok((
        PooledConnection::Http1(Http1Connection::connect(client).await?),
        server,
    ))
}

/// Opens an HTTP/2 connection over an in-memory stream; see [`http1`].
async fn http2() -> Result<(PooledConnection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, server) = duplex(64 * 1024);
    let connection = Http2Connection::connect(client, &chromium::v154_http2()).await?;
    Ok((PooledConnection::Http2(connection), server))
}

fn key(host: &str) -> Result<PoolKey, Box<dyn std::error::Error>> {
    let endpoint = Endpoint::new(format!("{host}:443").parse()?, 443)?;
    Ok(PoolKey::new(&endpoint, &Route::Direct))
}

/// The connections of a key that has never selected H2, with a memory of
/// its own.
fn connections(max: NonZeroUsize) -> Result<Arc<EntryConnections>, Box<dyn std::error::Error>> {
    Ok(Arc::new(EntryConnections::new(
        max,
        Arc::new(Http2Keys::default()),
        key("origin.test")?,
    )))
}

fn reserve(connections: &Arc<EntryConnections>) -> Result<Reservation, Box<dyn std::error::Error>> {
    match connections.checkout(false) {
        Checkout::Reserved(reservation) => Ok(reservation),
        Checkout::Found(_) => Err("a pool key without a free connection found one".into()),
    }
}

#[tokio::test]
async fn pre_selection_admission_survives_lru_eviction() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http1Or2Pool::new(one, one, one, one, one, one);
    let first = Endpoint::new("first.test:443".parse()?, 443)?;
    let second = Endpoint::new("second.test:443".parse()?, 443)?;

    let first_entry = pool.entry(PoolKey::new(&first, &Route::Direct)).await;
    let permit = first_entry.admit_before_selection().await?;
    pool.entry(PoolKey::new(&second, &Route::Direct)).await;
    drop(first_entry);
    let replacement = pool.entry(PoolKey::new(&first, &Route::Direct)).await;

    // A held permit keeps the original instance, so the recreated entry
    // counts against the same semaphore instead of a fresh one.
    assert!(Arc::ptr_eq(
        permit.admission(),
        &replacement.selection_admission
    ));
    assert_eq!(replacement.selection_admission.available_active(), 0);
    drop(permit);
    assert_eq!(replacement.selection_admission.available_active(), 1);
    Ok(())
}

#[tokio::test]
async fn pool_key_admits_as_many_connection_slots_as_the_http1_bound() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http1Or2Pool::new(one, bound(6)?, one, one, one, one);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let entry = pool.entry(PoolKey::new(&origin, &Route::Direct)).await;

    assert_eq!(entry.http1_admission.available_active(), 6);
    assert_eq!(entry.connections.max_http1.get(), 6);
    // Before ALPN chooses, every request that may open a connection passes.
    assert_eq!(entry.selection_admission.available_active(), 6);
    Ok(())
}

#[tokio::test]
async fn unknown_protocol_reserves_parallel_setups_up_to_the_bound() -> TestResult {
    let connections = connections(bound(2)?)?;
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::Admit(None)
    ));
    let first = reserve(&connections)?;
    // The first setup has not chosen a protocol, so the next request does not
    // wait for it.
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::Admit(None)
    ));
    let second = reserve(&connections)?;
    assert_eq!(connections.counts(), (0, 0, 2));

    let (connection, _first_peer) = http1().await?;
    let Acquired::Http1(lease) = first.finish(connection) else {
        return Err("an H1 connection was not leased as H1".into());
    };
    assert_eq!(connections.counts(), (0, 1, 1));
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::Admit(Some(HttpProtocol::Http1))
    ));
    drop(lease);
    assert_eq!(connections.counts(), (1, 0, 1));
    drop(second);
    assert_eq!(connections.counts(), (1, 0, 0));
    Ok(())
}

#[tokio::test]
async fn idle_http1_connection_is_leased_before_a_setup_is_reserved() -> TestResult {
    let connections = connections(bound(2)?)?;
    let (connection, _peer) = http1().await?;
    drop(reserve(&connections)?.finish(connection));
    assert_eq!(connections.counts(), (1, 0, 0));

    let Checkout::Found(Acquired::Http1(lease)) = connections.checkout(false) else {
        return Err("an idle connection was passed over".into());
    };
    assert_eq!(connections.counts(), (0, 1, 0));
    // A busy connection is not leased twice.
    let second = reserve(&connections)?;
    assert_eq!(connections.counts(), (0, 1, 1));
    drop((lease, second));
    Ok(())
}

#[tokio::test]
async fn fresh_connection_at_the_bound_closes_the_least_recently_used_idle_one() -> TestResult {
    let connections = connections(NonZeroUsize::MIN)?;
    let (connection, _peer) = http1().await?;
    drop(reserve(&connections)?.finish(connection));
    assert_eq!(connections.counts(), (1, 0, 0));

    let Checkout::Reserved(reservation) = connections.checkout(true) else {
        return Err("a fresh-connection attempt reused an idle connection".into());
    };
    assert_eq!(connections.counts(), (0, 0, 1));
    drop(reservation);
    Ok(())
}

#[tokio::test]
async fn retired_http1_connection_is_not_returned_to_idle() -> TestResult {
    let connections = connections(bound(2)?)?;
    let (connection, _peer) = http1().await?;
    let Acquired::Http1(mut lease) = reserve(&connections)?.finish(connection) else {
        return Err("an H1 connection was not leased as H1".into());
    };
    lease.retire();
    drop(lease);
    assert_eq!(connections.counts(), (0, 0, 0));
    Ok(())
}

#[tokio::test]
async fn known_http2_key_waits_for_the_setup_in_flight() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (connection, _first_peer) = http2().await?;
    let Acquired::Http2(first) = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    connections.invalidate_http2(&first.token);
    assert!(connections.current_http2().is_none());

    // The key has selected H2, so one setup in flight holds back the rest.
    let setup = reserve(&connections)?;
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::AwaitSetup
    ));
    assert!(matches!(
        connections.checkout(false),
        Checkout::Found(Acquired::AwaitSetup)
    ));
    let waiter = {
        let connections = Arc::clone(&connections);
        tokio::spawn(async move { connections.setup_finished().await })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    let (connection, _second_peer) = http2().await?;
    let Acquired::Http2(second) = setup.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    timeout(Duration::from_secs(5), waiter).await??;
    let Some(current) = connections.current_http2() else {
        return Err("the new H2 connection was not kept".into());
    };
    assert!(Arc::ptr_eq(&current.token, &second.token));
    Ok(())
}

#[tokio::test]
async fn failed_setup_releases_requests_waiting_for_it() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (connection, _peer) = http2().await?;
    let Acquired::Http2(first) = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    connections.invalidate_http2(&first.token);

    let setup = reserve(&connections)?;
    let waiter = {
        let connections = Arc::clone(&connections);
        tokio::spawn(async move { connections.setup_finished().await })
    };
    tokio::task::yield_now().await;
    drop(setup);
    timeout(Duration::from_secs(5), waiter).await??;
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::Admit(None)
    ));
    Ok(())
}

#[tokio::test]
async fn second_http2_connection_is_closed_in_favor_of_the_current_one() -> TestResult {
    let connections = connections(bound(6)?)?;
    let first_setup = reserve(&connections)?;
    let second_setup = reserve(&connections)?;
    let (idle, _idle_peer) = http1().await?;
    drop(reserve(&connections)?.finish(idle));
    assert_eq!(connections.counts(), (1, 0, 2));

    let (connection, _first_peer) = http2().await?;
    let Acquired::Http2(first) = first_setup.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    // The new H2 connection carries the key; its idle H1 connection closes.
    assert_eq!(connections.counts(), (0, 0, 1));

    let (connection, _second_peer) = http2().await?;
    let Acquired::Http2(second) = second_setup.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    assert!(Arc::ptr_eq(&first.token, &second.token));
    assert_eq!(connections.counts(), (0, 0, 0));
    Ok(())
}

#[tokio::test]
async fn negotiated_connections_are_never_shared_across_routes() -> TestResult {
    let four = bound(4)?;
    let pool = Http1Or2Pool::new(four, four, four, four, four, four);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let socks5 = Route::socks5(Socks5Proxy::new("socks5://proxy.test:1080")?);
    let other = Route::socks5(Socks5Proxy::new("socks5://other.test:1080")?);

    let direct = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    let proxied = pool.entry(PoolKey::new(&endpoint, &socks5)).await;
    let same_proxy = pool.entry(PoolKey::new(&endpoint, &socks5)).await;

    assert!(!Arc::ptr_eq(&direct, &proxied));
    assert!(Arc::ptr_eq(&proxied, &same_proxy));
    assert!(!Arc::ptr_eq(
        &proxied,
        &pool.entry(PoolKey::new(&endpoint, &other)).await
    ));
    Ok(())
}

#[tokio::test]
async fn negotiated_connections_through_http_proxies_are_keyed_by_proxy() -> TestResult {
    let eight = bound(8)?;
    let pool = Http1Or2Pool::new(eight, eight, eight, eight, eight, eight);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let plaintext = Route::http_proxy(HttpProxy::new("http://proxy.test:8080")?);
    let routes = [
        Route::Direct,
        plaintext.clone(),
        Route::http_proxy(HttpProxy::new("http://other.test:8080")?),
        Route::http_proxy(HttpProxy::new("https://proxy.test:8080")?),
        Route::http_proxy(HttpProxy::new("https://proxy.test:8080")?.with_http2_transport()?),
        Route::http_proxy(
            HttpProxy::new("http://proxy.test:8080")?.with_basic_auth("user", "secret")?,
        ),
        Route::socks5(Socks5Proxy::new("socks5://proxy.test:8080")?),
    ];

    let mut entries = Vec::new();
    for route in &routes {
        entries.push(pool.entry(PoolKey::new(&endpoint, route)).await);
    }
    for (index, entry) in entries.iter().enumerate() {
        for other in &entries[index + 1..] {
            assert!(!Arc::ptr_eq(entry, other));
        }
    }
    assert!(Arc::ptr_eq(
        &entries[1],
        &pool.entry(PoolKey::new(&endpoint, &plaintext)).await
    ));
    Ok(())
}

#[tokio::test]
async fn http2_selection_is_remembered_beyond_the_pool_entry() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http1Or2Pool::new(one, bound(6)?, one, one, one, one);
    let first = Endpoint::new("first.test:443".parse()?, 443)?;
    let second = Endpoint::new("second.test:443".parse()?, 443)?;

    let entry = pool.entry(PoolKey::new(&first, &Route::Direct)).await;
    let setup = reserve(&entry.connections)?;
    let (connection, _peer) = http2().await?;
    drop(setup.finish(connection));
    drop(entry);
    // The single retained entry is evicted, then recreated.
    pool.entry(PoolKey::new(&second, &Route::Direct)).await;
    let recreated = pool.entry(PoolKey::new(&first, &Route::Direct)).await;

    // The new entry already knows the key selects H2, so a setup in flight
    // holds back the next request.
    let _setup = reserve(&recreated.connections)?;
    assert!(matches!(
        recreated.connections.before_admission(),
        BeforeAdmission::AwaitSetup
    ));
    // Another route to the same origin is still a first contact.
    let socks5 = Route::socks5(Socks5Proxy::new("socks5://proxy.test:1080")?);
    let other_route = pool.entry(PoolKey::new(&first, &socks5)).await;
    let _other_setup = reserve(&other_route.connections)?;
    assert!(matches!(
        other_route.connections.before_admission(),
        BeforeAdmission::Admit(None)
    ));
    Ok(())
}

#[tokio::test]
async fn http1_selection_does_not_forget_http2() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (connection, _h2_peer) = http2().await?;
    let Acquired::Http2(first) = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    connections.invalidate_http2(&first.token);
    let (connection, _h1_peer) = http1().await?;
    let lease = reserve(&connections)?.finish(connection);

    let _setup = reserve(&connections)?;
    assert!(matches!(
        connections.before_admission(),
        BeforeAdmission::AwaitSetup
    ));
    drop(lease);
    Ok(())
}

#[test]
fn remembered_http2_keys_are_bounded_least_recently_used_first() -> TestResult {
    let keys = Http2Keys::default();
    let oldest = key("key-0.test")?;
    keys.insert(&oldest);
    for index in 1..MAX_HTTP2_KEYS {
        keys.insert(&key(&format!("key-{index}.test"))?);
    }
    // A lookup marks the oldest key recently used, so the next one goes.
    assert!(keys.contains(&oldest));
    keys.insert(&key("newest.test")?);
    assert!(keys.contains(&oldest));
    assert!(!keys.contains(&key("key-1.test")?));
    assert_eq!(keys.lock().len(), MAX_HTTP2_KEYS);
    Ok(())
}
