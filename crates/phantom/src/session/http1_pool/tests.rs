use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use phantom_net::http1::Http1Connection;
use tokio::io::{DuplexStream, duplex};

use super::{Checkout, EntryConnections, Http1ConnectionMode, Http1Pool, PoolKey};
use crate::{Route, authority::Endpoint};

mod slower_connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bound(value: usize) -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
    NonZeroUsize::new(value).ok_or_else(|| "zero bound".into())
}

fn connections(max: NonZeroUsize) -> Arc<EntryConnections> {
    timed_connections(max, None)
}

fn timed_connections(
    max: NonZeroUsize,
    used_idle_timeout: Option<Duration>,
) -> Arc<EntryConnections> {
    EntryConnections::new(max, used_idle_timeout)
}

/// Opens an HTTP/1.1 connection over an in-memory stream.
///
/// The returned peer half must outlive the connection, or its driver sees the
/// close and the connection stops being reusable.
async fn connection() -> Result<(Http1Connection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, server) = duplex(1024);
    Ok((Http1Connection::connect(client).await?, server))
}

#[tokio::test]
async fn per_origin_admission_survives_lru_eviction() -> TestResult {
    let one = NonZeroUsize::MIN;
    let pool = Http1Pool::new(one, one, one);
    let first = Endpoint::new("first.test:443".parse()?, 443)?;
    let second = Endpoint::new("second.test:443".parse()?, 443)?;

    let first_entry = pool
        .entry(PoolKey::new(
            &first,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    let permit = first_entry.admit().await?;
    pool.entry(PoolKey::new(
        &second,
        &Route::Direct,
        Http1ConnectionMode::TlsOrigin,
    ))
    .await;
    drop(first_entry);
    let replacement = pool
        .entry(PoolKey::new(
            &first,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;

    assert!(Arc::ptr_eq(permit.admission(), &replacement.admission));
    assert_eq!(replacement.admission.available_active(), 0);
    drop(permit);
    assert_eq!(replacement.admission.available_active(), 1);
    Ok(())
}

#[tokio::test]
async fn pool_entries_take_the_pool_used_idle_timeout() -> TestResult {
    let one = NonZeroUsize::MIN;
    let timeout = Some(Duration::from_secs(300));
    let pool = Http1Pool::new(one, one, one).with_used_idle_timeout(timeout);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let entry = pool
        .entry(PoolKey::new(
            &origin,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;
    assert_eq!(entry.connections.used_idle_timeout, timeout);
    Ok(())
}

#[tokio::test]
async fn pool_key_admits_as_many_requests_as_the_connection_bound() -> TestResult {
    let pool = Http1Pool::new(NonZeroUsize::MIN, bound(6)?, NonZeroUsize::MIN);
    let origin = Endpoint::new("origin.test:443".parse()?, 443)?;
    let entry = pool
        .entry(PoolKey::new(
            &origin,
            &Route::Direct,
            Http1ConnectionMode::TlsOrigin,
        ))
        .await;

    assert_eq!(entry.admission.available_active(), 6);
    assert_eq!(entry.connections.max.get(), 6);
    Ok(())
}

#[tokio::test]
async fn returned_connection_is_leased_again_before_a_slot_is_reserved() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));
    assert_eq!(connections.open(), 1);

    let Checkout::Idle(lease) = connections.checkout(false) else {
        return Err("an idle connection was passed over".into());
    };
    assert_eq!(connections.open(), 1);
    drop(lease);
    assert_eq!(connections.open(), 1);
    Ok(())
}

#[tokio::test]
async fn busy_connection_is_not_leased_to_a_second_request() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    let busy = reservation.into_lease(connection);

    let Checkout::Reserved(second) = connections.checkout(false) else {
        return Err("a busy connection was leased twice".into());
    };
    assert_eq!(connections.open(), 2);
    drop((busy, second));
    Ok(())
}

#[tokio::test]
async fn abandoned_connection_setup_frees_its_slot() -> TestResult {
    let connections = connections(NonZeroUsize::MIN);
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    assert_eq!(connections.open(), 1);

    drop(reservation);
    assert_eq!(connections.open(), 0);
    Ok(())
}

#[tokio::test]
async fn retired_connection_is_not_returned_to_idle() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    let mut lease = reservation.into_lease(connection);
    lease.retire();
    drop(lease);

    assert_eq!(connections.open(), 0);
    assert!(matches!(connections.checkout(false), Checkout::Reserved(_)));
    Ok(())
}

#[tokio::test]
async fn closed_idle_connection_is_discarded_instead_of_leased() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection.clone()));
    drop(peer);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while connection.is_reusable() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    assert!(matches!(connections.checkout(false), Checkout::Reserved(_)));
    assert_eq!(connections.open(), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connection_idle_less_than_the_timeout_is_reused() -> TestResult {
    let connections = timed_connections(bound(2)?, Some(Duration::from_secs(300)));
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));

    tokio::time::advance(Duration::from_secs(299)).await;
    let Checkout::Idle(lease) = connections.checkout(false) else {
        return Err("a connection idle 299 s was not reused".into());
    };
    drop(lease);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connection_idle_for_the_timeout_is_closed_and_replaced() -> TestResult {
    let connections = timed_connections(bound(2)?, Some(Duration::from_secs(300)));
    let (connection, mut peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));

    tokio::time::advance(Duration::from_secs(300)).await;
    let Checkout::Reserved(replacement) = connections.checkout(false) else {
        return Err("a connection idle 300 s was reused".into());
    };
    // The expired connection no longer counts, and its peer sees it close.
    assert_eq!(connections.open(), 1);
    let mut buffer = [0_u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await??;
    assert_eq!(read, 0);
    drop(replacement);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connection_without_a_timeout_is_reused_however_long_it_was_idle() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));

    tokio::time::advance(Duration::from_secs(3_600)).await;
    assert!(matches!(connections.checkout(false), Checkout::Idle(_)));
    Ok(())
}

#[tokio::test]
async fn fresh_connection_below_the_bound_keeps_idle_connections() -> TestResult {
    let connections = connections(bound(2)?);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));

    let Checkout::Reserved(fresh) = connections.checkout(true) else {
        return Err("a fresh-connection attempt reused an idle connection".into());
    };
    assert_eq!(connections.open(), 2);
    drop(fresh);
    assert_eq!(connections.open(), 1);
    Ok(())
}

#[tokio::test]
async fn fresh_connection_at_the_bound_closes_an_idle_connection() -> TestResult {
    let connections = connections(NonZeroUsize::MIN);
    let (connection, _peer) = connection().await?;
    let Checkout::Reserved(reservation) = connections.checkout(false) else {
        return Err("an empty pool key leased an idle connection".into());
    };
    drop(reservation.into_lease(connection));

    let Checkout::Reserved(fresh) = connections.checkout(true) else {
        return Err("a fresh-connection attempt reused an idle connection".into());
    };
    assert_eq!(connections.open(), 1);
    drop(fresh);
    assert_eq!(connections.open(), 0);
    Ok(())
}

/// A request awaits `acquire` whether it reuses a connection or opens one,
/// so only `open`, which a new connection boxes, may hold the connectors'
/// futures.
#[cfg(debug_assertions)]
#[test]
fn acquire_leaves_connection_setup_off_the_request_future() {
    // A reuse holds only the arguments and the boxed setup.
    let size = phantom_testkit::future_size::future_size(&super::PoolEntry::acquire);
    assert!(size <= 1024, "PoolEntry::acquire is {size} bytes");
}

/// `open` holds the connectors' futures for a new connection; see
/// `phantom_testkit::future_size`.
#[cfg(debug_assertions)]
#[test]
fn opening_a_connection_stays_within_the_setup_budget() {
    use phantom_testkit::future_size::{SETUP_FUTURE_BUDGET, assert_within, future_size};

    assert_within(
        SETUP_FUTURE_BUDGET,
        &[("PoolEntry::open", future_size(&super::PoolEntry::open))],
    );
}

/// A read-idle limit on a `407` body drain needs a timer; on a runtime
/// without its time driver the drain fails instead of panicking.
#[test]
fn challenge_drain_without_a_time_driver_is_runtime_unavailable() -> TestResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // The connection driver needs timers, so the connection and its `407`
    // come from a complete runtime, and only the drain runs without timers.
    let complete = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut body, _server, _connection) = complete.block_on(async {
        let (connection, mut server) = connection().await?;
        let target = phantom_net::http1::OriginForm::parse("/").map_err(|_| "invalid target")?;
        let host = vec![phantom_net::http1::RequestHeader::new(
            "host",
            b"proxy.test",
        )];
        let proxy = async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).await?;
                request.push(byte[0]);
            }
            // The body never arrives, so the drain waits on its timer.
            server
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 5\r\n\r\n",
                )
                .await?;
            Ok::<_, std::io::Error>(server)
        };
        let (response, server) = tokio::try_join!(
            async { Ok::<_, Box<dyn std::error::Error>>(connection.send_get(target, host).await?) },
            async { Ok(proxy.await?) },
        )?;
        let (_, body) = response.into_parts();
        Ok::<_, Box<dyn std::error::Error>>((body, server, connection))
    })?;
    let without_time = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    let drained = without_time.block_on(super::drain_challenge(
        &mut body,
        Some(Duration::from_secs(1)),
    ));

    let error = drained
        .err()
        .ok_or("the drain without a timer did not fail")?;
    assert_eq!(error.kind(), crate::RequestErrorKind::RuntimeUnavailable);
    Ok(())
}
