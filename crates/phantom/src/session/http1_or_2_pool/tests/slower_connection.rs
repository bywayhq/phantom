//! The slower connection of a backup connection, which a negotiated pool key
//! keeps as H1, closes when the key has H2, or takes as its H2 connection.

use std::{sync::Arc, time::Duration};

use phantom_net::{
    http1::Http1Connection,
    http1_or_2::Http1Or2Connection,
    http2::Http2Connection,
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use phantom_profile::{Http2Setting, firefox};
use phantom_testkit::http2::{CLIENT_CONNECTION_PREFACE, CapturedFrame};
use tokio::{
    io::{AsyncReadExt, DuplexStream, duplex},
    sync::oneshot,
    time::{Instant, timeout},
};

use super::{TestResult, bound, connections, current_token, http1, http2, reserve};
use crate::session::{
    http1_or_2_pool::{Acquired, BeforeAdmission, Checkout, EntryConnections},
    prune_timer::PrunedEntry,
};

const WAIT: Duration = Duration::from_secs(5);

type Finish = oneshot::Sender<Option<Http1Or2Connection>>;

/// A slower connection whose setup ends with the outcome the test sends.
fn gated() -> (SlowerConnection<Http1Or2Connection>, SlowerProgress, Finish) {
    let progress = SlowerProgress::new();
    let (sender, receiver) = oneshot::channel();
    let slower = SlowerConnection::new(
        progress.clone(),
        async move { receiver.await.ok().flatten() },
    );
    (slower, progress, sender)
}

async fn slower_http1() -> Result<(Http1Or2Connection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, server) = duplex(1024);
    Ok((
        Http1Or2Connection::Http1(Http1Connection::connect(client).await?),
        server,
    ))
}

/// Opens an HTTP/2 connection with Firefox 157's settings, as a Firefox
/// profile's slower connection would be.
async fn slower_http2() -> Result<(Http1Or2Connection, DuplexStream), Box<dyn std::error::Error>> {
    let (client, server) = duplex(64 * 1024);
    let connection = Http2Connection::connect(client, &firefox::v157_http2()).await?;
    Ok((Http1Or2Connection::Http2(connection), server))
}

/// The identifier and value of one SETTINGS entry (RFC 9113, section 6.5.2;
/// RFC 8441; RFC 9218).
fn setting_entry(setting: Http2Setting) -> Result<(u16, u32), Box<dyn std::error::Error>> {
    Ok(match setting {
        Http2Setting::HeaderTableSize(value) => (0x1, value),
        Http2Setting::EnablePush(value) => (0x2, value.into()),
        Http2Setting::MaxConcurrentStreams(value) => (0x3, value),
        Http2Setting::InitialWindowSize(value) => (0x4, value),
        Http2Setting::MaxFrameSize(value) => (0x5, value),
        Http2Setting::MaxHeaderListSize(value) => (0x6, value),
        Http2Setting::EnableConnectProtocol(value) => (0x8, value.into()),
        Http2Setting::NoRfc7540Priorities(value) => (0x9, value.into()),
        other => return Err(format!("no identifier for {other:?}").into()),
    })
}

/// Splits what the client wrote after its preface into frames.
fn frames(written: &[u8]) -> Result<Vec<CapturedFrame>, Box<dyn std::error::Error>> {
    let mut rest = written
        .strip_prefix(CLIENT_CONNECTION_PREFACE.as_slice())
        .ok_or("the client did not start with the HTTP/2 preface")?;
    let mut frames = Vec::new();
    while !rest.is_empty() {
        let header = rest.get(..9).ok_or("a truncated frame header")?;
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let (frame, after) = rest
            .split_at_checked(9 + length)
            .ok_or("a truncated frame payload")?;
        frames.push(CapturedFrame::from_wire_bytes(frame)?);
        rest = after;
    }
    Ok(frames)
}

fn finish(sender: Finish, connection: Option<Http1Or2Connection>) -> TestResult {
    sender
        .send(connection)
        .map_err(|_| "the slower connection's task ended".into())
}

/// Waits until the key's slower connections have finished.
async fn settled(connections: &EntryConnections) -> TestResult {
    timeout(WAIT, async {
        while !connections.lock().spares.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

/// Reads what the client wrote until it closes the connection.
async fn closed(mut peer: DuplexStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut written = Vec::new();
    timeout(WAIT, peer.read_to_end(&mut written)).await??;
    Ok(written)
}

/// Gives the key an H1 connection leased to a request, as the first
/// connection of a backup connection that selected H1.
async fn leased_http1(
    connections: &Arc<EntryConnections>,
) -> Result<(Acquired, DuplexStream), Box<dyn std::error::Error>> {
    let (connection, peer) = http1().await?;
    Ok((reserve(connections)?.finish(connection), peer))
}

#[tokio::test]
async fn a_slower_http1_connection_waits_idle_on_an_http1_key() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (_lease, _first_peer) = leased_http1(&connections).await?;
    let (slower, progress, sender) = gated();
    connections.adopt(slower);
    let (connection, _peer) = slower_http1().await?;
    progress.mark_connected();
    finish(sender, Some(connection))?;
    settled(&connections).await?;

    assert_eq!(connections.counts(), (1, 1, 0));
    Ok(())
}

#[tokio::test]
async fn a_slower_connection_counts_toward_the_http1_bound_once_it_connects() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (slower, progress, _sender) = gated();
    connections.adopt(slower);
    assert_eq!(connections.lock().open_http1_or_connecting(), 0);

    progress.mark_connected();

    assert_eq!(connections.lock().open_http1_or_connecting(), 1);
    Ok(())
}

#[tokio::test]
async fn a_request_claims_the_slower_connection_of_an_http1_key() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (_lease, _first_peer) = leased_http1(&connections).await?;
    let (slower, _progress, sender) = gated();
    connections.adopt(slower);
    let Checkout::Found(Acquired::Spare(claim)) = connections.checkout(false, false) else {
        return Err("the request did not claim the slower connection".into());
    };

    let (connection, _peer) = slower_http1().await?;
    finish(sender, Some(connection))?;
    let lease = timeout(WAIT, claim.wait())
        .await?
        .ok_or("the claim was dropped")?;

    assert_eq!(connections.counts(), (0, 2, 0));
    drop(lease);
    assert_eq!(connections.counts(), (1, 1, 0));
    Ok(())
}

#[tokio::test]
async fn a_slower_http1_connection_closes_once_the_key_has_http2() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (connection, _h2_peer) = http2().await?;
    let Acquired::Http2 = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    let (slower, _progress, sender) = gated();
    connections.adopt(slower);

    let (connection, peer) = slower_http1().await?;
    finish(sender, Some(connection))?;
    settled(&connections).await?;

    assert_eq!(connections.counts(), (0, 0, 0));
    assert_eq!(connections.http2_connections(), 1);
    closed(peer).await?;
    Ok(())
}

#[tokio::test]
async fn a_slower_http2_connection_closes_in_favor_of_the_current_one() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (connection, _h2_peer) = http2().await?;
    let Acquired::Http2 = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };
    let current = current_token(&connections)?;
    let (slower, _progress, sender) = gated();
    connections.adopt(slower);

    let (connection, peer) = slower_http2().await?;
    finish(sender, Some(connection))?;
    settled(&connections).await?;

    assert!(Arc::ptr_eq(&current, &current_token(&connections)?));
    assert_eq!(connections.http2_connections(), 1);

    // The slower connection sent its preface and the profile's SETTINGS,
    // then closed with GOAWAY(NO_ERROR) and no stream processed, as Firefox
    // closes a second HTTP/2 connection to an origin.
    let frames = frames(&closed(peer).await?)?;
    let settings = frames
        .first()
        .ok_or("the client sent no frame")?
        .settings()?
        .ok_or("the first frame was not SETTINGS")?;
    let sent: Vec<_> = settings
        .entries()
        .iter()
        .map(|entry| (entry.identifier(), entry.value()))
        .collect();
    let profile = firefox::v157_http2()
        .initial_settings
        .into_iter()
        .map(setting_entry)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(sent, profile);
    let goaway = frames.last().ok_or("the client sent no frame")?;
    assert_eq!(goaway.header().frame_type(), 0x7);
    assert_eq!(goaway.header().stream_id(), 0);
    assert_eq!(goaway.payload(), [0, 0, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn a_slower_http2_connection_becomes_the_http2_connection_of_an_http1_key() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (_lease, _first_peer) = leased_http1(&connections).await?;
    let (slower, _progress, sender) = gated();
    connections.adopt(slower);
    let Checkout::Found(Acquired::Spare(claim)) = connections.checkout(false, false) else {
        return Err("the request did not claim the slower connection".into());
    };

    let (connection, _peer) = slower_http2().await?;
    finish(sender, Some(connection))?;

    // The claimant goes to the new H2 connection instead.
    assert!(timeout(WAIT, claim.wait()).await?.is_none());
    assert_eq!(connections.http2_connections(), 1);
    assert!(matches!(
        connections.before_admission(false),
        BeforeAdmission::Http2
    ));
    Ok(())
}

#[tokio::test]
async fn a_failed_slower_connection_lets_its_claimant_open_a_connection() -> TestResult {
    let connections = connections(bound(6)?)?;
    let (slower, _progress, sender) = gated();
    connections.adopt(slower);
    let Checkout::Found(Acquired::Spare(claim)) = connections.checkout(false, false) else {
        return Err("the request did not claim the slower connection".into());
    };

    finish(sender, None)?;

    assert!(timeout(WAIT, claim.wait()).await?.is_none());
    reserve(&connections)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_prune_keeps_the_family_of_a_key_with_an_http2_connection() -> TestResult {
    let limit = Duration::from_secs(115);
    let connections = connections(bound(6)?)?;
    connections.family.remember(AddressFamily::Ipv4);
    let (connection, _peer) = http2().await?;
    let Acquired::Http2 = reserve(&connections)?.finish(connection) else {
        return Err("an H2 connection was not leased as H2".into());
    };

    assert_eq!(connections.prune(Instant::now(), limit), None);
    assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_prune_closes_expired_idle_http1_connections_and_forgets_the_family() -> TestResult {
    let limit = Duration::from_secs(115);
    let connections = connections(bound(6)?)?;
    connections.family.remember(AddressFamily::Ipv6);
    let (connection, _peer) = http1().await?;
    drop(reserve(&connections)?.finish(connection));
    assert_eq!(connections.counts(), (1, 0, 0));

    assert_eq!(connections.prune(Instant::now(), limit), Some(limit));
    assert_eq!(connections.family.family(), Some(AddressFamily::Ipv6));

    tokio::time::advance(limit).await;
    assert_eq!(connections.prune(Instant::now(), limit), None);
    assert_eq!(connections.counts(), (0, 0, 0));
    assert_eq!(connections.family.family(), None);
    Ok(())
}
