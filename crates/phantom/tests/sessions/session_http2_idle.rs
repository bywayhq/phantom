//! The idle limit a Firefox profile puts on a pooled HTTP/2 connection that
//! reads no response HEADERS or DATA, against a loopback TLS origin that
//! speaks raw HTTP/2 frames.
//!
//! The recipe's 170-second limit is shortened to 1 second so the tests run
//! quickly; the other HTTP/2 settings use the Firefox 157 recipe.

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    profile::{
        ClientProfile, Http2IdleTimeout, Http2Settings,
        browser::{chrome, firefox},
    },
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, split},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinError,
    time::{Instant, sleep, sleep_until, timeout},
};
use tokio_btls::SslStream;

use crate::support::{
    deadline::FixtureDeadline,
    h2 as h2_support, tls as tls_support,
    tunnel_proxy::connection_peer::{ConnectionPeer, finish_with_cleanup},
};

use h2_support::{Frame, accept_client_preface, read_frame, write_frame};
use tls_support::{H2_ALPN, TestIdentity, accept_tls_stream, tls_settings};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// The idle limit the tests give the Firefox recipe in place of its own.
const IDLE: Duration = Duration::from_secs(1);
/// Longest wait for one event at the origin; the prune timer closes a
/// connection within two seconds of its last read under a 1-second limit.
const EVENT_WAIT: Duration = Duration::from_secs(5);

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const GOAWAY: u8 = 0x7;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// What the origin saw on its connections, numbered in accept order.
#[derive(Debug, PartialEq)]
enum Seen {
    Request(usize),
    GoAway {
        connection: usize,
        last_stream: u32,
        payload: Vec<u8>,
    },
}

/// The Firefox 157 recipe with its idle limit scaled to [`IDLE`].
fn scaled_firefox() -> Http2Settings {
    let mut settings = firefox::v157_http2();
    settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(IDLE);
    settings
}

fn client(identity: &TestIdentity, http2: Http2Settings) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings()).with_http2(http2);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// Serves every connection: answers each request with an empty 200, except
/// that the first request on the first connection gets only its response
/// head until `release` fires, and reports what it sees.
async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    events: mpsc::UnboundedSender<Seen>,
    mut release: Option<oneshot::Receiver<()>>,
    mut stop: oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut peers: Vec<IdleConnection> = Vec::new();
    let mut connection = 0;
    let result = loop {
        tokio::select! {
            biased;
            completed = poll_fn(|context| {
                for (index, peer) in peers.iter_mut().enumerate() {
                    if let Poll::Ready(outcome) = Pin::new(&mut peer.task).poll(context) {
                        return Poll::Ready((index, outcome));
                    }
                }
                Poll::Pending
            }) => {
                let (index, outcome) = completed;
                drop(peers.remove(index));
                if let Err(error) = connection_outcome(outcome) {
                    break Err(error);
                }
            }
            requested = &mut stop => break requested.map_err(Into::into),
            accepted = listener.accept() => {
                let (tcp, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error.into()),
                };
                let (stop, stopped) = oneshot::channel();
                peers.push(IdleConnection {
                    task: ConnectionPeer::spawn(serve_connection(
                        tcp, acceptor.clone(), connection, events.clone(), release.take(), stopped,
                    )),
                    stop: Some(stop),
                });
                connection += 1;
            }
        }
    };
    drop(listener);
    for peer in &mut peers {
        // A completed peer can already have dropped its stop receiver; its
        // original task outcome is still collected below.
        if let Some(stop) = peer.stop.take() {
            let _ = stop.send(());
        }
    }
    let mut cleanup = Ok(());
    while !peers.is_empty() {
        let outcome = (&mut peers[0].task).await;
        drop(peers.remove(0));
        cleanup = finish_with_cleanup(cleanup, connection_outcome(outcome));
    }
    finish_with_cleanup(result, cleanup)
}

struct IdleConnection {
    task: ConnectionPeer<TestResult<()>>,
    stop: Option<oneshot::Sender<()>>,
}

fn connection_outcome(outcome: Result<TestResult<()>, JoinError>) -> TestResult<()> {
    match outcome {
        Ok(outcome) => outcome,
        Err(error) => Err(error.into()),
    }
}

async fn serve_connection(
    tcp: TcpStream,
    acceptor: SslAcceptor,
    connection: usize,
    events: mpsc::UnboundedSender<Seen>,
    release: Option<oneshot::Receiver<()>>,
    stop: oneshot::Receiver<()>,
) -> TestResult<()> {
    let protocol = async {
        let mut stream = accept_tls_stream(tcp, acceptor).await?;
        accept_client_preface(&mut stream).await?;
        serve_frames(stream, connection, events, release).await
    };
    tokio::select! {
        biased;
        result = protocol => result,
        requested = stop => {
            requested?;
            Ok(())
        }
    }
}

async fn serve_frames(
    stream: SslStream<TcpStream>,
    connection: usize,
    events: mpsc::UnboundedSender<Seen>,
    mut release: Option<oneshot::Receiver<()>>,
) -> TestResult<()> {
    let (mut reader, mut writer) = split(stream);
    let mut reader = BufReader::new(&mut reader);
    let holds = release.is_some();
    let mut held = None;
    let mut answered = 0_usize;
    loop {
        // Keep the same pending read across release events: a release must
        // never restart a partially consumed frame.
        let reading = read_idle_frame(&mut reader, answered != 0);
        tokio::pin!(reading);
        let frame = loop {
            tokio::select! {
                frame = &mut reading => break frame?,
                released = async {
                    match release.as_mut() {
                        Some(release) => release.await,
                        None => std::future::pending().await,
                    }
                } => {
                    release = None;
                    released?;
                    if let Some(stream) = held.take() {
                        write_frame(&mut writer, DATA, END_STREAM, stream, &[]).await?;
                        writer.flush().await?;
                    }
                }
            }
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        match frame {
            frame if frame.kind == HEADERS && frame.flags & END_STREAM != 0 => {
                events.send(Seen::Request(connection))?;
                // `:status: 200` is static table entry 8.
                let flags = if holds && answered == 0 {
                    held = Some(frame.stream_id);
                    END_HEADERS
                } else {
                    END_STREAM | END_HEADERS
                };
                answered += 1;
                write_frame(&mut writer, HEADERS, flags, frame.stream_id, &[0x88]).await?;
                writer.flush().await?;
            }
            frame if frame.kind == GOAWAY => {
                let last_stream = frame
                    .payload
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(u32::MAX, u32::from_be_bytes);
                events.send(Seen::GoAway {
                    connection,
                    last_stream,
                    payload: frame.payload,
                })?;
                return Ok(());
            }
            _ => {}
        }
    }
}

async fn read_idle_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    answered: bool,
) -> TestResult<Option<Frame>> {
    // Only a disconnect between complete frames after a request is expected.
    // Pre-request EOF and truncated frames keep the original read error.
    match reader.fill_buf().await {
        Ok([]) if answered => return Ok(None),
        Ok(_) => {}
        Err(error) if answered && tls_support::is_peer_gone(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    Ok(Some(read_frame(reader).await?))
}

struct IdleOrigin {
    task: Option<ConnectionPeer<TestResult<()>>>,
    stop: Option<oneshot::Sender<()>>,
    seen: mpsc::UnboundedReceiver<Seen>,
}

impl IdleOrigin {
    async fn finish(&mut self) -> TestResult<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let outcome = timeout(EVENT_WAIT, task)
            .await
            .map_err(|elapsed| FixtureDeadline::new("idle origin did not stop", elapsed))?;
        drop(self.task.take());
        connection_outcome(outcome)
    }
}

async fn finish_origin(origin: &mut Option<IdleOrigin>) -> TestResult<()> {
    match origin.as_mut() {
        Some(origin) => origin.finish().await,
        None => Ok(()),
    }
}

async fn origin(
    release: Option<oneshot::Receiver<()>>,
) -> TestResult<(TestIdentity, String, IdleOrigin)> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let base = format!("https://{}", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (events, seen) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel();
    let task = ConnectionPeer::spawn(serve(listener, acceptor, events, release, stopped));
    Ok((
        identity,
        base,
        IdleOrigin {
            task: Some(task),
            stop: Some(stop),
            seen,
        },
    ))
}

async fn next(seen: &mut mpsc::UnboundedReceiver<Seen>) -> TestResult<Seen> {
    timeout(EVENT_WAIT, seen.recv())
        .await
        .map_err(|elapsed| FixtureDeadline::new("the origin saw nothing in time", elapsed))?
        .ok_or_else(|| "the origin stopped".into())
}

async fn send(client: &Client, negotiated: bool, url: &str) -> TestResult<phantom::ResponseBody> {
    let request = if negotiated {
        client.get_negotiated(url)?
    } else {
        client.get(HttpProtocol::Http2, url)?
    };
    let response = request.send().await?;
    assert_eq!(response.status(), 200);
    Ok(response.into_body())
}

fn goaway(connection: usize) -> Seen {
    // Last stream ID 0 and `NO_ERROR`, with no debug data.
    Seen::GoAway {
        connection,
        last_stream: 0,
        payload: vec![0; 8],
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(Duration::from_secs(20), future)
        .await
        .map_err(|elapsed| FixtureDeadline::new("idle test exceeded its deadline", elapsed))?
}

/// With no request, the prune timer closes a connection idle past its limit
/// with `GOAWAY(0, NO_ERROR)`, at least the limit after the request and less
/// than three seconds past the limit, and the next request opens another.
///
/// The timer rounds to whole seconds, so the close comes about two seconds
/// after the request; the extra second allows for a slow machine.
async fn idle_connection_is_closed_and_replaced(negotiated: bool) -> TestResult<()> {
    let mut owner = None;
    let result = bounded(async {
        let (identity, base, origin) = origin(None).await?;
        owner = Some(origin);
        let seen = &mut owner.as_mut().ok_or("idle origin was not retained")?.seen;
        let client = client(&identity, scaled_firefox())?;

        let sent = Instant::now();
        send(&client, negotiated, &format!("{base}/a"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(seen).await?, Seen::Request(0));

        assert_eq!(next(seen).await?, goaway(0));
        let closed_after = sent.elapsed();
        assert!(
            closed_after >= IDLE && closed_after < IDLE + Duration::from_secs(3),
            "closed after {closed_after:?}"
        );

        send(&client, negotiated, &format!("{base}/b"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(seen).await?, Seen::Request(1));
        Ok(())
    })
    .await;
    finish_with_cleanup(result, finish_origin(&mut owner).await)
}

#[tokio::test]
async fn firefox_recipe_closes_an_idle_http2_connection_with_no_error() -> TestResult<()> {
    idle_connection_is_closed_and_replaced(false).await
}

#[tokio::test]
async fn firefox_recipe_closes_an_idle_negotiated_http2_connection_with_no_error() -> TestResult<()>
{
    idle_connection_is_closed_and_replaced(true).await
}

/// A connection whose open stream has read nothing for the limit takes no
/// new stream, so the next request opens another connection, but it stays
/// open until that stream ends and then closes with `GOAWAY(0, NO_ERROR)`.
#[tokio::test]
async fn an_open_stream_keeps_an_idle_connection_open_until_it_ends() -> TestResult<()> {
    let mut owner = None;
    let result = bounded(async {
        let (release, released) = oneshot::channel();
        let (identity, base, origin) = origin(Some(released)).await?;
        owner = Some(origin);
        let seen = &mut owner.as_mut().ok_or("idle origin was not retained")?.seen;
        let client = client(&identity, scaled_firefox())?;

        let mut held = send(&client, false, &format!("{base}/held")).await?;
        let head_read = Instant::now();
        assert_eq!(next(seen).await?, Seen::Request(0));

        // The last read on the connection was the response head.
        sleep_until(head_read + IDLE).await;
        send(&client, false, &format!("{base}/next"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(seen).await?, Seen::Request(1));
        // Past the prune timer's next wake-up, the open stream still holds
        // its connection. The second connection, idle, may close meanwhile.
        sleep(Duration::from_millis(2_500)).await;
        let mut early = Vec::new();
        while let Ok(event) = seen.try_recv() {
            early.push(event);
        }
        assert!(
            !early.contains(&goaway(0)),
            "the held connection closed early: {early:?}"
        );

        release.send(()).map_err(|()| "the origin went away")?;
        while held.frame().await.transpose()?.is_some() {}
        drop(held);
        loop {
            match next(seen).await? {
                event if event == goaway(0) => break,
                event if event == goaway(1) => {}
                event => return Err(format!("the origin saw {event:?}").into()),
            }
        }
        Ok(())
    })
    .await;
    finish_with_cleanup(result, finish_origin(&mut owner).await)
}

/// The Chromium recipe sets no idle limit: a connection idle past the
/// scaled Firefox limit carries the next request.
#[tokio::test]
async fn chromium_recipe_keeps_an_idle_http2_connection() -> TestResult<()> {
    let mut owner = None;
    let result = bounded(async {
        let (identity, base, origin) = origin(None).await?;
        owner = Some(origin);
        let seen = &mut owner.as_mut().ok_or("idle origin was not retained")?.seen;
        let client = client(&identity, chrome::v154_http2())?;

        send(&client, false, &format!("{base}/a"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(seen).await?, Seen::Request(0));
        sleep(IDLE * 3).await;
        assert!(seen.try_recv().is_err(), "the idle connection closed");
        send(&client, false, &format!("{base}/b"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(seen).await?, Seen::Request(0));
        Ok(())
    })
    .await;
    finish_with_cleanup(result, finish_origin(&mut owner).await)
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::poll_fn, io, task::Poll};

    use tokio::{
        io::{AsyncWriteExt, BufReader},
        time::timeout,
    };

    use super::{TestResult, bounded};

    #[tokio::test]
    async fn a_dropped_release_retains_the_original_connection_failure() -> TestResult<()> {
        let mut owner = None;
        let result = bounded(async {
            let (release, released) = tokio::sync::oneshot::channel();
            let (identity, base, origin) = super::origin(Some(released)).await?;
            owner = Some(origin);
            let origin = owner.as_mut().ok_or("idle origin was not retained")?;
            let client = super::client(&identity, super::scaled_firefox())?;
            let held = super::send(&client, false, &format!("{base}/held")).await?;
            assert_eq!(
                super::next(&mut origin.seen).await?,
                super::Seen::Request(0)
            );
            drop(release);
            timeout(super::EVENT_WAIT, async {
                while !origin.task.as_ref().is_some_and(|task| task.is_finished()) {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            let error = origin
                .finish()
                .await
                .err()
                .ok_or("the dropped release was ignored")?;
            assert!(
                error.is::<tokio::sync::oneshot::error::RecvError>(),
                "the original release failure was replaced: {error}"
            );
            assert!(origin.task.is_none());
            origin.finish().await?;
            drop(held);
            drop(client);
            Ok(())
        })
        .await;
        super::finish_with_cleanup(result, super::finish_origin(&mut owner).await)
    }

    #[tokio::test]
    async fn a_truncated_idle_frame_keeps_its_original_io_error() -> TestResult<()> {
        for bytes in [vec![0], vec![0, 0, 1, super::DATA, 0, 0, 0, 0, 1]] {
            let (mut writer, reader) = tokio::io::duplex(64);
            writer.write_all(&bytes).await?;
            writer.shutdown().await?;
            let mut reader = BufReader::new(reader);
            let error = super::read_idle_frame(&mut reader, true)
                .await
                .err()
                .ok_or("a truncated frame was accepted")?;
            assert_eq!(
                error
                    .downcast_ref::<io::Error>()
                    .ok_or("the frame's I/O cause changed")?
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn only_a_disconnect_between_idle_frames_is_accepted() -> TestResult<()> {
        let (mut writer, reader) = tokio::io::duplex(64);
        super::write_frame(&mut writer, super::GOAWAY, 0, 0, &[0; 8]).await?;
        writer.shutdown().await?;
        let mut reader = BufReader::new(reader);
        let frame = super::read_idle_frame(&mut reader, true)
            .await?
            .ok_or("the complete frame was discarded")?;
        assert_eq!(frame.kind, super::GOAWAY);
        assert_eq!(frame.payload, vec![0; 8]);
        assert!(super::read_idle_frame(&mut reader, true).await?.is_none());
        let error = super::read_idle_frame(&mut reader, false)
            .await
            .err()
            .ok_or("pre-request EOF was accepted")?;
        assert_eq!(
            error
                .downcast_ref::<io::Error>()
                .ok_or("the pre-request I/O cause changed")?
                .kind(),
            io::ErrorKind::UnexpectedEof,
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn entered_pending_deadline_retains_its_original_elapsed() -> TestResult<()> {
        let entered = Cell::new(false);
        let operation = bounded(poll_fn(|_| {
            entered.set(true);
            Poll::<TestResult<()>>::Pending
        }));
        tokio::pin!(operation);
        assert!(futures_util::poll!(&mut operation).is_pending());
        assert!(entered.get(), "the actual operation was not polled");
        tokio::time::advance(std::time::Duration::from_secs(20)).await;

        let error = operation.await.err().ok_or("pending operation succeeded")?;
        assert_eq!(error.to_string(), "idle test exceeded its deadline");
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()),
            "the fixture deadline discarded its original Elapsed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_the_original_operation_error() -> TestResult<()> {
        let failure = io::Error::new(io::ErrorKind::PermissionDenied, "fixture operation failed");
        let error = bounded(async { Err(failure.into()) })
            .await
            .err()
            .ok_or("failed operation succeeded")?;
        let original = error
            .downcast_ref::<io::Error>()
            .ok_or("operation error type changed")?;
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(original.to_string(), "fixture operation failed");
        Ok(())
    }

    #[tokio::test]
    async fn ready_deadline_keeps_success() -> TestResult<()> {
        bounded(async { Ok(()) }).await
    }

    #[tokio::test(start_paused = true)]
    async fn actual_pending_origin_event_keeps_its_original_elapsed() -> TestResult<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let operation = super::next(&mut receiver);
        tokio::pin!(operation);
        assert!(futures_util::poll!(&mut operation).is_pending());
        tokio::time::advance(std::time::Duration::from_secs(5)).await;

        let error = operation
            .await
            .err()
            .ok_or("pending origin event succeeded")?;
        assert_eq!(error.to_string(), "the origin saw nothing in time");
        assert!(
            error
                .source()
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()),
            "the origin event deadline discarded its original Elapsed"
        );
        drop(sender);
        Ok(())
    }

    #[tokio::test]
    async fn ready_origin_event_keeps_the_original_observation() -> TestResult<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        sender.send(super::Seen::GoAway {
            connection: 3,
            last_stream: 7,
            payload: vec![4, 2],
        })?;

        assert_eq!(
            super::next(&mut receiver).await?,
            super::Seen::GoAway {
                connection: 3,
                last_stream: 7,
                payload: vec![4, 2],
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn closed_origin_event_channel_keeps_its_distinct_failure() -> TestResult<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<super::Seen>();
        drop(sender);

        let error = super::next(&mut receiver)
            .await
            .err()
            .ok_or("closed origin event succeeded")?;
        assert_eq!(error.to_string(), "the origin stopped");
        assert!(error.source().is_none());
        Ok(())
    }
}
