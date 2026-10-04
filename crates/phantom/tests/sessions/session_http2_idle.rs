//! The idle limit a Firefox profile puts on a pooled HTTP/2 connection that
//! reads no response HEADERS or DATA, against a loopback TLS origin that
//! speaks raw HTTP/2 frames.
//!
//! The recipe's 170-second limit is shortened to 1 second so the tests run
//! quickly; everything else is the Firefox 157 recipe.

use crate::support::h2 as h2_support;
use crate::support::tls as tls_support;

use std::{error::Error, future::Future, net::Ipv4Addr, time::Duration};

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    profile::{ClientProfile, Http2IdleTimeout, Http2Settings, chromium, firefox},
};
use tokio::{
    io::{AsyncWriteExt, split},
    net::TcpListener,
    sync::{mpsc, oneshot},
    time::{Instant, sleep, sleep_until, timeout},
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
) -> TestResult<()> {
    for connection in 0.. {
        let (tcp, _) = listener.accept().await?;
        let events = events.clone();
        let acceptor = acceptor.clone();
        let release = release.take();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(tcp, acceptor, connection, events, release).await {
                eprintln!("origin connection {connection} failed: {error}");
            }
        });
    }
    Ok(())
}

/// What a connection's loop acts on next.
enum Input {
    Frame(Frame),
    /// The held response may end.
    Release,
}

async fn serve_connection(
    tcp: tokio::net::TcpStream,
    acceptor: SslAcceptor,
    connection: usize,
    events: mpsc::UnboundedSender<Seen>,
    release: Option<oneshot::Receiver<()>>,
) -> TestResult<()> {
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    accept_client_preface(&mut stream).await?;
    let (mut reader, mut writer) = split(stream);
    // Frames are read on their own task, so the loop below never cancels a
    // partly read frame.
    let (inputs, mut incoming) = mpsc::unbounded_channel();
    let frames = inputs.clone();
    tokio::spawn(async move {
        while let Ok(frame) = read_frame(&mut reader).await {
            if frames.send(Input::Frame(frame)).is_err() {
                break;
            }
        }
    });
    let holds = release.is_some();
    match release {
        Some(release) => {
            tokio::spawn(async move {
                if release.await.is_ok() {
                    let _ = inputs.send(Input::Release);
                }
            });
        }
        None => drop(inputs),
    }
    let mut held = None;
    let mut answered = 0_usize;
    while let Some(input) = incoming.recv().await {
        match input {
            Input::Frame(frame) if frame.kind == HEADERS && frame.flags & END_STREAM != 0 => {
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
            Input::Frame(frame) if frame.kind == GOAWAY => {
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
            Input::Frame(_) => {}
            Input::Release => {
                if let Some(stream) = held.take() {
                    write_frame(&mut writer, DATA, END_STREAM, stream, &[]).await?;
                    writer.flush().await?;
                }
            }
        }
    }
    Ok(())
}

async fn origin(
    release: Option<oneshot::Receiver<()>>,
) -> TestResult<(TestIdentity, String, mpsc::UnboundedReceiver<Seen>)> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let base = format!("https://{}", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (events, seen) = mpsc::unbounded_channel();
    tokio::spawn(serve(listener, acceptor, events, release));
    Ok((identity, base, seen))
}

async fn next(seen: &mut mpsc::UnboundedReceiver<Seen>) -> TestResult<Seen> {
    timeout(EVENT_WAIT, seen.recv())
        .await
        .map_err(|_| "the origin saw nothing in time")?
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
        .map_err(|_| "idle test exceeded its deadline")?
}

/// With no request, the prune timer closes a connection idle past its limit
/// with `GOAWAY(0, NO_ERROR)`, at least the limit after the request and less
/// than three seconds past the limit, and the next request opens another.
///
/// The timer rounds to whole seconds, so the close comes about two seconds
/// after the request; the extra second allows for a slow machine.
async fn idle_connection_is_closed_and_replaced(negotiated: bool) -> TestResult<()> {
    let (identity, base, mut seen) = origin(None).await?;
    let client = client(&identity, scaled_firefox())?;

    let sent = Instant::now();
    send(&client, negotiated, &format!("{base}/a"))
        .await?
        .collect()
        .await?;
    assert_eq!(next(&mut seen).await?, Seen::Request(0));

    assert_eq!(next(&mut seen).await?, goaway(0));
    let closed_after = sent.elapsed();
    assert!(
        closed_after >= IDLE && closed_after < IDLE + Duration::from_secs(3),
        "closed after {closed_after:?}"
    );

    send(&client, negotiated, &format!("{base}/b"))
        .await?
        .collect()
        .await?;
    assert_eq!(next(&mut seen).await?, Seen::Request(1));
    Ok(())
}

#[tokio::test]
async fn firefox_recipe_closes_an_idle_http2_connection_with_no_error() -> TestResult<()> {
    bounded(idle_connection_is_closed_and_replaced(false)).await
}

#[tokio::test]
async fn firefox_recipe_closes_an_idle_negotiated_http2_connection_with_no_error() -> TestResult<()>
{
    bounded(idle_connection_is_closed_and_replaced(true)).await
}

/// A connection whose open stream has read nothing for the limit takes no
/// new stream, so the next request opens another connection, but it stays
/// open until that stream ends and then closes with `GOAWAY(0, NO_ERROR)`.
#[tokio::test]
async fn an_open_stream_keeps_an_idle_connection_open_until_it_ends() -> TestResult<()> {
    bounded(async {
        let (release, released) = oneshot::channel();
        let (identity, base, mut seen) = origin(Some(released)).await?;
        let client = client(&identity, scaled_firefox())?;

        let mut held = send(&client, false, &format!("{base}/held")).await?;
        let head_read = Instant::now();
        assert_eq!(next(&mut seen).await?, Seen::Request(0));

        // The last read on the connection was the response head.
        sleep_until(head_read + IDLE).await;
        send(&client, false, &format!("{base}/next"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(&mut seen).await?, Seen::Request(1));
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
            match next(&mut seen).await? {
                event if event == goaway(0) => break,
                event if event == goaway(1) => {}
                event => return Err(format!("the origin saw {event:?}").into()),
            }
        }
        Ok(())
    })
    .await
}

/// The Chromium recipe sets no idle limit: a connection idle past the
/// scaled Firefox limit carries the next request.
#[tokio::test]
async fn chromium_recipe_keeps_an_idle_http2_connection() -> TestResult<()> {
    bounded(async {
        let (identity, base, mut seen) = origin(None).await?;
        let client = client(&identity, chromium::v154_http2())?;

        send(&client, false, &format!("{base}/a"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(&mut seen).await?, Seen::Request(0));
        sleep(IDLE * 3).await;
        assert!(seen.try_recv().is_err(), "the idle connection closed");
        send(&client, false, &format!("{base}/b"))
            .await?
            .collect()
            .await?;
        assert_eq!(next(&mut seen).await?, Seen::Request(0));
        Ok(())
    })
    .await
}
