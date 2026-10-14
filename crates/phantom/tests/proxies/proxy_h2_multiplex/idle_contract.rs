//! Outer TLS/H2 closure without another checkout, and live-stream survival.

use std::{io, net::Ipv4Addr, time::Duration};

use phantom::{Client, HttpProtocol, HttpProxy, Route, profile::Http2IdleTimeout};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, firefox_profile, get_forwarded,
    observe_log, read_head, spawn_proxy,
};
use crate::{
    proxy_h2::connection_tasks::finish_peer,
    support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(8);
const QUIET: Duration = Duration::from_millis(1400);
const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn profile(idle: Http2IdleTimeout) -> phantom::profile::ClientProfile {
    let mut settings = phantom::profile::browser::firefox::v157_http2();
    settings.idle_timeout = idle;
    settings.preface_ping_after = None;
    settings.ping_timeout = None;
    settings.ping_failure_retries = 0;
    firefox_profile().with_http2(settings)
}

fn forwarded_client(
    identity: &TestIdentity,
    address: std::net::SocketAddr,
    idle: Http2IdleTimeout,
) -> TestResult<Client> {
    Ok(Client::builder(profile(idle))
        .add_proxy_root_certificate_der(identity.root_der.clone())
        .route(Route::http_proxy(
            HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?,
        ))
        .build()?)
}

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// Clean EOF is distinct from truncated frames; lengths are bounded before
/// allocation. The peer observes raw closure bytes independently of h2.
async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> TestResult<Option<Frame>> {
    let mut head = [0_u8; 9];
    if reader.read(&mut head[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut head[1..]).await?;
    let length = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    if length > 64 * 1024 {
        return Err("proxy idle peer received an oversized frame".into());
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Frame {
        kind: head[3],
        flags: head[4],
        stream: u32::from_be_bytes(head[5..9].try_into()?) & 0x7fff_ffff,
        payload,
    }))
}

async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> TestResult<()> {
    let length = u32::try_from(payload.len())?.to_be_bytes();
    let mut head = [0_u8; 9];
    head[..3].copy_from_slice(&length[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&stream.to_be_bytes());
    writer.write_all(&head).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn raw_forward_peer(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    closed: oneshot::Sender<()>,
) -> TestResult<(usize, usize)> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    assert_eq!(&preface, PREFACE);
    write_frame(&mut stream, 4, 0, 0, &[]).await?;
    let mut requests = 0;
    let mut pings = 0;
    let mut going_away = false;
    while let Some(incoming) = frame(&mut stream).await? {
        match incoming.kind {
            4 if incoming.flags & 1 == 0 => write_frame(&mut stream, 4, 1, 0, &[]).await?,
            1 => {
                assert!(!going_away, "HEADERS followed GOAWAY");
                assert_ne!(incoming.stream, 0);
                assert_ne!(incoming.flags & 4, 0, "unexpected CONTINUATION");
                requests += 1;
                // HPACK static index8 is :status200. An empty final DATA
                // frame makes the response complete without retaining a body.
                write_frame(&mut stream, 1, 4, incoming.stream, &[0x88]).await?;
                write_frame(&mut stream, 0, 1, incoming.stream, &[]).await?;
            }
            6 if incoming.flags & 1 == 0 => {
                assert_eq!(incoming.payload.len(), 8);
                pings += 1;
                write_frame(&mut stream, 6, 1, 0, &incoming.payload).await?;
            }
            7 => {
                assert!(!going_away, "duplicate GOAWAY");
                assert_eq!(incoming.stream, 0);
                assert_eq!(incoming.flags, 0);
                assert_eq!(
                    incoming.payload, [0; 8],
                    "GOAWAY must be 0/NO_ERROR/no debug"
                );
                going_away = true;
            }
            3 => return Err("proxy idle peer observed a request reset".into()),
            _ => {}
        }
    }
    assert!(going_away, "EOF without the expected graceful GOAWAY");
    closed.send(()).map_err(|_| "closure receiver dropped")?;
    Ok((requests, pings))
}

async fn empty_forward(client: &Client) -> TestResult<()> {
    use http_body_util::BodyExt;

    let response = client
        .get(HttpProtocol::Http2, "http://idle.test/probe")?
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert!(response.into_body().collect().await?.to_bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_timed_outer_proxy_connection_closes_without_another_checkout() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (closed, closure) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        timeout(DEADLINE, raw_forward_peer(listener, acceptor, closed)).await?
    });

    let operation = async {
        let client = forwarded_client(
            &identity,
            address,
            Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(1)),
        )?;
        timeout(DEADLINE, empty_forward(&client)).await??;
        // The client and its proxy pool stay alive. No later request or
        // checkout is allowed to trigger this closure.
        timeout(DEADLINE, closure).await??;
        drop(client);
        Ok(())
    }
    .await;
    assert_eq!(finish_peer(operation, peer).await?, (1, 0));
    Ok(())
}

#[tokio::test]
async fn an_unlimited_outer_proxy_stays_open_and_is_reused() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (closed, mut closure) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        timeout(DEADLINE, raw_forward_peer(listener, acceptor, closed)).await?
    });

    let operation = async {
        let client = forwarded_client(&identity, address, Http2IdleTimeout::Unlimited)?;
        timeout(DEADLINE, empty_forward(&client)).await??;
        assert!(
            timeout(QUIET, &mut closure).await.is_err(),
            "untimed proxy closed"
        );
        timeout(DEADLINE, empty_forward(&client)).await??;
        drop(client);
        timeout(DEADLINE, closure).await??;
        Ok(())
    }
    .await;
    assert_eq!(finish_peer(operation, peer).await?, (2, 0));
    Ok(())
}

#[tokio::test]
async fn ping_acknowledgments_do_not_extend_the_outer_proxy_read_idle_limit() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (closed, closure) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        timeout(DEADLINE, raw_forward_peer(listener, acceptor, closed)).await?
    });

    let operation = async {
        let mut settings = phantom::profile::browser::firefox::v157_http2();
        settings.idle_timeout = Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(2));
        settings.preface_ping_after = None;
        settings.ping_timeout = None;
        settings.ping_failure_retries = 0;
        settings.idle_ping_after = Some(Duration::from_secs(1));
        settings.idle_ping_timeout = Some(Duration::from_secs(1));
        let client = Client::builder(firefox_profile().with_http2(settings))
            .add_proxy_root_certificate_der(identity.root_der.clone())
            .route(Route::http_proxy(
                HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?,
            ))
            .build()?;
        timeout(DEADLINE, empty_forward(&client)).await??;
        timeout(DEADLINE, closure).await??;
        drop(client);
        Ok(())
    }
    .await;
    let (requests, pings) = finish_peer(operation, peer).await?;
    assert_eq!(requests, 1);
    assert!(
        pings >= 1,
        "the independent peer must have acknowledged a PING"
    );
    Ok(())
}

#[tokio::test]
async fn expiry_preserves_a_live_connect_body_but_new_streams_use_another_outer() -> TestResult<()>
{
    use http_body_util::BodyExt;

    let proxy_identity = TestIdentity::generate()?;
    let origin_identity = TestIdentity::generate()?;
    let proxy = spawn_proxy(&proxy_identity).await?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin = listener.local_addr()?;
    let acceptor = origin_identity.acceptor(H1_ALPN)?;
    let (release, continue_body) = oneshot::channel();
    let origin_peer = ConnectionPeer::spawn(async move {
        timeout(DEADLINE, async {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nab")
                .await?;
            stream.flush().await?;
            continue_body.await?;
            stream.write_all(b"cd").await?;
            stream.shutdown().await?;
            TestResult::<()>::Ok(())
        })
        .await?
    });

    let operation = timeout(DEADLINE, async {
        let client = super::client(
            profile(Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(1))),
            &origin_identity,
            &proxy_identity,
            proxy.address,
        )?;
        let response = client
            .get(HttpProtocol::Http1, &format!("https://{origin}/"))?
            .send()
            .await?;
        let mut body = response.into_body();
        let mut prefix = Vec::new();
        while prefix.len() < 2 {
            let frame = body
                .frame()
                .await
                .ok_or("origin body missing")??
                .into_data()
                .map_err(|_| "origin body started with trailers")?;
            prefix.extend_from_slice(&frame);
        }
        assert_eq!(prefix, b"ab");
        // The observed body prefix establishes read readiness. This quiet
        // interval deliberately crosses the configured idle limit.
        tokio::time::sleep(QUIET).await;
        assert_eq!(proxy.completed_handlers()?, 0, "active CONNECT was aborted");
        get_forwarded(&client, "another.test").await?;
        let seen = observe_log(&proxy.log)?;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].method, http::Method::CONNECT);
        assert_eq!(seen[1].method, http::Method::GET);
        assert_ne!(seen[0].connection, seen[1].connection);

        release.send(()).map_err(|_| "origin body gate closed")?;
        assert_eq!(body.collect().await?.to_bytes(), "cd");
        timeout(DEADLINE, async {
            while proxy.completed_handlers()? == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            TestResult::<()>::Ok(())
        })
        .await??;
        drop(client);
        Ok(())
    })
    .await;
    let operation = match operation {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let origin = finish_peer(operation, origin_peer).await;
    finish_with_cleanup(origin, proxy.finish().await)
}

#[tokio::test]
async fn truncated_frame_header_is_an_error_instead_of_clean_eof() -> TestResult<()> {
    let mut bytes = &[0_u8, 0, 0][..];
    let error = frame(&mut bytes)
        .await
        .err()
        .ok_or("partial frame was accepted")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("partial header lost io error")?
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut eof = &[][..];
    assert!(frame(&mut eof).await?.is_none());
    Ok(())
}
