use std::{error::Error, net::Ipv4Addr, pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use http::StatusCode;
use phantom::{
    HttpProtocol, OrderedResponseHeaders, RequestHeader, ResponseInfo, Route, SseErrorKind,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, advance, timeout},
};
use tokio_btls::SslStream;

use super::{
    TestResult,
    tls_support::{H1_ALPN, TestIdentity, read_head, test_client},
};

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn session_event_source_reconnects_with_committed_state_and_stops_on_204() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (first_complete, first_complete_rx) = oneshot::channel();
    let (second_seen, second_seen_rx) = oneshot::channel();
    let (release_second, release_second_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut first = accept_tls_reusable(&listener, &acceptor).await?;
        let first_head = read_head(&mut first).await?;
        first
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  X-MiXeD: first\r\n\
                  Set-Cookie: sid=one; Path=/\r\n\
                  X-MiXeD: second\r\n\
                  Content-Length: 45\r\n\r\n\
                  retry: 1000\nid: first\ndata: one\n\nid: ignored\n",
            )
            .await?;
        first.flush().await?;
        first_complete
            .send(())
            .map_err(|_| "client stopped before the first SSE response completed")?;

        let second_head = read_head(&mut first).await?;
        second_seen
            .send(())
            .map_err(|_| "client stopped before the reconnect was observed")?;
        release_second_rx
            .await
            .map_err(|_| "client stopped before the reconnect response was released")?;
        first
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        first.shutdown().await?;

        Ok::<_, Box<dyn Error + Send + Sync>>((listener, first_head, second_head))
    });

    let client = test_client(&identity, false)?;
    #[cfg(feature = "cookies")]
    let session = client.session_builder().cookies().build();
    #[cfg(not(feature = "cookies"))]
    let session = client.session();
    let response = session
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .header(RequestHeader::new("X-User", "stable"))
        .route(Route::Direct)
        .initial_retry(Duration::from_secs(3))
        .max_reconnects(1)
        .connect()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let ordered = response
        .extensions()
        .get::<OrderedResponseHeaders>()
        .ok_or("SSE response omitted ordered fields")?;
    assert_eq!(
        ordered
            .iter()
            .map(|header| (header.name(), header.value()))
            .take(4)
            .collect::<Vec<_>>(),
        [
            ("Content-Type", b"text/event-stream".as_slice()),
            ("X-MiXeD", b"first".as_slice()),
            ("Set-Cookie", b"sid=one; Path=/".as_slice()),
            ("X-MiXeD", b"second".as_slice()),
        ]
    );
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("SSE response omitted response info")?;
    assert_eq!(info.effective_uri().path(), "/events");

    let mut source = response.into_body();
    let event = source.next_event().await?.ok_or("first event missing")?;
    assert_eq!(event.data(), "one");
    assert_eq!(event.id(), "first");
    assert_eq!(source.last_event_id(), "first");
    assert_eq!(source.retry_delay(), Duration::from_secs(1));
    first_complete_rx
        .await
        .map_err(|_| "server stopped before completing the first SSE response")?;

    assert!(
        timeout(Duration::from_millis(900), source.next_event())
            .await
            .is_err(),
        "reconnect completed before its server-supplied delay"
    );
    let resumed_at = Instant::now();
    {
        let reconnect = source.next_event();
        tokio::pin!(reconnect);
        tokio::select! {
            result = &mut reconnect => {
                return Err(format!("reconnect completed before its response was released: {result:?}").into());
            }
            observed = second_seen_rx => {
                observed.map_err(|_| "server stopped before observing the reconnect")?;
            }
        }
    }
    assert_eq!(
        Instant::now().duration_since(resumed_at),
        Duration::from_millis(100),
        "cancelled reconnect restarted its delay"
    );
    assert_eq!(source.reconnects(), 1);
    assert!(
        format!("{source:?}").contains("connecting: true"),
        "cancelled read did not retain its in-flight reconnect"
    );

    let continued_at = Instant::now();
    release_second
        .send(())
        .map_err(|_| "server stopped before reconnect response release")?;
    let stopped = source.next_event().await?;
    assert_eq!(
        Instant::now().duration_since(continued_at),
        Duration::ZERO,
        "resuming an in-flight reconnect started another delay"
    );
    assert_eq!(stopped, None);
    assert!(source.is_closed());
    assert_eq!(source.reconnects(), 1);
    assert_eq!(source.next_event().await?, None);

    advance(Duration::from_secs(1)).await;
    let (listener, first_head, second_head) = server.await??;
    for head in [&first_head, &second_head] {
        assert_eq!(count_header(head, b"accept"), 1);
        assert!(contains_header(head, b"accept", b"text/event-stream"));
        assert_eq!(count_header(head, b"cache-control"), 1);
        assert!(contains_header(head, b"cache-control", b"no-cache"));
    }
    assert!(contains_header(&first_head, b"x-user", b"stable"));
    assert_eq!(count_header(&first_head, b"last-event-id"), 0);
    assert!(contains_header(&second_head, b"x-user", b"stable"));
    assert_eq!(count_header(&second_head, b"last-event-id"), 1);
    assert!(contains_header(&second_head, b"last-event-id", b"first"));
    #[cfg(feature = "cookies")]
    assert!(contains_header(&second_head, b"cookie", b"sid=one"));
    let listener = listener.into_std()?;
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "204 triggered a third connection attempt"
    );
    Ok(())
}

#[tokio::test]
async fn event_source_retries_an_initial_transport_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let (failed, _) = listener.accept().await?;
        drop(failed);

        let mut stream = accept_tls_reusable(&listener, &acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(head)
    });

    let response = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .initial_retry(Duration::ZERO)
        .max_reconnects(1)
        .connect()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.body().is_closed());
    assert_eq!(response.body().reconnects(), 1);

    let head = server.await??;
    assert_eq!(count_header(&head, b"last-event-id"), 0);
    Ok(())
}

#[tokio::test]
async fn event_source_reports_the_last_initial_failure_after_exhaustion() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (failed, _) = listener.accept().await?;
            drop(failed);
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let error = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .initial_retry(Duration::ZERO)
        .max_reconnects(1)
        .connect()
        .await
        .err()
        .ok_or("exhausted initial reconnects unexpectedly succeeded")?;
    assert_eq!(error.kind(), SseErrorKind::ReconnectLimit);
    assert!(error.source().is_some());
    server.await??;
    Ok(())
}

#[tokio::test]
async fn invalid_initial_retry_fails_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;

    let error = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .initial_retry(Duration::MAX)
        .max_reconnects(1)
        .connect()
        .await
        .err()
        .ok_or("unrepresentable initial reconnect delay was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidReconnectDelay);

    let listener = listener.into_std()?;
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "invalid reconnect configuration touched the network"
    );
    Ok(())
}

#[tokio::test]
async fn event_source_rejects_caller_last_event_id_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let error = test_client(&identity, false)?
        .session()
        .event_source(HttpProtocol::Http1, "https://127.0.0.1:1/events")?
        .header(RequestHeader::new("Last-Event-ID", "caller-value"))
        .connect()
        .await
        .err()
        .ok_or("caller-supplied Last-Event-ID was accepted")?;

    assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    Ok(())
}

async fn accept_tls_reusable(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

fn count_header(head: &[u8], name: &[u8]) -> usize {
    header_values(head, name).count()
}

fn contains_header(head: &[u8], name: &[u8], value: &[u8]) -> bool {
    header_values(head, name).any(|observed| observed == value)
}

fn header_values<'a>(head: &'a [u8], name: &'a [u8]) -> impl Iterator<Item = &'a [u8]> + 'a {
    head.split(|byte| *byte == b'\n').filter_map(move |line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|byte| *byte == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(name)
            .then(|| line[colon + 1..].trim_ascii())
    })
}
