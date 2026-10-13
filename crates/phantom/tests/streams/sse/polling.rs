use std::{future::poll_fn, net::Ipv4Addr, pin::Pin, task::Poll, time::Duration};

use futures_core::Stream;
use phantom::{
    HttpProtocol, SseError, SseErrorKind, SseEvent, SseEventSource, SseLimits, SseStream,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    time::{Instant, timeout, timeout_at},
};

use super::{
    FixedResponsePeer, FixtureDeadline, SsePeer, TEST_TIMEOUT, TestResult, fixed_response,
    peer_completion,
    tls_support::{H1_ALPN, TestIdentity, accept_tls, read_head, test_client},
    write_chunk,
};

pub(super) async fn next<S>(stream: &mut S) -> Option<Result<SseEvent, SseError>>
where
    S: Stream<Item = Result<SseEvent, SseError>> + Unpin,
{
    poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
}

pub(super) async fn read(
    source: &mut SseEventSource,
    poll_stream: bool,
) -> Result<Option<SseEvent>, SseError> {
    if poll_stream {
        next(source).await.transpose()
    } else {
        source.next_event().await
    }
}

#[test]
fn stream_types_remain_send_and_unpin() {
    fn check<T: Send + Unpin + Stream<Item = Result<SseEvent, SseError>>>() {}
    check::<SseStream>();
    check::<SseEventSource>();
}

#[tokio::test]
async fn pending_stream_poll_can_be_dropped_and_resumed_with_next_event() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (partial_sent, partial_received) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
            )
            .await?;
        write_chunk(&mut stream, b"retry: 25\nid: private-event-id\ndata: hel").await?;
        partial_sent
            .send(())
            .map_err(|_| "client dropped before partial event")?;
        released.await?;
        write_chunk(&mut stream, b"lo\n\ndata: second\n\n").await?;
        stream.write_all(b"0\r\n\r\n").await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (_stream, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = test_client(&identity, false)?
            .get(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .send()
            .await?;
        let mut stream = SseStream::from_response(response)?.into_body();
        fn require_send<T: Send>(_: T) {}
        require_send(stream.next_event());
        partial_received.await?;
        // Cancel only after the decoder consumed the partial event. Socket
        // delivery can take longer than a short timer on a busy runner.
        poll_fn(|context| {
            assert!(Pin::new(&mut stream).poll_next(context).is_pending());
            if stream.retry_delay() == Some(Duration::from_millis(25)) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert_eq!(stream.last_event_id(), "");
        assert_eq!(stream.retry_delay(), Some(Duration::from_millis(25)));
        assert!(!format!("{stream:?}").contains("private-event-id"));
        release
            .send(())
            .map_err(|_| "server stopped before release")?;
        let first = stream.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.data(), "hello");
        assert_eq!(first.id(), "private-event-id");
        let second = next(&mut stream).await.ok_or("second event missing")??;
        assert_eq!(second.data(), "second");
        assert_eq!(second.id(), first.id());
        assert!(next(&mut stream).await.is_none());
        assert_eq!(stream.next_event().await?, None);
        Ok(stream)
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn stream_trait_reports_each_terminal_error_once() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut peer = FixedResponsePeer::default();
    let caller = {
        let operation = async {
            let identity = TestIdentity::generate()?;
            for (bytes, limits, kind) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 11\r\n\r\ndata: abc\n\n".as_slice(),
                SseLimits::new(4, 32),
                SseErrorKind::LineTooLong,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 11\r\n\r\ndata: abc\n\n".as_slice(),
                SseLimits::new(64, 4),
                SseErrorKind::EventTooLarge,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".as_slice(),
                SseLimits::default(),
                SseErrorKind::Body,
            ),
        ] {
            let response = fixed_response(&mut peer, &identity, bytes).await?;
            let mut stream = SseStream::from_response_with_limits(response, limits)?.into_body();
            let error = next(&mut stream)
                .await
                .ok_or("terminal error missing")?
                .err()
                .ok_or("invalid stream emitted an event")?;
            assert_eq!(error.kind(), kind);
            assert!(next(&mut stream).await.is_none());
            assert_eq!(stream.next_event().await?, None);
        }
            Ok(())
        };
        tokio::pin!(operation);
        match timeout_at(deadline, &mut operation).await {
            Ok(result) => result,
            Err(elapsed) => {
                Err(FixtureDeadline::new("SSE test exceeded its deadline", elapsed).into())
            }
        }
    };
    peer.finish(caller).await
}

#[tokio::test]
async fn event_source_trait_reports_reconnect_exhaustion_once() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Content-Length: 0\r\n\r\n",
            )
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (_source, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = test_client(&identity, false)?
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .max_reconnects(0)
            .connect()
            .await?;
        let mut source = response.into_body();
        fn require_send<T: Send>(_: T) {}
        require_send(source.next_event());
        let error = next(&mut source)
            .await
            .ok_or("reconnect exhaustion missing")?
            .err()
            .ok_or("empty response emitted an event")?;
        assert_eq!(error.kind(), SseErrorKind::ReconnectLimit);
        assert!(source.is_closed());
        assert_eq!(source.reconnects(), 0);
        assert!(next(&mut source).await.is_none());
        assert_eq!(source.next_event().await?, None);
        Ok(source)
    })
    .await?;
    Ok(())
}

#[test]
fn stream_polling_reports_missing_timer_driver_once() -> TestResult<()> {
    for idle_timeout in [None, Some(Duration::from_secs(1))] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut source = runtime.block_on(async {
            let deadline = Instant::now() + TEST_TIMEOUT;
            let identity = TestIdentity::generate()?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let acceptor = identity.acceptor(H1_ALPN)?;
            let mut server = SsePeer::spawn(async move {
                let mut stream = accept_tls(listener, acceptor).await?;
                read_head(&mut stream).await?;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                stream.shutdown().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            let (source, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
            let builder = test_client(&identity, false)?
                .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
                .initial_retry(Duration::ZERO)
                .max_reconnects(1);
            let builder = match idle_timeout {
                Some(timeout) => builder.idle_timeout(timeout),
                None => builder,
            };
            let source = builder.connect().await?.into_body();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(source)
            }).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(source)
        })?;
        drop(runtime);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        runtime.block_on(async {
            let error = next(&mut source)
                .await
                .ok_or("missing timer driver ended without an error")?
                .err()
                .ok_or("missing timer driver emitted an event")?;
            assert_eq!(error.kind(), SseErrorKind::Request);
            let cause = std::error::Error::source(&error)
                .and_then(|cause| cause.downcast_ref::<phantom::RequestError>())
                .ok_or("timer failure did not retain its request error")?;
            assert_eq!(cause.kind(), phantom::RequestErrorKind::RuntimeUnavailable);
            assert!(source.is_closed());
            assert_eq!(source.reconnects(), 0);
            assert!(next(&mut source).await.is_none());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_stream_poll_does_not_start_a_reconnect_between_polls() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (second_seen, mut second_seen_rx) = oneshot::channel();
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                      Content-Type: text/event-stream\r\n\
                      Content-Length: 0\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        read_head(&mut stream).await?;
        second_seen
            .send(())
            .map_err(|_| "client stopped before the reconnect was observed")?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (_source, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let mut source = test_client(&identity, false)?
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .initial_retry(Duration::from_secs(1))
            .max_reconnects(1)
            .connect()
            .await?
            .into_body();
        // Keep real time while TLS and socket I/O establish the response.
        // Freeze only the reconnect delay controlled by this assertion.
        tokio::time::pause();
        assert!(
            timeout(Duration::from_millis(500), next(&mut source))
                .await
                .is_err()
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(source.reconnects(), 0);
        assert!(matches!(
            second_seen_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        tokio::time::resume();
        assert!(next(&mut source).await.is_none());
        second_seen_rx.await?;
        assert_eq!(source.reconnects(), 1);
        assert!(source.is_closed());
        Ok(source)
    })
    .await?;
    Ok(())
}
