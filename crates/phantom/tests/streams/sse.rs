//! Public SSE response-decoder integration tests.

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode, header};
use phantom::{Client, HttpProtocol, SseErrorKind, SseLimits, SseStream, profile::ClientProfile};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    time::{Instant, timeout, timeout_at},
};
use tracing::instrument::WithSubscriber;

use crate::support::{
    deadline::FixtureDeadline, h3 as h3_support, tls as tls_support, tracing as tracing_support,
};
use h3_support::{accept_request, client_settings, server_endpoint};
use peer_completion::SsePeer;
use tls_support::{H1_ALPN, TestIdentity, accept_tls, read_head, test_client};
use tracing_support::OutcomeSubscriber;

mod idle;
mod ownership;
mod peer_completion;
mod peer_ownership;
mod polling;
mod reconnect;
mod request;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn stream_is_pull_driven_and_pending_reads_are_cancellation_safe() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (partial_sent, partial_received) = oneshot::channel();
    let (resume, resumed) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let _ = read_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                      Content-Type: Text/Event-Stream; charset=utf-8\r\n\
                      Content-Encoding: identity\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
            )
            .await?;
        write_chunk(&mut stream, b"\xef\xbb\xbfretry: 25\ndata: hel").await?;
        partial_sent
            .send(())
            .map_err(|_| "client stopped before partial event")?;
        resumed.await?;
        write_chunk(&mut stream, b"lo\rid: first\r\r").await?;
        finished.await?;
        write_chunk(&mut stream, b"data: second\n\n").await?;
        stream.write_all(b"0\r\n\r\n").await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let (_events, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = test_client(&identity, false)?
            .get_with_protocol(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .send()
            .await?;
        let status = response.status();
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(status, 200);
        partial_received.await?;

        let subscriber = OutcomeSubscriber::default();
        let pending = timeout(
            Duration::from_millis(25),
            events.next_event().with_subscriber(subscriber.dispatch()),
        )
        .await;
        assert!(pending.is_err(), "partial event unexpectedly dispatched");
        assert_eq!(subscriber.outcomes_for("sse.next_event"), ["cancelled"]);

        resume
            .send(())
            .map_err(|_| "server stopped before stream resumed")?;
        let first = events.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.data(), "hello");
        assert_eq!(first.event(), "message");
        assert_eq!(first.id(), "first");
        assert_eq!(events.last_event_id(), "first");
        assert_eq!(events.retry_delay(), Some(Duration::from_millis(25)));

        finish
            .send(())
            .map_err(|_| "server stopped before final event")?;
        let second = events.next_event().await?.ok_or("second event missing")?;
        assert_eq!(second.data(), "second");
        assert_eq!(second.id(), "first");
        assert_eq!(events.next_event().await?, None);
        Ok(events)
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn response_validation_and_decode_failures_have_stable_categories() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut peer = FixedResponsePeer::default();
    let caller = {
        let operation = async {
            let identity = TestIdentity::generate()?;

            let response = fixed_response(
                &mut peer,
                &identity,
                b"HTTP/1.1 204 No Content\r\nContent-Type: text/event-stream\r\n\r\n",
            )
            .await?;
            let error = SseStream::from_response(response)
                .err()
                .ok_or("204 SSE response was accepted")?;
            assert_eq!(error.kind(), SseErrorKind::UnexpectedStatus);

            let response = fixed_response(
                &mut peer,
                &identity,
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
            let error = SseStream::from_response(response)
                .err()
                .ok_or("non-SSE content type was accepted")?;
            assert_eq!(error.kind(), SseErrorKind::InvalidContentType);

            let response = fixed_response(
            &mut peer,
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
            let error = SseStream::from_response(response)
                .err()
                .ok_or("encoded SSE response was accepted")?;
            assert_eq!(error.kind(), SseErrorKind::UnsupportedContentEncoding);

            let response = fixed_response(
            &mut peer,
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 11\r\n\r\ndata: abc\n\n",
        )
        .await?;
            let mut events =
                SseStream::from_response_with_limits(response, SseLimits::new(4, 32))?.into_body();
            let error = events
                .next_event()
                .await
                .err()
                .ok_or("oversized SSE line was accepted")?;
            assert_eq!(error.kind(), SseErrorKind::LineTooLong);

            let response = fixed_response(
            &mut peer,
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        )
        .await?;
            let mut events = SseStream::from_response(response)?.into_body();
            let error = events
                .next_event()
                .await
                .err()
                .ok_or("malformed SSE body framing was accepted")?;
            assert_eq!(error.kind(), SseErrorKind::Body);
            assert!(error.source().is_some());
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
async fn decoder_consumes_http2_response_body() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(tls_support::H2_ALPN)?;
    let mut server = SsePeer::spawn(async move {
        let stream = accept_tls(listener, acceptor).await?;
        let mut connection = ::http2::server::handshake(stream).await?;
        let (_, mut respond) = connection
            .accept()
            .await
            .ok_or("HTTP/2 connection closed before SSE request")??;
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        send.send_data(Bytes::from_static(b"data: h2\n\n"), true)?;
        drop(send);
        drop(respond);
        poll_fn(|context| connection.poll_closed(context)).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let (_events, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = test_client(&identity, true)?
            .get_with_protocol(HttpProtocol::Http2, &format!("https://{address}/events"))?
            .send()
            .await?;
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(
            events
                .next_event()
                .await?
                .map(|event| event.data().to_owned()),
            Some("h2".to_owned())
        );
        assert_eq!(events.next_event().await?, None);
        Ok(events)
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn decoder_consumes_http3_response_body() -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let mut server = SsePeer::spawn(async move {
        let (_, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(())?,
            )
            .await?;
        stream
            .send_data(Bytes::from_static(b"data: h3\n\n"))
            .await?;
        stream.finish().await?;
        done_received.await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });

    let (_events, ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = h3_client(&identity)?
            .get_with_protocol(HttpProtocol::Http3, &format!("https://{address}/events"))?
            .send()
            .await?;
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(
            events
                .next_event()
                .await?
                .map(|event| event.data().to_owned()),
            Some("h3".to_owned())
        );
        assert_eq!(events.next_event().await?, None);
        client_done
            .send(())
            .map_err(|_| "HTTP/3 SSE server stopped before completion")?;
        Ok(events)
    })
    .await?;
    Ok(())
}

fn h3_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tcp_tls = tls_support::tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn fixed_response(
    peer: &mut FixedResponsePeer,
    identity: &TestIdentity,
    response: &'static [u8],
) -> TestResult<http::Response<phantom::ResponseBody>> {
    peer.response(identity, response, None).await
}

async fn fixed_response_observed(
    identity: &TestIdentity,
    response: &'static [u8],
    observation: Option<peer_ownership::Observation>,
) -> TestResult<http::Response<phantom::ResponseBody>> {
    let mut peer = FixedResponsePeer::default();
    let caller = match timeout(TEST_TIMEOUT, peer.request(identity, response, observation)).await {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("SSE test exceeded its deadline", elapsed).into()),
    };
    peer.finish(caller).await
}

/// Retain the current fixed-response worker across an ordinary caller deadline.
#[derive(Debug, Default)]
struct FixedResponsePeer {
    worker: Option<SsePeer<()>>,
}

impl FixedResponsePeer {
    async fn response(
        &mut self,
        identity: &TestIdentity,
        response: &'static [u8],
        observation: Option<peer_ownership::Observation>,
    ) -> TestResult<http::Response<phantom::ResponseBody>> {
        let caller = self.request(identity, response, observation).await;
        self.finish(caller).await
    }

    async fn request(
        &mut self,
        identity: &TestIdentity,
        response: &'static [u8],
        mut observation: Option<peer_ownership::Observation>,
    ) -> TestResult<http::Response<phantom::ResponseBody>> {
        if self.worker.is_some() {
            return Err("fixed-response worker has not been collected".into());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let worker = observation.as_mut().and_then(|value| value.take_worker());
        let lifetime = worker.as_ref().map(|value| value.lifetime());
        self.worker = Some(SsePeer::spawn(async move {
            let _lifetime = lifetime;
            let stream = accept_tls(listener, acceptor).await?;
            let mut stream = peer_ownership::ObservedStream::new(stream, worker);
            let _ = read_head(&mut stream).await?;
            stream.write_all(response).await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));

        let observed_target = match observation {
            Some(value) => {
                let worker = self
                    .worker
                    .as_ref()
                    .ok_or("fixed-response worker missing")?;
                value.before_client(address, worker.abort_handle()).await?
            }
            None => None,
        };
        let target = format!("https://{address}/events");
        let target = match observed_target {
            Some(target) => target,
            None => &target,
        };
        let response = test_client(identity, false)?
            .get_with_protocol(HttpProtocol::Http1, target)?
            .send()
            .await?;
        Ok(response)
    }

    async fn finish<T>(&mut self, caller: TestResult<T>) -> TestResult<T> {
        let Some(worker) = &mut self.worker else {
            return caller;
        };
        let result = worker.finish(caller, TEST_TIMEOUT).await;
        if worker.is_collected() {
            drop(self.worker.take());
        }
        result.map(|(value, ())| value)
    }
}

async fn write_chunk(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
) -> std::io::Result<()> {
    stream
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|elapsed| FixtureDeadline::new("SSE test exceeded its deadline", elapsed))?
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::poll_fn, io, task::Poll};

    use super::{TestResult, bounded};

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
        tokio::time::advance(super::TEST_TIMEOUT).await;

        let error = operation.await.err().ok_or("pending operation succeeded")?;
        assert_eq!(error.to_string(), "SSE test exceeded its deadline");
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
}
