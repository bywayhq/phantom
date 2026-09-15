use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use http_body_util::BodyExt;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tracing::{Dispatch, instrument::WithSubscriber};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    http1::{Http1Error, MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, RequestHeader, send_get},
    tracing_test::{OutcomeSubscriber, poll_once_then_drop},
};

#[tokio::test]
async fn cancelled_response_head_records_outcome_once() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(4096);
    let pending = poll_once_then_drop(
        send_get(client, target()?, vec![host()]),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/1 response-head future completed before cancellation".into());
    }

    assert_eq!(
        subscriber.outcomes_for("http1.response_head"),
        ["cancelled"]
    );
    Ok(())
}

#[tokio::test]
async fn writes_exact_order_casing_and_duplicates() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_get(
            client,
            target()?,
            vec![
                host(),
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ],
        ));

        let request = read_head(&mut server).await?;
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );

        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let response = transaction.await??;
        response.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_ambiguous_response_framing() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
        });

        let result = send_get(client, target()?, vec![host()])
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(result, Err(Http1Error::AmbiguousResponseFraming)));
        assert_eq!(
            subscriber.outcomes_for("http1.response_head"),
            ["invalid_response"]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepts_interim_response_across_one_byte_reads() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 100 Continue\r\nX-Interim: ignored\r\n\r\n\
                      HTTP/1.1 200 OK\r\nX-Final: kept\r\nContent-Length: 5\r\n\r\nhello",
                )
                .await
        });

        let response =
            send_get(OneByteReadStream { inner: client }, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get("x-final"), Some(&"kept".parse()?));
        assert!(response.headers().get("x-interim").is_none());
        assert_eq!(response.into_body().collect().await?.to_bytes(), "hello");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepts_multiple_distinct_interim_responses() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
                      HTTP/1.1 100 Continue\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                )
                .await
        });

        let response =
            send_get(OneByteReadStream { inner: client }, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 200);
        assert!(response.headers().get("link").is_none());
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn protocol_failure_has_specific_response_head_outcome() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(b"not an HTTP response\r\n\r\n").await?;
            server.shutdown().await
        });

        let result = send_get(client, target()?, vec![host()])
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(result, Err(Http1Error::Protocol(_))));
        assert_eq!(
            subscriber.outcomes_for("http1.response_head"),
            ["protocol_error"]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_request_is_traced_before_stream_io() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let writes = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_get(
        WriteCountingStream {
            inner: client,
            writes: Arc::clone(&writes),
        },
        target()?,
        Vec::new(),
    )
    .with_subscriber(Dispatch::new(subscriber.clone()))
    .await;

    assert!(matches!(result, Err(Http1Error::MissingHost)));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(subscriber.outcomes_for("http1.request.prepare"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("http1.request.prepare"),
        ["missing_host"]
    );
    assert!(subscriber.outcomes_for("http1.response_head").is_empty());
    Ok(())
}

#[tokio::test]
async fn invalid_headers_never_touch_the_stream() -> TestResult {
    bounded_peer_test(async {
        let mut cases = vec![
            vec![],
            vec![host(), host()],
            vec![host(), RequestHeader::new("Content-Length", "0")],
            vec![host(), RequestHeader::new("Transfer-Encoding", "chunked")],
            vec![host(), RequestHeader::new("bad name", "value")],
            vec![host(), RequestHeader::new("X-Bad", b"ok\r\nInjected: yes")],
        ];
        let mut too_many = Vec::with_capacity(MAX_REQUEST_HEADERS + 1);
        too_many.push(host());
        for index in 0..MAX_REQUEST_HEADERS {
            too_many.push(RequestHeader::new(format!("x-{index}"), "value"));
        }
        cases.push(too_many);
        cases.push(vec![
            host(),
            RequestHeader::new("X-Large", vec![b'a'; MAX_REQUEST_HEADER_BYTES]),
        ]);

        for headers in cases {
            let writes = Arc::new(AtomicUsize::new(0));
            let (client, _server) = duplex(128);
            let stream = WriteCountingStream {
                inner: client,
                writes: Arc::clone(&writes),
            };
            let result = send_get(stream, target()?, headers).await;
            assert!(result.is_err());
            assert_eq!(writes.load(Ordering::SeqCst), 0);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn canceling_request_closes_stream() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_get(client, target()?, vec![host()]));
        read_head(&mut server).await?;

        transaction.abort();
        let join_error = match transaction.await {
            Ok(_) => return Err("request task completed after cancellation".into()),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled());
        let mut byte = [0_u8; 1];
        let count = server.read(&mut byte).await?;
        assert_eq!(count, 0);
        Ok(())
    })
    .await
}

struct WriteCountingStream {
    inner: DuplexStream,
    writes: Arc<AtomicUsize>,
}

struct OneByteReadStream {
    inner: DuplexStream,
}

impl AsyncRead for OneByteReadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut byte = [0_u8; 1];
        let mut limited = ReadBuf::new(&mut byte);
        match Pin::new(&mut self.inner).poll_read(context, &mut limited) {
            Poll::Ready(Ok(())) => {
                buffer.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for OneByteReadStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl AsyncRead for WriteCountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for WriteCountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.writes.fetch_add(buffer.len(), Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
