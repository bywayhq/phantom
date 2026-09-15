use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::BodyExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{
    Http1Error, MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, OriginForm, RequestHeader, send_get,
};
use crate::request::InvalidOriginForm;
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(2);

async fn bounded_peer_test<F>(future: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    // One deadline covers all peer I/O and task joins; making progress does
    // not restart it and therefore cannot extend a hung test indefinitely.
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/1 peer test exceeded its absolute deadline".into()),
    }
}

fn target() -> Result<OriginForm, InvalidOriginForm> {
    OriginForm::parse("/resource?item=1")
}

fn host() -> RequestHeader {
    RequestHeader::new("Host", "example.test")
}

#[tokio::test]
async fn cancelled_response_head_records_outcome_once() -> Result<(), Box<dyn std::error::Error>> {
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

async fn read_head(stream: &mut DuplexStream) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

#[tokio::test]
async fn writes_exact_order_casing_and_duplicates() -> Result<(), Box<dyn std::error::Error>> {
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
async fn streams_first_data_before_later_data_exists() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            release_rx.await.map_err(std::io::Error::other)?;
            server.write_all(b"later").await
        });

        let response = send_get(client, target()?, vec![host()]).await?;
        let mut body = response.into_body();
        let first = body
            .frame()
            .await
            .ok_or("body ended before first data")??
            .into_data()
            .map_err(|_| "expected data frame")?;
        assert_eq!(first, "first");

        let _ = release_tx.send(());
        let rest = body.collect().await?.to_bytes();
        assert_eq!(rest, "later");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn content_length_ends_without_socket_eof() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });
        let target = target()?;

        let collected = async {
            let body = send_get(client, target, vec![host()]).await?.into_body();
            body.collect().await
        }
        .with_subscriber(subscriber.clone())
        .await?;
        assert_eq!(collected.to_bytes(), "hello");
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "complete".to_owned())]
        );
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn decodes_chunked_data_and_trailers() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n5\r\nhello\r\n0\r\nX-Final: yes\r\n\r\n",
                )
                .await
        });

        let mut body = send_get(client, target()?, vec![host()]).await?.into_body();
        let data = body
            .frame()
            .await
            .ok_or("missing data frame")??
            .into_data()
            .map_err(|_| "expected data frame")?;
        assert_eq!(data, "hello");
        let trailers = body
            .frame()
            .await
            .ok_or("missing trailers frame")??
            .into_trailers()
            .map_err(|_| "expected trailers frame")?;
        assert_eq!(trailers.get("x-final"), Some(&"yes".parse()?));
        assert!(body.frame().await.is_none());
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reads_close_delimited_body() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose body")
                .await?;
            server.shutdown().await
        });

        let body = send_get(client, target()?, vec![host()]).await?.into_body();
        assert_eq!(body.collect().await?.to_bytes(), "close body");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reports_truncated_content_length() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
                .await?;
            server.shutdown().await
        });
        let target = target()?;

        let collected = async {
            let body = send_get(client, target, vec![host()]).await?.into_body();
            body.collect().await
        }
        .with_subscriber(subscriber.clone())
        .await;
        let error = match collected {
            Ok(_) => return Err("truncated body accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(error, Http1Error::Protocol(_)), "{error:?}");
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "protocol_error".to_owned())]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_ambiguous_response_framing() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
        });

        let result = send_get(client, target()?, vec![host()]).await;
        assert!(matches!(result, Err(Http1Error::AmbiguousResponseFraming)));
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn status_204_has_no_body_without_socket_eof() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 99\r\n\r\n")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        let response = send_get(client, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 204);
        let body = response.into_body().collect().await?;
        assert!(body.to_bytes().is_empty());
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_headers_never_touch_the_stream() -> Result<(), Box<dyn std::error::Error>> {
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
async fn canceling_request_closes_stream() -> Result<(), Box<dyn std::error::Error>> {
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

#[tokio::test]
async fn dropping_body_closes_stream() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfirst")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        async {
            let response = send_get(client, target()?, vec![host()]).await?;
            let mut body = response.into_body();
            let data = body
                .frame()
                .await
                .ok_or("body ended before partial data")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            assert_eq!(data, "first");
            drop(body);
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "dropped".to_owned())]
        );
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn completed_body_deliberately_prevents_reuse() -> Result<(), Box<dyn std::error::Error>> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await?;
            Ok::<_, std::io::Error>(remaining)
        });

        send_get(client, target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?;
        assert!(server_task.await??.is_empty());
        Ok(())
    })
    .await
}

struct WriteCountingStream {
    inner: DuplexStream,
    writes: Arc<AtomicUsize>,
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
