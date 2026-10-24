use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};

use super::{TestResult, bounded_peer_test, host, peer_task::PeerTask, read_head, target};
use crate::http1::{Http1Connection, Http1Error, Http1WriteStrategy};

// Models a scalar transport such as TLS, including short writes and backpressure.
struct ShortWrites {
    inner: DuplexStream,
    coalesced: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
}

impl AsyncRead for ShortWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ShortWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .is_some_and(|end| end + 4 < bytes.len())
        {
            self.coalesced.store(true, Ordering::SeqCst);
        }
        Pin::new(&mut self.inner).poll_write(context, &bytes[..bytes.len().min(7)])
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn scalar_short_writes_preserve_upload_bytes_and_connection_reuse() -> TestResult {
    for strategy in [Http1WriteStrategy::Automatic, Http1WriteStrategy::Queued] {
        bounded_peer_test(async {
            let (client, mut server) = duplex(64);
            let coalesced = Arc::new(AtomicBool::new(false));
            let writes = Arc::new(AtomicUsize::new(0));
            let connection = Http1Connection::connect_with_write_strategy(
                ShortWrites {
                    inner: client,
                    coalesced: coalesced.clone(),
                    writes: writes.clone(),
                },
                strategy,
            )
            .await?;
            let target = target()?;
            let transaction = PeerTask::spawn(async move {
                for _ in 0..2 {
                    let response = connection
                        .send_request(
                            Method::POST,
                            target.clone(),
                            vec![
                                host(),
                                crate::request::RequestHeader::new("X-Order", "last"),
                            ],
                            Some(Bytes::from(vec![b'x'; 512])),
                        )
                        .await?;
                    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                }
                Ok::<_, Http1Error>(())
            });

            for _ in 0..2 {
                assert_eq!(
                    read_head(&mut server).await?,
                    b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\
                      X-Order: last\r\nContent-Length: 512\r\n\r\n"
                );
                let mut body = [0; 512];
                server.read_exact(&mut body).await?;
                assert_eq!(body, [b'x'; 512]);
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await?;
            }
            transaction.await??;
            assert!(writes.load(Ordering::SeqCst) > 0);
            assert_eq!(
                coalesced.load(Ordering::SeqCst),
                strategy == Http1WriteStrategy::Automatic
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn queued_request_validation_writes_nothing() -> TestResult {
    let (client, _server) = duplex(64);
    let writes = Arc::new(AtomicUsize::new(0));
    let coalesced = Arc::new(AtomicBool::new(false));
    let connection = Http1Connection::connect_with_write_strategy(
        ShortWrites {
            inner: client,
            coalesced: coalesced.clone(),
            writes: writes.clone(),
        },
        Http1WriteStrategy::Queued,
    )
    .await?;
    let result = connection
        .send_request(
            Method::POST,
            target()?,
            vec![
                host(),
                crate::request::RequestHeader::new("Content-Length", "1"),
            ],
            Some(Bytes::from_static(b"invalid length")),
        )
        .await;
    assert!(matches!(
        result,
        Err(Http1Error::InvalidContentLength { .. })
    ));
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert!(!coalesced.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn cancelling_a_backpressured_queued_upload_closes_its_stream() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(64);
        let connection =
            Http1Connection::connect_with_write_strategy(client, Http1WriteStrategy::Queued)
                .await?;
        let target = target()?;
        let transaction = PeerTask::spawn(async move {
            connection
                .send_request(
                    Method::POST,
                    target,
                    vec![host()],
                    Some(Bytes::from(vec![b'x'; 1024 * 1024])),
                )
                .await
        });
        assert_eq!(
            read_head(&mut server).await?,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\
              Content-Length: 1048576\r\n\r\n"
        );
        transaction.abort();
        let error = transaction
            .await
            .err()
            .ok_or("upload completed despite backpressure")?;
        assert!(error.is_cancelled());
        let mut partial = Vec::new();
        server.read_to_end(&mut partial).await?;
        assert!(partial.len() < 1024 * 1024);
        assert!(partial.iter().all(|byte| *byte == b'x'));
        Ok(())
    })
    .await
}
