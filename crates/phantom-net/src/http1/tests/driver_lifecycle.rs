use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http_body_util::BodyExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
};
use tracing::{dispatcher, instrument::WithSubscriber};

use super::{TestResult, bounded_peer_test, host, read_head, target, wait_for_driver_outcome};
use crate::{http1::send_get, tracing_test::OutcomeSubscriber};

#[tokio::test]
async fn dropping_body_closes_stream() -> TestResult {
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
        .with_subscriber(subscriber.dispatch())
        .await?;
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "dropped".to_owned())]
        );
        assert_eq!(server_task.await??, 0);
        wait_for_driver_outcome(&subscriber, "cancelled").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn response_body_may_be_dropped_on_plain_thread() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let other_subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfirst")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        let body = async {
            let response = send_get(client, target()?, vec![host()]).await?;
            let mut body = response.into_body();
            let data = body
                .frame()
                .await
                .ok_or("body ended before partial data")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            assert_eq!(data, "first");
            Ok::<_, Box<dyn std::error::Error>>(body)
        }
        .with_subscriber(subscriber.dispatch())
        .await?;

        let thread_subscriber = other_subscriber.clone();
        std::thread::spawn(move || {
            let dispatch = thread_subscriber.dispatch();
            dispatcher::with_default(&dispatch, || drop(body));
        })
        .join()
        .map_err(|_| "dropping HTTP/1 body outside its runtime panicked")?;
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "dropped".to_owned())]
        );
        assert!(other_subscriber.response_body_events().is_empty());
        assert_eq!(server_task.await??, 0);
        wait_for_driver_outcome(&subscriber, "cancelled").await?;
        assert_eq!(subscriber.connection_driver_events(), 1);
        assert_eq!(other_subscriber.connection_driver_events(), 0);
        Ok(())
    })
    .await
}

#[test]
fn response_body_poll_uses_origin_dispatch_on_plain_thread() -> TestResult {
    let (body_tx, body_rx) = std::sync::mpsc::sync_channel(1);
    let origin_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let origin_subscriber = OutcomeSubscriber::default();
            let (client, mut server) = duplex(4096);
            let server_task = tokio::spawn(async move {
                read_head(&mut server).await?;
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await?;
                let mut byte = [0_u8; 1];
                server.read(&mut byte).await
            });
            let request_target = target().map_err(|_| "test target should be valid")?;
            let body = async {
                send_get(client, request_target, vec![host()])
                    .await
                    .map(|response| response.into_body())
            }
            .with_subscriber(origin_subscriber.dispatch())
            .await?;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            body_tx
                .send((body, origin_subscriber, shutdown_tx))
                .map_err(|_| "test thread stopped before receiving the response body")?;
            let _ = shutdown_rx.await;
            if server_task.await?? != 0 {
                return Err("HTTP/1 transport remained open after body completion".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
    });

    let (body, origin_subscriber, shutdown_tx) = body_rx.recv_timeout(Duration::from_secs(1))?;
    let other_subscriber = OutcomeSubscriber::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let bytes = runtime
        .block_on(async { body.collect().await }.with_subscriber(other_subscriber.dispatch()))?;
    assert_eq!(bytes.to_bytes(), "hello");
    assert!(
        origin_subscriber.response_body_polls_on_origin_dispatch() > 0,
        "body polls did not restore their origin tracing dispatcher"
    );
    assert_eq!(other_subscriber.response_body_polls_on_origin_dispatch(), 0);

    let _ = shutdown_tx.send(());
    let origin_result = origin_thread
        .join()
        .map_err(|_| "origin runtime thread panicked")?;
    origin_result.map_err(|error| error as Box<dyn std::error::Error>)?;
    Ok(())
}

#[tokio::test]
async fn connection_driver_panic_records_task_error() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let panic_reads = Arc::new(AtomicBool::new(false));
        let (client, mut server) = duplex(4096);
        let stream = PanicReadStream {
            inner: client,
            panic_reads: Arc::clone(&panic_reads),
        };
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            release_rx.await.map_err(std::io::Error::other)?;
            let _ = server.write_all(b"!").await;
            Ok::<_, std::io::Error>(())
        });

        let body = async {
            let response = send_get(stream, target()?, vec![host()]).await?;
            let mut body = response.into_body();
            let data = body
                .frame()
                .await
                .ok_or("body ended before partial data")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            assert_eq!(data, "first");
            Ok::<_, Box<dyn std::error::Error>>(body)
        }
        .with_subscriber(subscriber.dispatch())
        .await?;

        panic_reads.store(true, Ordering::SeqCst);
        let _ = release_tx.send(());
        wait_for_driver_outcome(&subscriber, "task_error").await?;
        drop(body);
        server_task.await??;
        Ok(())
    })
    .await
}

#[test]
fn runtime_shutdown_records_driver_outcome_once() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let body = runtime.block_on(
        async {
            let (client, mut server) = duplex(4096);
            tokio::spawn(async move {
                read_head(&mut server).await?;
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                    .await?;
                std::future::pending::<Result<(), std::io::Error>>().await
            });
            let response = send_get(client, target()?, vec![host()]).await?;
            let mut body = response.into_body();
            let data = body
                .frame()
                .await
                .ok_or("body ended before partial data")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            assert_eq!(data, "first");
            Ok::<_, Box<dyn std::error::Error>>(body)
        }
        .with_subscriber(subscriber.dispatch()),
    )?;

    drop(runtime);
    assert_eq!(
        subscriber.outcomes_for("http1.connection_driver"),
        ["runtime_shutdown"]
    );
    drop(body);
    assert_eq!(
        subscriber.outcomes_for("http1.connection_driver"),
        ["runtime_shutdown"]
    );
    Ok(())
}

#[tokio::test]
async fn completed_body_deliberately_prevents_reuse() -> TestResult {
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

struct PanicReadStream {
    inner: DuplexStream,
    panic_reads: Arc<AtomicBool>,
}

impl AsyncRead for PanicReadStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        assert!(
            !self.panic_reads.load(Ordering::SeqCst),
            "injected connection driver panic"
        );
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PanicReadStream {
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

#[test]
fn polling_outside_tokio_returns_runtime_unavailable() -> TestResult {
    let (client, _server) = duplex(64);
    let mut request = Box::pin(send_get(client, target()?, vec![host()]));
    let mut context = Context::from_waker(std::task::Waker::noop());

    let Poll::Ready(result) = request.as_mut().poll(&mut context) else {
        return Err("HTTP/1 request waited without a Tokio runtime".into());
    };
    assert!(matches!(
        result,
        Err(crate::http1::Http1Error::RuntimeUnavailable)
    ));
    Ok(())
}
