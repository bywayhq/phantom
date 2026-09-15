use std::{
    error::Error,
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body::Body as _;
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    runtime::Builder,
    sync::{Notify, oneshot},
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{TestResult, bounded_peer_test, headers, target};
use crate::http2::{Http2Body, body::DRIVER_SHUTDOWN_GRACE, send_get};
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

#[tokio::test]
async fn streams_data_then_trailers_without_buffering_later_data() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(streaming_server(server, release_rx));

        let response = send_get(
            client,
            &v152_macos_http2(),
            "example.test",
            target()?,
            headers(),
        )
        .await?;
        assert_eq!(response.status(), 206);
        let mut body = response.into_body();
        let first = next_nonempty_data(&mut body).await?;
        assert_eq!(first, "first");

        release_tx
            .send(())
            .map_err(|_| "server stopped before later data release")?;
        let mut later = None;
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) if !data.is_empty() => later = Some(data),
                Ok(_) => {}
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailers = Some(fields);
                    }
                }
            }
        }
        assert_eq!(later.as_deref(), Some(&b"later"[..]));
        assert_eq!(
            trailers
                .as_ref()
                .and_then(|fields| fields.get("x-finished"))
                .and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        let request = server_task.await??;
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(
            request.uri.authority().map(|value| value.as_str()),
            Some("example.test")
        );
        assert_eq!(
            request.uri.path_and_query().map(|value| value.as_str()),
            Some("/resource?item=1")
        );
        assert_eq!(request.repeat_count, 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn terminal_data_completes_without_an_extra_body_poll() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(terminal_data_server(server));

        async {
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            let frame = body
                .frame()
                .await
                .ok_or("response ended before terminal DATA")??;
            assert_eq!(frame.into_data().map_err(|_| "expected DATA")?, "terminal");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        assert!(!server_task.await??, "terminal DATA was followed by CANCEL");
        assert_eq!(
            subscriber.response_body_events(),
            [(8, "complete".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn incomplete_body_drop_flushes_reset_and_driver_closes() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(reset_observing_server(server));

        async {
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        let (reason, connection_closed) = server_task.await??;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(connection_closed);
        assert_eq!(
            subscriber.response_body_events(),
            [(7, "dropped".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn response_body_may_be_dropped_on_plain_thread() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(reset_observing_server(server));
        let body = async {
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");
            Ok::<_, Box<dyn Error + Send + Sync>>(body)
        }
        .with_subscriber(subscriber.clone())
        .await?;

        std::thread::spawn(move || drop(body))
            .join()
            .map_err(|_| "dropping HTTP/2 body outside its runtime panicked")?;
        let (reason, connection_closed) = server_task.await??;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(connection_closed);
        timeout(Duration::from_secs(1), async {
            while subscriber.outcomes_for("http2.connection_driver") != ["complete"] {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(
            |_| "cross-thread driver outcome was not recorded on its originating subscriber",
        )?;
        Ok(())
    })
    .await
}

#[test]
fn body_drop_after_originating_runtime_shutdown_records_driver_outcome() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().enable_time().build()?;
    let body = runtime.block_on(
        async {
            // Keep the stream terminal so this isolates supervisor cancellation
            // from the vendored codec's cleanup of abandoned live streams.
            let control = WriteControl::default();
            let (client, server) = duplex(64 * 1024);
            let _server_task = tokio::spawn(terminal_headers_server(server, control.clone()));
            let response = send_get(
                BlockingWrites {
                    inner: client,
                    control,
                },
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let body = response.into_body();
            assert!(body.is_end_stream());
            Ok::<_, Box<dyn Error + Send + Sync>>(body)
        }
        .with_subscriber(subscriber.clone()),
    )?;

    drop(runtime);
    drop(body);

    assert_eq!(
        subscriber.outcomes_for("http2.connection_driver"),
        ["runtime_shutdown"]
    );
    Ok(())
}

#[tokio::test]
async fn stalled_connection_driver_is_aborted_after_shutdown_grace() -> TestResult<()> {
    bounded_peer_test(async {
        let control = WriteControl::default();
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(reset_observing_server(server));

        async {
            let response = send_get(
                BlockingWrites {
                    inner: client,
                    control: control.clone(),
                },
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");

            control.blocked.store(true, Ordering::SeqCst);
            drop(body);
            let dropped = control.dropped_notify.notified();
            if !control.dropped.load(Ordering::SeqCst) {
                timeout(DRIVER_SHUTDOWN_GRACE + Duration::from_secs(1), dropped)
                    .await
                    .map_err(|_| "stalled HTTP/2 transport was not dropped after grace")?;
            }
            timeout(Duration::from_secs(1), async {
                while subscriber.outcomes_for("http2.connection_driver") != ["timeout"] {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "driver timeout outcome was not recorded")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        server_task.abort();
        let _ = server_task.await;
        assert!(control.dropped.load(Ordering::SeqCst));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelled_response_head_records_outcome_once() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(4096);
    let settings = v152_macos_http2();
    let pending = poll_once_then_drop(
        send_get(client, &settings, "example.test", target()?, vec![]),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/2 response-head future completed before cancellation".into());
    }
    assert_eq!(
        subscriber.outcomes_for("http2.response_head"),
        ["cancelled"]
    );
    Ok(())
}

async fn streaming_server(
    stream: DuplexStream,
    release_later: oneshot::Receiver<()>,
) -> TestResult<RequestObservation> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(206).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"first"), false)?;

    tokio::pin!(release_later);
    tokio::select! {
        result = &mut release_later => {
            result.map_err(std::io::Error::other)?;
        }
        incoming = connection.accept() => {
            if incoming.is_none() {
                return Err("connection closed before later data release".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    }

    send.send_data(Bytes::from_static(b"later"), false)?;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-finished", http::HeaderValue::from_static("yes"));
    send.send_trailers(trailers)?;
    let observation = RequestObservation {
        method: request.method().clone(),
        uri: request.uri().clone(),
        repeat_count: request.headers().get_all("x-repeat").iter().count(),
    };
    drop(request);
    drop(send);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(observation)
}

struct RequestObservation {
    method: http::Method,
    uri: http::Uri,
    repeat_count: usize,
}

async fn reset_observing_server(stream: DuplexStream) -> TestResult<(::http2::Reason, bool)> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"partial"), false)?;

    let reason = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => result?,
        incoming = connection.accept() => {
            if incoming.is_none() {
                return Err("connection closed without an observable stream reset".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    };
    drop(send);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok((reason, true))
}

async fn terminal_data_server(stream: DuplexStream) -> TestResult<bool> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"terminal"), true)?;
    drop(request);
    drop(respond);

    let reset = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => {
            result?;
            true
        }
        incoming = connection.accept() => {
            if incoming.is_some() {
                return Err("one-shot client sent an unexpected second request".into());
            }
            false
        }
    };
    drop(send);
    Ok(reset)
}

async fn terminal_headers_server(stream: DuplexStream, control: WriteControl) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(204).body(())?;
    respond.send_response(response, true)?;
    control.blocked.store(true, Ordering::SeqCst);
    drop(request);
    drop(respond);

    if connection.accept().await.is_some() {
        return Err("one-shot client sent an unexpected second request".into());
    }
    Ok(())
}

async fn next_nonempty_data(body: &mut Http2Body) -> TestResult<Bytes> {
    loop {
        let frame = body
            .frame()
            .await
            .ok_or("response ended before non-empty DATA")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

#[derive(Clone, Default)]
struct WriteControl {
    blocked: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    dropped_notify: Arc<Notify>,
}

struct BlockingWrites {
    inner: DuplexStream,
    control: WriteControl,
}

impl AsyncRead for BlockingWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for BlockingWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_flush(context)
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.control.blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }
}

impl Drop for BlockingWrites {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::SeqCst);
        self.control.dropped_notify.notify_one();
    }
}
