use std::{
    error::Error,
    future::poll_fn,
    task::{Context, Waker},
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use http_body::Body as _;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{DuplexStream, duplex},
    runtime::Builder,
    time::timeout,
};
use tracing::{Dispatch, dispatcher, instrument::WithSubscriber};

use super::{TestResult, bounded_peer_test, next_nonempty_data, target};
use crate::http2::send_get;
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

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

#[test]
fn response_body_may_be_dropped_on_plain_thread() -> TestResult<()> {
    let origin = OutcomeSubscriber::default();
    let other = OutcomeSubscriber::default();
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let other_dispatch = Dispatch::new(other.clone());
    dispatcher::with_default(&other_dispatch, || {
        runtime.block_on(bounded_peer_test(async {
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
            .with_subscriber(origin.clone())
            .await?;

            let thread_subscriber = other.clone();
            std::thread::spawn(move || {
                let dispatch = Dispatch::new(thread_subscriber);
                dispatcher::with_default(&dispatch, || drop(body));
            })
            .join()
            .map_err(|_| "dropping HTTP/2 body outside its runtime panicked")?;
            assert_eq!(origin.response_body_events(), [(7, "dropped".to_owned())]);
            assert!(other.response_body_events().is_empty());

            let (reason, connection_closed) = server_task.await??;
            assert_eq!(reason, ::http2::Reason::CANCEL);
            assert!(connection_closed);
            timeout(Duration::from_secs(1), async {
                while origin.outcomes_for("http2.connection_driver") != ["complete"]
                    || origin.connection_driver_events() != 1
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "cross-thread driver terminal telemetry missed its origin subscriber")?;
            assert_eq!(origin.connection_driver_events(), 1);
            assert_eq!(other.connection_driver_events(), 0);
            Ok(())
        }))
    })
}

#[tokio::test]
async fn cross_thread_body_poll_uses_originating_dispatcher() -> TestResult<()> {
    bounded_peer_test(async {
        let origin = OutcomeSubscriber::default();
        let other = OutcomeSubscriber::default();
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
            Ok::<_, Box<dyn Error + Send + Sync>>(response.into_body())
        }
        .with_subscriber(origin.clone())
        .await?;

        let origin_before = origin.response_body_polls_on_origin_dispatch();
        let other_before = other.response_body_polls_on_origin_dispatch();
        let thread_subscriber = other.clone();
        std::thread::spawn(move || {
            let dispatch = Dispatch::new(thread_subscriber);
            dispatcher::with_default(&dispatch, || {
                let mut body = Box::pin(body);
                let mut context = Context::from_waker(Waker::noop());
                let _ = body.as_mut().poll_frame(&mut context);
            });
        })
        .join()
        .map_err(|_| "cross-thread HTTP/2 body poll panicked")?;

        assert_eq!(
            origin.response_body_polls_on_origin_dispatch(),
            origin_before + 1,
            "body poll did not restore its origin tracing dispatcher"
        );
        assert_eq!(other.response_body_polls_on_origin_dispatch(), other_before);
        let (reason, connection_closed) = server_task.await??;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(connection_closed);
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

pub(super) async fn reset_observing_server(
    stream: DuplexStream,
) -> TestResult<(::http2::Reason, bool)> {
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
