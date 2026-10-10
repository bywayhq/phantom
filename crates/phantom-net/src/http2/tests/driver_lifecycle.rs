use std::{
    error::Error,
    future::Future,
    task::{Context, Waker},
    time::Duration,
};

use http_body::Body as _;
use phantom_profile::browser::chrome::v154_http2;
use tokio::{io::duplex, runtime::Builder, task::JoinHandle, time::timeout};
use tracing::{Dispatch, dispatcher, instrument::WithSubscriber};

use super::{
    TestResult, bounded_peer_test, next_nonempty_data, reset_observing_server, send_once, target,
};

use crate::http2::PreparedRequest;
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

#[tokio::test]
async fn incomplete_body_drop_flushes_reset_and_driver_closes() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = spawn_reset_peer(reset_observing_server(server));

        let result = async {
            let response = send_once(client, {
                let settings = v154_http2();
                let method = http::Method::GET;
                let authority = "example.test";
                let target = target()?;
                let headers = vec![];
                let body = None;
                move || PreparedRequest::new(&settings, method, authority, target, headers, body)
            })
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await;

        finish_lifecycle_peer(server_task, result).await?;
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
            let server_task = spawn_reset_peer(reset_observing_server(server));
            let body = async {
                let response = send_once(client, {
                    let settings = v154_http2();
                    let method = http::Method::GET;
                    let authority = "example.test";
                    let target = target()?;
                    let headers = vec![];
                    let body = None;
                    move || {
                        PreparedRequest::new(&settings, method, authority, target, headers, body)
                    }
                })
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
            wait_for_origin_driver(&origin).await?;
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
        let server_task = spawn_reset_peer(reset_observing_server(server));
        let body = async {
            let response = send_once(client, {
                let settings = v154_http2();
                let method = http::Method::GET;
                let authority = "example.test";
                let target = target()?;
                let headers = vec![];
                let body = None;
                move || PreparedRequest::new(&settings, method, authority, target, headers, body)
            })
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
    let settings = v154_http2();
    let pending = poll_once_then_drop(
        send_once(client, {
            let settings = settings.clone();
            let method = http::Method::GET;
            let authority = "example.test";
            let target = target()?;
            let headers = vec![];
            let body = None;
            move || PreparedRequest::new(&settings, method, authority, target, headers, body)
        }),
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

#[test]
fn polling_outside_tokio_returns_runtime_unavailable() -> TestResult<()> {
    let (client, _server) = duplex(64);
    let settings = v154_http2();
    let mut request = Box::pin(send_once(client, {
        let settings = settings.clone();
        let method = http::Method::GET;
        let authority = "example.test";
        let target = target()?;
        let headers = vec![];
        let body = None;
        move || PreparedRequest::new(&settings, method, authority, target, headers, body)
    }));
    let mut context = Context::from_waker(Waker::noop());

    let std::task::Poll::Ready(result) = request.as_mut().poll(&mut context) else {
        return Err("HTTP/2 request waited without a Tokio runtime".into());
    };
    assert!(matches!(
        result,
        Err(crate::http2::Http2Error::RuntimeUnavailable)
    ));
    Ok(())
}

fn spawn_reset_peer(
    future: impl Future<Output = TestResult<(::http2::Reason, bool)>> + Send + 'static,
) -> JoinHandle<TestResult<(::http2::Reason, bool)>> {
    tokio::spawn(future)
}

async fn finish_lifecycle_peer(
    peer: JoinHandle<TestResult<(::http2::Reason, bool)>>,
    result: TestResult<()>,
) -> TestResult<()> {
    result?;

    let (reason, connection_closed) = peer.await??;
    assert_eq!(reason, ::http2::Reason::CANCEL);
    assert!(connection_closed);
    Ok(())
}

async fn wait_for_origin_driver(origin: &OutcomeSubscriber) -> TestResult<()> {
    timeout(Duration::from_secs(1), async {
        while origin.outcomes_for("http2.connection_driver") != ["complete"]
            || origin.connection_driver_events() != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "cross-thread driver terminal telemetry missed its origin subscriber")?;
    Ok(())
}

mod completion_controls;
