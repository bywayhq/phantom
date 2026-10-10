use std::{future::poll_fn, task::Poll, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response};
use tokio::{sync::oneshot, time::timeout};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{TestResult, has_ended};

#[derive(Clone, Copy)]
enum Ending {
    InternalError,
    Cancel,
    Eof,
}

async fn observed_ending(ending: Ending) -> TestResult<()> {
    let (client_io, server_io) = tokio::io::duplex(8192);
    let (ready, acquired) = oneshot::channel();
    let (observed, observation) = oneshot::channel();
    let server = ConnectionPeer::spawn(async move {
        let mut connection = ::http2::server::handshake(server_io).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("stream peer missed GET")??;
        assert_eq!(request.method(), Method::GET);
        let mut send = respond.send_response(Response::new(()), false)?;
        send.send_data(Bytes::from_static(b"forwarded"), true)?;
        let (first, first_response) = connection
            .accept()
            .await
            .ok_or("stream peer missed first CONNECT")??;
        let (second, mut second_response) = connection
            .accept()
            .await
            .ok_or("stream peer missed second CONNECT")??;
        assert_eq!(first.method(), Method::CONNECT);
        assert_eq!(second.method(), Method::CONNECT);
        assert_eq!(
            first.uri().authority().map(|value| value.as_str()),
            Some("origin.test:443")
        );
        let mut first = first.into_body();
        let mut second = second.into_body();
        ready
            .send(())
            .map_err(|_| "stream readiness receiver disappeared")?;

        let independent = poll_fn(|context| {
            if let Poll::Ready(Some(Err(error))) = connection.poll_accept(context) {
                return Poll::Ready(Err(error));
            }
            first.poll_data(context).map(Ok)
        })
        .await?;
        match ending {
            Ending::InternalError | Ending::Cancel => {
                let expected = if matches!(ending, Ending::InternalError) {
                    ::http2::Reason::INTERNAL_ERROR
                } else {
                    ::http2::Reason::CANCEL
                };
                let error = independent
                    .ok_or("reset stream appeared as EOF")?
                    .err()
                    .ok_or("reset stream produced data")?;
                assert_eq!(error.reason(), Some(expected));
                let reset = poll_fn(|context| {
                    if let Poll::Ready(Some(Err(error))) = connection.poll_accept(context) {
                        return Poll::Ready(Err(error));
                    }
                    second_response.poll_reset(context)
                })
                .await?;
                assert_eq!(reset, expected);
            }
            Ending::Eof => {
                assert!(independent.is_none());
                poll_fn(|context| {
                    if let Poll::Ready(Some(Err(error))) = connection.poll_accept(context) {
                        return Poll::Ready(Err(error));
                    }
                    if second.is_end_stream() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                })
                .await?;
            }
        }
        drop(first_response);
        drop(send);
        observed
            .send(has_ended(&mut second))
            .map_err(|_| "body observation receiver disappeared")?;
        std::future::pending::<()>().await;
        drop(connection);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (mut requests, driver) = timeout(
        Duration::from_secs(5),
        ::http2::client::handshake(client_io),
    )
    .await??;
    let client_driver = ConnectionPeer::spawn(async move {
        driver.await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let (response, _send) = requests.send_request(
        Request::builder()
            .uri("http://origin.test/ready")
            .body(())?,
        true,
    )?;
    let mut body = timeout(Duration::from_secs(5), response)
        .await??
        .into_body();
    let data = timeout(Duration::from_secs(5), body.data())
        .await?
        .ok_or("initial forwarding returned no body")??;
    assert_eq!(data, "forwarded");
    body.flow_control().release_capacity(data.len())?;
    assert!(
        timeout(Duration::from_secs(5), body.data())
            .await?
            .is_none()
    );
    let (_first_response, mut first) = requests.send_request(
        Request::builder()
            .method(Method::CONNECT)
            .uri("origin.test:443")
            .body(())?,
        false,
    )?;
    let (_second_response, mut second) = requests.send_request(
        Request::builder()
            .method(Method::CONNECT)
            .uri("origin.test:443")
            .body(())?,
        false,
    )?;
    timeout(Duration::from_secs(5), acquired).await??;
    match ending {
        Ending::InternalError => {
            first.send_reset(::http2::Reason::INTERNAL_ERROR);
            second.send_reset(::http2::Reason::INTERNAL_ERROR);
        }
        Ending::Cancel => {
            first.send_reset(::http2::Reason::CANCEL);
            second.send_reset(::http2::Reason::CANCEL);
        }
        Ending::Eof => {
            first.send_data(Bytes::new(), true)?;
            second.send_data(Bytes::new(), true)?;
        }
    }
    let joined = timeout(Duration::from_secs(5), observation).await;
    client_driver.abort();
    server.abort();
    let client_stop = client_driver.stop().await;
    let server_stop = server.stop().await;
    let cleanup = crate::support::tunnel_proxy::finish_with_cleanup(client_stop, server_stop);
    drop(requests);
    let observed: TestResult<TestResult<bool>> = (|| Ok(joined??))();
    let checked = (|| {
        let observed = observed?;
        match ending {
            Ending::InternalError => {
                let error = observed
                    .err()
                    .ok_or("actual INTERNAL_ERROR became an ordinary not-ended body")?;
                assert_eq!(
                    error
                        .downcast_ref::<::http2::Error>()
                        .ok_or("actual body reset lost its typed cause")?
                        .reason(),
                    Some(::http2::Reason::INTERNAL_ERROR)
                );
            }
            Ending::Cancel => assert!(!observed?, "CANCEL was incorrectly reported as END_STREAM"),
            Ending::Eof => assert!(observed?, "processed END_STREAM was not observed"),
        }
        Ok(())
    })();
    crate::support::tunnel_proxy::finish_with_cleanup(checked, cleanup)
}

#[tokio::test]
async fn an_actual_internal_error_keeps_its_body_cause() -> TestResult<()> {
    observed_ending(Ending::InternalError).await
}
#[tokio::test]
async fn an_actual_cancel_is_distinct_from_end_stream() -> TestResult<()> {
    observed_ending(Ending::Cancel).await
}
#[tokio::test]
async fn an_actual_end_stream_is_observed() -> TestResult<()> {
    observed_ending(Ending::Eof).await
}
