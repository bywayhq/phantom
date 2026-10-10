use std::{
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http::{Method, StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestError};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
    time::timeout,
};

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{TestResult, alps_client, alps_origin_answering_with_io};

const DEADLINE: Duration = Duration::from_secs(5);
const READ_FAULT: &str = "controlled post-response ALPS read failure";

enum QuietAction {
    RemainQuiet,
    SendAnotherRequest,
    FailRead,
}

struct QuietExchange {
    result: TestResult<Vec<String>>,
    read_fault_invoked: bool,
    second_error: Option<RequestError>,
}

#[tokio::test]
async fn the_actual_alps_origin_accepts_a_finite_quiet_connection() -> TestResult<()> {
    let exchange = exchange(QuietAction::RemainQuiet).await?;
    let names = exchange.result?;
    assert!(!exchange.read_fault_invoked);
    assert!(exchange.second_error.is_none());
    assert!(!names.is_empty());
    assert!(names.iter().any(|name| name == "sec-ch-ua"));
    Ok(())
}

#[tokio::test]
async fn the_actual_alps_origin_rejects_a_second_request() -> TestResult<()> {
    let exchange = exchange(QuietAction::SendAnotherRequest).await?;
    assert!(!exchange.read_fault_invoked);
    assert!(exchange.second_error.is_some());

    let error = exchange
        .result
        .err()
        .ok_or("ALPS origin accepted a second request")?;
    assert_eq!(error.to_string(), "the server saw a second request");
    Ok(())
}

#[tokio::test]
async fn the_actual_alps_quiet_check_keeps_a_post_response_read_failure() -> TestResult<()> {
    let exchange = exchange(QuietAction::FailRead).await?;
    assert!(
        exchange.read_fault_invoked,
        "the real H2 reader never reached its injected fault"
    );
    assert!(exchange.second_error.is_none());

    let error = exchange
        .result
        .err()
        .ok_or("ALPS quiet check accepted its actual failed read")?;
    let h2 = h2_cause(error.as_ref()).ok_or("ALPS quiet check replaced its concrete H2 failure")?;
    let source = h2
        .get_io()
        .ok_or("ALPS read failure omitted its actual IO cause")?;
    assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(source.to_string(), READ_FAULT);
    Ok(())
}

fn h2_cause<'a>(mut error: &'a (dyn Error + 'static)) -> Option<&'a ::http2::Error> {
    loop {
        if let Some(h2) = error.downcast_ref::<::http2::Error>() {
            return Some(h2);
        }
        error = error.source()?;
    }
}

async fn exchange(action: QuietAction) -> TestResult<QuietExchange> {
    let (enable_fault, wait_for_fault) = oneshot::channel();
    let invoked = Arc::new(AtomicBool::new(false));
    let reader_invoked = Arc::clone(&invoked);
    let (record, recorded) = oneshot::channel();
    let (identity, origin, task) = alps_origin_answering_with_io(
        "Sec-CH-UA-Arch",
        move |inner| FaultRead {
            inner,
            wait_for_fault: Some(wait_for_fault),
            invoked: reader_invoked,
        },
        Some(record),
    )
    .await?;
    let mut server = Some(ConnectionPeer::from_task(task));
    let mut client = None;
    let mut second_error = None;

    let operation = async {
        client = Some(alps_client(&identity)?);
        let client = client
            .as_ref()
            .ok_or("ALPS control client was not retained")?;
        let response = client
            .get(HttpProtocol::Http2, &format!("{origin}/quiet"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let request = recorded.await?;
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/quiet");
        assert_eq!(
            request.uri.authority().map(|value| value.as_str()),
            origin.strip_prefix("https://")
        );
        assert_eq!(request.version, Version::HTTP_2);
        assert!(request.body_ended);
        assert_eq!(request.headers["sec-ch-ua"], "baseline");
        assert_eq!(request.headers["sec-ch-ua-arch"], "\"arm\"");
        assert!(!request.headers.is_empty());
        assert!(!request.ordered_names.is_empty());
        assert!(request.ordered_names.iter().any(|name| name == "sec-ch-ua"));

        // The gate stays owned until an actual 204 has been collected.
        let retained_gate = match action {
            QuietAction::FailRead => {
                enable_fault
                    .send(())
                    .map_err(|_| "ALPS fault reader ended before injection")?;
                None
            }
            QuietAction::SendAnotherRequest => {
                let result = client
                    .get(HttpProtocol::Http2, &format!("{origin}/second"))?
                    .send()
                    .await;
                second_error = Some(
                    result
                        .err()
                        .ok_or("second request unexpectedly received an ALPS response")?,
                );
                Some(enable_fault)
            }
            QuietAction::RemainQuiet => Some(enable_fault),
        };

        let peer = server
            .as_mut()
            .ok_or("ALPS control peer was not retained")?;
        let joined = timeout(DEADLINE, peer).await?;
        // A completed task must not be polled again by error-path cleanup.
        drop(server.take());
        let result = joined?;
        drop(retained_gate);
        Ok(QuietExchange {
            result,
            read_fault_invoked: invoked.load(Ordering::SeqCst),
            second_error,
        })
    };
    let result = match timeout(DEADLINE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    let cleanup = match server {
        Some(server) => server.stop().await,
        None => Ok(()),
    };
    let result = finish_with_cleanup(result, cleanup);
    drop(client);
    result
}

struct FaultRead<I> {
    inner: I,
    wait_for_fault: Option<oneshot::Receiver<()>>,
    invoked: Arc<AtomicBool>,
}

impl<I: AsyncRead + Unpin> AsyncRead for FaultRead<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.invoked.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                READ_FAULT,
            )));
        }

        let signal = match this.wait_for_fault.as_mut() {
            Some(wait_for_fault) => Pin::new(wait_for_fault).poll(context),
            None => return Pin::new(&mut this.inner).poll_read(context, buffer),
        };
        match signal {
            Poll::Ready(Ok(())) => {
                this.wait_for_fault = None;
                this.invoked.store(true, Ordering::SeqCst);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    READ_FAULT,
                )))
            }
            Poll::Ready(Err(error)) => {
                this.wait_for_fault = None;
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Pending => Pin::new(&mut this.inner).poll_read(context, buffer),
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for FaultRead<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}
