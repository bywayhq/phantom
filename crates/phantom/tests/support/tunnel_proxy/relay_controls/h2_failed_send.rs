use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
    time::timeout,
};

use super::super::{
    ConnectionPeer, TestResult, finish_with_cleanup, relay_result, send_http2_data,
};
use super::DEADLINE;

const READ_FAILURE: &str = "observed fixture transport failure";

struct FailingRead {
    stream: DuplexStream,
    fail: Arc<AtomicBool>,
}

impl AsyncRead for FailingRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.fail.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                READ_FAILURE,
            )));
        }
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for FailingRead {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct DrivenSend {
    server: ConnectionPeer<TestResult<()>>,
    client: ConnectionPeer<TestResult<()>>,
    sender: ::http2::client::SendRequest<Bytes>,
    request: ::http2::SendStream<Bytes>,
    response: ::http2::RecvStream,
    server_send: ::http2::SendStream<Bytes>,
    fail: Arc<AtomicBool>,
}

impl DrivenSend {
    async fn ready() -> TestResult<Self> {
        let (client_io, server_io) = duplex(64 * 1024);
        let (send_response, receive_response) = oneshot::channel();
        let (observed, received) = oneshot::channel();
        let server = ConnectionPeer::spawn(async move {
            let mut connection = ::http2::server::Builder::new()
                .handshake::<_, Bytes>(server_io)
                .await?;
            let (request, mut respond) =
                connection.accept().await.ok_or("request was absent")??;
            assert_eq!(request.method(), http::Method::POST);
            let send = respond.send_response(http::Response::new(()), false)?;
            send_response
                .send(send)
                .map_err(|_| "response stream receiver was dropped")?;

            let read_request = async move {
                let mut body = request.into_body();
                let chunk = body.data().await.ok_or("request data was absent")??;
                assert_eq!(chunk.as_ref(), b"request");
                body.flow_control().release_capacity(chunk.len())?;
                observed
                    .send(())
                    .map_err(|()| "request observation receiver was dropped")?;
                TestResult::Ok(body)
            };
            tokio::pin!(read_request);
            let body = tokio::select! {
                result = &mut read_request => result?,
                accepted = connection.accept() => match accepted {
                    Some(Err(error)) => return Err(error.into()),
                    _ => return Err("connection ended before the request observation".into()),
                },
            };
            if let Some(accepted) = connection.accept().await {
                match accepted {
                    Ok(_) => return Err("unexpected second request".into()),
                    Err(error) => return relay_result(Err(error.into())),
                }
            }
            drop(body);
            Ok(())
        });
        let fail = Arc::new(AtomicBool::new(false));
        let (sender, connection) = ::http2::client::Builder::new()
            .handshake::<_, Bytes>(FailingRead {
                stream: client_io,
                fail: fail.clone(),
            })
            .await?;
        let client = ConnectionPeer::spawn(async move { connection.await.map_err(Into::into) });
        let mut sender = sender.ready().await?;
        let (response, mut request) = sender.send_request(
            http::Request::builder()
                .method(http::Method::POST)
                .uri("http://send.test/request")
                .body(())?,
            false,
        )?;
        let response = response.await?;
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut response = response.into_body();
        request.send_data(Bytes::from_static(b"request"), false)?;
        received.await?;
        let mut server_send = receive_response.await?;
        server_send.send_data(Bytes::from_static(b"response"), false)?;
        let chunk = response.data().await.ok_or("response data was absent")??;
        assert_eq!(chunk.as_ref(), b"response");
        response.flow_control().release_capacity(chunk.len())?;
        Ok(Self {
            server,
            client,
            sender,
            request,
            response,
            server_send,
            fail,
        })
    }

    async fn stop(self) -> TestResult<()> {
        drop(self.sender);
        drop(self.request);
        drop(self.response);
        drop(self.server_send);
        finish_with_cleanup(self.client.stop().await, self.server.stop().await)
    }
}

#[tokio::test]
async fn a_failed_send_preserves_an_observed_non_cancel_reset() -> TestResult<()> {
    let mut peer = timeout(DEADLINE, DrivenSend::ready()).await??;
    peer.server_send.send_reset(::http2::Reason::INTERNAL_ERROR);
    let observed = timeout(DEADLINE, peer.response.data())
        .await?
        .ok_or("reset response was absent")?
        .err()
        .ok_or("remote reset was accepted")?;
    assert_eq!(observed.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    assert!(observed.is_remote());
    let failed_send = send_http2_data(&mut peer.request, Bytes::new(), false);
    peer.stop().await?;
    let error = failed_send.err().ok_or("failed send was accepted")?;
    let error = error
        .downcast_ref::<::http2::Error>()
        .ok_or("typed H2 failure was lost")?;
    assert_eq!(error.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

#[tokio::test]
async fn a_failed_send_preserves_an_observed_connection_io_error() -> TestResult<()> {
    let mut peer = timeout(DEADLINE, DrivenSend::ready()).await??;
    peer.fail.store(true, Ordering::Release);
    // Actual DATA wakes the driver after the transport failure is enabled.
    peer.server_send
        .send_data(Bytes::from_static(b"wake"), false)?;
    let driven = timeout(DEADLINE, &mut peer.client).await??;
    let driver_error = driven.err().ok_or("injected read failure was accepted")?;
    assert_eq!(
        driver_error
            .downcast_ref::<::http2::Error>()
            .and_then(::http2::Error::get_io)
            .map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    let failed_send = send_http2_data(&mut peer.request, Bytes::new(), false);
    // The client task was already joined and its failure checked above.
    drop(peer.client);
    drop(peer.sender);
    drop(peer.request);
    drop(peer.response);
    drop(peer.server_send);
    peer.server.stop().await?;
    let error = failed_send.err().ok_or("failed send was accepted")?;
    let error = error
        .downcast_ref::<::http2::Error>()
        .and_then(::http2::Error::get_io)
        .ok_or("observed typed connection I/O error was lost")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), READ_FAILURE);
    Ok(())
}
