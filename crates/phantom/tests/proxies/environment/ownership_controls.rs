use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);

fn cause<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref() {
            return Some(cause);
        }

        error = error.source()?;
    }
}

#[tokio::test]
async fn proxy_deadline_retains_its_elapsed_cause() -> TestResult<()> {
    let error = bounded_for(QUIET, std::future::pending())
        .await
        .err()
        .ok_or("pending proxy operation completed")?;
    assert!(cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    Ok(())
}

struct FaultRead<S> {
    stream: S,
    fault: Option<oneshot::Receiver<()>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for FaultRead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(Poll::Ready(result)) = self
            .fault
            .as_mut()
            .map(|fault| Pin::new(fault).poll(context))
        {
            self.fault = None;
            let error = match result {
                Ok(()) => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "environment read fault 731",
                ),
                Err(error) => io::Error::other(error),
            };
            return Poll::Ready(Err(error));
        }

        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FaultRead<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct CompletionPeer {
    peer: ConnectionPeer<TestResult<()>>,
    client_driver: ConnectionPeer<Result<(), ::http2::Error>>,
    client: ::http2::client::SendRequest<Bytes>,
    done: oneshot::Sender<()>,
    fault: oneshot::Sender<()>,
}

async fn completion_peer() -> TestResult<CompletionPeer> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (done, done_rx) = oneshot::channel();
    let (fault, fault_rx) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let stream = FaultRead {
            stream,
            fault: Some(fault_rx),
        };
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection.accept().await.ok_or("missing H2 request")??;
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/h2");

        let mut body = respond.send_response(Response::new(()), false)?;
        body.send_data(Bytes::from_static(b"verified"), true)?;
        observe_h2_completion(&mut connection, done_rx).await
    });

    let stream = TcpStream::connect(address).await?;
    let (client, connection) = ::http2::client::handshake(stream).await?;
    let client_driver = ConnectionPeer::spawn(connection);
    let mut client = client.ready().await?;
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("http://{address}/h2"))
        .body(())?;
    let (response, _request_body) = client.send_request(request, true)?;

    let response = timeout(DEADLINE, response).await??;
    assert_eq!(response.status(), 200);

    let mut body = response.into_body();
    let data = timeout(DEADLINE, body.data())
        .await?
        .ok_or("missing verified DATA")??;
    assert_eq!(&data[..], b"verified");
    body.flow_control().release_capacity(data.len())?;
    assert!(timeout(DEADLINE, body.data()).await?.is_none());

    Ok(CompletionPeer {
        peer,
        client_driver,
        client,
        done,
        fault,
    })
}

async fn stop_client(driver: ConnectionPeer<Result<(), ::http2::Error>>) -> TestResult<()> {
    driver.abort();

    match timeout(DEADLINE, driver).await? {
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error.into()),
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) if error.get_io().is_some_and(is_peer_gone) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
    }
}

#[tokio::test]
async fn consumed_h2_response_keeps_the_completion_receiver_cause() -> TestResult<()> {
    let CompletionPeer {
        peer,
        client_driver,
        client,
        done,
        fault,
    } = completion_peer().await?;
    drop(done);
    let primary = timeout(DEADLINE, peer)
        .await?
        .map_err(Into::into)
        .and_then(|result| result);

    let cleanup = stop_client(client_driver).await;
    drop(client);
    drop(fault);

    let error = finish_with_cleanup(primary, cleanup)
        .err()
        .ok_or("missing completion failure")?;
    assert!(
        cause::<oneshot::error::RecvError>(error.as_ref()).is_some(),
        "completion receiver cause was replaced"
    );
    Ok(())
}

#[tokio::test]
async fn consumed_h2_response_keeps_the_unexpected_transport_cause() -> TestResult<()> {
    let CompletionPeer {
        peer,
        client_driver,
        client,
        done,
        fault,
    } = completion_peer().await?;
    fault
        .send(())
        .map_err(|_| "fault receiver ended before injection")?;
    let primary = timeout(DEADLINE, peer)
        .await?
        .map_err(Into::into)
        .and_then(|result| result);

    let cleanup = stop_client(client_driver).await;
    drop(client);
    drop(done);

    let error = finish_with_cleanup(primary, cleanup)
        .err()
        .ok_or("missing H2 transport failure")?;

    let h2 = cause::<::http2::Error>(error.as_ref()).ok_or("missing H2 error cause")?;
    let io = h2.get_io().ok_or("missing transport I/O cause")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), "environment read fault 731");
    Ok(())
}

#[tokio::test]
async fn an_observed_h2_completion_signal_succeeds_after_literal_data() -> TestResult<()> {
    let CompletionPeer {
        peer,
        client_driver,
        client,
        done,
        fault,
    } = completion_peer().await?;
    done.send(())
        .map_err(|_| "completion receiver ended before signal")?;
    let primary = timeout(DEADLINE, peer)
        .await?
        .map_err(Into::into)
        .and_then(|result| result);

    let cleanup = stop_client(client_driver).await;
    drop(client);
    drop(fault);
    finish_with_cleanup(primary, cleanup)
}

mod relay;
