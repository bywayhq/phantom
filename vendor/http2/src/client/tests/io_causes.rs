use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Request;
use tokio::{
    io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::oneshot,
    time::timeout,
};

use super::{accept_client_handshake, read_request_headers};

#[tokio::test]
async fn connection_and_two_streams_share_the_original_typed_io_failure() {
    let identity = Arc::new(());
    let fault = io::Error::new(
        io::ErrorKind::PermissionDenied,
        ReadFailure(identity.clone()),
    );
    let errors = failed_connection(fault).await;

    for error in &errors {
        let original = error.get_io().expect("original transport error missing");
        assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        let payload = original
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<ReadFailure>())
            .expect("original typed transport payload missing");
        assert!(Arc::ptr_eq(&payload.0, &identity));
    }

    assert_shared_original(errors);
}

#[tokio::test]
async fn connection_and_two_streams_preserve_the_original_os_error() {
    let fault = io::Error::from_raw_os_error(13);
    let original_kind = fault.kind();
    let original_message = fault.to_string();
    let errors = failed_connection(fault).await;

    for error in &errors {
        let original = error.get_io().expect("original OS error missing");
        assert_eq!(original.raw_os_error(), Some(13));
        assert_eq!(original.kind(), original_kind);
        assert_eq!(original.to_string(), original_message);
    }

    assert_shared_original(errors);
}

async fn failed_connection(fault: io::Error) -> [crate::Error; 3] {
    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (arm, fault_received) = oneshot::channel();
        let io = ReadFault {
            inner: client_io,
            fault: Some(fault_received),
        };
        let (mut sender, connection) = super::super::handshake(io)
            .await
            .expect("client handshake failed");
        let first = Request::builder()
            .uri("https://example.test/first")
            .body(())
            .expect("first static request must build");
        let second = Request::builder()
            .uri("https://example.test/second")
            .body(())
            .expect("second static request must build");
        let (first_response, first_send) = sender
            .send_request(first, true)
            .expect("first request was rejected");
        let (second_response, second_send) = sender
            .send_request(second, true)
            .expect("second request was rejected");

        let peer = async move {
            accept_client_handshake(&mut peer_io).await;
            read_request_headers(&mut peer_io, 1).await;
            read_request_headers(&mut peer_io, 3).await;
            arm.send(fault).expect("original read fault receiver closed");
            peer_io
        };
        let (driver, peer_io) = tokio::join!(connection, peer);
        let driver = driver.expect_err("faulted connection completed successfully");
        let first = first_response
            .await
            .expect_err("first stream lost its failure");
        let second = second_response
            .await
            .expect_err("second stream lost its failure");

        drop((first_send, second_send, sender, peer_io));

        [driver, first, second]
    })
    .await
    .expect("actual transport failure propagation timed out")
}

fn assert_shared_original(errors: [crate::Error; 3]) {
    let original = errors[0].get_io().expect("connection I/O cause missing");
    for error in &errors {
        let io = error.get_io().expect("stream I/O cause missing");
        assert!(std::ptr::eq(original, io));

        let source = std::error::Error::source(error)
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .expect("transport error missing from the public source chain");
        assert!(std::ptr::eq(original, source));
    }

    let [driver, first, second] = errors.map(|error| {
        error
            .into_io()
            .expect("consuming error lost the original I/O cause")
    });
    assert!(Arc::ptr_eq(&driver, &first));
    assert!(Arc::ptr_eq(&driver, &second));
}

#[derive(Debug)]
struct ReadFailure(Arc<()>);

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected transport read failure")
    }
}

impl std::error::Error for ReadFailure {}

struct ReadFault {
    inner: DuplexStream,
    fault: Option<oneshot::Receiver<io::Error>>,
}

impl AsyncRead for ReadFault {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if result.is_pending() {
            if let Some(fault) = &mut this.fault {
                match Pin::new(fault).poll(context) {
                    Poll::Ready(Ok(error)) => {
                        this.fault = None;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Err(error)) => {
                        this.fault = None;
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, error)));
                    }
                    Poll::Pending => {}
                }
            }
        }

        result
    }
}

impl AsyncWrite for ReadFault {
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
