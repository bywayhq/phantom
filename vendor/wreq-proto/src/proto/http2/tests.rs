use std::{
    error::Error as StdError,
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

use super::h2_to_io_error;
use crate::Error;

#[tokio::test]
async fn both_h2_conversions_keep_the_original_typed_transport_cause() {
    let identity = Arc::new(());
    let fault = io::Error::new(
        io::ErrorKind::PermissionDenied,
        ReadFailure(identity.clone()),
    );
    let [driver, response] = failed_connection(fault).await;
    let public = Error::new_h2(driver);
    let upgraded = h2_to_io_error(response);
    let original = assert_original_sources(&public, &upgraded);

    assert_eq!(upgraded.kind(), io::ErrorKind::PermissionDenied);
    let payload = original
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ReadFailure>())
        .expect("original typed transport payload missing");
    assert!(Arc::ptr_eq(&payload.0, &identity));
}

#[tokio::test]
async fn both_h2_conversions_keep_the_original_native_error_in_the_source() {
    let fault = io::Error::from_raw_os_error(13);
    let original_kind = fault.kind();
    let [driver, response] = failed_connection(fault).await;
    let public = Error::new_h2(driver);
    let upgraded = h2_to_io_error(response);
    let original = assert_original_sources(&public, &upgraded);

    assert_eq!(upgraded.kind(), original_kind);
    assert_eq!(original.kind(), original_kind);
    assert_eq!(original.raw_os_error(), Some(13));
    // The adapter is a custom I/O error; the native code belongs to its source.
    assert_eq!(upgraded.raw_os_error(), None);
}

#[test]
fn both_h2_conversions_keep_non_io_reasons() {
    let reason = http2::Reason::HTTP_1_1_REQUIRED;
    let public = Error::new_h2(reason.into());
    assert_eq!(public.h2_reason(), reason);
    let public_h2 = public
        .source()
        .and_then(|cause| cause.downcast_ref::<http2::Error>())
        .expect("public HTTP/2 reason owner missing");
    assert_eq!(public_h2.reason(), Some(reason));
    assert!(public_h2.get_io().is_none());

    let upgraded = h2_to_io_error(reason.into());
    assert_eq!(upgraded.kind(), io::ErrorKind::Other);
    let upgraded_h2 = upgraded
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<http2::Error>())
        .expect("upgraded HTTP/2 reason owner missing");
    assert_eq!(upgraded_h2.reason(), Some(reason));
    assert!(upgraded.source().is_none());
}

fn assert_original_sources<'a>(public: &'a Error, upgraded: &io::Error) -> &'a io::Error {
    let public_h2 = public
        .source()
        .and_then(|cause| cause.downcast_ref::<http2::Error>())
        .expect("public HTTP/2 error owner missing");
    let original = public_h2
        .get_io()
        .expect("public original I/O cause missing");
    let public_source = public
        .find_source::<io::Error>()
        .expect("public source traversal lost the original I/O cause");
    assert!(std::ptr::eq(original, public_source));
    assert_eq!(public.h2_reason(), http2::Reason::INTERNAL_ERROR);

    let upgraded_h2 = upgraded
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<http2::Error>())
        .expect("upgraded HTTP/2 error owner missing");
    let upgraded_original = upgraded_h2
        .get_io()
        .expect("upgraded original I/O cause missing");
    assert!(std::ptr::eq(original, upgraded_original));
    let upgraded_source = upgraded
        .source()
        .and_then(|cause| cause.downcast_ref::<io::Error>())
        .expect("upgraded source traversal lost the original I/O cause");
    assert!(std::ptr::eq(original, upgraded_source));

    original
}

async fn failed_connection(fault: io::Error) -> [http2::Error; 2] {
    timeout(Duration::from_secs(5), async {
        let (client_io, peer_io) = duplex(16 * 1024);
        let (arm, fault_received) = oneshot::channel();
        let io = ReadFault {
            inner: client_io,
            fault: Some(fault_received),
        };
        let (mut sender, connection) = http2::client::handshake(io)
            .await
            .expect("client handshake failed");
        let request = Request::builder()
            .uri("https://example.test/original-cause")
            .body(())
            .expect("static request must build");
        let (response, send_stream) = sender
            .send_request(request, true)
            .expect("request was rejected");

        let peer = async move {
            let mut connection = http2::server::handshake(peer_io)
                .await
                .expect("peer handshake failed");
            let (request, response) = connection
                .accept()
                .await
                .expect("peer ended before the request")
                .expect("peer rejected the actual request");
            assert_eq!(request.uri().path(), "/original-cause");
            assert_eq!(request.method(), http::Method::GET);
            assert!(request.body().is_end_stream());
            arm.send(fault)
                .expect("original read fault receiver closed");
            (connection, request, response)
        };
        let (driver, peer) = tokio::join!(connection, peer);
        let driver = driver.expect_err("faulted connection completed successfully");
        let response = response
            .await
            .expect_err("actual response lost its transport failure");

        drop((sender, send_stream, peer));

        [driver, response]
    })
    .await
    .expect("actual transport failure propagation timed out")
}

#[derive(Debug)]
struct ReadFailure(Arc<()>);

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected downstream transport read failure")
    }
}

impl StdError for ReadFailure {}

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
                        return Poll::Ready(Err(io::Error::other(error)));
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
