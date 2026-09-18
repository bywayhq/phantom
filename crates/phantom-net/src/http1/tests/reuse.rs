use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::Method;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    sync::oneshot,
    time::timeout,
};

struct PendingBody(Arc<AtomicBool>);

impl Body for PendingBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }
}

impl Drop for PendingBody {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct ErrorBody;

impl Body for ErrorBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("injected body error"))))
    }
}

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    OrderedResponseHeaders,
    http1::{Http1Connection, RequestHeader},
    request::RequestBody,
};

#[test]
fn connection_handle_is_send_sync_clone() {
    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
    assert_send_sync_clone::<Http1Connection>();
}

#[tokio::test]
async fn sequential_requests_reuse_connection_and_capture_each_head() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-FiRsT: one\r\n\r\nhello")
                .await?;
            let second = read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nx-SeCoNd: two\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, std::io::Error>((first, second))
        });

        let connection = Http1Connection::connect(client).await?;
        let first = connection.send_get(target()?, vec![host()]).await?;
        let first_headers = first
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("first ordered headers missing")?;
        assert_eq!(first_headers.as_slice()[1].name(), "X-FiRsT");
        assert_eq!(first.into_body().collect().await?.to_bytes(), "hello");

        let second = connection.send_get(target()?, vec![host()]).await?;
        let second_headers = second
            .extensions()
            .get::<OrderedResponseHeaders>()
            .ok_or("second ordered headers missing")?;
        assert_eq!(second_headers.as_slice()[0].name(), "x-SeCoNd");
        second.into_body().collect().await?;

        let (first, second) = server_task.await??;
        assert!(first.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn body_request_then_get_reuses_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_head(&mut server).await?;
            let mut body = [0_u8; 4];
            server.read_exact(&mut body).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            let second = read_head(&mut server).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            Ok::<_, std::io::Error>((first, body, second))
        });

        let connection = Http1Connection::connect(client).await?;
        connection
            .send_request(
                Method::POST,
                target()?,
                vec![host()],
                Some(Bytes::from_static(b"data")),
            )
            .await?
            .into_body()
            .collect()
            .await?;
        connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?;

        let (first, body, second) = server_task.await??;
        assert!(first.starts_with(b"POST /resource?item=1 HTTP/1.1\r\n"));
        assert_eq!(&body, b"data");
        assert!(second.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn streaming_body_then_get_reuses_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_head(&mut server).await?;
            let mut body = [0_u8; 7];
            server.read_exact(&mut body).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            let second = read_head(&mut server).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            Ok::<_, std::io::Error>((first, body, second))
        });

        let connection = Http1Connection::connect(client).await?;
        connection
            .send_request_body(
                Method::POST,
                target()?,
                vec![host()],
                Some(RequestBody::streaming(Full::new(Bytes::from_static(
                    b"payload",
                )))),
            )
            .await?
            .into_body()
            .collect()
            .await?;
        assert!(connection.is_reusable());
        connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?;

        let (first, body, second) = server_task.await??;
        assert!(first.ends_with(b"Content-Length: 7\r\n\r\n"));
        assert_eq!(&body, b"payload");
        assert!(second.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn head_response_without_framing_reuses_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Head: yes\r\n\r\n")
                .await?;
            let second = read_head(&mut server).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            Ok::<_, std::io::Error>((first, second))
        });

        let connection = Http1Connection::connect(client).await?;
        connection
            .send_request(Method::HEAD, target()?, vec![host()], None)
            .await?
            .into_body()
            .collect()
            .await?;
        assert!(connection.is_reusable());
        connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?;

        let (first, second) = server_task.await??;
        assert!(first.starts_with(b"HEAD /resource?item=1 HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn later_request_waits_for_the_current_body() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await?;
            let second = timeout(Duration::from_millis(50), read_head(&mut server)).await;
            if second.is_ok() {
                return Err(std::io::Error::other(
                    "second request was pipelined before body completion",
                ));
            }
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
        });

        let connection = Http1Connection::connect(client).await?;
        let first = connection.send_get(target()?, vec![host()]).await?;
        let later_connection = connection.clone();
        let later_target = target()?;
        let later =
            tokio::spawn(
                async move { later_connection.send_get(later_target, vec![host()]).await },
            );
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(!later.is_finished());

        first.into_body().collect().await?;
        later.await??.into_body().collect().await?;
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_an_incomplete_body_invalidates_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await
        });

        let connection = Http1Connection::connect(client).await?;
        let response = connection.send_get(target()?, vec![host()]).await?;
        drop(response);
        assert!(!connection.is_reusable());
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_a_dispatched_response_head_invalidates_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let (observed_tx, observed_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            let _ = observed_tx.send(());
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await?;
            Ok::<_, std::io::Error>(remaining)
        });

        let connection = Http1Connection::connect(client).await?;
        let request_target = target()?;
        let sending = tokio::spawn({
            let connection = connection.clone();
            async move { connection.send_get(request_target, vec![host()]).await }
        });
        observed_rx.await?;
        sending.abort();
        let _ = sending.await;
        assert!(!connection.is_reusable());
        assert!(server_task.await??.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_stalled_upload_drops_source_and_invalidates_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let (observed_tx, observed_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let head = read_head(&mut server).await?;
            let _ = observed_tx.send(head);
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await?;
            Ok::<_, std::io::Error>(remaining)
        });

        let dropped = Arc::new(AtomicBool::new(false));
        let connection = Http1Connection::connect(client).await?;
        let request_target = target()?;
        let sending = tokio::spawn({
            let connection = connection.clone();
            let dropped = Arc::clone(&dropped);
            async move {
                connection
                    .send_request_body(
                        Method::POST,
                        request_target,
                        vec![host()],
                        Some(RequestBody::streaming(PendingBody(dropped))),
                    )
                    .await
            }
        });
        let head = observed_rx.await?;
        assert!(head.ends_with(b"Transfer-Encoding: chunked\r\n\r\n"));
        sending.abort();
        let _ = sending.await;
        timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!connection.is_reusable());
        assert!(server_task.await??.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn streaming_body_error_invalidates_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut observed = Vec::new();
            server.read_to_end(&mut observed).await?;
            Ok::<_, std::io::Error>(observed)
        });

        let connection = Http1Connection::connect(client).await?;
        let result = connection
            .send_request_body(
                Method::POST,
                target()?,
                vec![host()],
                Some(RequestBody::streaming(ErrorBody)),
            )
            .await;
        assert!(result.is_err());
        assert!(!connection.is_reusable());

        let observed = server_task.await??;
        assert!(observed.is_empty() || observed.ends_with(b"Transfer-Encoding: chunked\r\n\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn streaming_body_error_suppresses_static_trailers_and_invalidates_connection() -> TestResult
{
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut observed = Vec::new();
            server.read_to_end(&mut observed).await?;
            Ok::<_, std::io::Error>(observed)
        });

        let connection = Http1Connection::connect(client).await?;
        let result = connection
            .send_request_body_with_trailers(
                Method::POST,
                target()?,
                vec![host()],
                Some(RequestBody::streaming(ErrorBody)),
                vec![RequestHeader::new("X-Must-Not-Appear", "no")],
            )
            .await;
        assert!(result.is_err());
        assert!(!connection.is_reusable());

        let observed = server_task.await??;
        assert!(
            !observed
                .windows(b"X-Must-Not-Appear: no".len())
                .any(|window| window == b"X-Must-Not-Appear: no")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn request_connection_close_prevents_reuse() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
        });

        let connection = Http1Connection::connect(client).await?;
        connection
            .send_get(
                target()?,
                vec![
                    host(),
                    RequestHeader::new("Connection", "keep-alive, close"),
                ],
            )
            .await?
            .into_body()
            .collect()
            .await?;
        assert!(!connection.is_reusable());
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http10_and_close_delimited_responses_prevent_reuse() -> TestResult {
    for response in [
        b"HTTP/1.0 204 No Content\r\nConnection: keep-alive\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\n\r\nbody".as_slice(),
    ] {
        bounded_peer_test(async {
            let (client, mut server) = duplex(4096);
            let server_task = tokio::spawn(async move {
                read_head(&mut server).await?;
                server.write_all(response).await?;
                server.shutdown().await
            });

            let connection = Http1Connection::connect(client).await?;
            connection
                .send_get(target()?, vec![host()])
                .await?
                .into_body()
                .collect()
                .await?;
            assert!(!connection.is_reusable());
            server_task.await??;
            Ok(())
        })
        .await?;
    }
    Ok(())
}
