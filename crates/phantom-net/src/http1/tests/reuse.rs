use std::time::Duration;

use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    sync::oneshot,
    time::timeout,
};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    OrderedResponseHeaders,
    http1::{Http1Connection, RequestHeader},
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
