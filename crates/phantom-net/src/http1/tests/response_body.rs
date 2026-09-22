use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    sync::oneshot,
};
use tracing::instrument::WithSubscriber;

use super::{TestResult, bounded_peer_test, host, read_head, target, wait_for_driver_outcome};
use crate::{
    http1::{Http1Connection, Http1Error, send_get},
    tracing_test::OutcomeSubscriber,
};

#[tokio::test]
async fn streams_first_data_before_later_data_exists() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            release_rx.await.map_err(std::io::Error::other)?;
            server.write_all(b"later").await
        });

        let response = send_get(client, target()?, vec![host()]).await?;
        let mut body = response.into_body();
        let first = body
            .frame()
            .await
            .ok_or("body ended before first data")??
            .into_data()
            .map_err(|_| "expected data frame")?;
        assert_eq!(first, "first");

        let _ = release_tx.send(());
        let rest = body.collect().await?.to_bytes();
        assert_eq!(rest, "later");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn content_length_ends_without_socket_eof() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });
        let target = target()?;

        let collected = async {
            let body = send_get(client, target, vec![host()]).await?.into_body();
            body.collect().await
        }
        .with_subscriber(subscriber.dispatch())
        .await?;
        assert_eq!(collected.to_bytes(), "hello");
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "complete".to_owned())]
        );
        assert_eq!(server_task.await??, 0);
        wait_for_driver_outcome(&subscriber, "complete").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn content_length_does_not_expose_surplus_bytes() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhellosurplus")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        let body = send_get(client, target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?;
        assert_eq!(body.to_bytes(), "hello");
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn decodes_fragmented_chunk_extensions_and_trailers_then_reuses_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let first = read_head(&mut server).await?;
            for fragment in [
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n"
                    .as_slice(),
                b"2;probe=alpha;flag\r",
                b"\nhe\r\n3;probe=ome",
                b"ga\r\nllo\r",
                b"\n0;terminal=yes\r",
                b"\nX-Final:",
                b" yes\r",
                b"\n\r",
                b"\n",
            ] {
                server.write_all(fragment).await?;
                tokio::task::yield_now().await;
            }
            let second = read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, std::io::Error>((first, second))
        });

        let connection = Http1Connection::connect(client).await?;
        let mut body = connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body();
        let mut data = Vec::new();
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => trailers = frame.into_trailers().ok(),
            }
        }
        assert_eq!(data, b"hello");
        let trailers = trailers.ok_or("missing trailers frame")?;
        assert_eq!(trailers.get("x-final"), Some(&"yes".parse()?));

        let followup = connection.send_get(target()?, vec![host()]).await?;
        assert_eq!(followup.status(), 204);
        assert!(followup.into_body().collect().await?.to_bytes().is_empty());

        let (first, second) = server_task.await??;
        assert!(first.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET /resource?item=1 HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reads_close_delimited_body() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose body")
                .await?;
            server.shutdown().await
        });
        let target = target()?;

        let bytes = async {
            let body = send_get(client, target, vec![host()]).await?.into_body();
            body.collect().await
        }
        .with_subscriber(subscriber.dispatch())
        .await?
        .to_bytes();
        assert_eq!(bytes, "close body");
        server_task.await??;
        wait_for_driver_outcome(&subscriber, "complete").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reports_truncated_content_length() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
                .await?;
            server.shutdown().await
        });
        let target = target()?;

        let collected = async {
            let body = send_get(client, target, vec![host()]).await?.into_body();
            body.collect().await
        }
        .with_subscriber(subscriber.dispatch())
        .await;
        let error = match collected {
            Ok(_) => return Err("truncated body accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(error, Http1Error::Protocol(_)), "{error:?}");
        assert_eq!(
            subscriber.response_body_events(),
            [(5, "protocol_error".to_owned())]
        );
        server_task.await??;
        wait_for_driver_outcome(&subscriber, "protocol_error").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn status_204_has_no_body_without_socket_eof() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 99\r\n\r\n")
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        let response = send_get(client, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 204);
        let body = response.into_body().collect().await?;
        assert!(body.to_bytes().is_empty());
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}
