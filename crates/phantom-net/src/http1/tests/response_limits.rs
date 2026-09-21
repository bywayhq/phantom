use std::{future::poll_fn, pin::Pin};

use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf, duplex};
use tracing::{Dispatch, instrument::WithSubscriber};

use super::{TestResult, bounded_peer_test, host, read_head, target, wait_for_driver_outcome};
use crate::{
    http1::{
        Http1Connection, Http1Error, PreparedGet,
        limits::{
            MAX_CHUNK_SIZE_LINE_BYTES, MAX_INFORMATIONAL_RESPONSES, MAX_RESPONSE_HEAD_BYTES,
            MAX_RESPONSE_HEADERS,
        },
        response_head::ResponseHeadObserver,
        send_get, send_prepared_upgrade,
    },
    tracing_test::OutcomeSubscriber,
};

fn padded_head(prefix: &[u8], length: usize) -> Vec<u8> {
    const SUFFIX: &[u8] = b"\r\n\r\n";
    assert!(prefix.len() + SUFFIX.len() <= length);
    let mut head = Vec::with_capacity(length);
    head.extend_from_slice(prefix);
    head.resize(length - SUFFIX.len(), b'a');
    head.extend_from_slice(SUFFIX);
    assert_eq!(head.len(), length);
    head
}

fn response_with_fields(status: &[u8], fields: usize) -> Vec<u8> {
    let mut response = status.to_vec();
    for index in 0..fields {
        response.extend_from_slice(format!("X-Field-{index}: value\r\n").as_bytes());
    }
    response.extend_from_slice(b"\r\n");
    response
}

fn chunked_response(line_length: usize) -> Vec<u8> {
    let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1".to_vec();
    response.resize(response.len() + line_length - 3, b' ');
    response.extend_from_slice(b"\r\na\r\n0\r\n\r\n");
    response
}

#[tokio::test]
async fn response_head_accepts_exact_limit_and_excludes_coalesced_body() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let mut response = padded_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Pad: ",
            MAX_RESPONSE_HEAD_BYTES,
        );
        response.extend_from_slice(b"body");
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(&response).await
        });

        let body = send_get(client, target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        assert_eq!(body, "body");
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn oversized_response_head_is_typed_and_discards_connection() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let response = padded_head(
            b"HTTP/1.1 204 No Content\r\nX-Pad: ",
            MAX_RESPONSE_HEAD_BYTES + 1,
        );
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(&response).await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });

        let result = send_get(client, target()?, vec![host()])
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(
            result,
            Err(Http1Error::ResponseHeadTooLarge {
                maximum: MAX_RESPONSE_HEAD_BYTES
            })
        ));
        assert_eq!(server_task.await??, 0);
        assert_eq!(
            subscriber.outcomes_for("http1.response_head"),
            ["invalid_response"]
        );
        wait_for_driver_outcome(&subscriber, "protocol_error").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn oversized_status_line_is_typed() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let response = padded_head(b"HTTP/1.1 200 ", MAX_RESPONSE_HEAD_BYTES + 1);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(&response).await
        });

        let result = send_get(client, target()?, vec![host()]).await;
        assert!(matches!(
            result,
            Err(Http1Error::ResponseHeadTooLarge {
                maximum: MAX_RESPONSE_HEAD_BYTES
            })
        ));
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn response_field_count_has_exact_boundary_and_typed_overflow() -> TestResult {
    bounded_peer_test(async {
        for (fields, accepted) in [
            (MAX_RESPONSE_HEADERS, true),
            (MAX_RESPONSE_HEADERS + 1, false),
        ] {
            let (client, mut server) = duplex(16 * 1024);
            let response = response_with_fields(b"HTTP/1.1 204 No Content\r\n", fields);
            let server_task = tokio::spawn(async move {
                read_head(&mut server).await?;
                server.write_all(&response).await
            });
            let result = send_get(client, target()?, vec![host()]).await;
            if accepted {
                assert_eq!(result?.status(), 204);
            } else {
                assert!(matches!(
                    result,
                    Err(Http1Error::TooManyResponseHeaders {
                        maximum: MAX_RESPONSE_HEADERS
                    })
                ));
            }
            server_task.await??;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn informational_response_resets_head_byte_budget() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let mut response = padded_head(
            b"HTTP/1.1 103 Early Hints\r\nX-Pad: ",
            MAX_RESPONSE_HEAD_BYTES - 1,
        );
        response.extend_from_slice(&padded_head(
            b"HTTP/1.1 204 No Content\r\nX-Pad: ",
            MAX_RESPONSE_HEAD_BYTES,
        ));
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(&response).await
        });

        let response = send_get(client, target()?, vec![host()]).await?;
        assert_eq!(response.status(), 204);
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_limit_informational_head_keeps_coalesced_final_head() -> TestResult {
    let mut wire = padded_head(
        b"HTTP/1.1 103 Early Hints\r\nX-Pad: ",
        MAX_RESPONSE_HEAD_BYTES,
    );
    wire.extend_from_slice(b"HTTP/1.1 204 No Content\r\nX-Final: yes\r\n\r\n");

    let (mut stream, observer) = ResponseHeadObserver::wrap(wire.as_slice());
    observer.begin();
    let mut storage = vec![0_u8; wire.len()];
    let mut read_buffer = ReadBuf::new(&mut storage);
    poll_fn(|context| Pin::new(&mut stream).poll_read(context, &mut read_buffer)).await?;
    assert_eq!(read_buffer.filled().len(), wire.len());

    let headers = observer
        .take()
        .ok_or("coalesced final response head was not observed")?;
    assert_eq!(headers.len(), 1);
    assert_eq!(headers.as_slice()[0].name(), "X-Final");
    assert_eq!(headers.as_slice()[0].value(), b"yes");
    Ok(())
}

#[tokio::test]
async fn chunk_size_line_has_exact_boundary_and_discards_on_overflow() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(&chunked_response(MAX_CHUNK_SIZE_LINE_BYTES))
                .await?;
            read_head(&mut server).await?;
            server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await
        });
        let connection = Http1Connection::connect(client).await?;
        let body = connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        assert_eq!(body, "a");
        assert_eq!(
            connection.send_get(target()?, vec![host()]).await?.status(),
            204
        );
        server_task.await??;

        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            server
                .write_all(&chunked_response(MAX_CHUNK_SIZE_LINE_BYTES + 1))
                .await?;
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });
        let connection = Http1Connection::connect(client).await?;
        let result = connection
            .send_get(target()?, vec![host()])
            .await?
            .into_body()
            .collect()
            .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("oversized chunk-size line was accepted".into()),
        };
        assert!(matches!(
            error,
            Http1Error::ChunkSizeLineTooLarge {
                maximum: MAX_CHUNK_SIZE_LINE_BYTES
            }
        ));
        assert!(!connection.is_reusable());
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn upgrade_head_limit_is_typed_and_driver_reports_protocol_error() -> TestResult {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(
            send_prepared_upgrade(client, prepared)
                .with_subscriber(Dispatch::new(subscriber.clone())),
        );
        read_head(&mut server).await?;
        server
            .write_all(&padded_head(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nX-Pad: ",
                MAX_RESPONSE_HEAD_BYTES + 1,
            ))
            .await?;
        let result = transaction.await?;
        assert!(matches!(
            result,
            Err(Http1Error::ResponseHeadTooLarge {
                maximum: MAX_RESPONSE_HEAD_BYTES
            })
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).await?, 0);
        assert_eq!(
            subscriber.outcomes_for("http1.upgrade.response_head"),
            ["invalid_response"]
        );
        wait_for_driver_outcome(&subscriber, "protocol_error").await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn upgrade_response_field_count_preserves_typed_error() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(16 * 1024);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));
        read_head(&mut server).await?;
        let mut response = response_with_fields(
            b"HTTP/1.1 101 Switching Protocols\r\n",
            MAX_RESPONSE_HEADERS,
        );
        let empty_line = response.len() - 2;
        response.splice(empty_line..empty_line, b"Upgrade: test\r\n".iter().copied());
        server.write_all(&response).await?;

        let result = transaction.await?;
        assert!(matches!(
            result,
            Err(Http1Error::TooManyResponseHeaders {
                maximum: MAX_RESPONSE_HEADERS
            })
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).await?, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_upgrade_body_preserves_chunk_size_limit_error() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES * 2);
        let prepared = PreparedGet::new(target()?, vec![host()])?;
        let transaction = tokio::spawn(send_prepared_upgrade(client, prepared));
        read_head(&mut server).await?;
        server
            .write_all(&chunked_response(MAX_CHUNK_SIZE_LINE_BYTES + 1))
            .await?;

        let outcome = transaction.await??;
        let super::super::Http1UpgradeOutcome::Rejected(response) = outcome else {
            return Err("ordinary response was treated as upgraded".into());
        };
        let result = response.into_body().collect().await;
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("oversized chunk-size line was accepted".into()),
        };
        assert!(matches!(
            error,
            Http1Error::ChunkSizeLineTooLarge {
                maximum: MAX_CHUNK_SIZE_LINE_BYTES
            }
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).await?, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn informational_responses_up_to_the_limit_reach_the_final_response() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            for _ in 0..MAX_INFORMATIONAL_RESPONSES {
                server
                    .write_all(
                        b"HTTP/1.1 103 Early Hints

",
                    )
                    .await?;
            }
            server
                .write_all(
                    b"HTTP/1.1 204 No Content

",
                )
                .await
        });
        let connection = Http1Connection::connect(client).await?;
        let response = connection.send_get(target()?, vec![host()]).await?;
        assert_eq!(response.status(), 204);
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn informational_flood_fails_typed_and_discards_the_connection() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(MAX_RESPONSE_HEAD_BYTES);
        let server_task = tokio::spawn(async move {
            read_head(&mut server).await?;
            // An unbounded peer would never send a final response.
            for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
                server
                    .write_all(
                        b"HTTP/1.1 100 Continue

",
                    )
                    .await?;
            }
            let mut byte = [0_u8; 1];
            server.read(&mut byte).await
        });
        let connection = Http1Connection::connect(client).await?;
        let error = match connection.send_get(target()?, vec![host()]).await {
            Err(error) => error,
            Ok(response) => {
                return Err(format!("informational flood produced {}", response.status()).into());
            }
        };
        assert!(matches!(
            error,
            Http1Error::TooManyInformationalResponses {
                maximum: MAX_INFORMATIONAL_RESPONSES
            }
        ));
        assert!(!connection.is_reusable());
        assert_eq!(server_task.await??, 0);
        Ok(())
    })
    .await
}
