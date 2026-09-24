use std::{future::poll_fn, time::Duration};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom_profile::chromium::v154_http2;
use tokio::{io::duplex, sync::oneshot, time::timeout};

use super::{TestResult, bounded_peer_test, next_nonempty_data, target};
use crate::http2::Http2Connection;

#[test]
fn connection_handle_is_send_sync_clone() {
    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
    assert_send_sync_clone::<Http2Connection>();
}

#[tokio::test]
async fn sequential_requests_reuse_one_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let mut stream_ids = Vec::new();
            for _ in 0..2 {
                let (_request, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("connection closed before request")??;
                stream_ids.push(respond.stream_id().as_u32());
                respond.send_response(Response::builder().status(204).body(())?, true)?;
            }
            if connection.accept().await.is_some() {
                return Err("client opened an unexpected third stream".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stream_ids)
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        for _ in 0..2 {
            let response = connection
                .send_get("example.test", target()?, vec![])
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        assert!(!connection.is_closed());
        drop(connection);
        assert_eq!(server_task.await??, [1, 3]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cloned_connection_opens_concurrent_streams() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before first request")??;
            let (_, mut second) = connection
                .accept()
                .await
                .ok_or("connection closed before second request")??;
            let mut stream_ids = [first.stream_id().as_u32(), second.stream_id().as_u32()];
            stream_ids.sort_unstable();
            first.send_response(Response::builder().status(200).body(())?, true)?;
            second.send_response(Response::builder().status(201).body(())?, true)?;
            if connection.accept().await.is_some() {
                return Err("client opened an unexpected third stream".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stream_ids)
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let first = connection.clone();
        let second = connection.clone();
        let first = tokio::spawn(async move {
            first
                .send_get("example.test", target()?, vec![])
                .await?
                .into_body()
                .collect()
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let second = tokio::spawn(async move {
            second
                .send_get("example.test", target()?, vec![])
                .await?
                .into_body()
                .collect()
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        first.await??;
        second.await??;
        drop(connection);
        assert_eq!(server_task.await??, [1, 3]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropped_stream_does_not_close_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;

            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before first request")??;
            let mut first_body =
                first.send_response(Response::builder().status(200).body(())?, false)?;
            first_body.send_data(Bytes::from_static(b"partial"), false)?;

            let (_, mut sibling) = connection
                .accept()
                .await
                .ok_or("connection closed before sibling request")??;
            sibling.send_response(Response::builder().status(204).body(())?, true)?;

            let mut reset = None;
            let mut third = None;
            while reset.is_none() || third.is_none() {
                tokio::select! {
                    observed = poll_fn(|context| first_body.poll_reset(context)), if reset.is_none() => {
                        reset = Some(observed?);
                    }
                    next = connection.accept(), if third.is_none() => {
                        third = Some(next.ok_or("connection closed before third request")??);
                    }
                }
            }
            let (_, mut third) = third.ok_or("third request was not retained")?;
            let third_id = third.stream_id().as_u32();
            third.send_response(Response::builder().status(204).body(())?, true)?;
            if connection.accept().await.is_some() {
                return Err("client opened an unexpected fourth stream".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                reset.ok_or("stream reset was not retained")?,
                third_id,
            ))
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let mut abandoned = connection
            .send_get("example.test", target()?, vec![])
            .await?
            .into_body();
        assert_eq!(next_nonempty_data(&mut abandoned).await?, "partial");

        timeout(Duration::from_secs(1), async {
            connection
                .send_get("example.test", target()?, vec![])
                .await?
                .into_body()
                .collect()
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "sibling stream did not complete")??;
        drop(abandoned);

        timeout(Duration::from_secs(1), async {
            connection
                .send_get("example.test", target()?, vec![])
                .await?
                .into_body()
                .collect()
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "new stream did not complete after sibling cancellation")??;
        assert!(!connection.is_closed());
        drop(connection);
        let (reset, third_id) = server_task.await??;
        assert_eq!(reset, ::http2::Reason::CANCEL);
        assert_eq!(third_id, 5);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelled_response_head_resets_only_its_stream() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (first_received, wait_for_first) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before cancelled request")??;
            first_received
                .send(())
                .map_err(|_| "client stopped waiting for request receipt")?;
            let mut reset = None;
            let mut second = None;
            while reset.is_none() || second.is_none() {
                tokio::select! {
                    observed = poll_fn(|context| first.poll_reset(context)), if reset.is_none() => {
                        reset = Some(observed?);
                    }
                    incoming = connection.accept(), if second.is_none() => {
                        second = Some(incoming.ok_or("connection closed before later request")??);
                    }
                }
            }
            let (_, mut second) = second.ok_or("later request was not retained")?;
            let second_id = second.stream_id().as_u32();
            second.send_response(Response::builder().status(204).body(())?, true)?;
            drop(first);
            drop(second);
            if connection.accept().await.is_some() {
                return Err("client opened an unexpected third stream".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                reset.ok_or("stream reset was not retained")?,
                second_id,
            ))
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let request_connection = connection.clone();
        let request_target = target()?;
        let request = tokio::spawn(async move {
            request_connection
                .send_get("example.test", request_target, vec![])
                .await
        });
        wait_for_first.await?;
        request.abort();
        let cancellation = match request.await {
            Ok(_) => return Err("aborted response-head future completed normally".into()),
            Err(error) => error,
        };
        assert!(cancellation.is_cancelled());

        timeout(Duration::from_secs(1), async {
            connection
                .send_get("example.test", target()?, vec![])
                .await?
                .into_body()
                .collect()
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "later request hung after response-head cancellation")??;
        assert!(!connection.is_closed());
        drop(connection);

        let (reset, second_id) = server_task.await??;
        assert_eq!(reset, ::http2::Reason::CANCEL);
        assert_eq!(second_id, 3);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn remote_close_is_observable() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (close_server, close_signal) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            respond.send_response(Response::builder().status(204).body(())?, true)?;
            tokio::select! {
                biased;
                _ = close_signal => {}
                next = connection.accept() => {
                    if next.is_some() {
                        return Err("client opened an unexpected second stream".into());
                    }
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        connection
            .send_get("example.test", target()?, vec![])
            .await?
            .into_body()
            .collect()
            .await?;
        let _ = close_server.send(());
        server_task.await??;
        timeout(Duration::from_secs(1), async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "closed HTTP/2 connection remained healthy")?;
        Ok(())
    })
    .await
}
