use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[test]
fn redirect_targets_only_serve_the_payload_after_the_final_hop() -> Result<()> {
    let body = Body::new(&Config {
        redirects: 3,
        bytes: 32,
        ..Config::default()
    })?;
    for remaining in 0..=3 {
        let response = body.for_target(&format!("/?redirects={remaining}"))?;
        let head = response.head()?;
        if remaining == 0 {
            assert_eq!(head.status(), 200);
            assert_eq!(response.bytes.len(), 32);
            assert!(!head.headers().contains_key("location"));
        } else {
            assert_eq!(head.status(), 302);
            assert!(response.bytes.is_empty());
            assert_eq!(
                head.headers()["location"],
                format!("/?redirects={}", remaining - 1)
            );
        }
    }
    for target in [
        "/",
        "/?redirects=4",
        "/?redirects=-1",
        "/?redirects=1&other=1",
    ] {
        assert!(body.for_target(target).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn completed_disconnects_keep_transport_and_application_errors_distinct() -> Result<()> {
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::UnexpectedEof,
    ] {
        let error = http2::server::handshake(AbruptPeer(b"", kind))
            .await
            .err()
            .ok_or("failed transport completed the handshake")?;
        assert!(completed_http2_close(&error, 1, 1));
        assert!(!completed_http2_close(&error, 0, 0));
        assert!(!completed_http2_close(&error, 2, 1));
    }
    assert!(!completed_http2_close(
        &http2::Reason::PROTOCOL_ERROR.into(),
        1,
        1
    ));
    let timeout = http2::server::handshake(AbruptPeer(b"", std::io::ErrorKind::TimedOut))
        .await
        .err()
        .ok_or("failed transport completed the handshake")?;
    assert!(!completed_http2_close(&timeout, 1, 1));
    let zero =
        h3::error::ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose {
            error_code: 0,
        });
    assert!(quic_application_zero(&zero));
    assert!(!quic_transport_no_error(&zero));
    assert!(!quic_application_zero(&h3::error::ConnectionError::Remote(
        h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0x102 },
    )));
    assert!(!quic_application_zero(&h3::error::ConnectionError::Local {
        error: h3::error::internal_error::InternalConnectionError::new(
            h3::error::Code::H3_NO_ERROR,
            "local close".into(),
        )
        .into(),
    }));
    Ok(())
}
use tokio::io::ReadBuf;

#[test]
fn transport_no_error_requires_the_remote_transport_close_code() {
    use h3::{error::ConnectionError, quic::ConnectionErrorIncoming};

    let reason = |error_code| {
        quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code,
            frame_type: None,
            reason: Bytes::new(),
        })
    };
    let remote =
        |reason| ConnectionError::Remote(ConnectionErrorIncoming::Undefined(Arc::new(reason)));
    assert!(quic_transport_no_error(&remote(reason(
        quinn::TransportErrorCode::NO_ERROR
    ))));
    assert!(!quic_application_zero(&remote(reason(
        quinn::TransportErrorCode::NO_ERROR
    ))));
    assert!(!quic_transport_no_error(&remote(reason(
        quinn::TransportErrorCode::INTERNAL_ERROR
    ))));
    assert!(!quic_transport_no_error(&remote(
        quinn::ConnectionError::Reset
    )));
    assert!(!quic_transport_no_error(&remote(
        quinn::ConnectionError::TimedOut
    )));
    assert!(!quic_transport_no_error(&ConnectionError::Timeout));
    assert!(!quic_transport_no_error(&ConnectionError::Local {
        error: h3::error::internal_error::InternalConnectionError::new(
            h3::error::Code::H3_SETTINGS_ERROR,
            "invalid settings".into(),
        )
        .into(),
    }));
    assert!(!quic_transport_no_error(&ConnectionError::Remote(
        ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
    )));
}

#[test]
fn only_a_typed_idle_timeout_after_all_requests_is_completed_retirement() {
    let stats = Stats {
        expected_requests: 2,
        ..Stats::default()
    };
    let timeout = h3::error::ConnectionError::Timeout;
    let reason = quinn::ConnectionError::TimedOut;
    stats.requests.store(2, Ordering::Relaxed);
    assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
    stats.phase_complete.store(true, Ordering::Release);
    assert!(stats.completed_idle_timeout(&timeout, Some(&reason)));
    stats.requests.store(1, Ordering::Relaxed);
    assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
    stats.requests.store(3, Ordering::Relaxed);
    assert!(!stats.completed_idle_timeout(&timeout, Some(&reason)));
    stats.requests.store(2, Ordering::Relaxed);
    assert!(!stats.completed_idle_timeout(&timeout, None));
    assert!(!stats.completed_idle_timeout(&timeout, Some(&quinn::ConnectionError::Reset)));
}
struct AbruptPeer(&'static [u8], std::io::ErrorKind);

struct ResetAtEof(tokio::io::DuplexStream);

impl AsyncRead for ResetAtEof {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.0).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => {
                Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for ResetAtEof {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn h2_disconnect_only_records_fully_completed_responses() -> Result<()> {
    for consume in [true, false] {
        let (client, server) = tokio::io::duplex(65536);
        let config = Config {
            bytes: 65536,
            chunk_bytes: 1024,
            chunk_delay_ms: 1,
            ..Config::default()
        };
        let stats = Arc::new(Stats::default());
        let peer = tokio::spawn(http2(
            ResetAtEof(server),
            Arc::new(Body::new(&config)?),
            stats.clone(),
        ));
        let (mut sender, connection) = http2::client::handshake(client).await?;
        let driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .uri("https://localhost/")
            .body(())?;
        let (response, _) = sender.send_request(request, true)?;
        let mut response = response.await?.into_body();
        if consume {
            let mut bytes = 0;
            while let Some(data) = response.data().await {
                let data = data?;
                assert!(data.iter().all(|byte| *byte == b'Z'));
                bytes += data.len();
                response.flow_control().release_capacity(data.len())?;
            }
            assert_eq!(bytes, config.bytes);
        }
        driver.abort();
        assert!(driver.await.is_err_and(|error| error.is_cancelled()));
        let outcome = tokio::time::timeout(Duration::from_secs(5), peer).await??;
        assert_eq!(outcome.is_ok(), consume);
        assert_eq!(
            stats.completed_h2_boundary_closes.load(Ordering::Relaxed),
            usize::from(consume)
        );
        assert_eq!(stats.requests.load(Ordering::Relaxed), usize::from(consume));
    }
    Ok(())
}

impl AsyncRead for AbruptPeer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.0.is_empty() {
            return Poll::Ready(Err(self.1.into()));
        }
        let length = self.0.len().min(buf.remaining());
        buf.put_slice(&self.0[..length]);
        self.0 = &self.0[length..];
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AbruptPeer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn abrupt_close_before_any_response_fails() -> Result<()> {
    let stats = Arc::new(Stats::default());
    let result = http1(
        AbruptPeer(b"", std::io::ErrorKind::UnexpectedEof),
        Arc::new(Body::new(&Config::default())?),
        stats.clone(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
        0
    );
    Ok(())
}

#[tokio::test]
async fn abrupt_close_after_complete_response_is_recorded() -> Result<()> {
    let stats = Arc::new(Stats::default());
    http1(
        AbruptPeer(b"GET / HTTP/1.1\r\n\r\n", std::io::ErrorKind::UnexpectedEof),
        Arc::new(Body::new(&Config::default())?),
        stats.clone(),
    )
    .await?;
    assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
    assert_eq!(
        stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
        1
    );
    Ok(())
}

#[tokio::test]
async fn partial_next_head_still_fails_after_a_complete_response() -> Result<()> {
    let stats = Arc::new(Stats::default());
    let result = http1(
        AbruptPeer(
            b"GET / HTTP/1.1\r\n\r\nGET /part",
            std::io::ErrorKind::UnexpectedEof,
        ),
        Arc::new(Body::new(&Config::default())?),
        stats.clone(),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        stats.completed_h1_boundary_closes.load(Ordering::Relaxed),
        0
    );
    Ok(())
}

#[tokio::test]
async fn h2_body_cancel_preserves_the_sibling_stream() -> Result<()> {
    for reason in [http2::Reason::CANCEL, http2::Reason::INTERNAL_ERROR] {
        let (client, server) = tokio::io::duplex(65536);
        let config = Config {
            bytes: 65536,
            chunk_bytes: 1024,
            chunk_delay_ms: 1,
            cancel_after_bytes: 1024,
            ..Config::default()
        };
        let stats = Arc::new(Stats::default());
        let peer = tokio::spawn(http2(
            ResetAtEof(server),
            Arc::new(Body::new(&config)?),
            stats.clone(),
        ));
        let (mut sender, mut connection) = http2::client::handshake(client).await?;
        let mut ping = connection.ping_pong().ok_or("missing H2 ping handle")?;
        let driver = tokio::spawn(connection);
        let (cancelled, mut reset) = sender.send_request(
            http::Request::builder()
                .uri("https://localhost/?cancel=1")
                .body(())?,
            true,
        )?;
        let (sibling, _) = sender.send_request(
            http::Request::builder()
                .uri("https://localhost/")
                .body(())?,
            true,
        )?;
        let mut cancelled = cancelled.await?.into_body();
        assert!(
            !cancelled
                .data()
                .await
                .ok_or("missing cancellation prefix")??
                .is_empty()
        );
        reset.send_reset(reason);
        drop(cancelled);
        if reason != http2::Reason::CANCEL {
            // Flush the queued reset before stopping the connection driver.
            tokio::time::timeout(Duration::from_secs(5), ping.ping(http2::Ping::opaque()))
                .await??;
            driver.abort();
            assert!(driver.await.is_err_and(|error| error.is_cancelled()));
            let error = tokio::time::timeout(Duration::from_secs(5), peer)
                .await??
                .err()
                .ok_or("INTERNAL_ERROR must fail the peer")?;
            assert_eq!(
                error
                    .downcast_ref::<http2::Error>()
                    .and_then(http2::Error::reason),
                Some(reason)
            );
            assert_eq!(stats.cancelled_streams.load(Ordering::Relaxed), 0);
            continue;
        }
        let mut sibling = sibling.await?.into_body();
        let mut received = 0;
        while let Some(data) = sibling.data().await {
            let data = data?;
            received += data.len();
            sibling.flow_control().release_capacity(data.len())?;
        }
        assert_eq!(received, config.bytes);
        driver.abort();
        assert!(driver.await.is_err_and(|error| error.is_cancelled()));
        let result = tokio::time::timeout(Duration::from_secs(5), peer).await??;
        assert!(
            result.is_ok(),
            "CANCEL disrupted the connection: {result:?}"
        );
        assert_eq!(
            stats.cancelled_streams.load(Ordering::Relaxed),
            usize::from(reason == http2::Reason::CANCEL)
        );
        assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
        if reason == http2::Reason::CANCEL {
            assert_eq!(stats.cancelled_while_multiplexed.load(Ordering::Relaxed), 1);
        }
    }
    Ok(())
}

#[test]
fn cancellation_targets_accept_both_http_uri_forms() -> Result<()> {
    let body = Body::new(&Config {
        cancel_after_bytes: 1024,
        ..Config::default()
    })?;
    for target in ["/?cancel=1", "https://localhost/?cancel=1"] {
        assert!(body.for_target(target)?.cancel);
    }
    for target in ["/", "https://localhost/"] {
        assert!(!body.for_target(target)?.cancel);
    }
    assert!(body.for_target("https://localhost/?cancel=0").is_err());
    Ok(())
}
#[tokio::test]
async fn h2_zero_window_cancel_preserves_a_warmed_body_free_get() -> Result<()> {
    for reason in [http2::Reason::CANCEL, http2::Reason::INTERNAL_ERROR] {
        let (client, server) = tokio::io::duplex(65536);
        let config = Config {
            cancel_stage: "upload".into(),
            method: "POST".into(),
            upload_bytes: 65536,
            bytes: 1024,
            ..Config::default()
        };
        let stats = Arc::new(Stats::default());
        let peer = tokio::spawn(http2(
            ResetAtEof(server),
            Arc::new(Body::new(&config)?),
            stats.clone(),
        ));
        let (mut sender, mut connection) = http2::client::handshake(client).await?;
        let mut ping = connection.ping_pong().ok_or("missing H2 ping handle")?;
        let driver = tokio::spawn(connection);
        let (warm, _) = sender.send_request(
            http::Request::builder()
                .uri("https://localhost/")
                .body(())?,
            true,
        )?;
        let mut warm = warm.await?.into_body();
        while let Some(data) = warm.data().await {
            let data = data?;
            warm.flow_control().release_capacity(data.len())?;
        }
        let (_selected, mut upload) = sender.send_request(
            http::Request::builder()
                .method("POST")
                .uri("https://localhost/?cancel=1")
                .header("content-length", config.upload_bytes)
                .body(())?,
            false,
        )?;
        upload.reserve_capacity(config.upload_bytes);
        assert_eq!(
            upload.capacity(),
            0,
            "warmup must apply the zero-window SETTINGS"
        );
        let (healthy, _) = sender.send_request(
            http::Request::builder()
                .uri("https://localhost/")
                .body(())?,
            true,
        )?;
        let mut healthy = tokio::time::timeout(Duration::from_secs(5), healthy)
            .await??
            .into_body();
        assert!(
            !healthy.is_end_stream(),
            "healthy response must stay open before cancellation"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let notified = stats.settlement.notified();
                if stats.upload_headers.load(Ordering::Acquire) == 1 {
                    break;
                }
                notified.await;
            }
        })
        .await?;
        assert_eq!(
            stats.requests.load(Ordering::Relaxed),
            1,
            "only the warmup may finish before cancellation"
        );
        upload.send_reset(reason);
        tokio::time::timeout(Duration::from_secs(5), ping.ping(http2::Ping::opaque())).await??;
        if reason == http2::Reason::CANCEL {
            let mut bytes = 0;
            while let Some(data) = healthy.data().await {
                let data = data?;
                bytes += data.len();
                healthy.flow_control().release_capacity(data.len())?;
            }
            assert_eq!(bytes, config.bytes);
        }
        driver.abort();
        assert!(driver.await.is_err_and(|error| error.is_cancelled()));
        let result = tokio::time::timeout(Duration::from_secs(5), peer).await??;
        if reason == http2::Reason::CANCEL {
            result?;
            assert_eq!(stats.cancelled_uploads.load(Ordering::Relaxed), 1);
            assert_eq!(stats.cancelled_while_multiplexed.load(Ordering::Relaxed), 1);
            assert_eq!(stats.requests.load(Ordering::Relaxed), 2);
        } else {
            assert!(result.is_err());
            assert_eq!(stats.cancelled_uploads.load(Ordering::Relaxed), 0);
        }
        assert_eq!(stats.uploaded_bytes.load(Ordering::Relaxed), 0);
    }
    Ok(())
}
