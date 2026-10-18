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
