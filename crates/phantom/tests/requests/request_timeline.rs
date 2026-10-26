//! Opt-in request observations through the public client.

use crate::support::{
    tls::{H1_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};
use phantom::{
    Client, HttpProtocol, RequestDiagnostics, RequestTimelineOutcome, RequestTimingOutcome,
    RequestTimingPhase, profile::ClientProfile,
};
use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

fn record(request: &mut phantom::RequestBuilder) -> RequestDiagnostics {
    request.diagnostics(NonZeroUsize::MIN.saturating_add(127))
}

#[tokio::test]
async fn streamed_body_finishes_after_headers_and_warm_requests_omit_setup() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/private?token=secret", listener.local_addr()?);
        let (release, released) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            let mut socket = accept_tls(listener, acceptor).await?;
            read_head(&mut socket).await?;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                .await?;
            socket.flush().await?;
            released.await?;
            socket.write_all(b"data").await?;
            socket.flush().await?;
            read_head(&mut socket).await?;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
                .await?;
            socket.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let caller = async {
            let client = client_builder(&identity, true).build()?;
            let mut request = client.get(&url)?;
            let trace = record(&mut request);
            let again = request.diagnostics(NonZeroUsize::MIN);
            assert_eq!(trace.snapshot().outcome, RequestTimelineOutcome::NotStarted);
            let outer = RequestDiagnostics::new(NonZeroUsize::MIN.saturating_add(127));
            let response = outer.observe(request.send()).await?;
            assert!(outer.snapshot().events.is_empty());
            let head = trace.snapshot();
            assert_eq!(head.outcome, RequestTimelineOutcome::ResponseHead);
            for phase in [
                RequestTimingPhase::PoolAdmission,
                RequestTimingPhase::ConnectionAcquisition,
                RequestTimingPhase::TcpConnect,
                RequestTimingPhase::TlsHandshake,
                RequestTimingPhase::SendResponseHead,
            ] {
                assert!(
                    head.events.iter().any(|event| event.phase == phase
                        && event.outcome == RequestTimingOutcome::Completed),
                    "missing {phase:?}: {head:?}"
                );
            }
            assert!(
                head.events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::ResponseBody
                        && event.outcome == RequestTimingOutcome::Pending)
            );
            assert!(head.events.len() > 1);
            assert_eq!(again.snapshot().events.len(), head.events.len());
            assert!(!format!("{head:?}").contains("secret"));
            release
                .send(())
                .map_err(|_| "server stopped before body release")?;
            assert_eq!(
                response.into_body().collect_with_limit(4).await?.as_ref(),
                b"data"
            );
            let complete = trace.snapshot();
            assert_eq!(complete.send_elapsed, head.send_elapsed);
            let body = complete
                .events
                .iter()
                .find(|event| event.phase == RequestTimingPhase::ResponseBody)
                .ok_or("missing body timing")?;
            assert_eq!(body.outcome, RequestTimingOutcome::Completed);
            assert!(
                body.finished.ok_or("unfinished body")?
                    >= head.send_elapsed.ok_or("missing head duration")?
            );
            let mut warm = client.get(&url)?;
            let warm_trace = record(&mut warm);
            assert_eq!(
                warm.send()
                    .await?
                    .into_body()
                    .collect_with_limit(4)
                    .await?
                    .as_ref(),
                b"data"
            );
            assert!(!warm_trace.snapshot().events.iter().any(|event| matches!(
                event.phase,
                RequestTimingPhase::TcpConnect
                    | RequestTimingPhase::TlsHandshake
                    | RequestTimingPhase::ResolutionWait
            )));
            Ok(())
        };
        let result = caller.await;
        finish_with_cleanup(result, peer.stop().await)
    })
    .await?
}

#[tokio::test]
async fn cancelled_tls_setup_remains_inspectable() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let (seen, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            socket.read_exact(&mut [0u8; 1]).await?;
            seen.send(())
                .map_err(|_| "caller stopped before ClientHello")?;
            released.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let caller = async {
            let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
            let mut request = client.get_with_protocol(HttpProtocol::Http1, &url)?;
            let trace = record(&mut request);
            let running = tokio::spawn(request.send());
            received.await?;
            assert!(
                trace
                    .snapshot()
                    .events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::TlsHandshake
                        && event.outcome == RequestTimingOutcome::Pending)
            );
            running.abort();
            assert!(matches!(running.await, Err(error) if error.is_cancelled()));
            let snapshot = trace.snapshot();
            assert_eq!(snapshot.outcome, RequestTimelineOutcome::Cancelled);
            assert!(
                snapshot
                    .events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::TlsHandshake
                        && event.outcome == RequestTimingOutcome::Interrupted)
            );
            release
                .send(())
                .map_err(|_| "server stopped before cleanup")?;
            Ok(())
        };
        let result = caller.await;
        finish_with_cleanup(result, peer.stop().await)
    })
    .await?
}

#[tokio::test]
async fn dropping_an_unread_body_is_abandonment_and_does_not_leak_admission() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let peer = ConnectionPeer::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await?;
                read_head(&mut socket).await?;
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .await?;
                socket.flush().await?;
                let mut buffer = [0u8; 32];
                let _closed = socket.read(&mut buffer).await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let caller = async {
            let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
            for _ in 0..2 {
                let mut request = client.get_with_protocol(HttpProtocol::Http1, &url)?;
                let trace = record(&mut request);
                drop(request.send().await?);
                let snapshot = trace.snapshot();
                assert_eq!(snapshot.outcome, RequestTimelineOutcome::ResponseHead);
                assert!(
                    snapshot
                        .events
                        .iter()
                        .any(|event| event.phase == RequestTimingPhase::ResponseBody
                            && event.outcome == RequestTimingOutcome::Abandoned)
                );
            }
            Ok(())
        };
        let result = caller.await;
        finish_with_cleanup(result, peer.stop().await)
    })
    .await?
}

#[tokio::test]
async fn empty_success_and_one_frame_collection_failure_have_distinct_outcomes() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/", listener.local_addr()?);
        let peer = ConnectionPeer::spawn(async move {
            for reply in [
                b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata".as_slice(),
            ] {
                let (mut socket, _) = listener.accept().await?;
                read_head(&mut socket).await?;
                socket.write_all(reply).await?;
                socket.flush().await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let caller = async {
            let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
            let mut empty = client.get_with_protocol(HttpProtocol::Http1, &url)?;
            let trace = record(&mut empty);
            let response = empty.send().await?;
            let snapshot = trace.snapshot();
            assert!(
                snapshot
                    .events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::ConnectionAcquisition)
            );
            assert!(
                snapshot
                    .events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::ResponseBody
                        && event.outcome == RequestTimingOutcome::Completed)
            );
            drop(response);
            let mut oversized = client.get_with_protocol(HttpProtocol::Http1, &url)?;
            let trace = record(&mut oversized);
            let error = oversized
                .send()
                .await?
                .into_body()
                .collect_with_limit(3)
                .await
                .err()
                .ok_or("oversized body succeeded")?;
            assert_eq!(error.kind(), phantom::RequestErrorKind::ResponseBodyLimit);
            let snapshot = trace.snapshot();
            assert_eq!(snapshot.outcome, RequestTimelineOutcome::ResponseHead);
            assert!(
                snapshot
                    .events
                    .iter()
                    .any(|event| event.phase == RequestTimingPhase::ResponseBody
                        && event.outcome == RequestTimingOutcome::Failed)
            );
            Ok(())
        }
        .await;
        finish_with_cleanup(caller, peer.stop().await)
    })
    .await?
}
