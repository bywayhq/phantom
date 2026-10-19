//! Direct prior knowledge against a framed HTTP/2 peer without a server stack.

use std::{io, net::Ipv4Addr, time::Duration};

use phantom::{
    Client, HttpAttemptBudget, HttpProtocol, RequestErrorKind, RequestTimingPhase,
    TlsConnectionState, profile::browser::chrome,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

use crate::support::{
    h2,
    tls::{TestResult, read_head},
};

const LIMIT: Duration = Duration::from_secs(10);

fn client() -> TestResult<Client> {
    use phantom::profile::{ClientProfile, Http2PseudoHeader};
    let mut http2 = chrome::v154_http2();
    http2.pseudo_header_order = vec![
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Path,
    ];
    Ok(Client::builder(ClientProfile::new(chrome::v154_tcp_tls()).with_http2(http2)).build()?)
}

#[test]
fn unsupported_plaintext_proxy_route_fails_before_runtime_or_network_work() -> TestResult<()> {
    let client = Client::builder(chrome::v154_windows())
        .route(phantom::Route::http_proxy(phantom::HttpProxy::new(
            "http://127.0.0.1:9",
        )?))
        .build()?;
    let future = client
        .get(HttpProtocol::Http2, "http://origin.test/")?
        .send();
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(std::future::Future::poll(future.as_mut(), &mut context),
        std::task::Poll::Ready(Err(error)) if error.kind() == RequestErrorKind::UnsupportedRoute)
    );
    Ok(())
}

async fn headers(stream: &mut TcpStream) -> TestResult<u32> {
    loop {
        let frame = h2::read_frame(stream).await?;
        if frame.kind != 1 {
            continue;
        }
        assert_ne!(frame.flags & 4, 0, "small request needs no continuation");
        let payload = if frame.flags & 0x20 != 0 {
            &frame.payload[5..]
        } else {
            &frame.payload
        };
        // This test profile places :scheme first. RFC7541 AppendixA entry6
        // is :scheme=http. No server table-size change precedes it.
        assert_eq!(payload.first(), Some(&0x86));
        return Ok(frame.stream_id);
    }
}

async fn response(stream: &mut TcpStream, id: u32, end: bool) -> io::Result<()> {
    // HPACK static-table entry8 is :status=200.
    h2::write_frame(stream, 1, if end { 5 } else { 4 }, id, &[0x88]).await?;
    stream.flush().await
}

#[tokio::test]
async fn explicit_h2c_reuses_one_connection_and_spends_the_shared_budget() -> TestResult<()> {
    timeout(LIMIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            h2::accept_client_preface(&mut stream).await?;
            let first = headers(&mut stream).await?;
            response(&mut stream, first, true).await?;
            let second = headers(&mut stream).await?;
            assert!(second > first);
            response(&mut stream, second, true).await?;
            // No third origin request can be sent after budget exhaustion.
            loop {
                match h2::read_frame(&mut stream).await {
                    Ok(frame) => assert_ne!(frame.kind, 1),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            TestResult::Ok(())
        });
        let client = client()?;
        let budget = HttpAttemptBudget::new(2);
        let url = format!("http://{address}/prior-knowledge");
        for reused in [false, true] {
            let mut request = client
                .get(HttpProtocol::Http2, &url)?
                .attempt_budget(budget.clone());
            let trace = request.diagnostics(std::num::NonZeroUsize::MIN.saturating_add(63));
            let received = request.send().await?;
            assert_eq!(received.version(), http::Version::HTTP_2);
            assert!(received.into_body().collect_with_limit(0).await?.is_empty());
            let snapshot = trace.snapshot();
            let used = snapshot
                .events
                .iter()
                .find_map(|event| event.connection.as_ref())
                .ok_or("missing connection facts")?;
            assert_eq!(used.reused, reused);
            assert_eq!(used.peer_address, Some(address));
            assert!(matches!(used.origin_tls, TlsConnectionState::NotUsed));
            assert!(
                snapshot
                    .events
                    .iter()
                    .all(|event| event.phase != RequestTimingPhase::TlsHandshake)
            );
        }
        let error = client
            .get(HttpProtocol::Http2, &url)?
            .attempt_budget(budget)
            .send()
            .await
            .err()
            .ok_or("exhausted request succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        drop(client);
        peers.join_next().await.ok_or("missing peer")???;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_a_cleartext_body_preserves_the_reused_connection() -> TestResult<()> {
    timeout(LIMIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            h2::accept_client_preface(&mut stream).await?;
            let first = headers(&mut stream).await?;
            response(&mut stream, first, false).await?;
            let mut cancelled = false;
            let mut next = None;
            while !cancelled || next.is_none() {
                let frame = h2::read_frame(&mut stream).await?;
                if frame.kind == 3 {
                    assert_eq!(frame.stream_id, first);
                    assert_eq!(frame.payload, 8_u32.to_be_bytes());
                    cancelled = true;
                } else if frame.kind == 1 {
                    assert!(frame.stream_id > first);
                    next = Some(frame.stream_id);
                }
            }
            let next = next.ok_or("missing surviving stream")?;
            response(&mut stream, next, true).await?;
            TestResult::Ok(())
        });
        let client = client()?;
        let url = format!("http://{address}/cancel");
        let first = client.get(HttpProtocol::Http2, &url)?.send().await?;
        drop(first);
        let next = client.get(HttpProtocol::Http2, &url)?.send().await?;
        assert!(next.into_body().collect_with_limit(0).await?.is_empty());
        peers.join_next().await.ok_or("missing peer")???;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn negotiated_cleartext_remains_http1_and_incompatible_h2c_never_falls_back() -> TestResult<()>
{
    timeout(LIMIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut peers = JoinSet::new();
        peers.spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert!(
                read_head(&mut stream)
                    .await?
                    .starts_with(b"GET / HTTP/1.1\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            stream.flush().await?;
            drop(stream);
            let (mut stream, _) = listener.accept().await?;
            let mut preface = [0; 24];
            stream.read_exact(&mut preface).await?;
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            stream.flush().await?;
            drop(stream);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(listener)
        });
        let client = Client::builder(chrome::v154_windows()).build()?;
        let url = format!("http://{address}/");
        let result = client.get_negotiated(&url)?.send().await?;
        assert_eq!(result.version(), http::Version::HTTP_11);
        assert!(result.into_body().collect_with_limit(0).await?.is_empty());
        let error = client
            .get(HttpProtocol::Http2, &url)?
            .send()
            .await
            .err()
            .ok_or("HTTP/1 peer accepted HTTP/2")?;
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        let listener = peers.join_next().await.ok_or("missing peer")???;
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        Ok(())
    })
    .await?
}
