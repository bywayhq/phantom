use super::*;
use crate::support::{
    tls::{H1_ALPN, accept_tls_stream, read_head},
    websocket::{append_and_write_server_frame, header_value, read_client_frame, websocket_accept},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    PreparedRequestTemplate, WebSocketMessage,
    profile::{RequestField, RequestTemplate},
};
use phantom_net::route::ConnectedStream;
#[derive(Clone, Copy)]
enum Claim {
    Ordinary,
    Upgrade,
    Rejected,
}

#[tokio::test]
async fn socks_h1_websocket_keeps_authenticated_tunnel_quiet_and_claimable_before_101()
-> TestResult<()> {
    for socks in [Socks::Four, Socks::FiveRemote, Socks::FiveLocal] {
        for policy in [false, true] {
            control(socks, policy, false, Claim::Ordinary).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn socks_plaintext_policy_websocket_spare_belongs_to_ordinary_http1_pool() -> TestResult<()> {
    control(Socks::FiveRemote, true, true, Claim::Ordinary).await
}
#[tokio::test]
async fn cancelled_socks_h1_websocket_leaves_quiet_tunnel_for_current_upgrade() -> TestResult<()> {
    for policy in [false, true] {
        control(Socks::FiveRemote, policy, false, Claim::Upgrade).await?;
    }
    Ok(())
}
#[tokio::test]
async fn claimed_socks_h1_upgrade_preserves_rejection_body_without_old_fields_or_redial()
-> TestResult<()> {
    control(Socks::Four, true, false, Claim::Rejected).await
}

async fn control(socks: Socks, policy: bool, plaintext: bool, claim: Claim) -> TestResult<()> {
    timeout(WAIT, run(socks, policy, plaintext, claim)).await?
}

async fn run(socks: Socks, policy: bool, plaintext: bool, claim: Claim) -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(HOST)?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let password = password()?;
    let client = client(
        &identity,
        listener.local_addr()?.port(),
        socks,
        false,
        &password,
    )?;
    let ws = format!("{}://{HOST}/first", if plaintext { "ws" } else { "wss" });
    let page = format!("{}://{HOST}/page", if plaintext { "http" } else { "https" });
    let current = format!("{}://{HOST}/socket", if plaintext { "ws" } else { "wss" });
    let (ready, was_ready) = oneshot::channel();
    let (claim_tx, claimed) = oneshot::channel();
    let (ack, was_quiet) = oneshot::channel();
    let caller = async {
        let builder = if policy {
            client.websocket_with_profile_policy(&ws)?
        } else {
            client.websocket(&ws)?
        };
        let mut opening = Some(Box::pin(
            builder
                .header(RequestHeader::new("x-claim", "first"))
                .connect(),
        ));
        tokio::select! {
            result = opening.as_mut().ok_or("missing first opening")? => {
                drop(result);
                return Err("first opening settled before its held TLS/101".into());
            }
            observed = was_ready => observed?,
        }
        if !matches!(claim, Claim::Ordinary) {
            drop(opening.take());
        }
        claim_tx.send(()).map_err(|_| "quiet peer ended")?;
        was_quiet.await?;
        match claim {
            Claim::Ordinary => {
                let fields = PreparedRequestTemplate::new(RequestTemplate {
                    http1_fields: vec![RequestField::required_caller("x-claim")],
                    http2_fields: vec![RequestField::required_caller("x-claim")],
                    http3_fields: None,
                    http2_priority: None,
                    requested_client_hint_placement: false,
                    restarts_for_connection_accept_ch: false,
                })?;
                let request = if policy {
                    client.get_negotiated(&page)?
                } else {
                    client.get(HttpProtocol::Http1, &page)?
                };
                let response = request
                    .template(&fields)
                    .header(RequestHeader::new("x-claim", "current"))
                    .send()
                    .await?;
                assert_eq!(response.status(), 200);
                assert_eq!(response.into_body().collect().await?.to_bytes(), "done");
            }
            Claim::Upgrade | Claim::Rejected => {
                let request = if policy {
                    client.websocket_with_profile_policy(&current)?
                } else {
                    client.websocket(&current)?
                };
                let result = request
                    .header(RequestHeader::new("x-claim", "current"))
                    .connect()
                    .await;
                if matches!(claim, Claim::Rejected) {
                    let error = match result {
                        Err(error) => error,
                        Ok(_) => return Err("rejected opening succeeded".into()),
                    };
                    let response = error.into_response().ok_or("missing rejection body")?;
                    assert_eq!(response.status(), 403);
                    assert_eq!(response.into_body().collect().await?.to_bytes(), "denied");
                } else {
                    let mut socket = result?;
                    socket
                        .send(WebSocketMessage::Binary(Bytes::from_static(b"client")))
                        .await?;
                    assert_eq!(
                        socket.receive().await?,
                        WebSocketMessage::Binary(Bytes::from_static(b"peer"))
                    );
                    drop(socket);
                }
            }
        }
        drop(opening.take());
        drop(client);
        TestResult::Ok(())
    };
    let peer = async {
        let port = if plaintext { 80 } else { 443 };
        let mut spare = peer::negotiate(&listener, socks, port, &password).await?;
        let mut winner = peer::negotiate(&listener, socks, port, &password).await?;
        peer::reply(&mut winner, socks).await?;
        if plaintext {
            let first = read_head(&mut winner).await?;
            assert!(first.starts_with(b"GET /first HTTP/1.1\r\n"));
            assert_eq!(header_value(&first, "x-claim"), Some("first"));
        } else {
            let mut hello = [0; 6];
            winner.read_exact(&mut hello).await?;
            assert_eq!((hello[0], hello[5]), (22, 1));
        }
        peer::reply(&mut spare, socks).await?;
        ready.send(()).map_err(|_| "first owner ended")?;
        peer::quiet(&mut spare, claimed, ack).await?;
        let mut spare = if plaintext {
            ConnectedStream::new(spare)
        } else {
            ConnectedStream::new(accept_tls_stream(spare, acceptor).await?)
        };
        let head = read_head(&mut spare).await?;
        assert_eq!(header_value(&head, "x-claim"), Some("current"));
        assert!(
            !head
                .windows(b"Proxy-Authorization".len())
                .any(|part| part == b"Proxy-Authorization")
        );
        if !matches!(claim, Claim::Ordinary) {
            let key = header_value(&head, "sec-websocket-key").ok_or("missing current key")?;
            assert_eq!(head, format!("GET /socket HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nx-claim: current\r\n\r\n").as_bytes());
        }
        match claim {
            Claim::Ordinary => {
                assert_eq!(
                    head,
                    format!("GET /page HTTP/1.1\r\nHost: {HOST}\r\nx-claim: current\r\n\r\n")
                        .as_bytes()
                );
                spare
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
                    )
                    .await?;
            }
            Claim::Rejected => {
                assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
                spare.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied").await?;
            }
            Claim::Upgrade => {
                assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
                let accept = websocket_accept(
                    header_value(&head, "sec-websocket-key").ok_or("missing key")?,
                );
                spare.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
                let frame = read_client_frame(&mut spare).await?;
                assert_eq!(frame.payload, b"client");
                append_and_write_server_frame(&mut spare, true, 2, b"peer").await?;
            }
        }
        peer::closed(&mut spare).await?;
        let mut rest = Vec::new();
        match winner.read_to_end(&mut rest).await {
            Ok(_) => {}
            Err(error) if crate::support::tls::is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
        }
        if plaintext {
            assert!(rest.is_empty(), "held first opening sent an extra request");
        }
        peer::no_redial(&listener)?;
        TestResult::Ok(())
    };
    // These joined futures own every peer; failure/cancellation drops all sockets.
    tokio::try_join!(caller, peer)?;
    Ok(())
}
