use super::*;
use crate::support::{
    tls::{H2_ALPN, accept_tls_stream},
    websocket::append_server_frame,
};
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{WebSocketErrorKind, WebSocketMessage};
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Accept,
    Cancel,
    Reject,
}
#[tokio::test]
async fn socks_h2_websocket_retires_complete_quiet_tunnel_before_connect_headers() -> TestResult<()>
{
    for socks in [Socks::Four, Socks::FiveRemote, Socks::FiveLocal] {
        for policy in [false, true] {
            control(socks, policy, Mode::Accept).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn cancelled_socks_h2_websocket_tunnel_uses_only_current_claimant_fields() -> TestResult<()> {
    for policy in [false, true] {
        control(Socks::FiveRemote, policy, Mode::Cancel).await?;
    }
    Ok(())
}
#[tokio::test]
async fn rejected_socks_h2_websocket_retains_body_without_replay_or_redial() -> TestResult<()> {
    control(Socks::Four, true, Mode::Reject).await
}
async fn control(socks: Socks, policy: bool, mode: Mode) -> TestResult<()> {
    timeout(WAIT, run(socks, policy, mode)).await?
}

async fn run(socks: Socks, policy: bool, mode: Mode) -> TestResult<()> {
    let identity = TestIdentity::generate_for_dns(HOST)?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let password = password()?;
    let client = client(
        &identity,
        listener.local_addr()?.port(),
        socks,
        true,
        &password,
    )?;
    let url = format!("wss://{HOST}/events");
    let (ready, was_ready) = oneshot::channel();
    let (claim, claimed) = oneshot::channel();
    let (quiet, was_quiet) = oneshot::channel();
    let (done, completed) = oneshot::channel();
    let caller = async {
        if mode == Mode::Cancel {
            let builder = if policy {
                client.websocket_with_profile_policy(&url)?
            } else {
                client.websocket_with_protocol(HttpProtocol::Http2, &url)?
            };
            let mut opening = Box::pin(
                builder
                    .header(RequestHeader::new("x-claim", "first"))
                    .connect(),
            );
            tokio::select! {
                result = &mut opening => {
                    drop(result);
                    return Err("first opening settled before cancellation".into());
                }
                observed = was_ready => observed?,
            }
            drop(opening);
            claim.send(()).map_err(|_| "quiet peer ended")?;
            was_quiet.await?;
        } else {
            drop((was_ready, claim, was_quiet));
        }
        let request = if policy {
            client.websocket_with_profile_policy(&url)?
        } else {
            client.websocket_with_protocol(HttpProtocol::Http2, &url)?
        };
        let result = request
            .header(RequestHeader::new("x-claim", "current"))
            .connect()
            .await;
        if mode == Mode::Reject {
            let error = match result {
                Err(error) => error,
                Ok(_) => return Err("rejected CONNECT succeeded".into()),
            };
            assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
            let response = error.into_response().ok_or("missing rejection body")?;
            assert_eq!(response.status(), 403);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "denied");
        } else {
            let mut socket = result?;
            assert_eq!(socket.handshake_response().version(), http::Version::HTTP_2);
            assert_eq!(
                socket.receive().await?,
                WebSocketMessage::Binary(Bytes::from_static(b"peer"))
            );
            drop(socket);
        }
        done.send(()).map_err(|_| "H2 peer ended")?;
        drop(client);
        TestResult::Ok(())
    };
    let peer = async {
        let mut spare = peer::negotiate(&listener, socks, 443, &password).await?;
        let mut winner = peer::negotiate(&listener, socks, 443, &password).await?;
        peer::reply(&mut winner, socks).await?;
        // An actual ClientHello fences which complete SOCKS attempt won.
        // Peek leaves it intact for the TLS acceptor; no fixture prefix shim.
        let mut first = [0];
        assert_eq!(winner.peek(&mut first).await?, 1);
        assert_eq!(first[0], 22);
        // The backup completes SOCKS while the winner's origin TLS is held.
        peer::reply(&mut spare, socks).await?;
        let mut spare = Some(spare);
        let transport = if mode == Mode::Cancel {
            let mut hello = [0; 6];
            winner.read_exact(&mut hello).await?;
            assert_eq!((hello[0], hello[5]), (22, 1));
            ready.send(()).map_err(|_| "cancellation owner ended")?;
            peer::quiet(spare.as_mut().ok_or("missing spare")?, claimed, quiet).await?;
            drop(winner);
            spare.take().ok_or("missing claimed spare")?
        } else {
            drop((ready, claimed, quiet));
            winner
        };
        let tls = accept_tls_stream(transport, acceptor).await?;
        assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
        let mut builder = ::http2::server::Builder::new();
        builder.enable_connect_protocol();
        let mut connection = builder.handshake::<_, Bytes>(tls).await?;
        if let Some(mut spare) = spare {
            peer::closed(&mut spare).await?;
        }
        let (request, mut respond) = connection.accept().await.ok_or("missing CONNECT")??;
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(request.uri().path(), "/events");
        assert_eq!(
            request
                .extensions()
                .get::<::http2::ext::Protocol>()
                .map(|protocol| protocol.as_str()),
            Some("websocket")
        );
        assert_eq!(
            request
                .headers()
                .get("x-claim")
                .ok_or("missing current field")?,
            "current"
        );
        assert!(!request.headers().contains_key("proxy-authorization"));
        let mut send = respond.send_response(
            Response::builder()
                .status(if mode == Mode::Reject { 403 } else { 200 })
                .body(())?,
            false,
        )?;
        let data = if mode == Mode::Reject {
            b"denied".to_vec()
        } else {
            let mut wire = Vec::new();
            append_server_frame(&mut wire, true, 2, b"peer");
            wire
        };
        send.send_data(Bytes::from(data), mode == Mode::Reject)?;
        let finish = async {
            completed
                .await
                .map_err(|_| "caller ended before completion")?;
            TestResult::Ok(())
        };
        tokio::pin!(finish);
        tokio::select! {
            biased;
            result = &mut finish => result?,
            next = connection.accept() => match next {
                Some(Ok(_)) => return Err("unexpected additional CONNECT or request".into()),
                Some(Err(error)) if error.get_io().is_some_and(crate::support::tls::is_peer_gone) => finish.await?,
                Some(Err(error)) => return Err(error.into()),
                None => finish.await?,
            },
        }
        peer::no_redial(&listener)?;
        drop((send, respond, request));
        TestResult::Ok(())
    };
    tokio::try_join!(caller, peer)?;
    Ok(())
}
