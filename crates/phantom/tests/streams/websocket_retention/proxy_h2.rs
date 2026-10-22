//! Proxy TCP backup ownership controls.
use super::proxy_h2_peer::{self, Mode};
use super::{TEST_TIMEOUT, TestIdentity, TestResult};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use phantom::{
    AddressResolver, Client, HttpProtocol, HttpProxy, RequestHeader, Route, WebSocketErrorKind,
    WebSocketMessage,
    profile::{ClientProfile, WebSocketField, WebSocketNewConnection, browser::firefox},
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::oneshot,
    time::timeout,
};

fn client(
    origin: &TestIdentity,
    proxy_identity: &TestIdentity,
    port: u16,
    https: bool,
) -> TestResult<Client> {
    let mut websocket = firefox::v157_websocket();
    // Force the new-H2 path without changing Firefox's physical Backup policy.
    websocket.connection.without_http2_session = WebSocketNewConnection::Http2ExtendedConnect;
    websocket.http2_fields = vec![
        WebSocketField::caller("user-agent"),
        WebSocketField::literal("sec-websocket-version", "13"),
        WebSocketField::client_cookies("cookie"),
        WebSocketField::caller("x-claim"),
    ];
    let profile = ClientProfile::new(crate::support::tls::tls_settings())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_tcp(firefox::v157_tcp())
        .with_websocket(websocket)
        .with_proxy_connect(firefox::v157_proxy_connect());
    let addresses = AddressResolver::from_fn(|host| async move {
        if host != "proxy.test" {
            return Err(io::Error::other("origin DNS must remain remote to CONNECT"));
        }
        Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
    });
    let route = Route::http_proxy(
        HttpProxy::new(&format!(
            "{}://proxy.test:{port}",
            if https { "https" } else { "http" }
        ))?
        .with_basic_auth("alice", "secret")?,
    );
    let builder = Client::builder(profile)
        .add_root_certificate_der(origin.root_der.clone())
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .dns_resolver(addresses)
        .preemptive_proxy_authentication(true)
        .route(route);
    #[cfg(feature = "cookies")]
    let builder = builder.cookies();
    Ok(builder.build()?)
}

async fn control(negotiated: bool, https: bool, mode: Mode) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // A bound but unlistening IPv6 socket leaves a real slower IPv4 attempt.
        let unlistened = TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: host has no IPv6 loopback"); return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let origin = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate_for_dns("proxy.test")?;
        let client = client(&origin, &proxy_identity, port, https)?;
        let url = "wss://127.0.0.1:443/events";
        let (ready, primary_ready) = oneshot::channel();
        let (completed, done) = oneshot::channel();
        let caller = async {
            if mode == Mode::Cancel {
                let request = if negotiated { client.websocket_with_profile_policy(url)? }
                    else { client.websocket_with_protocol(HttpProtocol::Http2, url)? };
                let mut opening = Box::pin(request.header(RequestHeader::new("user-agent", "first")).connect());
                tokio::select! {
                    result = &mut opening => { drop(result); return Err("opening settled before cancellation barrier".into()); }
                    observed = primary_ready => observed?,
                }
                drop(opening);
            } else if mode == Mode::Reuse {
                let response = client.get_negotiated("https://127.0.0.1:443/page")?.send().await?;
                assert_eq!(response.status(), 200);
                assert!(response.into_body().collect().await?.to_bytes().is_empty());
                primary_ready.await?;
            } else { drop(primary_ready); }
            #[cfg(feature = "cookies")]
            client.cookie_jar().ok_or("missing cookie jar")?.set_cookie("https://127.0.0.1/", "claim=current; Path=/")?;
            let request = if negotiated { client.websocket_with_profile_policy(url)? }
                else { client.websocket_with_protocol(HttpProtocol::Http2, url)? };
            let result = request.header(RequestHeader::new("user-agent", "current"))
                .header(RequestHeader::new("x-claim", "current")).connect().await;
            if mode == Mode::Reject {
                let error = match result { Ok(_) => return Err("rejected opening succeeded".into()), Err(error) => error };
                assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
                let response = error.into_response().ok_or("missing rejected response owner")?;
                assert_eq!(response.status(), 403);
                assert_eq!(response.into_body().collect().await?.to_bytes(), b"denied".as_slice());
            } else {
                let mut socket = result?;
                assert_eq!(socket.handshake_response().version(), http::Version::HTTP_2);
                assert_eq!(socket.receive().await?, WebSocketMessage::Binary(Bytes::from_static(b"peer")));
                drop(socket);
            }
            completed.send(()).map_err(|_| "peer ended before caller finished")?;
            drop(client);
            TestResult::Ok(())
        };
        let peer = proxy_h2_peer::serve(listener, &origin, &proxy_identity, https, mode, ready, done);
        // Lexically owned futures/sockets: cancellation, panic and deadline drop
        // both peers; no worker task can escape the bounded test body.
        tokio::try_join!(caller, peer)?;
        drop(unlistened);
        Ok(())
    }).await.map_err(|_| "proxied H2 WebSocket control exceeded its deadline")?
}

#[tokio::test]
async fn proxy_h2_websocket_retires_raw_backup_before_exactly_one_opening() -> TestResult<()> {
    for negotiated in [false, true] {
        for https in [false, true] {
            control(negotiated, https, Mode::Accept).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn cancelled_proxy_h2_opening_leaves_quiet_backup_for_current_claimant() -> TestResult<()> {
    for negotiated in [false, true] {
        for https in [false, true] {
            control(negotiated, https, Mode::Cancel).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn rejected_proxy_h2_opening_retains_response_without_replay_or_redial() -> TestResult<()> {
    for negotiated in [false, true] {
        for https in [false, true] {
            control(negotiated, https, Mode::Reject).await?;
        }
    }
    Ok(())
}
#[tokio::test]
async fn profile_proxy_h2_websocket_reuses_ordinary_origin_session_without_redial() -> TestResult<()>
{
    for https in [false, true] {
        control(true, https, Mode::Reuse).await?;
    }
    Ok(())
}
