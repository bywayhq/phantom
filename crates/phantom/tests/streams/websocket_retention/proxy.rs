//! Public two-address ownership controls; source-only until native execution.
use super::proxy_peer as peer;
use crate::support::tls::{H1_ALPN, TestIdentity, TestResult, tls_settings};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use phantom::{
    AddressResolver, Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, RequestHeader,
    Route, WebSocketMessage,
    profile::{
        ClientProfile, ProxyConnectField, RequestField, RequestTemplate, WebSocketField,
        WebSocketNewConnection,
        browser::{chrome, firefox},
    },
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    task::Poll,
};
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpSocket},
    time::timeout,
};

#[derive(Clone, Copy)]
pub(super) enum Auth {
    Basic,
    Digest,
}
#[derive(Clone, Copy)]
pub(super) enum Claim {
    Ordinary,
    Upgrade,
    Rejected,
}

#[tokio::test]
async fn exact_proxy_websocket_publishes_plain_backup_before_connect_for_current_request()
-> TestResult<()> {
    control(false, false, false, Auth::Basic, Claim::Ordinary).await
}
#[tokio::test]
async fn policy_proxy_websocket_publishes_verified_https_backup_before_primary_tls()
-> TestResult<()> {
    control(true, true, false, Auth::Digest, Claim::Ordinary).await
}
#[tokio::test]
async fn exact_proxy_websocket_claims_https_backup_after_primary_cancel_without_an_extra_get()
-> TestResult<()> {
    control(false, true, true, Auth::Basic, Claim::Upgrade).await
}
#[tokio::test]
async fn policy_proxy_websocket_claims_plain_backup_with_current_cookie_and_rejection_body()
-> TestResult<()> {
    control(true, false, true, Auth::Digest, Claim::Rejected).await
}

async fn control(
    policy: bool,
    https: bool,
    cancel: bool,
    auth: Auth,
    claim: Claim,
) -> TestResult<()> {
    timeout(super::TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate_for_dns("proxy.test")?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let refused = TcpSocket::new_v6()?;
        refused.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port))?;
        let resolver = AddressResolver::from_fn(|host| async move {
            if host != "proxy.test" { return Err(io::Error::other("proxy-resolved origin leaked into local DNS")); }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        });
        let mut connect = firefox::v157_proxy_connect();
        connect.http1_fields = vec![ProxyConnectField::FromRequest {name:"X-Claim".into()}, ProxyConnectField::Authority{name:"host".into()}, ProxyConnectField::ProxyAuthorization{name:"Proxy-Authorization".into()}];
        let mut websocket = chrome::v154_websocket();
        websocket.connection.without_http2_session = WebSocketNewConnection::Http1Upgrade;
        websocket.http1_fields = vec![WebSocketField::authority("Host"), WebSocketField::literal("Upgrade", "websocket"), WebSocketField::literal("Connection", "Upgrade"), WebSocketField::key("Sec-WebSocket-Key"), WebSocketField::literal("Sec-WebSocket-Version", "13"), WebSocketField::client_cookies("Cookie"), WebSocketField::caller("X-Claim")];
        // Its H1 offer differs from the ordinary negotiated connector's h2/H1.
        websocket.connection.http1_alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp())
            .with_http1(firefox::v157_http1()).with_http2(firefox::v157_http2())
            .with_websocket(websocket).with_proxy_connect(connect);
        let proxy = HttpProxy::new(&format!("{}://proxy.test:{port}", if https {"https"} else {"http"}))?;
        let proxy = match auth { Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let builder = Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone()).dns_resolver(resolver).route(Route::http_proxy(proxy));
        #[cfg(feature = "cookies")]
        let builder = builder.cookies();
        let client = builder.build()?;
        #[cfg(feature = "cookies")]
        client.cookie_jar().ok_or("missing cookie jar")?.set_cookie("https://127.0.0.1/", "current=1; Path=/")?;
        let first = if policy { client.websocket_with_profile_policy("wss://127.0.0.1/first")? } else {client.websocket("wss://127.0.0.1/first")?};
        let mut primary = Box::pin(first.header(RequestHeader::new("X-Claim", "first")).connect());
        let (mut primary_peer, _) = tokio::select! {
            result = &mut primary => { drop(result?); return Err("primary completed before proxy TCP accept".into()); }
            accepted = listener.accept() => accepted?,
        };
        if https {
            let mut record = [0; 5];
            tokio::select! {
                result = &mut primary => { drop(result?); return Err("primary completed without proxy TLS response".into()); }
                read = primary_peer.read_exact(&mut record) => { read?; }
            }
            assert_eq!(record[0], 22);
        } else {
            let head = tokio::select! {
                result = &mut primary => { drop(result?); return Err("primary completed without CONNECT response".into()); }
                head = crate::support::tls::read_head(&mut primary_peer) => head?,
            };
            assert_eq!(head, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: first\r\nhost: 127.0.0.1:443\r\n\r\n");
        }
        // Adoption must already have happened, despite the primary's held
        // proxy TLS/CONNECT. A joined peer future observes real outer TLS.
        let (backup, _) = listener.accept().await?;
        let mut backup = peer::outer(backup, https, proxy_acceptor).await?;
        peer::quiet(&mut backup).await?;
        let mut primary = Some(primary);
        if cancel { drop(primary.take()); }
        #[cfg(feature = "cookies")]
        client.cookie_jar().ok_or("missing cookie jar")?.set_cookie("https://127.0.0.1/", "current=2; Path=/")?;
        let request = async {
            match claim {
                Claim::Ordinary => {
                    let fields = PreparedRequestTemplate::new(RequestTemplate {
                        http1_fields: vec![RequestField::required_caller("X-Claim")],
                        http2_fields: vec![RequestField::required_caller("x-claim")], http3_fields:None, http2_priority:None,
                        requested_client_hint_placement:false, restarts_for_connection_accept_ch:false,
                    })?;
                    let request = if policy {client.get("https://127.0.0.1/page")?} else {client.get_with_protocol(HttpProtocol::Http1,"https://127.0.0.1/page")?};
                    let response = request.template(&fields).headers(vec![RequestHeader::new("X-Claim", "second")]).send().await?;
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.into_body().collect().await?.to_bytes(), "done");
                }
                Claim::Upgrade | Claim::Rejected => {
                    let request = if policy {client.websocket_with_profile_policy("wss://127.0.0.1/socket")?} else {client.websocket("wss://127.0.0.1/socket")?};
                    let result = request.header(RequestHeader::new("X-Claim", "second")).connect().await;
                    if matches!(claim, Claim::Rejected) {
                        let error = match result { Err(error) => error, Ok(_) => return Err("rejected WebSocket succeeded".into()) };
                        let response = error.into_response().ok_or("rejection lost its response body")?;
                        assert_eq!(response.status(), 403);
                        assert_eq!(response.into_body().collect().await?.to_bytes(), "denied");
                        #[cfg(feature = "cookies")]
                        assert!(client.cookie_jar().ok_or("missing cookie jar")?.request_value("https://127.0.0.1/")?.ok_or("empty cookie jar")?.contains("result=3"));
                    } else {
                        let mut socket = result?;
                        assert_eq!(socket.handshake_response().version(), http::Version::HTTP_11);
                        socket.send(WebSocketMessage::Binary(Bytes::from_static(b"client"))).await?;
                        assert_eq!(socket.receive().await?, WebSocketMessage::Binary(Bytes::from_static(b"peer")));
                        drop(socket);
                    }
                }
            }
            TestResult::Ok(())
        };
        let (request, peer) = tokio::join!(request, peer::claim(backup, acceptor, auth, claim));
        match (request, peer) {
            (Ok(()), Ok(())) => {},
            (Err(first), Err(second)) => return Err(format!("request: {first}; peer: {second}").into()),
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }
        drop(primary.take());
        drop(client);
        // For HTTPS, only the unread tail of its first ClientHello can remain.
        if https {
            let mut bytes = Vec::new();
            match primary_peer.read_to_end(&mut bytes).await {
                Ok(_) => {}, Err(error) if crate::support::tls::is_peer_gone(&error) => {}, Err(error) => return Err(error.into()),
            }
            assert!(!bytes.windows(b"CONNECT ".len()).any(|part| part == b"CONNECT "));
        } else { peer::closed(&mut primary_peer).await?; }
        assert!(std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await, "claim opened a third physical proxy socket");
        drop(refused);
        Ok(())
    }).await?
}
