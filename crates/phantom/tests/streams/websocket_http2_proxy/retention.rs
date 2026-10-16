//! Public WSS paths share the physical proxy's H2 activation boundary.

mod peer;

use super::{
    H1_ALPN, H2_ALPN, HttpProtocol, TestIdentity, TestResult, bind, bounded, exchange_echo,
    firefox, text_frame, websocket_origin,
};
use phantom::{
    AddressResolver, Client, HttpProxy, RequestHeader, Route,
    profile::{ClientProfile, WebSocketField, WebSocketNewConnection},
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::oneshot,
};

#[tokio::test]
async fn http1_websocket_retires_outer_h2_raw_backup_before_connect() -> TestResult<()> {
    control(false).await
}

#[tokio::test]
async fn http2_websocket_retires_outer_h2_raw_backup_before_connect() -> TestResult<()> {
    control(true).await
}

async fn control(inner_h2: bool) -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // Windows delays a real refused loopback TCP connect. Holding the
        // bound IPv6 endpoint unlistening lets the IPv4 backup win before the
        // primary advances to IPv4. This is not a portable refusal oracle.
        let unlistened = TcpSocket::new_v6()?;
        unlistened.bind((Ipv6Addr::LOCALHOST, port).into())?;
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate_for_dns("proxy.test")?;
        let (origin_address, origin_listener) = bind().await?;
        let origin_acceptor = identity.acceptor(if inner_h2 { H2_ALPN } else { H1_ALPN })?;
        let proxy_acceptor = proxy_identity.acceptor(H2_ALPN)?;
        let mut tls_settings = firefox::v157_tcp_tls();
        tls_settings.ech = phantom::profile::EchSettings::Disabled;
        assert!(tls_settings.tcp_early_data);
        let mut websocket = firefox::v157_websocket();
        websocket.connection.without_http2_session = if inner_h2 {
            WebSocketNewConnection::Http2ExtendedConnect
        } else {
            WebSocketNewConnection::Http1Upgrade
        };
        websocket.http2_fields = vec![
            WebSocketField::caller("user-agent"),
            WebSocketField::literal("sec-websocket-version", "13"),
            WebSocketField::caller("x-current"),
        ];
        websocket
            .http1_fields
            .push(WebSocketField::caller("x-current"));
        let profile = ClientProfile::new(tls_settings)
            .with_http1(firefox::v157_http1())
            .with_http2(firefox::v157_http2())
            .with_tcp(firefox::v157_tcp())
            .with_proxy_connect(firefox::v157_proxy_connect())
            .with_websocket(websocket);
        let addresses = AddressResolver::from_fn(|host| async move {
            if host != "proxy.test" {
                return Err(io::Error::other(
                    "CONNECT must not resolve the origin locally",
                ));
            }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        });
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .dns_resolver(addresses)
            .preemptive_proxy_authentication(true)
            .route(Route::http_proxy(
                HttpProxy::new(&format!("https://proxy.test:{port}"))?
                    .with_http2_transport()?
                    .with_basic_auth("alice", "secret")?,
            ))
            .build()?;
        let (completed, done) = oneshot::channel();
        let caller = async {
            let socket = client
                .websocket_with_protocol(
                    if inner_h2 {
                        HttpProtocol::Http2
                    } else {
                        HttpProtocol::Http1
                    },
                    &format!("wss://{origin_address}/current"),
                )?
                .header(RequestHeader::new("user-agent", "current"))
                .header(RequestHeader::new("x-current", "marker"))
                .connect()
                .await?;
            assert_eq!(
                socket.handshake_response().version(),
                if inner_h2 {
                    http::Version::HTTP_2
                } else {
                    http::Version::HTTP_11
                }
            );
            exchange_echo(socket).await?;
            completed
                .send(())
                .map_err(|_| "proxy ended before WebSocket echo")?;
            drop(client);
            TestResult::Ok(())
        };
        let origin = async {
            if inner_h2 {
                let record =
                    websocket_origin::serve_h2_echo(origin_listener, origin_acceptor).await?;
                assert_eq!(record.protocol.as_deref(), Some("websocket"));
                assert_eq!(record.path.as_deref(), Some("/current"));
                assert_eq!(
                    record.authority.as_deref(),
                    Some(origin_address.to_string().as_str())
                );
                assert_eq!(record.message, text_frame("hello"));
            } else {
                let (head, message) =
                    websocket_origin::serve_h1_echo(origin_listener, origin_acceptor).await?;
                assert!(head.starts_with(b"GET /current HTTP/1.1\r\n"));
                assert_eq!(
                    websocket_origin::header_value(&head, "x-current"),
                    Some("marker")
                );
                assert_eq!(message, text_frame("hello"));
            }
            TestResult::Ok(())
        };
        // All fixture sockets and relay futures are lexical: error, panic and
        // the unchanged enclosing deadline drop every peer without detaching.
        tokio::try_join!(
            caller,
            peer::serve(listener, proxy_acceptor, origin_address, done),
            origin
        )?;
        drop(unlistened);
        Ok(())
    })
    .await
}
