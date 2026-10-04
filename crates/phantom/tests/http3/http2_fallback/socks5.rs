//! The HTTP/2 fallback on a SOCKS5 route: QUIC goes through a UDP
//! association, and the fallback through a CONNECT tunnel of the same proxy.

use crate::support::socks5 as socks5_support;
use crate::support::socks5_udp as socks5_udp_support;

use std::net::{Ipv4Addr, SocketAddr};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestErrorKind, ResponseInfo, Route, Socks5Proxy};
use tokio::{net::TcpListener, time::timeout};

use socks5_support::{ObservedSocks5Connect, forward_socks5_stream};
use socks5_udp_support::{
    Socks5UdpAssociateReply, Socks5UdpAuthentication, Socks5UdpScript, Socks5UdpTarget,
    serve_socks5_udp_associate_stream,
};

use super::{
    H2_ALPN, Origin, QUIET_WINDOW, TestIdentity, TestResult, bounded, client, fallback,
    no_tcp_connection, refuse, serve_http2,
};

fn socks5_route(proxy: SocketAddr) -> TestResult<Route> {
    Ok(Route::socks5(Socks5Proxy::new(&format!(
        "socks5://{proxy}"
    ))?))
}

async fn no_quic_handshake(endpoint: &quinn::Endpoint) -> TestResult<()> {
    match timeout(QUIET_WINDOW, endpoint.accept()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the client attempted another QUIC handshake".into()),
    }
}

async fn no_proxy_connection(listener: &TcpListener) -> TestResult<()> {
    match timeout(QUIET_WINDOW, listener.accept()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the client opened another proxy connection".into()),
    }
}

#[tokio::test]
async fn a_refused_quic_handshake_through_socks5_sends_the_request_through_a_socks5_tunnel()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        let origin = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let refused = tokio::spawn(async move {
            refuse(&quic, 1).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(quic)
        });
        let served = tokio::spawn(serve_http2(tcp, identity.acceptor(H2_ALPN)?));

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            // QUIC first, through a UDP association to the origin's port.
            let (control, _) = proxy_listener.accept().await?;
            let relay = tokio::spawn(serve_socks5_udp_associate_stream(
                control,
                origin,
                Socks5UdpTarget::Ip(origin),
                Socks5UdpScript::no_auth(),
            ));
            // Then HTTP/2, through a CONNECT tunnel to the same origin.
            let (tunnel, _) = proxy_listener.accept().await?;
            let connect = tokio::spawn(forward_socks5_stream(tunnel, origin));
            no_proxy_connection(&proxy_listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((relay.await??, connect.await??))
        });

        let client = client(&identity, true)?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{origin}/upload"),
            )?
            .body("payload")
            .route(socks5_route(proxy_address)?)
            .retry_policy(fallback())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted ResponseInfo")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);
        assert_eq!(info.retries_performed(), 0);
        response.into_body().collect().await?;
        drop(client);

        let quic = refused.await??;
        no_quic_handshake(&quic).await?;
        let received = served.await??;
        assert_eq!(received.method, Method::POST);
        assert_eq!(received.path, "/upload");
        assert_eq!(received.body, "payload");

        let (relay, connect) = proxy.await??;
        // The refused handshake went to the origin and came back through the
        // association.
        assert_eq!(relay.target, Some(Socks5UdpTarget::Ip(origin)));
        assert!(relay.client_datagrams > 0);
        assert!(relay.origin_datagrams > 0);
        assert_eq!(
            connect,
            ObservedSocks5Connect {
                host: "127.0.0.1".to_owned(),
                port,
            }
        );
        Ok(())
    })
    .await
}

/// A SOCKS5 proxy failure is not a failed QUIC connection, so it returns the
/// HTTP/3 error and opens no tunnel; see `RetryPolicy::with_http2_fallback`.
#[tokio::test]
async fn a_refused_socks5_udp_association_returns_the_http3_error_without_a_tunnel()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        let origin = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (control, _) = proxy_listener.accept().await?;
            let observed = serve_socks5_udp_associate_stream(
                control,
                origin,
                Socks5UdpTarget::Ip(origin),
                Socks5UdpScript {
                    authentication: Socks5UdpAuthentication::None,
                    // General SOCKS server failure.
                    reply: Socks5UdpAssociateReply::Reject(1),
                },
            )
            .await?;
            no_proxy_connection(&proxy_listener).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let error = client(&identity, true)?
            .get(HttpProtocol::Http3, &format!("https://{origin}/refused"))?
            .route(socks5_route(proxy_address)?)
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a refused UDP association returned a response")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));

        proxy.await??;
        no_quic_handshake(&quic).await?;
        no_tcp_connection(&tcp).await
    })
    .await
}
