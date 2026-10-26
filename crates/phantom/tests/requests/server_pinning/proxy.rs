use std::net::Ipv4Addr;

use phantom::{HttpProtocol, HttpProxy, RequestErrorKind, Route};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::*;
use crate::support::{
    h2,
    tls::{H1_ALPN, H2_ALPN, accept_tls, read_head},
    tunnel_proxy::{self, finish_with_cleanup},
};

#[tokio::test]
async fn nested_origin_and_secure_proxy_have_independent_pins() -> TestResult<()> {
    for proxy_http2 in [false, true] {
        for wrong_origin in [false, true] {
            timeout(DEADLINE, async {
                let identity = TestIdentity::generate()?;
                let proxy_identity = TestIdentity::generate()?;
                let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let origin_address = origin.local_addr()?;
                let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let proxy_address = proxy.local_addr()?;
                let origin_acceptor = identity.acceptor(H2_ALPN)?;
                let proxy_acceptor =
                    proxy_identity.acceptor(if proxy_http2 { H2_ALPN } else { H1_ALPN })?;
                let mut route = HttpProxy::new(&format!("https://{proxy_address}"))?;
                if proxy_http2 {
                    route = route.with_http2_transport()?;
                }
                let client = builder(&identity)
                    .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                    .server_spki_pins(if wrong_origin {
                        ServerSpkiPins::new(vec![[0; 32]])?
                    } else {
                        pins(&identity)?
                    })
                    .proxy_server_spki_pins(pins(&proxy_identity)?)
                    .route(Route::http_proxy(route))
                    .build()?;
                let origin = async {
                    let connected = accept_tls(origin, origin_acceptor).await;
                    if wrong_origin {
                        assert!(
                            connected.is_err(),
                            "wrong origin pin completed through proxy"
                        );
                    } else {
                        let mut socket = connected?;
                        h2::accept_client_preface(&mut socket).await?;
                        h2::read_request_headers(&mut socket, 1).await?;
                        h2::write_frame(&mut socket, 1, 5, 1, &[0x88]).await?;
                        socket.flush().await?;
                    }
                    TestResult::Ok(())
                };
                let proxy = async {
                    if proxy_http2 {
                        tunnel_proxy::http2_connect(proxy, proxy_acceptor, origin_address)
                            .await
                            .map(|tunnel| tunnel.map(|_| ()))
                    } else {
                        tunnel_proxy::https1_connect(proxy, proxy_acceptor, origin_address)
                            .await
                            .map(|tunnel| tunnel.map(|_| ()))
                    }
                };
                let caller = async {
                    let result = client
                        .get_with_protocol(
                            HttpProtocol::Http2,
                            &format!("https://{origin_address}/"),
                        )?
                        .send()
                        .await;
                    if wrong_origin {
                        let error = result.err().ok_or("proxy bypassed origin pins")?;
                        assert_eq!(tls_error(&error)?, TlsErrorKind::SpkiPinMismatch);
                    } else {
                        let response = result?;
                        assert_eq!(response.status(), 200);
                        response.into_body().collect_with_limit(0).await?;
                    }
                    drop(client);
                    TestResult::Ok(())
                };
                let (caller, proxy, origin) = tokio::join!(caller, proxy, origin);
                let primary = finish_with_cleanup(caller, origin);
                let mut proxy = proxy?;
                proxy.finish(primary).await
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn wrong_secure_proxy_pin_fails_before_connect_is_sent() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let client = builder(&identity)
            .add_proxy_root_certificate_der(identity.root_der.clone())
            .proxy_server_spki_pins(ServerSpkiPins::new(vec![[0; 32]])?)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "https://{address}"
            ))?))
            .build()?;
        let peer = async {
            assert!(
                accept_tls(listener, acceptor).await.is_err(),
                "wrong proxy pin completed"
            );
            TestResult::Ok(())
        };
        let caller = async {
            let error = client
                .get_with_protocol(HttpProtocol::Http1, "https://origin.phantom.test/")?
                .send()
                .await
                .err()
                .ok_or("wrong proxy pin was accepted")?;
            assert_eq!(error.kind(), RequestErrorKind::Proxy);
            assert_eq!(tls_error(&error)?, TlsErrorKind::SpkiPinMismatch);
            TestResult::Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        finish_with_cleanup(caller, peer)
    })
    .await?
}

#[tokio::test]
async fn proxy_pins_allow_plaintext_direct_origins_without_a_proxy_leg() -> TestResult<()> {
    timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = builder(&identity)
            .proxy_server_spki_pins(pins(&identity)?)
            .build()?;
        let peer = async {
            let (mut socket, _) = listener.accept().await?;
            read_head(&mut socket).await?;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await?;
            TestResult::Ok(())
        };
        let caller = async {
            let response = client
                .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/"))?
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect_with_limit(0).await?;
            TestResult::Ok(())
        };
        let (caller, peer) = tokio::join!(caller, peer);
        finish_with_cleanup(caller, peer)
    })
    .await?
}
