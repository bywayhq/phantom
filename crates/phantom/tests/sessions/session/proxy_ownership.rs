use std::net::Ipv4Addr;

use btls::ssl::SslAcceptor;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, HttpProxy, Route};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use super::body_ownership::{Control, Observation, ObservedTcp, PeerLife, Setup, accept_peer};
use super::{
    ASCII_ORIGIN_NAME, H1_ALPN, H2_ALPN, TestIdentity, TestResult, UNICODE_ORIGIN_NAME, bounded,
    client_builder, read_head, reuse_ownership, test_client, tls_support,
};

pub(super) async fn plaintext() -> TestResult<()> {
    plaintext_controlled(None).await
}

async fn plaintext_controlled(control: Option<Control>) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin = reuse_ownership::spawn_server(origin_listener, acceptor, 2, None);

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        let proxy = tokio::spawn(forward_one_connect(
            proxy_listener,
            origin_address,
            observed,
        ));

        let target = match control {
            Some(control) => {
                control
                    .coordinate(Setup {
                        address: proxy_address,
                        peer: proxy.abort_handle(),
                        sibling: Some(origin.abort_handle()),
                    })
                    .await?
            }
            None => None,
        };

        let route = Route::http_proxy(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let session = test_client(&identity, true)?;
        for (host, path) in [
            (UNICODE_ORIGIN_NAME, "/first"),
            (ASCII_ORIGIN_NAME, "/second"),
        ] {
            let original_target = format!("https://{host}:{}{path}", origin_address.port());
            let response = session
                .get(
                    HttpProtocol::Http2,
                    target.as_deref().unwrap_or(&original_target),
                )?
                .route(route.clone())
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        drop(session);

        let requests = origin.await??;
        assert_eq!(
            requests,
            vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        assert_eq!(
            proxy.await??,
            format!(
                "CONNECT {ASCII_ORIGIN_NAME}:{} HTTP/1.1\r\nHost: {ASCII_ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port(),
                origin_address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

pub(super) async fn https() -> TestResult<()> {
    https_controlled(None).await
}

async fn https_controlled(control: Option<Control>) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ASCII_ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin = reuse_ownership::spawn_server(origin_listener, acceptor, 2, None);

        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let observed = control.as_ref().map(|control| control.observed.clone());
        let proxy = tokio::spawn(forward_one_https_connect(
            proxy_listener,
            proxy_acceptor,
            origin_address,
            observed,
        ));

        let target = match control {
            Some(control) => {
                control
                    .coordinate(Setup {
                        address: proxy_address,
                        peer: proxy.abort_handle(),
                        sibling: Some(origin.abort_handle()),
                    })
                    .await?
            }
            None => None,
        };

        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let session = client_builder(&identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .build()?;
        for (host, path) in [
            (UNICODE_ORIGIN_NAME, "/first"),
            (ASCII_ORIGIN_NAME, "/second"),
        ] {
            let original_target = format!("https://{host}:{}{path}", origin_address.port());
            let response = session
                .get(
                    HttpProtocol::Http2,
                    target.as_deref().unwrap_or(&original_target),
                )?
                .route(route.clone())
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        drop(session);

        let requests = origin.await??;
        assert_eq!(
            requests,
            vec![(1, "/first".to_owned()), (3, "/second".to_owned())]
        );
        assert_eq!(
            proxy.await??,
            format!(
                "CONNECT {ASCII_ORIGIN_NAME}:{} HTTP/1.1\r\nHost: {ASCII_ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port(),
                origin_address.port()
            )
            .as_bytes()
        );
        Ok(())
    })
    .await
}

async fn forward_one_connect(
    listener: TcpListener,
    origin: std::net::SocketAddr,
    observed: Option<Observation>,
) -> TestResult<Vec<u8>> {
    let _life = PeerLife(observed.clone());
    let (downstream, _) = listener.accept().await?;
    let mut downstream = ObservedTcp::new(downstream, observed);
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(request)
}

async fn forward_one_https_connect(
    listener: TcpListener,
    acceptor: SslAcceptor,
    origin: std::net::SocketAddr,
    observed: Option<Observation>,
) -> TestResult<Vec<u8>> {
    let _life = PeerLife(observed.clone());
    let mut downstream = accept_peer(&listener, &acceptor, observed).await?;
    let request = read_head(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    downstream.flush().await?;
    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok(_) => {}
        // The client may close its proxy TCP connection before the relay
        // finishes writing its own TLS close_notify during shutdown.
        Err(error) if tls_support::is_peer_gone(&error) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(request)
}

mod tests;
