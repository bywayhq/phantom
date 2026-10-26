//! Windows' refused IPv6 connect keeps a real IPv4 backup alive.
use crate::support::tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, tls_settings};
use http_body_util::BodyExt as _;
use phantom::{
    AddressResolver, Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, RequestHeader,
    Route,
    profile::{ClientProfile, ProxyConnectField, RequestField, RequestTemplate, browser::firefox},
};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpListener, TcpSocket},
    time::timeout,
};
mod peer;

#[derive(Clone, Copy)]
enum Auth {
    Basic,
    Digest,
}

#[tokio::test]
async fn negotiated_h1_claims_plain_connect_backup_before_primary_finishes() -> TestResult<()> {
    control(false, false, false, Auth::Basic).await
}

#[tokio::test]
async fn negotiated_h2_claims_https_connect_backup_and_uses_its_current_digest_fields()
-> TestResult<()> {
    control(false, true, true, Auth::Digest).await
}

#[tokio::test]
async fn exact_h2_claims_plain_connect_backup_after_primary_cancellation() -> TestResult<()> {
    control(true, false, true, Auth::Digest).await
}

#[tokio::test]
async fn exact_h2_claims_https_connect_backup_after_primary_cancellation() -> TestResult<()> {
    control(true, true, true, Auth::Basic).await
}

async fn control(exact: bool, https: bool, h2: bool, auth: Auth) -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let origin = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate_for_dns("proxy.test")?;
        let origin_acceptor = origin.acceptor(if h2 { H2_ALPN } else { H1_ALPN })?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        // Reserve but do not listen. Windows refusal stays pending while the
        // real IPv4 backup connects. No synthetic completion enters the pool.
        let refused = TcpSocket::new_v6()?;
        refused.bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port))?;
        let resolver = AddressResolver::from_fn(|host| async move {
            if host != "proxy.test" { return Err(io::Error::other("origin leaked into proxy DNS resolution")); }
            Ok(vec![Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()])
        });
        let mut template = firefox::v157_proxy_connect();
        template.http1_fields = vec![ProxyConnectField::FromRequest { name: "X-Claim".into() },
            ProxyConnectField::Authority { name: "host".into() },
            ProxyConnectField::ProxyAuthorization { name: "Proxy-Authorization".into() }];
        let profile = ClientProfile::new(tls_settings()).with_tcp(firefox::v157_tcp())
            .with_http1(firefox::v157_http1()).with_http2(firefox::v157_http2()).with_proxy_connect(template);
        let proxy = HttpProxy::new(&format!("{}://proxy.test:{port}", if https { "https" } else { "http" }))?;
        let proxy = match auth { Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let client = Client::builder(profile).add_root_certificate_der(origin.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .dns_resolver(resolver).route(Route::http_proxy(proxy)).build()?;
        // Negotiated requests validate both lists before dialing. Keep the
        // original HTTP/1 spelling while supplying a valid HTTP/2 field.
        let fields = PreparedRequestTemplate::new(RequestTemplate {
            http1_fields: vec![RequestField::required_caller("X-Claim")],
            http2_fields: vec![RequestField::required_caller("x-claim")],
            http3_fields: None,
            http2_priority: None,
            requested_client_hint_placement: false,
            restarts_for_connection_accept_ch: false,
        })?;
        let first = if exact { client.get_with_protocol(HttpProtocol::Http2, "https://127.0.0.1/first")? }
            else { client.get("https://127.0.0.1/first")? };
        let mut primary = Box::pin(first.template(&fields).headers(vec![RequestHeader::new("X-Claim", "first")]).send());
        let mut primary_peer = tokio::select! {
            result = &mut primary => { let _response = result?; return Err("primary completed before proxy accepted TCP".into()); }
            accepted = listener.accept() => accepted?.0,
        };
        if https {
            let mut header = [0; 5];
            tokio::select! {
                result = &mut primary => { let _response = result?; return Err("primary completed without outer TLS response".into()); }
                result = primary_peer.read_exact(&mut header) => { result?; }
            }
            assert_eq!(header[0], 22, "primary omitted outer TLS");
        } else {
            tokio::select! {
                result = &mut primary => { let _response = result?; return Err("primary completed without CONNECT response".into()); }
                head = peer::head(&mut primary_peer) => assert_eq!(head?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: first\r\nhost: 127.0.0.1:443\r\n\r\n"),
            }
        }
        let (backup, _) = listener.accept().await?;
        let mut backup = peer::proxy_stream(backup, https, proxy_acceptor).await?;
        let mut byte = [0];
        let mut unread = Box::pin(backup.read(&mut byte));
        assert!(std::future::poll_fn(|cx| Poll::Ready(unread.as_mut().poll(cx).is_pending())).await,
            "unclaimed backup sent CONNECT or origin TLS");
        drop(unread);
        let mut primary = Some(primary);
        if exact { drop(primary.take()); }
        let second = if exact { client.get_with_protocol(HttpProtocol::Http2, "https://127.0.0.1/claimed")? }
            else { client.get("https://127.0.0.1/claimed")? };
        let request = async {
            let response = second.template(&fields).headers(vec![RequestHeader::new("X-Claim", "second")]).send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.version(), if h2 { http::Version::HTTP_2 } else { http::Version::HTTP_11 });
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let (request, peer) = tokio::join!(request, peer::serve(backup, origin_acceptor, h2, auth));
        match (request, peer) {
            (Ok(()), Ok(())) => {},
            (Err(first), Err(second)) => return Err(format!("request: {first}; peer: {second}").into()),
            (Err(error), _) | (_, Err(error)) => return Err(error),
        }
        drop(primary.take());
        let mut remainder = Vec::new(); primary_peer.read_to_end(&mut remainder).await?;
        if !https { assert!(remainder.is_empty(), "cancelled primary sent origin TLS"); }
        assert!(std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await,
            "claim dialled a third physical proxy socket");
        drop(refused);
        Ok(())
    }).await?
}
