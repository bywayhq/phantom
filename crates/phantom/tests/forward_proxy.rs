//! Public HTTP/1.1 forward-proxy integration tests.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{future::Future, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RedirectPolicy, RequestErrorKind, RequestHeader, Route,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use h3_support::client_settings;
use tls_support::{TestIdentity, TestResult, client_builder, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn one_shot_forwarding_preserves_absolute_target_fields_and_body() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, body))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                "http://BÜCHER.Example:8080/a/%2e%2e/final?value=%2f",
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "through");

        let (head, body) = proxy.await??;
        assert_eq!(
            head,
            b"POST http://xn--bcher-kva.example:8080/a/%2e%2e/final?value=%2f HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nContent-Length: 7\r\n\r\n"
        );
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_proxy_status_is_returned_without_direct_fallback() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 9\r\n\r\nchallenge",
                )
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let response = client_builder(&identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://unresolvable.invalid/resource")?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "challenge");

        let head = proxy.await??;
        assert!(head.starts_with(b"GET http://unresolvable.invalid/resource HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn bare_client_forward_requests_remain_one_shot() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let mut heads = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                heads.push(read_head(&mut stream).await?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        for path in ["first", "second"] {
            client
                .get(HttpProtocol::Http1, &format!("http://origin.test/{path}"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }

        let heads = proxy.await??;
        assert!(heads[0].starts_with(b"GET http://origin.test/first HTTP/1.1\r\n"));
        assert!(heads[1].starts_with(b"GET http://origin.test/second HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_reuses_same_origin_and_forward_route() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst")
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond")
                .await?;
            let opened_another = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second, opened_another))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let session = client_builder(&identity, false)
            .route(route)
            .build()?
            .session();
        let first = session
            .get(HttpProtocol::Http1, "http://origin.test/first")?
            .send()
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        let second = session
            .get(HttpProtocol::Http1, "http://origin.test/second")?
            .send()
            .await?
            .into_body()
            .collect()
            .await?
            .to_bytes();
        assert_eq!(first, "first");
        assert_eq!(second, "second");

        let (first, second, opened_another) = proxy.await??;
        assert!(first.starts_with(b"GET http://origin.test/first HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET http://origin.test/second HTTP/1.1\r\n"));
        assert!(!opened_another);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn session_isolates_forward_connections_by_origin() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut first_stream, _) = listener.accept().await?;
            let first = read_head(&mut first_stream).await?;
            first_stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;

            let (mut second_stream, _) = listener.accept().await?;
            let second = read_head(&mut second_stream).await?;
            second_stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let session = client_builder(&identity, false)
            .route(route)
            .build()?
            .session();
        for origin in ["first.test", "second.test"] {
            session
                .get(HttpProtocol::Http1, &format!("http://{origin}/resource"))?
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }

        let (first, second) = proxy.await??;
        assert!(first.starts_with(b"GET http://first.test/resource HTTP/1.1\r\n"));
        assert!(second.starts_with(b"GET http://second.test/resource HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unsupported_forward_combinations_fail_before_proxy_io() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let identity = TestIdentity::generate()?;
        let proxy_uri = format!("http://{address}");
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?);

        let direct = client_builder(&identity, false).build()?;
        let direct_error = direct
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("direct plaintext HTTP unexpectedly succeeded")?;
        assert_eq!(direct_error.kind(), RequestErrorKind::UnsupportedScheme);

        let direct_policy_error = direct
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .header(RequestHeader::new("Proxy-Authorization", "Basic secret"))
            .send()
            .await
            .err()
            .ok_or("direct plaintext HTTP unexpectedly reached forwarding validation")?;
        assert_eq!(
            direct_policy_error.kind(),
            RequestErrorKind::UnsupportedScheme
        );

        let forward_client = client_builder(&identity, false)
            .route(route.clone())
            .build()?;
        let fragment_error = forward_client
            .get(HttpProtocol::Http1, "http://origin.test/path#fragment")
            .err()
            .ok_or("fragment-bearing forwarding target was accepted")?;
        assert_eq!(fragment_error.kind(), RequestErrorKind::InvalidTarget);
        let connection_error = forward_client
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .header(RequestHeader::new("Connection", "content-length"))
            .send()
            .await
            .err()
            .ok_or("critical Connection token unexpectedly succeeded")?;
        assert_eq!(connection_error.kind(), RequestErrorKind::Http1);

        let h2_client = client_builder(&identity, true)
            .route(route.clone())
            .build()?;
        let h2_error = h2_client
            .get(HttpProtocol::Http2, "http://origin.test/")?
            .header(RequestHeader::new("Proxy-Authorization", "Basic secret"))
            .send()
            .await
            .err()
            .ok_or("HTTP/2 forwarding unexpectedly succeeded")?;
        assert_eq!(h2_error.kind(), RequestErrorKind::UnsupportedRoute);
        let negotiated_error = h2_client
            .get_negotiated("http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("negotiated forwarding unexpectedly succeeded")?;
        assert_eq!(negotiated_error.kind(), RequestErrorKind::UnsupportedRoute);

        let h3_profile = ClientProfile::new(tls_settings()).with_http3(client_settings());
        let h3_client = Client::builder(h3_profile)
            .add_root_certificate_der(identity.root_der.clone())
            .route(route.clone())
            .build()?;
        let h3_error = h3_client
            .get(HttpProtocol::Http3, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("HTTP/3 forwarding unexpectedly succeeded")?;
        assert_eq!(h3_error.kind(), RequestErrorKind::UnsupportedRoute);

        let secure_route = Route::http_proxy(HttpProxy::new(&format!("https://{address}"))?);
        let secure_error = client_builder(&identity, false)
            .route(secure_route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("TLS forward proxy unexpectedly succeeded")?;
        assert_eq!(secure_error.kind(), RequestErrorKind::UnsupportedRoute);

        let authenticated_route =
            Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_basic_auth("user", "secret")?);
        let authenticated_error = client_builder(&identity, false)
            .route(authenticated_route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("authenticated forwarding unexpectedly succeeded")?;
        assert_eq!(
            authenticated_error.kind(),
            RequestErrorKind::UnsupportedRoute
        );

        let header_error = client_builder(&identity, false)
            .route(route.clone())
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .header(RequestHeader::new("Proxy-Authorization", "Basic secret"))
            .send()
            .await
            .err()
            .ok_or("forward Proxy-Authorization unexpectedly succeeded")?;
        assert_eq!(header_error.kind(), RequestErrorKind::InvalidHeader);

        let redirect_error = client_builder(&identity, false)
            .route(route)
            .build()?
            .session_builder()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("forward redirect policy unexpectedly succeeded")?;
        assert_eq!(redirect_error.kind(), RequestErrorKind::Redirect);

        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "an unsupported forwarding combination reached the proxy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_proxy_connection_failure_has_proxy_category() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        drop(listener);

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let error = client_builder(&identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("request unexpectedly reached a closed forward proxy")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_forwarding_does_not_generate_or_learn_client_hints() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nAccept-CH: Sec-CH-UA-Arch\r\nCritical-CH: Sec-CH-UA-Arch\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first, second))
        });

        let identity = TestIdentity::generate()?;
        let hints = ClientHintSettings::new(vec![
            ClientHint::new("sec-ch-ua", "profile", ClientHintDelivery::Default),
            ClientHint::new(
                "sec-ch-ua-arch",
                "\"arm\"",
                ClientHintDelivery::AcceptCh,
            ),
        ]);
        let profile = ClientProfile::new(tls_settings()).with_client_hints(hints);
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let session = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .route(route)
            .build()?
            .session();
        session
            .get(HttpProtocol::Http1, "http://origin.test/first")?
            .header(RequestHeader::new("Sec-CH-UA", "caller"))
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        session
            .get(HttpProtocol::Http1, "http://origin.test/second")?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;

        let (first, second) = proxy.await??;
        let first = std::str::from_utf8(&first)?;
        let second = std::str::from_utf8(&second)?;
        assert!(first.contains("\r\nSec-CH-UA: caller\r\n"));
        assert!(!first.contains("Sec-CH-UA-Arch"));
        assert!(!second.to_ascii_lowercase().contains("sec-ch-ua"));
        Ok(())
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "forward-proxy test exceeded its deadline")?
}
