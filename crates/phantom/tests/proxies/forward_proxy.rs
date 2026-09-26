//! Public HTTP/1.1 forward-proxy integration tests.

use crate::support::h3 as h3_support;
use crate::support::reserved_port;
use crate::support::tls as tls_support;
use crate::support::tracing as tracing_support;

use std::{
    future::Future,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestErrorKind, RequestHeader, RequestTimeouts, Route,
    TimeoutPhase,
    profile::{ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, sleep, timeout},
};
use tracing::instrument::WithSubscriber;

use h3_support::client_settings;
use reserved_port::ReservedPort;
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
    read_head, tls_settings,
};
use tracing_support::OutcomeSubscriber;

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
async fn basic_challenge_replays_owned_body_and_trailers_on_the_challenged_connection()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous_stream, _) = listener.accept().await?;
            let anonymous_head = read_head(&mut anonymous_stream).await?;
            let anonymous_body = read_chunked_message(&mut anonymous_stream).await?;
            anonymous_stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=forward\r\n\
                      Content-Length: 4\r\n\r\n\
                      deny",
                )
                .await?;

            // The 407 body is drained and the connection kept open, so the
            // replay arrives on the challenged connection.
            let mut authenticated_stream = anonymous_stream;
            let authenticated_head = read_head(&mut authenticated_stream).await?;
            let authenticated_body = read_chunked_message(&mut authenticated_stream).await?;
            authenticated_stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            let third_attempted = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                anonymous_head,
                anonymous_body,
                authenticated_head,
                authenticated_body,
                third_attempted,
            ))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let subscriber = OutcomeSubscriber::default();
        let response = client_builder(&identity, false)
            .route(route)
            .build()?
            .request(
                HttpProtocol::Http1,
                Method::POST,
                "http://BÜCHER.Example:8080/upload?part=%2f",
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .body(Bytes::from_static(b"payload"))
            .trailers(vec![
                RequestHeader::new("X-Checksum", "first"),
                RequestHeader::new("X-Middle", "between"),
                RequestHeader::new("X-Checksum", "second"),
            ])
            .send()
            .with_subscriber(subscriber.dispatch())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let (anonymous_head, anonymous_body, authenticated_head, authenticated_body, third) =
            proxy.await??;
        assert_eq!(
            anonymous_head,
            b"POST http://xn--bcher-kva.example:8080/upload?part=%2f HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, X-Middle\r\n\r\n"
        );
        assert_eq!(
            authenticated_head,
            b"POST http://xn--bcher-kva.example:8080/upload?part=%2f HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, X-Middle\r\n\r\n"
        );
        let expected_body =
            b"7\r\npayload\r\n0\r\nX-Checksum: first\r\nX-Middle: between\r\nX-Checksum: second\r\n\r\n";
        assert_eq!(anonymous_body, expected_body);
        assert_eq!(authenticated_body, expected_body);
        assert!(!third);
        assert_eq!(
            subscriber.proxy_authentication_retries_for("client.request"),
            [false, true]
        );
        assert_eq!(subscriber.proxy_attempts_for("client.request"), [1, 2]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn basic_challenge_retries_on_the_challenged_verified_tls_proxy_connection() -> TestResult<()>
{
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(async move {
            let (anonymous_tcp, _) = listener.accept().await?;
            let mut anonymous = accept_tls_stream(anonymous_tcp, acceptor).await?;
            let anonymous_alpn = anonymous
                .ssl()
                .selected_alpn_protocol()
                .map(<[u8]>::to_vec);
            let anonymous_head = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=tls-forward\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            // The replay reuses the TLS connection that carried the challenge.
            let authenticated_head = read_head(&mut anonymous).await?;
            anonymous
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let second_connection = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                anonymous_alpn,
                anonymous_head,
                authenticated_head,
                second_connection,
            ))
        });

        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let response = client_builder(&origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/secure")?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (anonymous_alpn, anonymous_head, authenticated_head, second_connection) =
            proxy.await??;
        assert_eq!(anonymous_alpn.as_deref(), Some(b"http/1.1".as_slice()));
        assert!(!second_connection);
        assert_eq!(
            anonymous_head,
            b"GET http://origin.test/secure HTTP/1.1\r\nHost: origin.test\r\n\r\n"
        );
        assert_eq!(
            authenticated_head,
            b"GET http://origin.test/secure HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn second_basic_challenge_is_proxy_error_redacted_and_bounded() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous, _) = listener.accept().await?;
            let anonymous_head = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=private-realm\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            // The 407 kept the connection open, so the replay arrives on it.
            let mut authenticated = anonymous;
            let authenticated_head = read_head(&mut authenticated).await?;
            authenticated
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=private-realm\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let third_attempted = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                anonymous_head,
                authenticated_head,
                third_attempted,
            ))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?
                .with_basic_auth("marker-user", "marker-password")?,
        );
        let error = client_builder(&identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/private")?
            .send()
            .await
            .err()
            .ok_or("a second forward-proxy challenge unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        let diagnostic = format!("{error:?} {error}");
        for secret in [
            "marker-user",
            "marker-password",
            "private-realm",
            "bWFya2VyLXVzZXI6bWFya2VyLXBhc3N3b3Jk",
        ] {
            assert!(!diagnostic.contains(secret));
        }

        let (anonymous, authenticated, third_attempted) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authenticated,
            b"proxy-authorization: basic"
        ));
        assert!(!third_attempted);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unusable_basic_challenge_is_proxy_error_without_retry() -> TestResult<()> {
    for challenge in [
        b"Proxy-Authenticate: Digest realm=ignored\r\n".as_slice(),
        b"Proxy-Authenticate: Basic realm\r\n".as_slice(),
    ] {
        bounded(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let challenge = challenge.to_vec();
            let proxy = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let head = read_head(&mut stream).await?;
                let mut response = b"HTTP/1.1 407 Proxy Authentication Required\r\n".to_vec();
                response.extend_from_slice(&challenge);
                response.extend_from_slice(b"Content-Length: 0\r\n\r\n");
                stream.write_all(&response).await?;
                let retried = timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_ok();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, retried))
            });

            let identity = TestIdentity::generate()?;
            let route = Route::http_proxy(
                HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
            );
            let error = client_builder(&identity, false)
                .route(route)
                .build()?
                .get(HttpProtocol::Http1, "http://origin.test/")?
                .send()
                .await
                .err()
                .ok_or("an unusable forward-proxy challenge unexpectedly succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::Proxy);
            let (head, retried) = proxy.await??;
            assert!(!contains_ascii_case_insensitive(
                &head,
                b"proxy-authorization"
            ));
            assert!(!retried);
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn one_shot_streaming_body_is_not_replayed_after_basic_challenge() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=stream\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let retried = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, body, retried))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let subscriber = OutcomeSubscriber::default();
        let error = client_builder(&identity, false)
            .route(route)
            .build()?
            .request(
                HttpProtocol::Http1,
                Method::POST,
                "http://origin.test/upload",
            )?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .send()
            .with_subscriber(subscriber.dispatch())
            .await
            .err()
            .ok_or("a one-shot body was replayed for forward-proxy authentication")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);

        let (head, body, retried) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &head,
            b"proxy-authorization"
        ));
        assert_eq!(&body, b"payload");
        assert!(!retried);
        assert_eq!(
            subscriber.proxy_authentication_retries_for("client.request"),
            [false]
        );
        assert_eq!(subscriber.proxy_attempts_for("client.request"), [1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn configured_basic_credentials_are_omitted_without_a_challenge() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let opened_another = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((head, opened_another))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let response = client_builder(&identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/public")?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (head, opened_another) = proxy.await??;
        assert_eq!(
            head,
            b"GET http://origin.test/public HTTP/1.1\r\nHost: origin.test\r\n\r\n"
        );
        assert!(!opened_another);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn disabled_preemptive_authentication_starts_every_forwarded_request_without_credentials()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous, _) = listener.accept().await?;
            let first_anonymous = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=forward\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            // The 407 kept the connection open, so the replay arrives on it.
            let mut authenticated = anonymous;
            let first_authenticated = read_head(&mut authenticated).await?;
            authenticated
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let second_anonymous = read_head(&mut authenticated).await?;
            authenticated
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let third_connection = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                first_anonymous,
                first_authenticated,
                second_anonymous,
                third_connection,
            ))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false)
            .route(route)
            .preemptive_proxy_authentication(false)
            .build()?;
        for path in ["first", "second"] {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://origin.test/{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
        }

        let (first_anonymous, first_authenticated, second_anonymous, third_connection) =
            proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &first_anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &first_authenticated,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        assert!(
            second_anonymous
                .starts_with(b"GET http://origin.test/second HTTP/1.1\r\nHost: origin.test\r\n")
        );
        assert!(!contains_ascii_case_insensitive(
            &second_anonymous,
            b"proxy-authorization"
        ));
        assert!(!third_connection);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepted_forward_credentials_are_sent_first_on_the_pooled_connection() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous, _) = listener.accept().await?;
            let first_anonymous = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=forward\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            // The 407 kept the connection open, so the replay arrives on it.
            let mut authenticated = anonymous;
            let mut heads = vec![first_anonymous];
            for _ in 0..3 {
                heads.push(read_head(&mut authenticated).await?);
                authenticated
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await?;
            }
            let third_connection = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((heads, third_connection))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let subscriber = OutcomeSubscriber::default();
        let client = client_builder(&identity, false).route(route).build()?;
        for path in ["first", "second", "third"] {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://origin.test/{path}"))?
                .send()
                .with_subscriber(subscriber.dispatch())
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
        }

        let (heads, third_connection) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &heads[0],
            b"proxy-authorization"
        ));
        for (head, path) in heads[1..].iter().zip(["first", "second", "third"]) {
            assert_eq!(
                head,
                format!(
                    "GET http://origin.test/{path} HTTP/1.1\r\nHost: origin.test\r\n\
                     Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
                )
                .as_bytes()
            );
        }
        // Two requests saved a 407 each, and the replay the proxy connection.
        assert!(!third_connection);
        assert_eq!(
            subscriber.proxy_authentication_retries_for("client.request"),
            [false, true, false, false]
        );
        assert_eq!(
            subscriber.proxy_attempts_for("client.request"),
            [1, 2, 1, 1]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_challenge_to_remembered_forward_credentials_retries_once_and_relearns() -> TestResult<()>
{
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let challenge: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
            Proxy-Authenticate: Basic realm=forward\r\n\
            Content-Length: 0\r\n\r\n";
        let no_content: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let proxy = tokio::spawn(async move {
            let mut heads = Vec::new();
            let (mut first, _) = listener.accept().await?;
            heads.push(read_head(&mut first).await?);
            first.write_all(challenge).await?;
            let mut second = first;
            heads.push(read_head(&mut second).await?);
            second.write_all(no_content).await?;
            // The proxy now rejects the remembered credentials once.
            heads.push(read_head(&mut second).await?);
            second.write_all(challenge).await?;
            let mut third = second;
            heads.push(read_head(&mut third).await?);
            third.write_all(no_content).await?;
            heads.push(read_head(&mut third).await?);
            third.write_all(no_content).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        for path in ["first", "second", "third"] {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://origin.test/{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
        }

        let heads = proxy.await??;
        let sent: Vec<bool> = heads
            .iter()
            .map(|head| {
                contains_ascii_case_insensitive(
                    head,
                    b"proxy-authorization: basic ywxpy2u6c2vjcmv0",
                )
            })
            .collect();
        assert_eq!(sent, [false, true, true, true, true]);
        Ok(())
    })
    .await
}

/// A request queued behind a challenged one never takes the challenged
/// connection before the replay: the replay is the next request on it.
#[tokio::test]
async fn queued_request_does_not_take_the_challenged_connection_from_the_replay() -> TestResult<()>
{
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_seen_tx, first_seen_rx) = oneshot::channel();
        let (release_challenge_tx, release_challenge_rx) = oneshot::channel();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let proxy = tokio::spawn({
            let heads = Arc::clone(&heads);
            async move {
                let (mut challenged, _) = listener.accept().await?;
                let challenged_head = read_head(&mut challenged).await?;
                first_seen_tx
                    .send(())
                    .map_err(|()| "first-request signal receiver dropped")?;
                release_challenge_rx.await?;
                challenged
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=forward\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;
                // Answer every later request with 204, recording the
                // connection that carried it; the sibling may queue for the
                // challenged connection or open its own.
                tokio::spawn(answer_no_content(challenged, 0, Arc::clone(&heads)));
                let mut connections = 1;
                while let Ok(accepted) =
                    timeout(Duration::from_millis(300), listener.accept()).await
                {
                    let (stream, _) = accepted?;
                    tokio::spawn(answer_no_content(stream, connections, Arc::clone(&heads)));
                    connections += 1;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(challenged_head)
            }
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        let first_client = client.clone();
        let first = tokio::spawn(async move {
            let response = first_client
                .get(HttpProtocol::Http1, "http://origin.test/first")?
                .send()
                .await?;
            response.into_body().collect().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        first_seen_rx.await?;
        let sibling = tokio::spawn(async move {
            let response = client
                .get(HttpProtocol::Http1, "http://origin.test/sibling")?
                .send()
                .await?;
            response.into_body().collect().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        tokio::task::yield_now().await;
        release_challenge_tx
            .send(())
            .map_err(|()| "challenge release receiver dropped")?;

        first.await??;
        sibling.await??;
        let challenged_head = proxy.await??;
        assert!(
            challenged_head
                .starts_with(b"GET http://origin.test/first HTTP/1.1\r\nHost: origin.test\r\n")
        );
        let heads = heads
            .lock()
            .map_err(|_| "proxy head lock was poisoned")?
            .clone();
        let on_challenged: Vec<&Vec<u8>> = heads
            .iter()
            .filter(|(connection, _)| *connection == 0)
            .map(|(_, head)| head)
            .collect();
        assert!(on_challenged[0].starts_with(
            b"GET http://origin.test/first HTTP/1.1\r\nHost: origin.test\r\n\
              Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"
        ));
        let sibling_head = heads
            .iter()
            .map(|(_, head)| head)
            .find(|head| head.starts_with(b"GET http://origin.test/sibling HTTP/1.1\r\n"))
            .ok_or("the sibling request did not reach the proxy")?;
        assert!(!contains_ascii_case_insensitive(
            sibling_head,
            b"proxy-authorization"
        ));
        assert_eq!(heads.len(), 2);
        Ok(())
    })
    .await
}

/// Request heads a test proxy saw, with the index of the connection that
/// carried each.
type ConnectionHeads = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

/// Answers each request on `stream` with `204`, recording its head.
async fn answer_no_content(
    mut stream: TcpStream,
    connection: usize,
    heads: ConnectionHeads,
) -> std::io::Result<()> {
    loop {
        let head = read_head(&mut stream).await?;
        if let Ok(mut heads) = heads.lock() {
            heads.push((connection, head));
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
    }
}

#[tokio::test]
async fn basic_authentication_retry_shares_the_total_deadline() -> TestResult<()> {
    const CHALLENGE_DELAY: Duration = Duration::from_millis(600);
    const TOTAL_DEADLINE: Duration = Duration::from_millis(1_000);
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous, _) = listener.accept().await?;
            let anonymous_head = read_head(&mut anonymous).await?;
            sleep(CHALLENGE_DELAY).await;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=forward\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            // The 407 kept the connection open, so the replay arrives on it.
            let mut authenticated = anonymous;
            let authenticated_head = read_head(&mut authenticated).await?;
            // Never answer the replay: only the client's deadline ends it.
            let mut rest = Vec::new();
            let _ = authenticated.read_to_end(&mut rest).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((anonymous_head, authenticated_head))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let started = Instant::now();
        let error = client_builder(&identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, "http://origin.test/deadline")?
            .timeouts(RequestTimeouts::new().total(TOTAL_DEADLINE))
            .send()
            .await
            .err()
            .ok_or("authentication replay completed without a response")?;
        let elapsed = started.elapsed();
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        // A deadline restarted by the replay would end no earlier than
        // CHALLENGE_DELAY + TOTAL_DEADLINE after the first request.
        assert!(
            elapsed < CHALLENGE_DELAY + TOTAL_DEADLINE,
            "authentication replay restarted the total deadline after {elapsed:?}"
        );

        let (anonymous_head, authenticated_head) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous_head,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authenticated_head,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        Ok(())
    })
    .await
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn intermediate_proxy_challenge_does_not_poison_origin_cookies() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut anonymous, _) = listener.accept().await?;
            let anonymous_head = read_head(&mut anonymous).await?;
            anonymous
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=forward\r\n\
                      Set-Cookie: poisoned=challenge; Path=/\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;

            // The 407 kept the connection open, so the replay arrives on it.
            let mut authenticated = anonymous;
            let authenticated_head = read_head(&mut authenticated).await?;
            authenticated
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Set-Cookie: accepted=final; Path=/\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let followup_head = read_head(&mut authenticated).await?;
            authenticated
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                anonymous_head,
                authenticated_head,
                followup_head,
            ))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false)
            .route(route)
            .cookies()
            .build()?;
        client
            .get(HttpProtocol::Http1, "http://origin.test/first")?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        client
            .get(HttpProtocol::Http1, "http://origin.test/followup")?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;

        let (anonymous_head, authenticated_head, followup_head) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous_head,
            b"cookie:"
        ));
        assert!(!contains_ascii_case_insensitive(
            &authenticated_head,
            b"cookie:"
        ));
        assert!(contains_ascii_case_insensitive(
            &followup_head,
            b"cookie: accepted=final"
        ));
        assert!(!contains_ascii_case_insensitive(
            &followup_head,
            b"poisoned=challenge"
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_reuses_same_origin_and_forward_route() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut heads = Vec::new();
            for _ in 0..2 {
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
async fn tls_forwarding_preserves_wire_shape_and_reuses_the_proxy_connection() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(async move {
            let (tcp, _) = proxy_listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, proxy_acceptor).await?;
            let first = read_head(&mut stream).await?;
            let mut framed = Vec::new();
            while !framed.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                stream.read_exact(&mut byte).await?;
                framed.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nthrough")
                .await?;

            let second = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let opened_another = timeout(Duration::from_millis(100), proxy_listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                first,
                framed,
                second,
                opened_another,
            ))
        });

        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let client = client_builder(&origin_identity, false)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                "http://BÜCHER.Example:8080/upload?part=%2f",
            )?
            .headers(vec![
                RequestHeader::new("X-First", "one"),
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("X-Repeat", "beta"),
            ])
            .body(Bytes::from_static(b"payload"))
            .trailers(vec![
                RequestHeader::new("X-Checksum", "first"),
                RequestHeader::new("X-Middle", "between"),
                RequestHeader::new("X-Checksum", "second"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "through");

        let response = client
            .get(
                HttpProtocol::Http1,
                "http://BÜCHER.Example:8080/reused",
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;

        let (first, framed, second, opened_another) = proxy.await??;
        assert_eq!(
            first,
            b"POST http://xn--bcher-kva.example:8080/upload?part=%2f HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum, X-Middle\r\n\r\n"
        );
        assert_eq!(
            framed,
            b"7\r\npayload\r\n0\r\nX-Checksum: first\r\nX-Middle: between\r\nX-Checksum: second\r\n\r\n"
        );
        assert_eq!(
            second,
            b"GET http://xn--bcher-kva.example:8080/reused HTTP/1.1\r\nHost: xn--bcher-kva.example:8080\r\n\r\n"
        );
        assert!(!opened_another);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn untrusted_tls_forward_proxy_fails_without_direct_fallback() -> TestResult<()> {
    bounded(async {
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(async move {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                accept_tls(proxy_listener, proxy_acceptor).await.is_err(),
            )
        });

        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let error = client_builder(&origin_identity, false)
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, &format!("http://{origin_address}/"))?
            .send()
            .await
            .err()
            .ok_or("untrusted TLS forward proxy unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(proxy.await??, "proxy TLS unexpectedly authenticated");
        assert!(
            timeout(Duration::from_millis(100), origin_listener.accept())
                .await
                .is_err(),
            "TLS proxy failure fell back to the origin"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tls_forward_proxy_rejects_h2_alpn_without_direct_fallback() -> TestResult<()> {
    bounded(async {
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H2_ALPN)?;
        let proxy = tokio::spawn(async move {
            let stream = accept_tls(proxy_listener, proxy_acceptor).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
            )
        });

        let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
        let error = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?
            .get(HttpProtocol::Http1, &format!("http://{origin_address}/"))?
            .send()
            .await
            .err()
            .ok_or("TLS forward proxy unexpectedly accepted h2 ALPN")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(proxy.await??.as_deref(), Some(b"h2".as_slice()));
        assert!(
            timeout(Duration::from_millis(100), origin_listener.accept())
                .await
                .is_err(),
            "proxy ALPN failure fell back to the origin"
        );
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

        let h3_profile = ClientProfile::new(tls_settings()).with_http3(client_settings());
        let h3_client = Client::builder(h3_profile)
            .add_root_certificate_der(identity.root_der.clone())
            .route(route)
            .build()?;
        let h3_error = h3_client
            .get(HttpProtocol::Http3, "http://origin.test/")?
            .send()
            .await
            .err()
            .ok_or("HTTP/3 forwarding unexpectedly succeeded")?;
        assert_eq!(h3_error.kind(), RequestErrorKind::UnsupportedRoute);

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
async fn caller_proxy_authorization_is_forwarded_without_configured_credentials() -> TestResult<()>
{
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let client = client_builder(&identity, false).route(route).build()?;
        let response = client
            .get(HttpProtocol::Http1, "http://origin.test/preemptive")?
            .header(RequestHeader::new("Proxy-Authorization", "Basic YWxpY2U6c2VjcmV0").sensitive())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        assert_eq!(
            proxy.await??,
            b"GET http://origin.test/preemptive HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_proxy_authorization_is_refused_directly_and_with_configured_credentials()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let identity = TestIdentity::generate()?;
        let credentialed = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );

        for (route, target) in [
            (Route::direct(), format!("http://{address}/direct")),
            (credentialed, "http://origin.test/configured".to_owned()),
        ] {
            let error = client_builder(&identity, false)
                .route(route)
                .build()?
                .get(HttpProtocol::Http1, &target)?
                .header(RequestHeader::new("Proxy-Authorization", "Basic secret"))
                .send()
                .await
                .err()
                .ok_or("caller Proxy-Authorization unexpectedly succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        }
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a refused Proxy-Authorization request reached the network"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_proxy_connection_failure_has_proxy_category() -> TestResult<()> {
    bounded(async {
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();

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

async fn read_chunked_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Vec<u8>, std::io::Error> {
    let mut framed = Vec::new();
    while !framed.ends_with(b"\r\n\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        framed.push(byte[0]);
    }
    Ok(framed)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Sends one forwarded request through a plaintext proxy that answers its
/// first request with `challenge`, and returns the request heads the proxy
/// saw on each connection, in accept order.
///
/// With `close_after_challenge`, the proxy reads the next request on the
/// challenged connection and closes it without an answer.
async fn forward_challenge_connections(
    challenge: Vec<u8>,
    close_after_challenge: bool,
) -> TestResult<Vec<Vec<Vec<u8>>>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let proxy = tokio::spawn({
        let heads = Arc::clone(&heads);
        async move {
            let (mut challenged, _) = listener.accept().await?;
            let head = read_head(&mut challenged).await?;
            if let Ok(mut heads) = heads.lock() {
                heads.push((0, head));
            }
            challenged.write_all(&challenge).await?;
            challenged.flush().await?;
            if close_after_challenge {
                let head = read_head(&mut challenged).await?;
                if let Ok(mut heads) = heads.lock() {
                    heads.push((0, head));
                }
                drop(challenged);
            } else {
                tokio::spawn(answer_no_content(challenged, 0, Arc::clone(&heads)));
            }
            let mut connections = 1;
            while let Ok(accepted) = timeout(Duration::from_millis(300), listener.accept()).await {
                let (stream, _) = accepted?;
                tokio::spawn(answer_no_content(stream, connections, Arc::clone(&heads)));
                connections += 1;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connections)
        }
    });

    let identity = TestIdentity::generate()?;
    let route = Route::http_proxy(
        HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
    );
    let response = client_builder(&identity, false)
        .route(route)
        .build()?
        .get(HttpProtocol::Http1, "http://origin.test/challenged")?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    let connections = proxy.await??;
    let heads = heads
        .lock()
        .map_err(|_| "proxy head lock was poisoned")?
        .clone();
    Ok((0..connections)
        .map(|connection| {
            heads
                .iter()
                .filter(|(index, _)| *index == connection)
                .map(|(_, head)| head.clone())
                .collect()
        })
        .collect())
}

const FORWARD_ANONYMOUS: &[u8] =
    b"GET http://origin.test/challenged HTTP/1.1\r\nHost: origin.test\r\n\r\n";
const FORWARD_AUTHENTICATED: &[u8] = b"GET http://origin.test/challenged HTTP/1.1\r\n\
    Host: origin.test\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n";

fn forward_challenge(fields_and_body: &[u8]) -> Vec<u8> {
    [
        &b"HTTP/1.1 407 Proxy Authentication Required\r\n\
           Proxy-Authenticate: Basic realm=forward\r\n"[..],
        fields_and_body,
    ]
    .concat()
}

#[tokio::test]
async fn keep_alive_forward_challenge_costs_one_proxy_connection() -> TestResult<()> {
    bounded(async {
        for fields_and_body in [
            &b"Content-Length: 0\r\n\r\n"[..],
            b"Content-Type: text/html\r\nContent-Length: 11\r\n\r\n<p>deny</p>",
            b"Transfer-Encoding: chunked\r\n\r\n4\r\ndeny\r\n0\r\n\r\n",
        ] {
            let connections =
                forward_challenge_connections(forward_challenge(fields_and_body), false).await?;
            assert_eq!(
                connections,
                [vec![
                    FORWARD_ANONYMOUS.to_vec(),
                    FORWARD_AUTHENTICATED.to_vec()
                ]],
                "{}",
                String::from_utf8_lossy(fields_and_body)
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn closing_or_oversized_forward_challenge_costs_a_second_proxy_connection() -> TestResult<()>
{
    bounded(async {
        let mut oversized = format!(
            "Content-Length: {}\r\n\r\n",
            phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES + 1
        )
        .into_bytes();
        oversized.resize(
            oversized.len() + phantom_net::proxy::MAX_CHALLENGE_BODY_BYTES + 1,
            b'x',
        );
        for fields_and_body in [
            &b"Connection: close\r\nContent-Length: 0\r\n\r\n"[..],
            b"Proxy-Connection: close\r\nContent-Length: 0\r\n\r\n",
            &oversized,
        ] {
            let connections =
                forward_challenge_connections(forward_challenge(fields_and_body), false).await?;
            assert_eq!(
                connections,
                [
                    vec![FORWARD_ANONYMOUS.to_vec()],
                    vec![FORWARD_AUTHENTICATED.to_vec()]
                ],
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn forward_replay_moves_to_a_new_connection_when_the_proxy_closes_the_challenged_one()
-> TestResult<()> {
    bounded(async {
        let connections =
            forward_challenge_connections(forward_challenge(b"Content-Length: 0\r\n\r\n"), true)
                .await?;
        // The replay reached the challenged connection, which the proxy
        // closed; it is sent once more on a new one without a retry policy.
        assert_eq!(
            connections,
            [
                vec![FORWARD_ANONYMOUS.to_vec(), FORWARD_AUTHENTICATED.to_vec()],
                vec![FORWARD_AUTHENTICATED.to_vec()]
            ],
        );
        Ok(())
    })
    .await
}

/// A POST whose replay reached the challenged connection may already have
/// been forwarded when the proxy closes it, so the error is returned and the
/// body is not sent again.
#[tokio::test]
async fn post_replay_is_not_resent_when_the_proxy_closes_the_challenged_connection()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut challenged, _) = listener.accept().await?;
            let anonymous = read_head(&mut challenged).await?;
            let mut body = [0_u8; 7];
            challenged.read_exact(&mut body).await?;
            challenged
                .write_all(&forward_challenge(b"Content-Length: 0\r\n\r\n"))
                .await?;
            let replay = read_head(&mut challenged).await?;
            challenged.read_exact(&mut body).await?;
            drop(challenged);
            let second_connection = timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_ok();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                anonymous,
                replay,
                second_connection,
            ))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let result = client_builder(&identity, false)
            .route(route)
            .build()?
            .request(HttpProtocol::Http1, Method::POST, "http://origin.test/post")?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await;
        assert!(
            result.is_err(),
            "the closed POST replay returned a response"
        );

        let (anonymous, replay, second_connection) = proxy.await??;
        assert!(anonymous.starts_with(b"POST http://origin.test/post HTTP/1.1\r\n"));
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &replay,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        assert!(
            !second_connection,
            "the POST was sent on a second connection"
        );
        Ok(())
    })
    .await
}

/// A `407` body that stalls ends the request with the configured timeout; the
/// replay is never sent.
#[tokio::test]
async fn stalled_challenge_body_ends_with_the_configured_timeout() -> TestResult<()> {
    for (timeouts, phase) in [
        (
            RequestTimeouts::new().read_idle(Duration::from_millis(200)),
            TimeoutPhase::ReadIdle,
        ),
        (
            RequestTimeouts::new().total(Duration::from_millis(500)),
            TimeoutPhase::Total,
        ),
        (
            RequestTimeouts::new().response_head(Duration::from_millis(500)),
            TimeoutPhase::ResponseHead,
        ),
    ] {
        bounded(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let proxy = tokio::spawn(async move {
                let (mut challenged, _) = listener.accept().await?;
                read_head(&mut challenged).await?;
                challenged
                    .write_all(&forward_challenge(b"Content-Length: 10\r\n\r\nabc"))
                    .await?;
                let second_connection = timeout(Duration::from_millis(1_500), listener.accept())
                    .await
                    .is_ok();
                let mut rest = Vec::new();
                let _ = timeout(
                    Duration::from_millis(100),
                    challenged.read_to_end(&mut rest),
                )
                .await;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((second_connection, rest))
            });

            let identity = TestIdentity::generate()?;
            let route = Route::http_proxy(
                HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
            );
            let error = client_builder(&identity, false)
                .route(route)
                .build()?
                .get(HttpProtocol::Http1, "http://origin.test/stalled")?
                .timeouts(timeouts)
                .send()
                .await
                .err()
                .ok_or("a stalled challenge body produced a response")?;
            assert_eq!(error.kind(), RequestErrorKind::Timeout, "{phase:?}");
            assert_eq!(error.timeout_phase(), Some(phase));

            let (second_connection, rest) = proxy.await??;
            assert!(
                !second_connection,
                "{phase:?}: the replay opened a connection"
            );
            assert!(rest.is_empty(), "{phase:?}: the replay reached the proxy");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A proxy that shuts its side of the connection right after a keep-alive
/// `407` gets the replay on a new connection, and nothing more on the old one.
#[tokio::test]
async fn proxy_that_shuts_down_after_the_challenge_gets_the_replay_on_a_new_connection()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = tokio::spawn(async move {
            let (mut challenged, _) = listener.accept().await?;
            let anonymous = read_head(&mut challenged).await?;
            challenged
                .write_all(&forward_challenge(b"Content-Length: 0\r\n\r\n"))
                .await?;
            challenged.shutdown().await?;
            let leftover = tokio::spawn(async move {
                let mut rest = Vec::new();
                let _ = challenged.read_to_end(&mut rest).await;
                rest
            });
            let (mut second, _) = listener.accept().await?;
            let replay = read_head(&mut second).await?;
            second
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((anonymous, replay, leftover))
        });

        let identity = TestIdentity::generate()?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("alice", "secret")?,
        );
        let client = client_builder(&identity, false).route(route).build()?;
        let response = client
            .get(HttpProtocol::Http1, "http://origin.test/challenged")?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);

        let (anonymous, replay, leftover) = proxy.await??;
        assert_eq!(anonymous, FORWARD_ANONYMOUS);
        assert_eq!(replay, FORWARD_AUTHENTICATED);
        let leftover = timeout(Duration::from_secs(2), leftover).await??;
        assert!(
            leftover.is_empty(),
            "the replay was written to the closed connection"
        );
        Ok(())
    })
    .await
}
