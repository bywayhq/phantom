//! Actual quiet TCP openings; no OS race timing is asserted here.
use std::{io, net::Ipv4Addr, pin::Pin};

use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{read_plaintext_head, test_connector};
use crate::{
    http1::Http1TlsError,
    proxy::{
        HttpBasicCredentials, HttpConnectHeader, HttpDigestCredentials, HttpProxyAuthentication,
    },
    request::{OriginForm, RequestHeader},
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
    tcp::{AddressFamily, AddressFamilyMemory},
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};

fn route<'a>(
    host: &'a str,
    port: u16,
    fields: &'a [HttpConnectHeader],
    credentials: Option<HttpProxyAuthentication<'a>>,
) -> HttpConnectRoute<'a> {
    HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tcp(Endpoint { host, port }),
        authority: "server.phantom.test:443",
        headers: fields,
        credentials,
    }
}

fn fields(value: &str, authenticated: bool) -> Vec<HttpConnectHeader> {
    let mut fields = vec![
        HttpConnectHeader::field(RequestHeader::new("X-Claim", value)),
        HttpConnectHeader::authority("host"),
    ];
    if authenticated {
        fields.push(HttpConnectHeader::proxy_authorization(
            "Proxy-Authorization",
        ));
    }
    fields
}

#[tokio::test]
async fn an_unclaimed_proxy_opening_is_quiet_and_records_the_proxy_family() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?.with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", true);
        let credentials = HttpBasicCredentials::new("quiet-user", "quiet-secret")?;
        let family = AddressFamilyMemory::default();
        let (opening, slower) = connector.open_http_connect_retaining(HttpConnectRoute { speculative_tls: true, ..route("127.0.0.1", address.port(), &fields, Some(HttpProxyAuthentication::Basic(&credentials))) }, TEST_SERVER_NAME, &family).await?;
        assert!(slower.is_none());
        let debug = format!("{opening:?}");
        assert!(!debug.contains("quiet-user"));
        assert!(!debug.contains("quiet-secret"));
        let (mut peer, _) = listener.accept().await?;
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        drop(opening);
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn changing_a_proxy_openings_endpoint_authority_or_credentials_sends_no_connect()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        for changed_part in 0..4 {
            let identity = TestIdentity::generate()?;
            let connector = test_connector(&identity)?;
            let (address, listener) = loopback_listener().await?;
            let fields = fields("bound", false);
            let family = AddressFamilyMemory::default();
            let original = route("127.0.0.1", address.port(), &fields, None);
            let (opening, _) = connector.open_http_connect_retaining(original, TEST_SERVER_NAME, &family).await?;
            let (mut peer, _) = listener.accept().await?;
            let credentials = HttpBasicCredentials::new("user", "secret")?;
            let changed = if changed_part == 0 {
                HttpConnectRoute { credentials: Some(HttpProxyAuthentication::Basic(&credentials)), ..original }
            } else if changed_part == 1 { HttpConnectRoute { authority: "other.test:443", ..original } }
            else if changed_part == 2 { HttpConnectRoute { speculative_tls: false, proxy: ProxyTransport::Tcp(Endpoint { host: "other.invalid", port: address.port() }), ..original } }
            else { HttpConnectRoute { speculative_tls: true, ..original } };
            let result = opening.finish(changed).await;
            assert!(matches!(result, Err(Http1TlsError::Connect(error)) if error.kind() == io::ErrorKind::InvalidInput));
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty());
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn invalid_connect_fields_do_not_resolve_or_open_a_proxy_socket() -> TestResult<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let identity = TestIdentity::generate()?;
    let lookups = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&lookups);
    let resolver = crate::host_resolver::AddressResolver::from_fn(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        async { Ok(vec![Ipv4Addr::LOCALHOST.into()]) }
    });
    let resolver = crate::host_resolver::HostResolver::default().with_resolver(resolver);
    let connector = test_connector(&identity)?.with_host_resolver(resolver);
    let invalid = [HttpConnectHeader::field(RequestHeader::new(
        "X-Test",
        "invalid\r\nfield",
    ))];
    let family = AddressFamilyMemory::default();
    let result = connector
        .open_http_connect_retaining(
            route("proxy.invalid", 1, &invalid, None),
            TEST_SERVER_NAME,
            &family,
        )
        .await;
    assert!(matches!(result, Err(Http1TlsError::Proxy(_))));
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn claimed_anonymous_opening_uses_current_fields_and_verified_origin_tls() -> TestResult<()> {
    claimed(None).await
}

#[tokio::test]
async fn claimed_basic_opening_keeps_challenge_replay_on_its_original_socket() -> TestResult<()> {
    claimed(Some(HttpProxyAuthentication::Basic(
        &HttpBasicCredentials::new("user", "secret")?,
    )))
    .await
}

#[tokio::test]
async fn claimed_digest_opening_reserves_its_first_nonce_only_after_claim() -> TestResult<()> {
    claimed(Some(HttpProxyAuthentication::Digest(
        &HttpDigestCredentials::new("user", "secret")?,
    )))
    .await
}

async fn claimed(credentials: Option<HttpProxyAuthentication<'_>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let original = fields("old", credentials.is_some());
        let current = fields("current", credentials.is_some());
        let family = AddressFamilyMemory::default();
        let (opening, _) = connector.open_http_connect_retaining(route("127.0.0.1", address.port(), &original, credentials), TEST_SERVER_NAME, &family).await?;
        let (mut peer, _) = listener.accept().await?;
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        let client = async {
            let connection = opening.finish(route("127.0.0.1", address.port(), &current, credentials)).await?;
            let response = connection.send_get(OriginForm::parse("/claimed")?, vec![RequestHeader::new("Host", TEST_SERVER_NAME)]).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let server = async {
            let head = read_plaintext_head(&mut peer).await?;
            assert_eq!(head, b"CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: current\r\nhost: server.phantom.test:443\r\n\r\n");
            if let Some(credentials) = credentials {
                let challenge = match credentials {
                    HttpProxyAuthentication::Basic(_) => "Basic realm=\"proxy\"",
                    HttpProxyAuthentication::Digest(_) => "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"",
                };
                peer.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                let retry = String::from_utf8(read_plaintext_head(&mut peer).await?)?;
                assert!(retry.starts_with("CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: current\r\nhost: server.phantom.test:443\r\nProxy-Authorization: "));
                match credentials {
                    HttpProxyAuthentication::Basic(_) => assert!(retry.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
                    HttpProxyAuthentication::Digest(_) => {
                        assert!(retry.contains("Proxy-Authorization: Digest "));
                        assert!(retry.contains("nc=00000001"));
                        assert!(retry.contains("uri=\"server.phantom.test:443\""));
                    }
                }
            }
            peer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let ssl = btls::ssl::Ssl::new(acceptor.context())?;
            let mut tls = SslStream::new(ssl, peer)?;
            Pin::new(&mut tls).accept().await?;
            let request = read_plaintext_head(&mut tls).await?;
            assert_eq!(request, b"GET /claimed HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n");
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        Ok(())
    }).await?
}

mod nonce;

#[tokio::test]
async fn cancelling_a_claimed_connect_closes_the_socket_and_records_each_outcome() -> TestResult<()>
{
    use tracing::instrument::WithSubscriber;

    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("cancelled", false);
        let route = route("127.0.0.1", address.port(), &fields, None);
        let family = AddressFamilyMemory::default();
        let (opening, _) = connector
            .open_http_connect_retaining(route, TEST_SERVER_NAME, &family)
            .await?;
        let (mut peer, _) = listener.accept().await?;
        let subscriber = crate::tracing_test::OutcomeSubscriber::default();
        let mut finish = Box::pin(opening.finish(route).with_subscriber(subscriber.dispatch()));
        let head = tokio::select! {
            result = &mut finish => return Err(format!("CONNECT unexpectedly completed: {result:?}").into()),
            head = read_plaintext_head(&mut peer) => head?,
        };
        assert_eq!(head, b"CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: cancelled\r\nhost: server.phantom.test:443\r\n\r\n");
        drop(finish);
        let mut remaining = Vec::new();
        peer.read_to_end(&mut remaining).await?;
        assert!(remaining.is_empty());
        assert_eq!(subscriber.outcomes_for("http1.tls.connect"), ["cancelled"]);
        assert_eq!(subscriber.outcomes_for("proxy.http_connect"), ["cancelled"]);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn finishing_the_slower_tcp_result_does_not_start_connect_or_origin_tls() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", false);
        let binding = crate::proxy::http1_opening::ProxyBinding::new(
            route("127.0.0.1", address.port(), &fields, None), TEST_SERVER_NAME,
        ).map_err(crate::http1::Http1TlsError::from)?;
        let attempt = crate::tcp::SlowerAttempt::scripted(
            async move { tokio::net::TcpStream::connect(address).await },
            std::time::Duration::ZERO, None,
        );
        let slower = connector.slower_proxy_opening(attempt, binding);
        let progress = slower.progress();
        assert!(!progress.has_connected());
        let opening = slower.finish().await.ok_or("slower TCP failed")?;
        let (mut peer, _) = listener.accept().await?;
        assert!(progress.has_connected());
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(opening);
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

mod https;
