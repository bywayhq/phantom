use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tracing::Span;

use super::{
    Http1Outcome, PreparedConnectUdp, PreparedLeg, http1_exchange, http2_request,
    parse_upgrade_response,
};
use crate::{
    proxy::{HttpBasicCredentials, HttpConnectError, HttpsProxyProtocol},
    request::{OriginForm, RequestHeader},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const AUTHORITY: &str = "proxy.example:8443";
const UPGRADED: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
    Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n";

fn path() -> TestResult<OriginForm> {
    Ok(OriginForm::parse("/.well-known/masque/udp/192.0.2.6/443/")?)
}

fn prepare(
    protocol: HttpsProxyProtocol,
    headers: &[RequestHeader],
    credentials: Option<&HttpBasicCredentials>,
) -> Result<PreparedConnectUdp, HttpConnectError> {
    PreparedConnectUdp::new(
        protocol,
        AUTHORITY,
        &path().map_err(|_| HttpConnectError::InvalidAuthority)?,
        headers,
        credentials,
    )
}

fn http1_bytes(leg: &PreparedLeg) -> TestResult<&[u8]> {
    match leg {
        PreparedLeg::Http1(bytes) => Ok(bytes),
        PreparedLeg::Http2(_) => Err("expected an HTTP/1.1 request".into()),
    }
}

#[test]
fn http1_request_uses_rfc9298_upgrade_fields_in_order() -> TestResult {
    let credentials = HttpBasicCredentials::new("user", "pass")?;
    let request = prepare(
        HttpsProxyProtocol::Http1,
        &[RequestHeader::new("X-Client", "phantom")],
        Some(&credentials),
    )?;

    assert_eq!(
        http1_bytes(&request.anonymous)?,
        b"GET /.well-known/masque/udp/192.0.2.6/443/ HTTP/1.1\r\n\
          Host: proxy.example:8443\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\
          Capsule-Protocol: ?1\r\nX-Client: phantom\r\n\r\n"
    );
    let authenticated = request
        .authenticated
        .as_ref()
        .ok_or("credentials produced no authenticated form")?;
    assert!(
        http1_bytes(authenticated)?
            .ends_with(b"X-Client: phantom\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n")
    );
    Ok(())
}

#[test]
fn http2_request_is_extended_connect_with_sensitive_authorization() -> TestResult {
    let credentials = HttpBasicCredentials::new("user", "pass")?;
    let request = http2_request(
        AUTHORITY,
        path()?,
        &[RequestHeader::new("x-client", "phantom")],
        Some(credentials.authorization()),
    )?;

    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().scheme_str(), Some("https"));
    assert_eq!(
        request.uri().authority().map(|value| value.as_str()),
        Some(AUTHORITY)
    );
    assert_eq!(
        request
            .extensions()
            .get::<::http2::ext::Protocol>()
            .map(::http2::ext::Protocol::as_str),
        Some("connect-udp")
    );
    let ordered = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("request has no field order")?
        .as_slice();
    let names = ordered
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["capsule-protocol", "x-client", "proxy-authorization"]
    );
    assert!(ordered[2].1.is_sensitive());
    Ok(())
}

#[test]
fn generated_and_framing_fields_are_rejected_before_io() -> TestResult {
    let credentials = HttpBasicCredentials::new("user", "pass")?;
    for protocol in [HttpsProxyProtocol::Http1, HttpsProxyProtocol::Http2] {
        for (name, credentials, expected) in [
            ("Host", None, "AuthorityHeader"),
            ("connection", None, "ConnectUdpGeneratedHeader"),
            ("Upgrade", None, "ConnectUdpGeneratedHeader"),
            ("capsule-protocol", None, "ConnectUdpGeneratedHeader"),
            ("content-length", None, "RequestFramingHeader"),
            (
                "proxy-authorization",
                Some(&credentials),
                "ProxyAuthorizationHeader",
            ),
        ] {
            let error = prepare(protocol, &[RequestHeader::new(name, "1")], credentials)
                .err()
                .ok_or("generated field was accepted")?;
            assert!(
                format!("{error:?}").starts_with(expected),
                "{name}: {error:?}"
            );
        }
    }
    // Without generated credentials a literal field is the caller's choice.
    prepare(
        HttpsProxyProtocol::Http1,
        &[RequestHeader::new("Proxy-Authorization", "Bearer token")],
        None,
    )?;
    Ok(())
}

#[tokio::test]
async fn upgrade_keeps_capsule_bytes_that_follow_the_101_head() -> TestResult {
    let (client, mut proxy) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut head = vec![0; 16];
        proxy.read_exact(&mut head).await?;
        proxy
            .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n")
            .await?;
        let mut response = UPGRADED.to_vec();
        response.extend_from_slice(b"\x00\x03\x00ab");
        proxy.write_all(&response).await?;
        Ok::<_, std::io::Error>(proxy)
    });

    let outcome = http1_exchange(client, b"GET / HTTP/1.1\r\n", false, &Span::none()).await?;
    let Http1Outcome::Upgraded(mut stream) = outcome else {
        return Err("101 did not upgrade".into());
    };
    let mut capsule = [0; 5];
    stream.read_exact(&mut capsule).await?;
    assert_eq!(&capsule, b"\x00\x03\x00ab");
    drop(server.await??);
    Ok(())
}

#[tokio::test]
async fn non_upgrade_responses_fail_without_opening_a_tunnel() -> TestResult {
    for (response, inspect, expected) in [
        (&b"HTTP/1.1 200 OK\r\n\r\n"[..], false, "InvalidResponse"),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
            false,
            "InvalidResponse",
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            false,
            "InvalidResponse",
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Length: 0\r\n\r\n",
            false,
            "InvalidResponse",
        ),
        (b"HTTP/1.1 403 Forbidden\r\n\r\n", false, "Rejected"),
        (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
            true,
            "UnsupportedAuthenticationChallenge",
        ),
    ] {
        let (client, mut proxy) = duplex(4096);
        let owned = response.to_vec();
        let server = tokio::spawn(async move {
            let mut head = vec![0; 16];
            proxy.read_exact(&mut head).await?;
            proxy.write_all(&owned).await?;
            Ok::<_, std::io::Error>(proxy)
        });
        let request = b"GET / HTTP/1.1\r\n";
        let error = match http1_exchange(client, request, inspect, &Span::none()).await {
            Ok(_) => return Err("non-upgrade response opened a tunnel".into()),
            Err(error) => error,
        };
        assert!(format!("{error:?}").starts_with(expected), "{error:?}");
        drop(server.await??);
    }
    Ok(())
}

#[tokio::test]
async fn valid_basic_challenge_requests_one_retry() -> TestResult {
    let (client, mut proxy) = duplex(4096);
    let server = tokio::spawn(async move {
        let mut head = vec![0; 16];
        proxy.read_exact(&mut head).await?;
        proxy
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"masque\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        Ok::<_, std::io::Error>(proxy)
    });
    let outcome = http1_exchange(client, b"GET / HTTP/1.1\r\n", true, &Span::none()).await?;
    assert!(matches!(outcome, Http1Outcome::Retry));
    drop(server.await??);
    Ok(())
}

#[test]
fn upgrade_tokens_match_case_insensitively_within_connection_lists() -> TestResult {
    let head = b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, UPGRADE\r\n\
        Upgrade: Connect-UDP\r\n\r\n";
    assert!(parse_upgrade_response(head, false)?.valid_upgrade);
    let doubled = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
        Upgrade: connect-udp\r\nUpgrade: connect-udp\r\n\r\n";
    assert!(!parse_upgrade_response(doubled, false)?.valid_upgrade);
    Ok(())
}
