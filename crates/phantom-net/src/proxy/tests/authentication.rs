use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::{TestResult, read_head};
use crate::{
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectErrorKind, HttpConnectHeader,
        connect_http_tunnel, connect_http_tunnel_direct_with_basic_auth,
        http_connect::PreparedBasicConnect,
    },
    request::RequestHeader,
};

#[test]
fn validates_credentials_and_redacts_debug() -> TestResult {
    let credentials = HttpBasicCredentials::new("user", "secret")?;
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("user"));
    assert!(!debug.contains("secret"));
    assert!(HttpBasicCredentials::new("user", "").is_ok());

    for (username, password, expected) in [
        ("", "secret", HttpConnectError::InvalidBasicUsername),
        (
            "user:name",
            "secret",
            HttpConnectError::InvalidBasicUsername,
        ),
        ("us\ner", "secret", HttpConnectError::InvalidBasicUsername),
        ("usér", "secret", HttpConnectError::InvalidBasicUsername),
        (
            "user",
            "sec\u{7f}ret",
            HttpConnectError::InvalidBasicPassword,
        ),
        ("user", "sëcret", HttpConnectError::InvalidBasicPassword),
    ] {
        let error = HttpBasicCredentials::new(username, password)
            .err()
            .ok_or("invalid HTTP Basic credentials were accepted")?;
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected)
        );
        assert_eq!(error.kind(), HttpConnectErrorKind::InvalidRequest);
        if !username.is_empty() {
            assert!(!format!("{error:?}").contains(username));
        }
        assert!(!error.to_string().contains(password));
    }
    Ok(())
}

#[test]
fn authenticated_preparation_requires_one_unambiguous_placeholder() -> TestResult {
    let credentials = HttpBasicCredentials::new("user", "secret")?;
    let cases = [
        (
            vec![HttpConnectHeader::authority("Host")],
            HttpConnectError::MissingProxyAuthorizationPlaceholder,
        ),
        (
            vec![
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
                HttpConnectHeader::proxy_authorization("proxy-authorization"),
            ],
            HttpConnectError::MultipleProxyAuthorizationPlaceholders,
        ),
        (
            vec![
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
                HttpConnectHeader::field(RequestHeader::new("proxy-authorization", "literal")),
            ],
            HttpConnectError::ProxyAuthorizationHeader,
        ),
    ];

    for (headers, expected) in cases {
        let error = PreparedBasicConnect::new("origin.example:443", &headers, &credentials)
            .err()
            .ok_or("ambiguous authentication fields were accepted")?;
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected)
        );
        assert_eq!(error.kind(), HttpConnectErrorKind::InvalidRequest);
    }
    Ok(())
}

#[tokio::test]
async fn challenge_retry_uses_fresh_connection_and_placeholder_order() -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let anonymous = read_head(&mut first).await?;
        first
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Digest realm=\"other\", Basic realm=\"a,b\", charset=\"UTF-8\"\r\n\r\n",
            )
            .await?;
        first.shutdown().await?;

        let (mut second, _) = listener.accept().await?;
        let authenticated = read_head(&mut second).await?;
        second
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nprefix")
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((anonymous, authenticated))
    });

    let credentials = HttpBasicCredentials::new("user", "secret")?;
    let mut tunnel = connect_http_tunnel_direct_with_basic_auth(
        "127.0.0.1",
        address.port(),
        "origin.example:443",
        &[
            HttpConnectHeader::field(RequestHeader::new("User-Agent", "fixture")),
            HttpConnectHeader::proxy_authorization("proxy-authorization"),
            HttpConnectHeader::authority("Host"),
        ],
        &credentials,
    )
    .await?;
    let mut prefix = [0_u8; 6];
    tunnel.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"prefix");

    let (anonymous, authenticated) = proxy.await??;
    assert_eq!(
        anonymous,
        b"CONNECT origin.example:443 HTTP/1.1\r\n\
          User-Agent: fixture\r\n\
          Host: origin.example:443\r\n\r\n"
    );
    assert_eq!(
        authenticated,
        b"CONNECT origin.example:443 HTTP/1.1\r\n\
          User-Agent: fixture\r\n\
          proxy-authorization: Basic dXNlcjpzZWNyZXQ=\r\n\
          Host: origin.example:443\r\n\r\n"
    );
    Ok(())
}

#[tokio::test]
async fn rejects_second_407_as_authentication_failure() -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await?;
            let _request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n",
                )
                .await?;
        }
        Ok::<_, std::io::Error>(())
    });

    let error = connect_http_tunnel_direct_with_basic_auth(
        "127.0.0.1",
        address.port(),
        "origin.example:443",
        &[
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
        ],
        &HttpBasicCredentials::new("user", "secret")?,
    )
    .await
    .err()
    .ok_or("second 407 established a tunnel")?;
    assert!(matches!(error, HttpConnectError::AuthenticationRejected));
    assert_eq!(error.kind(), HttpConnectErrorKind::Authentication);
    proxy.await??;
    Ok(())
}

#[tokio::test]
async fn malformed_or_unsupported_challenge_does_not_retry() -> TestResult {
    for challenge in [
        "Digest realm=\"proxy\"",
        "Basic charset=\"UTF-8\"",
        "Basic realm=\"unterminated",
        "Basic realm=\"proxy\", realm=\"duplicate\"",
        "Basic realm=\"proxy\", charset=\"ISO-8859-1\"",
        "Basic\trealm=\"proxy\"",
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let response = format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\n\r\n"
        );
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _request = read_head(&mut stream).await?;
            stream.write_all(response.as_bytes()).await?;
            let retried = timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok();
            Ok::<_, std::io::Error>(retried)
        });

        let error = connect_http_tunnel_direct_with_basic_auth(
            "127.0.0.1",
            address.port(),
            "origin.example:443",
            &[
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
            ],
            &HttpBasicCredentials::new("user", "secret")?,
        )
        .await
        .err()
        .ok_or("unusable challenge established a tunnel")?;
        assert_eq!(error.kind(), HttpConnectErrorKind::Authentication);
        assert!(!error.to_string().contains(challenge));
        assert!(!proxy.await??, "unusable challenge triggered a retry");
    }
    Ok(())
}

#[tokio::test]
async fn accepts_token68_padding_and_empty_challenge_list_members() -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let _request = read_head(&mut first).await?;
        first
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Bearer abc==, , Basic realm=\"proxy\", charset=\"UTF\\-8\",\r\n\r\n",
            )
            .await?;
        let (mut second, _) = listener.accept().await?;
        let _request = read_head(&mut second).await?;
        second.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
        Ok::<_, std::io::Error>(())
    });

    let _tunnel = connect_http_tunnel_direct_with_basic_auth(
        "127.0.0.1",
        address.port(),
        "origin.example:443",
        &[
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
        ],
        &HttpBasicCredentials::new("user", "secret")?,
    )
    .await?;
    proxy.await??;
    Ok(())
}

#[tokio::test]
async fn rejects_excessive_authentication_parameters_without_retry() -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let mut challenge = String::from("Basic realm=\"proxy\"");
    for index in 0..64 {
        challenge.push_str(&format!(", p{index}=v"));
    }
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\n\r\n"
    );
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _request = read_head(&mut stream).await?;
        stream.write_all(response.as_bytes()).await?;
        let retried = timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_ok();
        Ok::<_, std::io::Error>(retried)
    });

    let error = connect_http_tunnel_direct_with_basic_auth(
        "127.0.0.1",
        address.port(),
        "origin.example:443",
        &[
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
        ],
        &HttpBasicCredentials::new("user", "secret")?,
    )
    .await
    .err()
    .ok_or("excessive challenge parameters established a tunnel")?;
    assert_eq!(error.kind(), HttpConnectErrorKind::Authentication);
    assert!(
        !proxy.await??,
        "excessive challenge parameters triggered a retry"
    );
    Ok(())
}

#[tokio::test]
async fn placeholder_requires_the_matching_api_before_stream_io() -> TestResult {
    let (client, _proxy) = tokio::io::duplex(1024);
    let error = connect_http_tunnel(
        client,
        "origin.example:443",
        &[
            HttpConnectHeader::authority("Host"),
            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
        ],
    )
    .await
    .err()
    .ok_or("unauthenticated CONNECT accepted an authorization placeholder")?;
    assert!(matches!(
        error,
        HttpConnectError::ProxyAuthorizationPlaceholder
    ));
    Ok(())
}
