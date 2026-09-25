//! Replay of a challenged CONNECT on the connection that carried the `407`.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{TestResult, read_head};
use crate::{
    proxy::{
        HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, MAX_CHALLENGE_BODY_BYTES,
        ProxyCredentialCache, ProxyScheme,
        challenged_connection::{ChallengeBody, drain},
        connect_http_tunnel_direct_with_basic_auth, http_connect_tunnel_with_basic_auth,
    },
    request::RequestHeader,
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestServerAlpn, accept_tls, loopback_listener,
    },
};

const CHALLENGE_HEAD: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"proxy\"\r\n";
const ANONYMOUS: &[u8] = b"CONNECT origin.example:443 HTTP/1.1\r\n\
    Host: origin.example:443\r\n\
    User-Agent: fixture\r\n\r\n";
const AUTHENTICATED: &[u8] = b"CONNECT origin.example:443 HTTP/1.1\r\n\
    Host: origin.example:443\r\n\
    User-Agent: fixture\r\n\
    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// How long a test waits for a connection that must not arrive.
const NO_CONNECTION: Duration = Duration::from_millis(200);

fn connect_fields() -> [HttpConnectHeader; 3] {
    [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::field(RequestHeader::new("User-Agent", "fixture")),
        HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
    ]
}

fn challenge(fields_and_body: &[u8]) -> Vec<u8> {
    [CHALLENGE_HEAD, fields_and_body].concat()
}

/// Opens a tunnel through a plaintext proxy on loopback that answers the
/// first CONNECT with `response`, and returns the proxy connections' request
/// bytes in accept order.
async fn exchange_with(response: Vec<u8>) -> TestResult<Vec<Vec<u8>>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let mut first_bytes = read_head(&mut first).await?;
        first.write_all(&response).await?;
        first.flush().await?;
        // The replay either arrives on this connection or on a new one.
        let next = tokio::select! {
            head = read_head(&mut first) => head.ok(),
            accepted = listener.accept() => {
                let (second, _) = accepted?;
                return replay_on(second, vec![first_bytes], &listener).await;
            }
        };
        if let Some(head) = next {
            first_bytes.extend_from_slice(&head);
            return finish(vec![first_bytes], first, &listener).await;
        }
        let (second, _) = listener.accept().await?;
        replay_on(second, vec![first_bytes], &listener).await
    });

    let credentials = HttpBasicCredentials::new("user", "secret")?;
    let mut tunnel = timeout(
        TEST_TIMEOUT,
        connect_http_tunnel_direct_with_basic_auth(
            "127.0.0.1",
            address.port(),
            "origin.example:443",
            &connect_fields(),
            &credentials,
        ),
    )
    .await??;
    let mut prefix = [0_u8; 6];
    tunnel.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"tunnel");
    timeout(TEST_TIMEOUT, proxy).await??
}

/// Reads the replay from a second connection and accepts the tunnel on it.
async fn replay_on(
    mut stream: TcpStream,
    mut connections: Vec<Vec<u8>>,
    listener: &TcpListener,
) -> TestResult<Vec<Vec<u8>>> {
    connections.push(read_head(&mut stream).await?);
    finish(connections, stream, listener).await
}

/// Accepts the tunnel on `stream` and checks that no further connection
/// arrives.
async fn finish(
    connections: Vec<Vec<u8>>,
    mut stream: TcpStream,
    listener: &TcpListener,
) -> TestResult<Vec<Vec<u8>>> {
    stream.write_all(ESTABLISHED).await?;
    stream.write_all(b"tunnel").await?;
    stream.flush().await?;
    assert!(
        timeout(NO_CONNECTION, listener.accept()).await.is_err(),
        "the client opened an unexpected proxy connection"
    );
    Ok(connections)
}

#[tokio::test]
async fn keep_alive_challenge_replays_on_the_same_connection() -> TestResult {
    for fields_and_body in [
        &b"Content-Length: 0\r\n\r\n"[..],
        b"Content-Length: 13\r\nContent-Type: text/plain\r\n\r\ndenied, retry",
        b"Proxy-Connection: keep-alive\r\nContent-Length: 2\r\n\r\nno",
        b"Transfer-Encoding: chunked\r\n\r\n5;note=x\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n",
    ] {
        let connections = exchange_with(challenge(fields_and_body)).await?;
        assert_eq!(connections, [[ANONYMOUS, AUTHENTICATED].concat()]);
    }
    Ok(())
}

#[tokio::test]
async fn http10_challenge_reuses_the_connection_only_with_keep_alive() -> TestResult {
    let keep_alive = b"HTTP/1.0 407 Proxy Authentication Required\r\n\
        Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
        Proxy-Connection: keep-alive\r\n\
        Content-Length: 0\r\n\r\n";
    let connections = exchange_with(keep_alive.to_vec()).await?;
    assert_eq!(connections, [[ANONYMOUS, AUTHENTICATED].concat()]);

    let default = b"HTTP/1.0 407 Proxy Authentication Required\r\n\
        Proxy-Authenticate: Basic realm=\"proxy\"\r\n\
        Content-Length: 0\r\n\r\n";
    let connections = exchange_with(default.to_vec()).await?;
    assert_eq!(connections, [ANONYMOUS, AUTHENTICATED]);
    Ok(())
}

#[tokio::test]
async fn closing_or_unframed_challenge_replays_on_a_new_connection() -> TestResult {
    let oversized = format!("Content-Length: {}\r\n\r\n", MAX_CHALLENGE_BODY_BYTES + 1);
    for fields_and_body in [
        &b"Connection: close\r\nContent-Length: 0\r\n\r\n"[..],
        b"Proxy-Connection: close\r\nContent-Length: 0\r\n\r\n",
        b"Connection: keep-alive, close\r\nContent-Length: 0\r\n\r\n",
        // Delimited by the connection close.
        b"\r\n",
        b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nx",
        b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
        b"Transfer-Encoding: gzip\r\n\r\n",
        b"Transfer-Encoding: chunked\r\n\r\nzz\r\n",
        // Bytes the replay did not ask for follow the body.
        b"Content-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        oversized.as_bytes(),
    ] {
        let connections = exchange_with(challenge(fields_and_body)).await?;
        assert_eq!(
            connections,
            [ANONYMOUS, AUTHENTICATED],
            "{}",
            String::from_utf8_lossy(fields_and_body)
        );
    }
    Ok(())
}

#[tokio::test]
async fn challenge_body_over_the_bound_replays_on_a_new_connection() -> TestResult {
    let body = vec![b'x'; MAX_CHALLENGE_BODY_BYTES + 1];
    let mut chunked = b"Transfer-Encoding: chunked\r\n\r\n".to_vec();
    for piece in body.chunks(4096) {
        chunked.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        chunked.extend_from_slice(piece);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let connections = exchange_with(challenge(&chunked)).await?;
    assert_eq!(connections, [ANONYMOUS, AUTHENTICATED]);

    // A body exactly at the bound keeps the connection.
    let mut at_bound = format!("Content-Length: {MAX_CHALLENGE_BODY_BYTES}\r\n\r\n").into_bytes();
    at_bound.resize(at_bound.len() + MAX_CHALLENGE_BODY_BYTES, b'x');
    let connections = exchange_with(challenge(&at_bound)).await?;
    assert_eq!(connections, [[ANONYMOUS, AUTHENTICATED].concat()]);
    Ok(())
}

#[tokio::test]
async fn proxy_that_closes_the_challenged_connection_gets_the_replay_on_a_new_one() -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let anonymous = read_head(&mut first).await?;
        // A keep-alive 407, then a close after the replay arrives.
        first
            .write_all(&challenge(b"Content-Length: 0\r\n\r\n"))
            .await?;
        first.flush().await?;
        let replay_on_first = read_head(&mut first).await?;
        drop(first);
        let (mut second, _) = listener.accept().await?;
        let authenticated = read_head(&mut second).await?;
        second.write_all(ESTABLISHED).await?;
        second.write_all(b"tunnel").await?;
        let third = timeout(NO_CONNECTION, listener.accept()).await.is_ok();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
            anonymous,
            replay_on_first,
            authenticated,
            third,
        ))
    });

    let credentials = HttpBasicCredentials::new("user", "secret")?;
    let mut tunnel = timeout(
        TEST_TIMEOUT,
        connect_http_tunnel_direct_with_basic_auth(
            "127.0.0.1",
            address.port(),
            "origin.example:443",
            &connect_fields(),
            &credentials,
        ),
    )
    .await??;
    let mut prefix = [0_u8; 6];
    tunnel.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"tunnel");
    let (anonymous, replay_on_first, authenticated, third) =
        timeout(TEST_TIMEOUT, proxy).await???;
    assert_eq!(anonymous, ANONYMOUS);
    assert_eq!(replay_on_first, AUTHENTICATED);
    assert_eq!(authenticated, AUTHENTICATED);
    assert!(!third, "the client opened a third proxy connection");
    Ok(())
}

#[tokio::test]
async fn tls_proxy_replays_on_the_challenged_connection() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = HttpsProxyConnector::new_with_additional_roots(
            &super::https_connect::tls_settings(),
            [identity.root_der()],
        )?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = accept_tls(listener, acceptor).await?;
            let anonymous = read_head(&mut stream).await?;
            stream
                .write_all(&challenge(b"Content-Length: 4\r\n\r\nnope"))
                .await?;
            stream.flush().await?;
            let authenticated = read_head(&mut stream).await?;
            stream.write_all(ESTABLISHED).await?;
            stream.write_all(b"tunnel").await?;
            stream.flush().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((anonymous, authenticated))
        });

        let credentials = HttpBasicCredentials::new("user", "secret")?;
        let mut tunnel = connector
            .connect_tunnel_with_basic_auth(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                "origin.example:443",
                &connect_fields(),
                &credentials,
            )
            .await?;
        let mut prefix = [0_u8; 6];
        tunnel.read_exact(&mut prefix).await?;
        assert_eq!(&prefix, b"tunnel");
        // `accept_tls` took the listener, so the replay reaching this task
        // proves it used the TLS connection that carried the challenge.
        let (anonymous, authenticated) = proxy_task.await??;
        assert_eq!(anonymous, ANONYMOUS);
        assert_eq!(authenticated, AUTHENTICATED);
        Ok(())
    })
    .await
    .map_err(|_| "TLS proxy reuse test exceeded its deadline")?
}

#[test]
fn keep_alive_follows_both_connection_fields_and_the_version() {
    fn body(version: u8, fields: &[(&str, &str)]) -> Option<ChallengeBody> {
        let headers: Vec<_> = fields
            .iter()
            .map(|(name, value)| httparse::Header {
                name,
                value: value.as_bytes(),
            })
            .collect();
        ChallengeBody::from_head(version, &headers)
    }

    assert_eq!(
        body(1, &[("Content-Length", "7")]),
        Some(ChallengeBody::Length(7))
    );
    assert_eq!(
        body(1, &[("content-length", "7"), ("Content-Length", " 7 ")]),
        Some(ChallengeBody::Length(7))
    );
    assert_eq!(
        body(1, &[("Transfer-Encoding", "gzip, chunked")]),
        Some(ChallengeBody::Chunked)
    );
    assert_eq!(
        body(0, &[("Connection", "Keep-Alive"), ("Content-Length", "0")]),
        Some(ChallengeBody::Length(0))
    );
    for (version, fields) in [
        (1, &[("Connection", "Close"), ("Content-Length", "0")][..]),
        (1, &[("Proxy-Connection", "close"), ("Content-Length", "0")]),
        (
            1,
            &[
                ("Connection", "keep-alive"),
                ("Proxy-Connection", "close"),
                ("Content-Length", "0"),
            ],
        ),
        (0, &[("Content-Length", "0")]),
        (1, &[("Content-Length", "-1")]),
        (1, &[("Content-Length", "")]),
        (1, &[("Content-Length", "+1")]),
        (1, &[]),
    ] {
        assert_eq!(body(version, fields), None, "{fields:?}");
    }
}

#[tokio::test]
async fn drain_reads_split_chunked_bodies_and_stops_at_their_end() -> TestResult {
    let body = b"3\r\nabc\r\nA\r\n0123456789\r\n0\r\n\r\n";
    for split in 0..=body.len() {
        let (mut client, mut proxy) = duplex(1024);
        proxy.write_all(&body[split..]).await?;
        assert!(
            drain(&mut client, ChallengeBody::Chunked, &body[..split]).await,
            "split at {split}"
        );
    }

    // Stops at the end of the body even while the proxy keeps writing.
    let (mut client, mut proxy) = duplex(1024);
    proxy.write_all(b"0\r\n\r\n").await?;
    assert!(drain(&mut client, ChallengeBody::Chunked, b"2\r\nok\r\n").await);

    // A body that ends early, or a malformed line, leaves nothing to reuse.
    let (mut client, proxy) = duplex(1024);
    drop(proxy);
    assert!(!drain(&mut client, ChallengeBody::Length(3), b"ab").await);
    let (mut client, _proxy) = duplex(1024);
    assert!(!drain(&mut client, ChallengeBody::Chunked, b"3\nabc\r\n").await);
    let (mut client, _proxy) = duplex(1024);
    assert!(
        !drain(
            &mut client,
            ChallengeBody::Chunked,
            b"11111111111111111\r\n"
        )
        .await
    );
    Ok(())
}

#[tokio::test]
async fn replay_on_the_challenged_connection_is_remembered_by_the_credential_record() -> TestResult
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let proxy = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let mut heads = vec![read_head(&mut first).await?];
        first
            .write_all(&challenge(b"Content-Length: 0\r\n\r\n"))
            .await?;
        heads.push(read_head(&mut first).await?);
        first.write_all(ESTABLISHED).await?;
        let (mut second, _) = listener.accept().await?;
        heads.push(read_head(&mut second).await?);
        second.write_all(ESTABLISHED).await?;
        let third = timeout(NO_CONNECTION, listener.accept()).await.is_ok();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((heads, third, first, second))
    });

    let cache = ProxyCredentialCache::new();
    let credentials = HttpBasicCredentials::new("user", "secret")?;
    for _ in 0..2 {
        timeout(
            TEST_TIMEOUT,
            http_connect_tunnel_with_basic_auth(
                crate::direct::Dialer::default(),
                Some(&cache),
                "127.0.0.1",
                address.port(),
                "origin.example:443",
                &connect_fields(),
                &credentials,
            ),
        )
        .await??;
    }
    let (heads, third, _first, _second) = timeout(TEST_TIMEOUT, proxy).await???;
    // One challenge and its replay on the first connection, then a tunnel
    // that carries the credentials first on the second.
    assert_eq!(heads, [ANONYMOUS, AUTHENTICATED, AUTHENTICATED]);
    assert!(!third, "the client opened a third proxy connection");
    assert!(cache.contains(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials));
    Ok(())
}
