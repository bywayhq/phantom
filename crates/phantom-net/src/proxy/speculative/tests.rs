use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::proxy::{HttpBasicCredentials, HttpConnectHeader};
use crate::route::Endpoint;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn request() -> Result<PreparedConnect, HttpConnectError> {
    PreparedConnect::new("origin.test:443", &[HttpConnectHeader::authority("Host")])
}

async fn read_head(peer: &mut tokio::io::DuplexStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(peer.read_u8().await?);
    }
    Ok(head)
}

#[tokio::test]
async fn first_tls_write_arrives_before_proxy_acceptance_despite_partial_writes() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        for capacity in [1, 7, 65536] {
            let (socket, mut peer) = tokio::io::duplex(capacity);
            let mut client = SpeculativeConnect::new(socket, request()?);
            let client_task = async {
                client.write_all(b"client-hello").await?;
                let mut tls = [0; 12];
                client.read_exact(&mut tls).await?;
                assert_eq!(&tls, b"server-hello");
                client.write_all(b"after").await?;
                client.flush().await?;
                io::Result::Ok(())
            };
            let peer_task = async {
                assert_eq!(
                    read_head(&mut peer).await?,
                    b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n"
                );
                let mut hello = [0; 12];
                peer.read_exact(&mut hello).await?;
                assert_eq!(&hello, b"client-hello");
                peer.write_all(
                    b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 201 Created\r\n\r\nserver-hello",
                )
                .await?;
                let mut after = [0; 5];
                peer.read_exact(&mut after).await?;
                assert_eq!(&after, b"after");
                io::Result::Ok(())
            };
            tokio::try_join!(client_task, peer_task)?;
        }
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn large_first_write_is_bounded_and_preserves_all_bytes() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, mut peer) = tokio::io::duplex(7);
        let mut client = SpeculativeConnect::new(socket, request()?);
        let payload = vec![42; FIRST_WRITE_BYTES * 3 + 17];
        let client_task = async {
            let written = client.write(&payload).await?;
            assert_eq!(written, FIRST_WRITE_BYTES);
            assert!(client.outgoing.len() <= MAX_CONNECT_HEAD_BYTES + FIRST_WRITE_BYTES);
            client.write_all(&payload[written..]).await?;
            client.flush().await?;
            io::Result::Ok(())
        };
        let peer_task = async {
            read_head(&mut peer).await?;
            let mut received = vec![0; payload.len()];
            peer.read_exact(&mut received).await?;
            assert_eq!(received, payload);
            io::Result::Ok(())
        };
        tokio::try_join!(client_task, peer_task)?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn failed_responses_close_the_stream_without_exposing_bytes_or_retrying() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let responses = [
            b"HTTP/1.1 407 Auth Required\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec(),
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec(),
            b"invalid response\r\n\r\n".to_vec(),
            vec![b'x'; MAX_CONNECT_HEAD_BYTES],
            b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_INFORMATIONAL_RESPONSES + 1),
        ];
        for (index, response) in responses.into_iter().enumerate() {
            let (socket, mut peer) = tokio::io::duplex(MAX_CONNECT_HEAD_BYTES * 2);
            let mut client = SpeculativeConnect::new(socket, request()?);
            let client_task = async {
                client.write_all(b"hello").await?;
                let mut output = [0; 1];
                let error = client
                    .read(&mut output)
                    .await
                    .err()
                    .ok_or("proxy response exposed")?;
                assert_eq!(output, [0]);
                let source = error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<ProxyFailure>())
                    .ok_or("proxy error type lost")?;
                match index {
                    0..=2 => assert!(matches!(source.0, HttpConnectError::Rejected { .. })),
                    3 => assert!(matches!(source.0, HttpConnectError::InvalidResponse)),
                    4 => assert!(matches!(
                        source.0,
                        HttpConnectError::ResponseHeadTooLarge { .. }
                    )),
                    _ => assert!(matches!(
                        source.0,
                        HttpConnectError::TooManyInformationalResponses { .. }
                    )),
                }
                assert_eq!(
                    client
                        .write(b"again")
                        .await
                        .err()
                        .ok_or("closed stream wrote")?
                        .kind(),
                    io::ErrorKind::BrokenPipe
                );
                TestResult::Ok(())
            };
            let peer_task = async {
                read_head(&mut peer).await?;
                let mut hello = [0; 5];
                peer.read_exact(&mut hello).await?;
                peer.write_all(&response).await?;
                assert_eq!(peer.read(&mut hello).await?, 0);
                TestResult::Ok(())
            };
            tokio::try_join!(client_task, peer_task)?;
        }
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn shutdown_before_dispatch_sends_nothing_and_closes_the_socket() -> TestResult {
    let (socket, mut peer) = tokio::io::duplex(7);
    let mut client = SpeculativeConnect::new(socket, request()?);
    client.shutdown().await?;
    assert_eq!(peer.read(&mut [0]).await?, 0);
    Ok(())
}

#[test]
fn basic_credentials_keep_their_exact_field_position_and_digest_is_rejected() -> TestResult {
    let basic = HttpBasicCredentials::new("user", "secret")?;
    let fields = [
        HttpConnectHeader::proxy_authorization("proxy-authorization"),
        HttpConnectHeader::authority("host"),
    ];
    let route = HttpConnectRoute {
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "127.0.0.1",
            port: 8080,
        }),
        authority: "origin.test:443",
        headers: &fields,
        credentials: Some(HttpProxyAuthentication::Basic(&basic)),
        speculative_tls: true,
    };
    assert_eq!(prepare(route)?.bytes(), b"CONNECT origin.test:443 HTTP/1.1\r\nproxy-authorization: Basic dXNlcjpzZWNyZXQ=\r\nhost: origin.test:443\r\n\r\n");
    let digest = crate::proxy::HttpDigestCredentials::new("user", "secret")?;
    assert!(matches!(
        prepare(HttpConnectRoute {
            credentials: Some(HttpProxyAuthentication::Digest(&digest)),
            ..route
        }),
        Err(HttpConnectError::SpeculativeTlsUnsupported)
    ));
    let debug = format!("{route:?}");
    assert!(!debug.contains("secret"));
    Ok(())
}

#[tokio::test]
async fn a_first_write_after_acceptance_goes_directly_to_the_tunnel() -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (socket, mut peer) = tokio::io::duplex(7);
        let mut client = SpeculativeConnect::new(socket, request()?);
        let caller = async {
            assert_eq!(client.read_u8().await?, 42);
            client.write_all(b"hello").await?;
            io::Result::Ok(())
        };
        let proxy = async {
            read_head(&mut peer).await?;
            peer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n*")
                .await?;
            let mut bytes = [0; 5];
            peer.read_exact(&mut bytes).await?;
            assert_eq!(&bytes, b"hello");
            io::Result::Ok(())
        };
        tokio::try_join!(caller, proxy)?;
        TestResult::Ok(())
    })
    .await?
}
