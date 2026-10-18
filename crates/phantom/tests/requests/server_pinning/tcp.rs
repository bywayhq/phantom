use std::net::Ipv4Addr;

use phantom::{HttpProtocol, RequestErrorKind};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::*;
use crate::support::{
    h2,
    tls::{H1_ALPN, H2_ALPN, accept_tls, accept_tls_stream, read_head},
    tunnel_proxy::finish_with_cleanup,
};

#[tokio::test]
async fn pins_survive_pool_reuse_and_refresh_with_resumption() -> TestResult<()> {
    for (protocol, negotiated) in [
        (HttpProtocol::Http1, false),
        (HttpProtocol::Http2, false),
        (HttpProtocol::Http2, true),
    ] {
        timeout(DEADLINE, async {
            let identity = TestIdentity::generate()?;
            let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 {
                H1_ALPN
            } else {
                H2_ALPN
            })?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let valid = pins(&identity)?;
            let mut rotation = valid.sha256_digests().to_vec();
            rotation.push([0; 32]);
            let client = builder(&identity)
                .server_spki_pins(ServerSpkiPins::new(rotation)?)
                .build()?;
            let peer = async {
                for connection in 0..2 {
                    let (socket, _) = listener.accept().await?;
                    let mut socket = accept_tls_stream(socket, acceptor.clone()).await?;
                    assert_eq!(socket.ssl().session_reused(), connection != 0);
                    let http2 = protocol == HttpProtocol::Http2;
                    if http2 {
                        h2::accept_client_preface(&mut socket).await?;
                    }
                    for index in 0..if connection == 0 { 2 } else { 1 } {
                        if http2 {
                            let stream = 1 + index * 2;
                            h2::read_request_headers(&mut socket, stream).await?;
                            h2::write_frame(&mut socket, 1, 5, stream, &[0x88]).await?;
                        } else {
                            read_head(&mut socket).await?;
                            socket
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                .await?;
                        }
                        socket.flush().await?;
                    }
                }
                Ok(())
            };
            let caller = async {
                for index in 0..3 {
                    if index == 2 {
                        client.refresh_connections();
                    }
                    let clone = client.clone();
                    let url = format!("https://{address}/");
                    let request = if negotiated {
                        clone.get_negotiated(&url)?
                    } else {
                        clone.get(protocol, &url)?
                    };
                    let response = request.send().await?;
                    assert_eq!(response.status(), 200);
                    response.into_body().collect_with_limit(0).await?;
                }
                Ok(())
            };
            let (caller, peer) = tokio::join!(caller, peer);
            finish_with_cleanup(caller, peer)
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn wrong_pin_is_typed_and_sends_no_origin_http() -> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        timeout(DEADLINE, async {
            let identity = TestIdentity::generate()?;
            let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 {
                H1_ALPN
            } else {
                H2_ALPN
            })?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let client = builder(&identity)
                .server_spki_pins(ServerSpkiPins::new(vec![[0; 32]])?)
                .build()?;
            let peer = async {
                match accept_tls(listener, acceptor).await {
                    Err(_) => Ok(()),
                    Ok(_) => Err("a wrong-pin handshake completed at the origin".into()),
                }
            };
            let caller = async {
                let error = client
                    .get(protocol, &format!("https://{address}/"))?
                    .send()
                    .await
                    .err()
                    .ok_or("wrong pin was accepted")?;
                assert_eq!(error.kind(), RequestErrorKind::Tls);
                assert_eq!(tls_error(&error)?, TlsErrorKind::SpkiPinMismatch);
                Ok(())
            };
            let (caller, peer) = tokio::join!(caller, peer);
            finish_with_cleanup(caller, peer)
        })
        .await??;
    }
    Ok(())
}
