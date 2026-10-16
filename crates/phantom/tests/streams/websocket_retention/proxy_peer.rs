//! Caller-owned CONNECT peers; no peer task outlives its bounded control.
use super::proxy::{Auth, Claim};
use crate::support::{
    tls::{TestResult, accept_tls_stream, is_peer_gone, read_head},
    websocket::{append_and_write_server_frame, header_value, read_client_frame, websocket_accept},
};
use btls::ssl::{Ssl, SslAcceptor};
use phantom_net::route::ConnectedStream;
use std::{pin::Pin, task::Poll};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

pub(super) async fn outer(
    tcp: TcpStream,
    https: bool,
    acceptor: SslAcceptor,
) -> TestResult<ConnectedStream> {
    Ok(if https {
        ConnectedStream::new(accept_tls_stream(tcp, acceptor).await?)
    } else {
        ConnectedStream::new(tcp)
    })
}

pub(super) async fn quiet(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    let mut read = Box::pin(stream.read(&mut byte));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await,
        "unclaimed backup sent CONNECT/inner TLS or closed"
    );
    Ok(())
}

pub(super) async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if is_peer_gone(&error) => Ok(()),
        Ok(_) => Err("cancelled opening sent an application byte".into()),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn claim(
    mut stream: ConnectedStream,
    acceptor: SslAcceptor,
    auth: Auth,
    kind: Claim,
) -> TestResult<()> {
    let current =
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\n\r\n";
    assert_eq!(read_head(&mut stream).await?, current);
    let challenge = match auth {
        Auth::Basic => "Basic realm=\"proxy\"",
        Auth::Digest => "Digest realm=\"proxy\", nonce=\"claim\", algorithm=SHA-256, qop=\"auth\"",
    };
    stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
    let replay = String::from_utf8(read_head(&mut stream).await?)?;
    assert!(replay.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\nProxy-Authorization: "));
    match auth {
        Auth::Basic => assert!(replay.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
        Auth::Digest => {
            assert!(replay.contains("Digest "));
            assert!(replay.contains("nonce=\"claim\""));
            assert!(replay.contains("nc=00000001"));
        }
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let mut tls = tokio_btls::SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut tls).accept().await?;
    assert_eq!(tls.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
    let head = read_head(&mut tls).await?;
    assert_eq!(header_value(&head, "x-claim"), Some("second"));
    assert!(
        !head
            .windows(b"Proxy-Authorization".len())
            .any(|part| part == b"Proxy-Authorization")
    );
    match kind {
        Claim::Ordinary => {
            assert!(head.starts_with(b"GET /page HTTP/1.1\r\n"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone")
                .await?;
        }
        Claim::Upgrade | Claim::Rejected => {
            assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
            #[cfg(feature = "cookies")]
            assert_eq!(header_value(&head, "cookie"), Some("current=2"));
            if matches!(kind, Claim::Rejected) {
                tls.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nSet-Cookie: result=3; Path=/\r\nConnection: close\r\n\r\ndenied").await?;
            } else {
                let key = header_value(&head, "sec-websocket-key")
                    .ok_or("missing current WebSocket key")?;
                let accept = websocket_accept(key);
                tls.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
                let frame = read_client_frame(&mut tls).await?;
                assert_eq!(frame.opcode, 2);
                assert_eq!(frame.payload, b"client");
                append_and_write_server_frame(&mut tls, true, 2, b"peer").await?;
            }
        }
    }
    tls.flush().await?;
    // A retry/replay of the GET is an unexpected application byte here.
    closed(&mut tls).await?;
    Ok(())
}
