//! Peers own their streams directly; no spawned task can outlive a control.
use super::Auth;
use crate::support::{
    h2::{accept_client_preface, read_request_headers, write_frame},
    tls::{TestResult, accept_tls_stream, read_head},
};
use btls::ssl::{Ssl, SslAcceptor};
use phantom_net::route::ConnectedStream;
use std::{io, pin::Pin};
use tokio::{
    io::{AsyncRead, AsyncWriteExt as _},
    net::TcpStream,
};

pub(super) async fn head(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    read_head(stream).await
}

pub(super) async fn proxy_stream(
    stream: TcpStream,
    https: bool,
    acceptor: SslAcceptor,
) -> TestResult<ConnectedStream> {
    Ok(if https {
        ConnectedStream::new(accept_tls_stream(stream, acceptor).await?)
    } else {
        ConnectedStream::new(stream)
    })
}

pub(super) async fn serve(
    mut stream: ConnectedStream,
    acceptor: SslAcceptor,
    h2: bool,
    auth: Auth,
) -> TestResult<()> {
    assert_eq!(
        head(&mut stream).await?,
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\n\r\n"
    );
    let challenge = match auth {
        Auth::Basic => "Basic realm=\"proxy\"",
        Auth::Digest => "Digest realm=\"proxy\", nonce=\"claim\", algorithm=SHA-256, qop=\"auth\"",
    };
    stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
    let authenticated = String::from_utf8(head(&mut stream).await?)?;
    assert!(authenticated.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\nProxy-Authorization: "));
    match auth {
        Auth::Basic => assert!(authenticated.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
        Auth::Digest => {
            assert!(authenticated.contains("Digest "));
            assert!(authenticated.contains("nonce=\"claim\""));
            assert!(authenticated.contains("nc=00000001"));
        }
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let mut tls = tokio_btls::SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut tls).accept().await?;
    if h2 {
        accept_client_preface(&mut tls).await?;
        read_request_headers(&mut tls, 3).await?;
        write_frame(&mut tls, 0x1, 0x4, 3, &[0x88]).await?;
        write_frame(&mut tls, 0x0, 0x1, 3, b"ok").await?;
        tls.flush().await?;
    } else {
        assert_eq!(
            read_head(&mut tls).await?,
            b"GET /claimed HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Claim: second\r\n\r\n"
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
    }
    Ok(())
}
