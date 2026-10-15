//! In-future outer TLS, CONNECT and separate inner TLS; no spawned peer tasks.
use super::{Auth, TestResult};
use btls::ssl::{Ssl, SslAcceptor};
use std::pin::Pin;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_btls::SslStream;

pub(super) async fn serve(stream: TcpStream, acceptor: SslAcceptor, auth: Auth) -> TestResult {
    let mut outer = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut outer).accept().await?;
    assert_eq!(
        super::super::peer::head(&mut outer).await?,
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\n\r\n"
    );
    if !matches!(auth, Auth::None) {
        let challenge = match auth {
            Auth::Basic => "Basic realm=\"proxy\"",
            Auth::Digest => {
                "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\""
            }
            Auth::None => return Err("anonymous exchange challenged".into()),
        };
        outer.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
        let retry = String::from_utf8(super::super::peer::head(&mut outer).await?)?;
        assert!(retry.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\nProxy-Authorization: "));
        match auth {
            Auth::Basic => assert!(retry.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
            Auth::Digest => {
                assert!(retry.contains("nc=00000001"));
                assert!(retry.contains("uri=\"127.0.0.1:443\""));
            }
            Auth::None => return Err("anonymous replay".into()),
        }
    }
    outer
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let mut inner = SslStream::new(Ssl::new(acceptor.context())?, outer)?;
    Pin::new(&mut inner).accept().await?;
    assert_eq!(
        super::super::peer::head(&mut inner).await?,
        b"GET /claimed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    );
    inner
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    Ok(())
}
