use std::{error::Error, net::Ipv4Addr, pin::Pin, time::Duration};

use btls::{
    error::ErrLib,
    ssl::{ErrorCode, Ssl, SslAcceptor},
};
use phantom::{HttpProtocol, HttpProxy, RequestErrorKind, Route};
use phantom_net::{TlsError, TlsErrorKind};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};
use tokio_btls::SslStream;

use crate::support::{
    tls::{H1_ALPN, TestIdentity},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{TestResult, browsers, head_names, open_tunnel, profile_client, read_head};

const DEADLINE: Duration = Duration::from_secs(5);
// Pinned btls-sys 0.5.6 BoringSSL err.h/ssl.h: library-scoped SSL reasons.
const SSL_LIBRARY: ErrLib = ErrLib(16);
const CERTIFICATE_VERIFY_FAILED: i32 = 125;
const TLS_ALERT_UNKNOWN_CA: i32 = 1048;

fn source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }

        error = error.source()?;
    }
}

fn assert_ssl_reason(error: &btls::ssl::Error, reason: i32) -> TestResult<()> {
    assert_eq!(error.code(), ErrorCode::SSL);
    assert!(error.io_error().is_none());

    let stack = error.ssl_error().ok_or("TLS failure lost its SSL stack")?;
    assert!(
        stack
            .errors()
            .iter()
            .any(|error| error.library_reason(SSL_LIBRARY) == Some(reason))
    );
    Ok(())
}

async fn present_untrusted_origin(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<Vec<String>> {
    let mut heads = Vec::new();
    for _ in 0..2 {
        let (mut tcp, _) = listener.accept().await?;
        heads.push(String::from_utf8(read_head(&mut tcp).await?)?);
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let ssl = Ssl::new(acceptor.context())?;
        let mut stream = SslStream::new(ssl, tcp)?;
        let failure = Pin::new(&mut stream)
            .accept()
            .await
            .err()
            .ok_or("client unexpectedly trusted the generated origin certificate")?;
        // An actual client trust rejection must reach the server as this alert.
        assert_ssl_reason(&failure, TLS_ALERT_UNKNOWN_CA)?;
    }

    Ok(heads)
}

#[tokio::test]
async fn an_untrusted_origin_certificate_is_not_a_recording_peer_close() -> TestResult<()> {
    let browser = browsers().swap_remove(0);
    let identity = TestIdentity::generate_for_dns("origin.phantom.test")?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?;
    // The generated root is deliberately absent from this real client's trust store.
    let client = profile_client(&browser, Route::http_proxy(proxy))?;
    let mut server = ConnectionPeer::spawn(present_untrusted_origin(listener, acceptor));

    let operation: TestResult<_> = async {
        let failure = timeout(
            DEADLINE,
            client
                .get(HttpProtocol::Http1, "https://origin.phantom.test/page")?
                .send(),
        )
        .await?
        .err()
        .ok_or("client unexpectedly served the untrusted origin")?;
        assert_eq!(failure.kind(), RequestErrorKind::Tls);
        let tls = source::<TlsError>(&failure).ok_or("request lost its typed TLS failure")?;
        assert_eq!(tls.kind(), TlsErrorKind::Handshake);
        let backend =
            source::<btls::ssl::Error>(&failure).ok_or("request lost its backend TLS failure")?;
        assert_ssl_reason(backend, CERTIFICATE_VERIFY_FAILED)?;

        let helper_result = timeout(DEADLINE, open_tunnel(&client, &browser, Vec::new())).await?;
        Ok(helper_result)
    }
    .await;

    let observations: TestResult<Vec<String>> = match timeout(DEADLINE, &mut server).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(error) => finish_with_cleanup(Err(error.into()), server.stop().await),
    };
    // Keep the client alive until both ordinary completion and bounded fallback cleanup.
    let (helper_result, observations) = match (operation, observations) {
        (Ok(result), Ok(observed)) => (result, observed),
        (Err(primary), Err(cleanup)) => return finish_with_cleanup(Err(primary), Err(cleanup)),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
    };
    drop(client);

    assert_eq!(observations.len(), 2);
    for head in observations {
        let (line, _) = head_names(&head)?;
        assert_eq!(line, "CONNECT origin.phantom.test:443 HTTP/1.1");
        assert!(head.contains("\r\nHost: origin.phantom.test:443\r\n"));
    }
    let failure = helper_result
        .err()
        .ok_or("untrusted origin certificate was discarded as a recording peer close")?;
    let backend = source::<btls::ssl::Error>(failure.as_ref())
        .ok_or("helper lost its typed backend TLS failure")?;
    assert_ssl_reason(backend, CERTIFICATE_VERIFY_FAILED)
}
