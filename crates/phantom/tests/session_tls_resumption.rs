//! Public TLS 1.3 session-resumption integration tests.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use btls::ssl::{ExtensionType, SelectCertError, Ssl, SslAcceptor, SslVersion};
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol,
    profile::{CipherSuite, ClientProfile, NamedGroup, TlsVersion, chromium},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, H2_ALPN, TestIdentity};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn tls13_resumption_is_scoped_to_one_session() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let early_data_hellos = Arc::new(AtomicUsize::new(0));
        let acceptor = tls13_acceptor(&identity, early_data_hellos.clone())?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept_tls(&listener, &acceptor).await?;
            assert_tls(first.ssl(), SslVersion::TLS1_3, b"h2", false);
            serve_one(first, "/").await?;
            first_closed
                .send(())
                .map_err(|_| "client stopped before the first connection closed")?;

            let second = accept_tls(&listener, &acceptor).await?;
            assert_tls(second.ssl(), SslVersion::TLS1_3, b"h2", true);
            serve_one(second, "/.well-known/phantom/resume").await?;

            let isolated = accept_tls(&listener, &acceptor).await?;
            assert_tls(isolated.ssl(), SslVersion::TLS1_3, b"h2", false);
            serve_one(isolated, "/isolated").await
        });

        let client = tls13_client(&identity)?;
        let session = client.session();
        send(&session, HttpProtocol::Http2, format!("https://{address}/")).await?;
        if wait_for_first_close.await.is_err() {
            server.await??;
            return Err("server stopped before closing the first connection".into());
        }
        send(
            &session,
            HttpProtocol::Http2,
            format!("https://{address}/.well-known/phantom/resume"),
        )
        .await?;
        drop(session);
        send(
            &client.session(),
            HttpProtocol::Http2,
            format!("https://{address}/isolated"),
        )
        .await?;

        server.await??;
        assert_eq!(
            early_data_hellos.load(Ordering::SeqCst),
            0,
            "client attempted TLS early data"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn tls12_resumption_survives_http1_connection_close() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = tls12_acceptor(&identity)?;
        let server = tokio::spawn(async move {
            let first = accept_tls(&listener, &acceptor).await?;
            assert_tls(first.ssl(), SslVersion::TLS1_2, b"http/1.1", false);
            serve_http1(first, "/").await?;

            let second = accept_tls(&listener, &acceptor).await?;
            assert_tls(second.ssl(), SslVersion::TLS1_2, b"http/1.1", true);
            serve_http1(second, "/resumed").await?;

            let isolated = accept_tls(&listener, &acceptor).await?;
            assert_tls(isolated.ssl(), SslVersion::TLS1_2, b"http/1.1", false);
            serve_http1(isolated, "/isolated").await
        });

        let client = tls_support::test_client(&identity, false)?;
        let session = client.session();
        send(&session, HttpProtocol::Http1, format!("https://{address}/")).await?;
        send(
            &session,
            HttpProtocol::Http1,
            format!("https://{address}/resumed"),
        )
        .await?;
        drop(session);
        send(
            &client.session(),
            HttpProtocol::Http1,
            format!("https://{address}/isolated"),
        )
        .await?;

        server.await??;
        Ok(())
    })
    .await
}

fn tls13_acceptor(
    identity: &TestIdentity,
    early_data_hellos: Arc<AtomicUsize>,
) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_select_certificate_callback(move |hello| {
        if hello.get_extension(ExtensionType::EARLY_DATA).is_some() {
            early_data_hellos.fetch_add(1, Ordering::SeqCst);
        }
        Ok::<_, SelectCertError>(())
    });
    Ok(acceptor.build())
}

fn tls12_acceptor(identity: &TestIdentity) -> TestResult<SslAcceptor> {
    let mut acceptor = identity.acceptor_builder(H1_ALPN)?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    Ok(acceptor.build())
}

fn tls13_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tls = tls_support::tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    tls.groups = vec![NamedGroup::X25519];
    tls.key_shares = vec![NamedGroup::X25519];
    let profile = ClientProfile::new(tls).with_http2(chromium::v154_http2());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

fn assert_tls(ssl: &btls::ssl::SslRef, version: SslVersion, alpn: &[u8], resumed: bool) {
    assert_eq!(ssl.version2(), Some(version));
    assert_eq!(ssl.selected_alpn_protocol(), Some(alpn));
    assert_eq!(ssl.session_reused(), resumed);
}

async fn serve_one(stream: SslStream<TcpStream>, expected_path: &str) -> TestResult<()> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), expected_path);
    respond.send_response(Response::builder().status(StatusCode::OK).body(())?, true)?;
    connection.graceful_shutdown();
    match poll_fn(|context| connection.poll_closed(context)).await {
        Ok(()) => Ok(()),
        // The client may close its socket after reading GOAWAY but before the
        // shutdown PING is acknowledged; that teardown is not under test.
        Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn serve_http1(mut stream: SslStream<TcpStream>, expected_path: &str) -> TestResult<()> {
    let head = tls_support::read_head(&mut stream).await?;
    let expected = format!("GET {expected_path} HTTP/1.1\r\n");
    assert!(head.starts_with(expected.as_bytes()));
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    Ok(())
}

async fn send(session: &phantom::Session, protocol: HttpProtocol, uri: String) -> TestResult<()> {
    let response = session.get(protocol, &uri)?.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

async fn bounded<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await?
}
