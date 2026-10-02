//! A negotiated request leased onto a connection whose TLS early data the
//! server already rejected under another ALPN protocol.

use std::{
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::{
    pkey::PKey,
    ssl::{
        AlpnError, ExtensionType, SelectCertError, Ssl, SslAcceptor, SslMethod, select_next_proto,
    },
    x509::X509,
};
use http::{Method, StatusCode};
use phantom_net::{http1_or_2::Http1Or2TlsConnector, request::OriginForm};
use phantom_profile::firefox;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;
use tracing::Span;

use super::super::{EarlyDataConnection, Http1Or2Pool, NegotiatedLease, validate_request};
use super::{TestResult, bound};
use crate::{
    RequestTimeouts, RetryPolicy, Route, authority::Endpoint, retry::ConnectionSetupRetryState,
    timeout::TimeoutBudget,
};

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HTTP1: &[u8] = b"\x08http/1.1";
const H2: &[u8] = b"\x02h2";

/// The second connection resumes an `http/1.1` ticket, and the server rejects
/// its early data and selects `h2`. The lease is dispatched only once that is
/// settled, so the pool must still restart the request on a full handshake.
#[tokio::test]
async fn a_lease_whose_alpn_change_settled_before_dispatch_restarts() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let (root, acceptor, offers) = server_identity()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            serve_http1(accept(&listener, &acceptor).await?).await?;
            // The client leaves this connection without a request.
            let mut rejected = accept(&listener, &acceptor).await?;
            let mut unprocessed = Vec::new();
            let _ = rejected.read_to_end(&mut unprocessed).await;
            let restarted = accept(&listener, &acceptor).await?;
            let resumed = restarted.ssl().session_reused();
            let head = serve_http1(restarted).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((unprocessed, resumed, head))
        });

        let connector = Http1Or2TlsConnector::new_with_additional_roots(
            &firefox::v156_tls(),
            &firefox::v156_http2(),
            [root.as_slice()],
        )?;
        let pool = Http1Or2Pool::new(
            bound(4)?,
            bound(4)?,
            bound(4)?,
            bound(4)?,
            bound(4)?,
            bound(4)?,
        );
        let endpoint = Endpoint::new(format!("127.0.0.1:{port}").parse()?, 443)?;
        let budget = TimeoutBudget::new(RequestTimeouts::new())?;
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), Span::none());

        send(
            &pool,
            &connector,
            &endpoint,
            "/",
            None,
            budget,
            &mut retries,
        )
        .await?;
        let lease = pool
            .acquire_lease(
                &connector,
                None,
                &endpoint,
                &Route::Direct,
                &Span::none(),
                budget,
                &mut retries,
            )
            .await?;
        // Let the server's answer reach the connection before dispatch.
        let early_data = EarlyDataConnection::of(&lease.lease);
        early_data.answered().await;
        assert!(early_data.alpn_changed());
        send(
            &pool,
            &connector,
            &endpoint,
            "/restarted",
            Some(lease),
            budget,
            &mut retries,
        )
        .await?;

        let (unprocessed, resumed, head) = server.await?.map_err(|error| error.to_string())?;
        assert!(unprocessed.is_empty());
        assert!(!resumed);
        assert!(head.starts_with(b"GET /restarted HTTP/1.1\r\n"));
        let offers = offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(offers, [false, true, false]);
        Ok(())
    })
    .await?
}

async fn send(
    pool: &Http1Or2Pool,
    connector: &Http1Or2TlsConnector,
    endpoint: &Endpoint,
    path: &str,
    leased: Option<NegotiatedLease>,
    budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
) -> TestResult {
    let target = OriginForm::parse(path)?;
    let fields = validate_request(
        endpoint,
        &Method::GET,
        &target,
        Vec::new(),
        Vec::new(),
        &[],
        None,
        None,
    )?;
    let (response, _, _) = pool
        .send_request(
            connector,
            None,
            endpoint,
            &Route::Direct,
            &Span::none(),
            Method::GET,
            target,
            fields,
            Vec::new(),
            None,
            None,
            None,
            false,
            leased,
            budget,
            retries,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

type Offers = Arc<Mutex<Vec<bool>>>;

/// Builds a server certificate for `127.0.0.1` and an acceptor that selects
/// `http/1.1`, then `h2`, then `http/1.1` again, recording whether each
/// ClientHello offered early data.
fn server_identity() -> Result<(Vec<u8>, SslAcceptor, Offers), Box<dyn std::error::Error>> {
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;
    let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
    leaf_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&leaf_key, &root)?;

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let certificate = X509::from_der(leaf.der())?;
    acceptor.set_certificate(&certificate)?;
    let private_key = PKey::private_key_from_pkcs8(&leaf_key.serialize_der())?;
    acceptor.set_private_key(&private_key)?;
    acceptor.add_extra_chain_cert(X509::from_der(root.der())?)?;
    let offers = Offers::default();
    let recorded = Arc::clone(&offers);
    acceptor.set_select_certificate_callback(move |hello| {
        recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hello.get_extension(ExtensionType::EARLY_DATA).is_some());
        Ok::<_, SelectCertError>(())
    });
    let handshakes = AtomicUsize::new(0);
    acceptor.set_alpn_select_callback(move |_, offered| {
        let alpn = if handshakes.fetch_add(1, Ordering::SeqCst) == 1 {
            H2
        } else {
            HTTP1
        };
        select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
    });
    Ok((root.der().to_vec(), acceptor.build(), offers))
}

async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> Result<SslStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let (tcp, _) = listener.accept().await?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.set_early_data_enabled(true);
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

/// Reads one request head, answers `200` and closes; returns the head.
async fn serve_http1(
    mut stream: SslStream<TcpStream>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    Ok(head)
}
