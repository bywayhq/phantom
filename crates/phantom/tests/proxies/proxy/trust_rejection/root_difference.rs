use std::{
    cmp::Ordering,
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr},
};

use btls::{
    asn1::Asn1Time,
    pkey::PKey,
    ssl::{AlpnError, ErrorCode, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use phantom::{Client, HttpProtocol, HttpProxy, RequestError, RequestErrorKind, Route};
use phantom_net::{TlsErrorKind, http1::Http1TlsError, proxy::HttpConnectError};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType, date_time_ymd,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use super::{
    ConnectionPeer, H1_ALPN, HandshakeOutcome, ObservedAcceptor, TestIdentity, TestResult, bounded,
    client_builder, finish_peer, observe_handshake, observed_acceptor_builder, read_head,
};

// The retained native headers define ERR_LIB_SSL and SSL_R_CERTIFICATE_VERIFY_FAILED.
// These identify certificate verification, not a particular verification reason.
const ERR_LIB_SSL: i32 = 16;
const SSL_R_CERTIFICATE_VERIFY_FAILED: i32 = 125;
const REJECT_CONNECT: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

#[tokio::test]
async fn adding_only_proxy_roots_authenticates_the_same_proxy() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let observed =
        observe_root_difference(ProxyCertificate::from_identity(&identity), false).await?;

    require_root_added_connect(&observed)?;
    assert!(is_root_rejection(&observed));
    Ok(())
}

#[tokio::test]
async fn adding_proxy_roots_does_not_remove_the_same_leafs_expiry() -> TestResult<()> {
    let certificate = ProxyCertificate::expired()?;
    let leaf = X509::from_der(&certificate.leaf)?;
    let now = Asn1Time::days_from_now(0)?;
    assert_eq!(leaf.not_after().compare(&now)?, Ordering::Less);

    let observed = observe_root_difference(certificate, false).await?;
    assert!(certificate_verification_failed(&observed.first_error));
    assert!(certificate_verification_failed(&observed.second_error));
    assert!(observed.first.connect.is_none());
    assert!(observed.second.connect.is_none());
    assert!(observed.second.handshake.result.is_err());

    assert!(
        !is_root_rejection(&observed),
        "outer proxy observer accepted persistent expiry as a roots-only rejection"
    );
    Ok(())
}

#[tokio::test]
async fn closing_after_client_hello_does_not_prove_proxy_trust_rejection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let observed =
        observe_root_difference(ProxyCertificate::from_identity(&identity), true).await?;

    assert!(!certificate_verification_failed(&observed.first_error));
    assert!(!certificate_verification_failed(&observed.second_error));
    for attempt in [&observed.first, &observed.second] {
        let prefix = attempt
            .client_hello
            .ok_or("actual ClientHello prefix was not retained")?;
        assert_eq!(prefix[0], 22);
        assert_eq!(prefix[1], 3);
        assert_eq!(prefix[5], 1);
        assert!(u16::from_be_bytes([prefix[3], prefix[4]]) >= 4);
        assert_ne!(&prefix[6..9], &[0, 0, 0]);
    }
    assert!(observed.first.connect.is_none());
    assert!(observed.second.connect.is_none());

    assert!(
        !is_root_rejection(&observed),
        "outer proxy observer accepted a plain peer closure as trust evidence"
    );
    Ok(())
}

pub(in super::super) async fn ordinary_outer_proxy_rejection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let observed =
        observe_root_difference(ProxyCertificate::from_identity(&identity), false).await?;

    require_root_added_connect(&observed)?;
    let rejected = is_root_rejection(&observed);
    assert!(rejected);
    Ok(())
}

fn is_root_rejection(observed: &RootDifference) -> bool {
    // A server may observe a disconnect instead of the client's verification alert.
    // Adding only the root must enable the same peer's TLS and literal CONNECT.
    let expected_connect = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        observed.origin_address, observed.origin_address
    );
    let second_cause = observed
        .second_error
        .source()
        .and_then(|source| source.downcast_ref::<Http1TlsError>());

    certificate_verification_failed(&observed.first_error)
        && observed.first.handshake.result.is_err()
        && observed.first.connect.is_none()
        && observed.second.handshake.result.is_ok()
        && observed.second.connect.as_deref() == Some(expected_connect.as_bytes())
        && matches!(
            second_cause,
            Some(Http1TlsError::Proxy(HttpConnectError::Rejected {
                status: 502
            }))
        )
}

struct RootDifference {
    origin_address: SocketAddr,
    first_error: RequestError,
    second_error: RequestError,
    first: ProxyAttempt,
    second: ProxyAttempt,
}

struct ProxyAttempt {
    handshake: HandshakeOutcome,
    connect: Option<Vec<u8>>,
    client_hello: Option<[u8; 9]>,
}

async fn observe_root_difference(
    certificate: ProxyCertificate,
    close_after_client_hello: bool,
) -> TestResult<RootDifference> {
    let origin_identity = TestIdentity::generate()?;
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let origin_address = origin.local_addr()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = listener.local_addr()?;
    let route = Route::http_proxy(HttpProxy::new(&format!("https://{proxy_address}"))?);
    let first_acceptor = certificate.observed_acceptor()?;
    let second_acceptor = certificate.observed_acceptor()?;

    let first_client = client_builder(&origin_identity, false)
        .route(route.clone())
        .build()?;
    let second_client = client_builder(&origin_identity, false)
        .route(route)
        .add_proxy_root_certificate_der(certificate.root)
        .build()?;
    let mut errors = None;
    let peer = ConnectionPeer::spawn(async move {
        let (first_tcp, _) = listener.accept().await?;
        let first =
            observe_proxy_attempt(first_tcp, first_acceptor, close_after_client_hello).await?;
        let (second_tcp, _) = listener.accept().await?;
        let second =
            observe_proxy_attempt(second_tcp, second_acceptor, close_after_client_hello).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>((first, second))
    });

    let operation = bounded(async {
        let first = request_failure(&first_client, origin_address).await?;
        if first.kind() != RequestErrorKind::Proxy {
            return Err(first.into());
        }

        let expected_verification_failure = !close_after_client_hello;
        if certificate_verification_failed(&first) != expected_verification_failure {
            return Err(first.into());
        }

        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        let second = request_failure(&second_client, origin_address).await?;
        assert_eq!(second.kind(), RequestErrorKind::Proxy);

        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));

        errors = Some((first, second));
        Ok(())
    })
    .await;

    let completed = finish_peer(operation, peer).await;
    drop(first_client);
    drop(second_client);
    let (first, second) = completed?;
    let (first_error, second_error) = errors.ok_or("two actual client errors were not retained")?;

    Ok(RootDifference {
        origin_address,
        first_error,
        second_error,
        first,
        second,
    })
}

async fn request_failure(client: &Client, origin: SocketAddr) -> TestResult<RequestError> {
    match client
        .get(HttpProtocol::Http1, &format!("https://{origin}/"))?
        .send()
        .await
    {
        Ok(_) => Err("untrusted HTTPS proxy connection succeeded".into()),
        Err(error) => Ok(error),
    }
}

async fn observe_proxy_attempt(
    mut tcp: TcpStream,
    acceptor: ObservedAcceptor,
    close_after_client_hello: bool,
) -> TestResult<ProxyAttempt> {
    let client_hello = if close_after_client_hello {
        let mut prefix = [0_u8; 9];
        loop {
            let received = tcp.peek(&mut prefix).await?;
            if received == 0 {
                return Err("closure peer reached EOF before the ClientHello prefix".into());
            }

            if received == prefix.len() {
                break;
            }

            // Peek leaves partial arrivals buffered; yield until the bounded operation expires.
            tokio::task::yield_now().await;
        }

        if prefix[0] != 22
            || prefix[1] != 3
            || prefix[5] != 1
            || u16::from_be_bytes([prefix[3], prefix[4]]) < 4
            || prefix[6..9] == [0, 0, 0]
        {
            return Err("closure peer did not observe an actual ClientHello header".into());
        }

        tcp.shutdown().await?;
        Some(prefix)
    } else {
        None
    };

    let mut handshake = observe_handshake(tcp, acceptor).await?;
    let connect = if let Ok(stream) = &mut handshake.result {
        let request = read_head(stream).await?;
        stream.write_all(REJECT_CONNECT).await?;
        stream.shutdown().await?;
        Some(request)
    } else {
        None
    };

    Ok(ProxyAttempt {
        handshake,
        connect,
        client_hello,
    })
}

fn certificate_verification_failed(error: &RequestError) -> bool {
    let Some(http1) = error
        .source()
        .and_then(|source| source.downcast_ref::<Http1TlsError>())
    else {
        return false;
    };

    let Http1TlsError::Proxy(HttpConnectError::ProxyTls(tls)) = http1 else {
        return false;
    };

    if tls.kind() != TlsErrorKind::Handshake {
        return false;
    }

    let Some(ssl) = tls
        .source()
        .and_then(|source| source.downcast_ref::<btls::ssl::Error>())
    else {
        return false;
    };

    ssl.code() == ErrorCode::SSL
        && ssl.ssl_error().is_some_and(|stack| {
            stack.errors().iter().any(|entry| {
                entry.library_code() == ERR_LIB_SSL
                    && entry.reason_code() == SSL_R_CERTIFICATE_VERIFY_FAILED
            })
        })
}

fn require_root_added_connect(observed: &RootDifference) -> TestResult<()> {
    if !certificate_verification_failed(&observed.first_error) {
        return Err("first actual proxy error was not certificate verification".into());
    }

    assert!(observed.first.handshake.result.is_err());
    assert!(observed.first.connect.is_none());
    assert!(observed.second.handshake.result.is_ok());
    assert_eq!(
        observed.second.connect.as_deref(),
        Some(
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                observed.origin_address, observed.origin_address
            )
            .as_bytes()
        )
    );

    let http1 = observed
        .second_error
        .source()
        .and_then(|source| source.downcast_ref::<Http1TlsError>())
        .ok_or("root-added request did not retain its HTTP/1 proxy cause")?;
    assert!(matches!(
        http1,
        Http1TlsError::Proxy(HttpConnectError::Rejected { status: 502 })
    ));
    Ok(())
}

struct ProxyCertificate {
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: Vec<u8>,
}

impl ProxyCertificate {
    fn from_identity(identity: &TestIdentity) -> Self {
        Self {
            root: identity.root_der.clone(),
            leaf: identity.leaf_der().to_vec(),
            key: identity.private_key_der().to_vec(),
        }
    }

    fn expired() -> TestResult<Self> {
        let mut root = CertificateParams::new(Vec::<String>::new())?;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = CertifiedIssuer::self_signed(root, KeyPair::generate()?)?;

        let mut leaf = CertificateParams::new(Vec::<String>::new())?;
        leaf.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.use_authority_key_identifier_extension = true;
        leaf.not_before = date_time_ymd(2000, 1, 1);
        leaf.not_after = date_time_ymd(2001, 1, 1);
        let key = KeyPair::generate()?;
        let certificate = leaf.signed_by(&key, &issuer)?;

        Ok(Self {
            root: issuer.der().to_vec(),
            leaf: certificate.der().to_vec(),
            key: key.serialize_der(),
        })
    }

    fn observed_acceptor(&self) -> TestResult<ObservedAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(&self.leaf)?;
        let private_key = PKey::private_key_from_pkcs8(&self.key)?;
        builder.set_certificate(&certificate)?;
        builder.set_private_key(&private_key)?;
        builder.add_extra_chain_cert(X509::from_der(&self.root)?)?;
        builder.check_private_key()?;
        builder.set_alpn_select_callback(|_, offered| {
            select_next_proto(H1_ALPN, offered).ok_or(AlpnError::NOACK)
        });
        observed_acceptor_builder(builder)
    }
}
