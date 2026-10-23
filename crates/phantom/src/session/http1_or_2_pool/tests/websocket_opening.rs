//! Actual Upgrade cancellation and rejection retain only their HTTP owner.
use std::{net::Ipv4Addr, pin::Pin, sync::Arc, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::X509,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio_btls::SslStream;

use phantom_net::tcp::AddressFamily;
use phantom_profile::{
    ClientProfile,
    browser::{chrome, firefox},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::TestResult;
use crate::{Client, Route, authority::Endpoint, session::prune_timer::PruneTimer};

mod tls_backup;

const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum End {
    Cancelled,
    Rejected,
    Upgraded,
}

async fn lifecycle(end: End) -> TestResult {
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let profile = ClientProfile::new(firefox::v157_tcp_tls())
            .with_tcp(firefox::v157_tcp())
            .with_http1(firefox::v157_http1())
            .with_http2(firefox::v157_http2())
            .with_websocket(chrome::v154_websocket());
        let (root, acceptor) = identity()?;
        let mut client = Client::builder(profile).add_root_certificate_der(root).build()?;
        let state = Arc::get_mut(&mut client.state).ok_or("new client state already shared")?;
        state.http1_or_2 = super::super::Http1Or2Pool::new(std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN).with_prune_timer(Some(Arc::clone(&timer)));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let endpoint = Endpoint::new(address.to_string().parse()?, 443)?;
        let entry = client.state.http1_or_2.entry(super::super::PoolKey::new(&endpoint, &Route::Direct)).await;
        let (seen, head_seen) = oneshot::channel();
        let uri = format!("wss://{address}/opening");
        let builder = client.websocket_with_profile_policy(&uri)?;
        let caller = async {
            let mut opening = Box::pin(builder.connect());
            if matches!(end, End::Cancelled) {
                tokio::select! {
                    result = &mut opening => {
                        drop(result);
                        return Err("opening settled before cancellation".into());
                    }
                    observed = head_seen => observed?,
                }
                assert_eq!(entry.connections.lock().openings, 1);
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                timer.fire();
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                drop(opening);
            } else if matches!(end, End::Rejected) {
                let result = opening.await;
                let error = match result {
                    Err(error) => error,
                    Ok(_) => return Err("403 upgraded a socket".into()),
                };
                let response = error.into_response().ok_or("403 lost its rejection response")?;
                assert_eq!(response.status(), 403);
                assert_eq!(entry.connections.lock().openings, 1);
                timer.fire();
                assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
                drop(response);
            } else {
                let socket = opening.await?;
                // The accepted WebSocket has left the HTTP pool even while alive.
                assert_eq!(entry.connections.lock().openings, 0);
                timer.fire();
                assert_eq!(entry.connections.family.family(), None);
                drop(socket);
            }
            assert_eq!(entry.connections.lock().openings, 0);
            timer.fire();
            assert_eq!(entry.connections.family.family(), None);
            TestResult::Ok(())
        };
        let peer = async {
            let (tcp, _) = listener.accept().await?;
            let ssl = Ssl::new(acceptor.context())?;
            let mut stream = SslStream::new(ssl, tcp)?;
            Pin::new(&mut stream).accept().await?;
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await?;
                head.push(byte[0]);
            }
            seen.send(()).map_err(|()| "opening observer ended")?;
            if matches!(end, End::Rejected) {
                // Keep the body incomplete so the rejection still owns HTTP.
                stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\n").await?;
            } else if matches!(end, End::Upgraded) {
                let text = std::str::from_utf8(&head)?;
                let key = text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim())
                }).ok_or("missing WebSocket key")?;
                let mut bytes = key.as_bytes().to_vec();
                bytes.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                let accept = btls::base64::encode_block(&btls::sha::sha1(&bytes));
                stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
            }
            let mut remaining = Vec::new();
            match stream.read_to_end(&mut remaining).await {
                Ok(_) => {},
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof) => {},
                Err(error) => return Err(error.into()),
            }
            assert!(remaining.is_empty(), "cancelled/rejected/upgraded owner sent unexpected application bytes");
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await?
}

fn identity() -> Result<(Vec<u8>, SslAcceptor), Box<dyn std::error::Error>> {
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;
    let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
    leaf_params.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
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
    acceptor.set_alpn_select_callback(|_, offered| {
        btls::ssl::select_next_proto(b"\x08http/1.1", offered).ok_or(btls::ssl::AlpnError::NOACK)
    });
    Ok((root.der().to_vec(), acceptor.build()))
}

#[tokio::test]
async fn cancelled_upgrade_releases_its_opening_and_family() -> TestResult {
    lifecycle(End::Cancelled).await
}

#[tokio::test]
async fn rejected_upgrade_body_keeps_family_until_dropped() -> TestResult {
    lifecycle(End::Rejected).await
}

#[tokio::test]
async fn accepted_upgrade_releases_http_family_before_socket_drop() -> TestResult {
    lifecycle(End::Upgraded).await
}

#[tokio::test]
async fn cancelled_opening_leaves_pending_spare_owned_until_last_pool_drop() -> TestResult {
    use phantom_net::tcp::{SlowerConnection, SlowerProgress};
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let one = std::num::NonZeroUsize::MIN;
        let pool = super::super::Http1Or2Pool::new(one, one, one, one, one, one)
            .with_prune_timer(Some(Arc::clone(&timer)));
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let opening = pool.origin_opening(&endpoint).await;
        let family = Arc::clone(opening.family());
        family.remember(AddressFamily::Ipv4);
        let (started, running) = oneshot::channel();
        let (dropped, cancelled) = oneshot::channel::<()>();
        opening.adopt(
            SlowerConnection::new(SlowerProgress::new(), async move {
                let _drop_signal = dropped;
                if started.send(()).is_err() {
                    return None;
                }
                std::future::pending().await
            }),
            phantom_profile::WebSocketTlsBackup::Keep,
        );
        running.await?;
        drop(opening);
        timer.fire();
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        drop(pool);
        assert!(
            cancelled.await.is_err(),
            "pending spare did not drop its owned future"
        );
        Ok(())
    })
    .await?
}
