use btls::{
    hpke::HpkeKey,
    ssl::{NameType, SslEchKeys},
};
use phantom_testkit::tls::{CaptureLimits, EchOuterExtension, capture_client_hello};

use super::*;

pub(super) fn acceptor(identity: &TestIdentity, behavior: Peer) -> TestResult<SslAcceptor> {
    let mut builder = identity.acceptor_builder()?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    let (config_id, key) = match behavior {
        Peer::Accepted => (1, TEST_ECH_KEYS[0]),
        Peer::AuthenticatedRetry => (2, TEST_ECH_KEYS[1]),
    };
    let config = ech_config(config_id, &key, PUBLIC_NAME);
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(true, &config, HpkeKey::dhkem_p256_sha256(&key.private_key)?)?;
    builder.set_ech_keys(&keys.build())?;
    Ok(builder.build())
}

pub(super) async fn requests(
    listener: TcpListener,
    acceptor: SslAcceptor,
    behavior: Peer,
) -> TestResult<()> {
    let rejected_peer = if matches!(behavior, Peer::AuthenticatedRetry) {
        let (tcp, address) = listener.accept().await?;
        let mut tls = BoringStream::new(Ssl::new(acceptor.context())?, tcp)?;
        if let Err(error) = Pin::new(&mut tls).accept().await {
            if !ech_required(&error) {
                return Err(error.into());
            }
        } else {
            let mut byte = [0];
            match tls.read(&mut byte).await {
                Ok(0) => {}
                Err(error)
                    if disconnected(&error)
                        || error
                            .get_ref()
                            .and_then(|cause| cause.downcast_ref::<btls::ssl::Error>())
                            .is_some_and(ech_required) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("rejected ECH transport received HTTP bytes".into()),
            }
        }
        assert!(!tls.ssl().ech_accepted());
        assert_eq!(tls.ssl().servername(NameType::HOST_NAME), Some(PUBLIC_NAME));
        Some(address)
    } else {
        None
    };
    let (tcp, address) = listener.accept().await?;
    if let Some(previous) = rejected_peer {
        assert_ne!(
            address, previous,
            "ECH retry reused the rejected TCP transport"
        );
        assert_eq!(address.ip(), previous.ip());
    }
    let mut tls = BoringStream::new(Ssl::new(acceptor.context())?, tcp)?;
    Pin::new(&mut tls).accept().await?;
    assert!(tls.ssl().ech_accepted());
    assert_eq!(tls.ssl().servername(NameType::HOST_NAME), Some(INNER_NAME));
    assert_eq!(tls.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
    let mut connection = ::http2::server::handshake(tls).await?;
    for path in ["/first", "/second"] {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("retained ECH H2 connection closed before request")??;
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), path);
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some(INNER_NAME)
        );
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    if connection.accept().await.is_some() {
        return Err("retained ECH H2 session received an extra request".into());
    }
    Ok(())
}

pub(super) async fn cancelled(listener: TcpListener, seen: oneshot::Sender<()>) -> TestResult<()> {
    let (mut tcp, _) = listener.accept().await?;
    let capture = capture_client_hello(
        &mut tcp,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        CaptureLimits::new(64 * 1024, 64 * 1024, 8),
    )
    .await?;
    let summary = capture.summary()?;
    assert_eq!(summary.server_name(), Some(PUBLIC_NAME.as_bytes()));
    assert_eq!(
        summary
            .encrypted_client_hello()
            .and_then(EchOuterExtension::parse)
            .map(|ech| ech.config_id),
        Some(1)
    );
    seen.send(())
        .map_err(|_| "retained ECH caller left before ClientHello")?;
    let mut byte = [0];
    match tcp.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if disconnected(&error) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("cancelled retained ECH handshake sent bytes after ClientHello".into()),
    }
}

fn disconnected(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

fn ech_required(error: &btls::ssl::Error) -> bool {
    error.ssl_error().is_some_and(|stack| {
        !stack.errors().is_empty()
            && stack
                .errors()
                .iter()
                .all(|error| error.library_code() == 16 && error.reason_code() == 1121)
    })
}
