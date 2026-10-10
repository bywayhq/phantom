use std::{
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use btls::ssl::{
    ErrorCode, Ssl3AlertLevel, SslAcceptor, SslAlert, SslConnector, SslInfoCallbackMode,
    SslInfoCallbackValue, SslMethod, SslVerifyError, SslVerifyMode,
};
use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_btls::SslStream;

use super::{
    ConnectionPeer, H1_ALPN, TestIdentity, TestResult, accept_tls_stream, bounded, client_builder,
    finish_peer, read_head,
};
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn a_completed_trusted_handshake_is_not_a_trust_rejection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = observed_acceptor(&identity)?;
    let client = client_builder(&identity, false).build()?;

    let peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let outcome = observe_handshake(tcp, acceptor).await?;
        let rejected = is_rejected(&outcome);
        let HandshakeOutcome { result, alert } = outcome;
        let mut stream = result?;
        let request = read_head(&mut stream).await?;

        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((request, alert, rejected))
    });

    let operation = bounded(async {
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{address}/trust-observer"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        Ok(())
    })
    .await;

    let observed = finish_peer(operation, peer).await;
    drop(client);
    let (request, alert, rejected) = observed?;

    assert_eq!(
        request,
        format!("GET /trust-observer HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
    );
    assert!(alert.is_none(), "healthy handshake received a fatal alert");
    assert!(
        !rejected,
        "completed actual handshake was called a trust rejection"
    );
    Ok(())
}

#[tokio::test]
async fn a_distinct_received_fatal_alert_is_not_an_unknown_ca_rejection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = observed_acceptor(&identity)?;
    let certificate_observed = Arc::new(AtomicBool::new(false));
    let verification_observed = Arc::clone(&certificate_observed);
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
        verification_observed.store(ssl.peer_certificate().is_some(), Ordering::SeqCst);
        Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_EXPIRED))
    });
    let connector = connector.build();
    let mut client = None;

    let peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        observe_handshake(tcp, acceptor).await
    });

    let operation = bounded(async {
        let tcp = TcpStream::connect(address).await?;
        let ssl = connector.configure()?.into_ssl("127.0.0.1")?;
        client = Some(SslStream::new(ssl, tcp)?);
        let stream = client
            .as_mut()
            .ok_or("controlled TLS client owner missing")?;
        let error = match Pin::new(stream).connect().await {
            Ok(()) => return Err("controlled certificate rejection completed its handshake".into()),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::SSL);
        assert!(error.ssl_error().is_some());
        Ok(())
    })
    .await;

    let observed = finish_peer(operation, peer).await;
    drop(client);
    let outcome = observed?;

    assert!(
        certificate_observed.load(Ordering::SeqCst),
        "controlled verifier did not observe a real certificate"
    );

    require_received_alert(&outcome, SslAlert::CERTIFICATE_EXPIRED)?;
    assert_ne!(
        outcome.alert.map(|alert| alert.description),
        Some(SslAlert::UNKNOWN_CA)
    );

    assert!(
        !is_rejected(&outcome),
        "trust observer accepted an actual unrelated fatal alert as unknown CA"
    );
    Ok(())
}

pub(super) struct ObservedAcceptor {
    acceptor: SslAcceptor,
    observation: AlertObservation,
}

pub(super) fn observed_acceptor(identity: &TestIdentity) -> TestResult<ObservedAcceptor> {
    let mut acceptor = identity.acceptor_builder(H1_ALPN)?;
    let (sender, receiver) = oneshot::channel();
    let state = Arc::new(AlertState {
        sender: Mutex::new(Some(sender)),
        entered: AtomicBool::new(false),
        poisoned: AtomicBool::new(false),
        delivery_failed: AtomicBool::new(false),
        duplicate: AtomicBool::new(false),
    });
    let capture = Arc::clone(&state);
    acceptor.set_info_callback(move |_, mode, value| {
        if mode == SslInfoCallbackMode::HANDSHAKE_START {
            capture.entered.store(true, Ordering::SeqCst);
        }

        if mode != SslInfoCallbackMode::READ_ALERT {
            return;
        }

        let SslInfoCallbackValue::Alert(alert) = value else {
            return;
        };

        if alert.alert_level() != Ssl3AlertLevel::FATAL {
            return;
        }

        let Ok(mut sender) = capture.sender.lock() else {
            capture.poisoned.store(true, Ordering::SeqCst);
            return;
        };

        let Some(sender) = sender.take() else {
            capture.duplicate.store(true, Ordering::SeqCst);
            return;
        };

        let observed = TerminalAlert {
            level: alert.alert_level(),
            description: alert.alert(),
        };

        if sender.send(observed).is_err() {
            capture.delivery_failed.store(true, Ordering::SeqCst);
        }
    });

    Ok(ObservedAcceptor {
        acceptor: acceptor.build(),
        observation: AlertObservation { state, receiver },
    })
}

pub(super) fn require_unknown_ca(outcome: &HandshakeOutcome) -> TestResult<()> {
    require_received_alert(outcome, SslAlert::UNKNOWN_CA)
}

pub(super) struct HandshakeOutcome {
    result: TestResult<SslStream<TcpStream>>,
    alert: Option<TerminalAlert>,
}

pub(super) async fn observe_handshake(
    tcp: TcpStream,
    acceptor: ObservedAcceptor,
) -> TestResult<HandshakeOutcome> {
    let ObservedAcceptor {
        acceptor,
        observation,
    } = acceptor;
    let result = accept_tls_stream(tcp, acceptor).await;

    let alert = match observation.finish() {
        Ok(alert) => alert,
        Err(error) => return finish_with_cleanup(Err(error), result.map(|_| ())),
    };

    Ok(HandshakeOutcome { result, alert })
}

pub(super) fn is_rejected(outcome: &HandshakeOutcome) -> bool {
    outcome.result.is_err()
}

fn require_received_alert(outcome: &HandshakeOutcome, expected: SslAlert) -> TestResult<()> {
    let error = outcome
        .result
        .as_ref()
        .err()
        .ok_or("actual server handshake did not fail")?;

    let ssl = error
        .downcast_ref::<btls::ssl::Error>()
        .ok_or("actual server failure was not a TLS handshake error")?;
    eprintln!(
        "actual server TLS evidence: code={:?}, received_alert={:?}",
        ssl.code(),
        outcome.alert
    );
    assert_eq!(ssl.code(), ErrorCode::SSL);
    assert!(
        ssl.ssl_error().is_some(),
        "actual server failure had no SSL error stack"
    );

    let alert = outcome
        .alert
        .ok_or("actual handshake had no received fatal alert")?;
    assert_eq!(alert.level, Ssl3AlertLevel::FATAL);
    assert_eq!(alert.description, expected);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct TerminalAlert {
    level: Ssl3AlertLevel,
    description: SslAlert,
}

struct AlertState {
    sender: Mutex<Option<oneshot::Sender<TerminalAlert>>>,
    entered: AtomicBool,
    poisoned: AtomicBool,
    delivery_failed: AtomicBool,
    duplicate: AtomicBool,
}

struct AlertObservation {
    state: Arc<AlertState>,
    receiver: oneshot::Receiver<TerminalAlert>,
}

impl AlertObservation {
    fn finish(mut self) -> TestResult<Option<TerminalAlert>> {
        if self.state.poisoned.load(Ordering::SeqCst) {
            return Err(io::Error::other("TLS alert observer lock poisoned").into());
        }

        if self.state.delivery_failed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS alert observer delivery failed",
            )
            .into());
        }

        if self.state.duplicate.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS alert observer received duplicate terminal alerts",
            )
            .into());
        }

        if !self.state.entered.load(Ordering::SeqCst) {
            return Err("actual TLS handshake never entered its callback".into());
        }

        match self.receiver.try_recv() {
            Ok(alert) => Ok(Some(alert)),
            Err(oneshot::error::TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}
