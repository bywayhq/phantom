use std::{future::poll_fn, sync::Arc, time::Duration};

use bytes::Buf;
use http::{Request, StatusCode};
use rustls::pki_types::CertificateDer;
use tokio::{task::JoinSet, time::timeout};

use super::{Origin, TestIdentity, TestResult, bounded, identities};

const DEADLINE: Duration = Duration::from_secs(5);

struct Peer {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _driver: JoinSet<h3::error::ConnectionError>,
}

impl Peer {
    async fn connect(identity: &TestIdentity, origin: &Origin) -> TestResult<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(identity.root_der.clone()))?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let connection = endpoint.connect(origin.address, "127.0.0.1")?.await?;
        let (mut h3, send) = h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
        let mut driver = JoinSet::new();
        driver.spawn(async move { poll_fn(|context| h3.poll_close(context)).await });
        send.peer_settings().ready().await?;
        Ok(Self {
            endpoint,
            connection,
            send,
            _driver: driver,
        })
    }

    async fn complete_response(&mut self, origin: &Origin) -> TestResult<()> {
        let request = Request::builder().uri(origin.uri("/complete")).body(())?;
        let mut stream = self.send.send_request(request).await?;
        stream.finish().await?;
        assert_eq!(stream.recv_response().await?.status(), StatusCode::OK);

        let mut body = Vec::new();
        while let Some(mut data) = stream.recv_data().await? {
            let remaining = data.remaining();
            body.extend_from_slice(&data.copy_to_bytes(remaining));
        }
        assert_eq!(body, b"/complete");
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.requests(), ["/complete"]);
        assert!(self.connection.close_reason().is_none());
        Ok(())
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"test peer dropped");
    }
}

async fn closed_origin(code: u32) -> TestResult<()> {
    let (identity, _) = identities()?;
    let origin = Origin::spawn(&identity)?;
    let mut peer = Peer::connect(&identity, &origin).await?;
    peer.complete_response(&origin).await?;

    peer.connection.close(code.into(), b"explicit peer close");
    // The original accepted task owns the third request-log handle. Observe
    // its actual destruction before asking the listener for its result.
    timeout(DEADLINE, async {
        while Arc::strong_count(&origin.requests) > 2 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let result = origin.finish().await;

    if code == 0 {
        result?;
    } else {
        let error = result
            .err()
            .ok_or("origin discarded the peer application error")?;
        let mut cause: &(dyn std::error::Error + 'static) = error.as_ref();
        loop {
            if matches!(
                cause.downcast_ref::<h3::error::ConnectionError>(),
                Some(h3::error::ConnectionError::Remote(
                    h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }, ..
                )) if *error_code == u64::from(code)
            ) {
                break;
            }

            cause = cause
                .source()
                .ok_or("origin lost the typed remote application code")?;
        }
    }
    drop(peer);
    Ok(())
}

#[tokio::test]
async fn finish_preserves_an_actual_peer_internal_error() -> TestResult<()> {
    bounded(closed_origin(0x102)).await
}

#[tokio::test]
async fn finish_accepts_an_actual_peer_code_zero_close() -> TestResult<()> {
    bounded(closed_origin(0)).await
}
