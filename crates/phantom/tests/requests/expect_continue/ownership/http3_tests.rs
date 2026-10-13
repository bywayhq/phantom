use std::{future::poll_fn, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use tokio::time::timeout;

use super::super::TestResult;
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const LIMIT: Duration = Duration::from_secs(5);

pub(super) struct ExternalQuic {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: Option<ConnectionPeer<h3::error::ConnectionError>>,
}

impl ExternalQuic {
    pub(super) async fn connect(address: SocketAddr, root: Vec<u8>) -> TestResult<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(root))?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            phantom_testkit::udp::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let connection = timeout(LIMIT, endpoint.connect(address, "127.0.0.1")?).await??;
        let (mut driver, send) = timeout(
            LIMIT,
            h3::client::new(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;
        let driver =
            ConnectionPeer::spawn(
                async move { poll_fn(|context| driver.poll_close(context)).await },
            );
        let mut peer = Self {
            endpoint,
            connection,
            send,
            driver: Some(driver),
        };

        let ready: TestResult = async {
            timeout(LIMIT, peer.send.peer_settings().ready()).await??;
            if peer.connection.close_reason().is_some() {
                return Err("original QUIC peer closed before acquisition prerequisite".into());
            }

            Ok(())
        }
        .await;

        match ready {
            Ok(()) => Ok(peer),
            Err(error) => {
                let cleanup = peer.stop().await;
                finish_with_cleanup(Err(error), cleanup)
            }
        }
    }

    pub(super) async fn closed(&self, bound: Duration) -> TestResult {
        let error = timeout(bound, self.connection.closed())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("original QUIC connection remained live", elapsed)
            })?;

        match error {
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == quinn::VarInt::from_u32(0x100) =>
            {
                Ok(())
            }
            error => Err(error.into()),
        }
    }

    pub(super) async fn stop(&mut self) -> TestResult {
        // H3_NO_ERROR matches the original server connection's Drop closure.
        let code = quinn::VarInt::from_u32(0x100);
        self.connection
            .close(code, b"expect-continue control backup");
        self.endpoint.close(code, b"expect-continue control backup");

        let Some(mut driver) = self.driver.take() else {
            return Ok(());
        };
        let result = match timeout(LIMIT, &mut driver).await {
            Ok(joined) => driver_result(joined),
            Err(elapsed) => {
                let requested = !driver.is_finished();
                if requested {
                    driver.abort();
                }

                let collected = match timeout(LIMIT, &mut driver).await {
                    Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                    Ok(joined) => driver_result(joined),
                    Err(elapsed) => Err(FixtureDeadline::new(
                        "external H3 driver cleanup timed out",
                        elapsed,
                    )
                    .into()),
                };

                finish_with_cleanup(
                    Err(FixtureDeadline::new("external H3 driver did not finish", elapsed).into()),
                    collected,
                )
            }
        };

        let idle = timeout(LIMIT, self.endpoint.wait_idle())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("external QUIC endpoint cleanup timed out", elapsed).into()
            });

        finish_with_cleanup(result, idle)
    }
}

fn driver_result(joined: Result<h3::error::ConnectionError, tokio::task::JoinError>) -> TestResult {
    match joined {
        Ok(error) if error.is_h3_no_error() => Ok(()),
        Ok(error) => Err(error.into()),
        Err(error) => Err(error.into()),
    }
}
