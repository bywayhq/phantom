use std::{error::Error, mem, sync::Arc, time::Duration};

use btls::{
    hpke::HpkeKey,
    ssl::{SslContextBuilder, SslEchKeys, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};
use bytes::{Buf, Bytes};
use h3::{
    error::{Code, ConnectionError},
    quic::ConnectionErrorIncoming,
};
use phantom_quic_btls::QuicClientConfig;
use phantom_testkit::{tls::TEST_ECH_KEYS, udp};
use tokio::{
    task::{AbortHandle, JoinSet},
    time::timeout,
};

use super::super::{Server, ServerMode, TestResult, test_identity};
use crate::{
    CaptureResult, Captured, GRACE_PERIOD, HOSTNAME, PAGE, PUBLIC_NAME, capture_errors, ech_config,
    finish_capture, spawn_origin_quic,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct QuicPeer {
    connection: quinn::Connection,
    pub(super) requests: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) worker: AbortHandle,
    captured: Arc<Captured>,
    slot: usize,
}

impl QuicPeer {
    pub(super) async fn page(&mut self) -> TestResult {
        timeout(CONTROL_TIMEOUT, async {
            let request = http::Request::get(format!("https://{HOSTNAME}/quic-serving")).body(())?;
            let mut stream = self.requests.send_request(request).await?;
            stream.finish().await?;

            let response = stream.recv_response().await?;
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(response.headers()["content-type"], "text/html");
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await? {
                while data.has_remaining() {
                    let length = data.chunk().len();
                    body.extend_from_slice(data.chunk());
                    data.advance(length);
                }
            }
            assert_eq!(body, PAGE);
            super::response_delivery::completed(&self.captured, self.slot).await?;
            Ok(())
        })
        .await?
    }

    pub(super) async fn close(&self) -> TestResult {
        self.connection.close(
            quinn::VarInt::from_u64(Code::H3_NO_ERROR.value())?,
            b"control peer finished",
        );
        let error = timeout(CONTROL_TIMEOUT, self.connection.closed()).await?;
        assert!(matches!(error, quinn::ConnectionError::LocallyClosed));
        Ok(())
    }

    pub(super) async fn completed(&self) -> TestResult {
        timeout(CONTROL_TIMEOUT, async {
            while !self.worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}

pub(super) struct RawQuicPeer {
    pub(super) connection: quinn::Connection,
    pub(super) worker: AbortHandle,
    slot: usize,
}

#[derive(Default)]
pub(super) struct QuicCapture {
    server: Option<quinn::Endpoint>,
    client: Option<quinn::Endpoint>,
    connections: Vec<quinn::Connection>,
    pub(super) captured: Arc<Captured>,
    tasks: JoinSet<CaptureResult<()>>,
    drivers: JoinSet<CaptureResult<()>>,
    pub(super) dns: Option<Server>,
}

impl QuicCapture {
    pub(super) async fn start(&mut self) -> TestResult {
        let (identity, trust_root) = test_identity()?;
        let configuration = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
        let mut keys = SslEchKeys::builder()?;
        keys.add_key(
            true,
            &configuration,
            HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
        )?;
        let crypto = identity.quic_server(&keys.build())?;
        let server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        self.server = Some(quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server),
            udp::bind("127.0.0.1:0".parse()?)?,
            Arc::new(quinn::TokioRuntime),
        )?);

        let mut context = SslContextBuilder::new(SslMethod::tls())?;
        context.set_verify(SslVerifyMode::PEER);
        context
            .cert_store_mut()
            .add_cert(X509::from_der(&trust_root)?)?;
        context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_alpn_protos(b"\x02h3")?;
        let client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::new(context.build())));
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            udp::bind("127.0.0.1:0".parse()?)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client);
        self.client = Some(endpoint);

        self.dns = Some(Server::start(ServerMode::Capture).await?);
        Ok(())
    }

    pub(super) async fn peer(&mut self) -> CaptureResult<QuicPeer> {
        self.configured_peer(h3::client::builder()).await
    }

    pub(super) async fn peer_with_header_limit(&mut self, limit: u64) -> CaptureResult<QuicPeer> {
        let mut builder = h3::client::builder();
        builder.max_field_section_size(limit);
        self.configured_peer(builder).await
    }

    async fn configured_peer(
        &mut self,
        mut builder: h3::client::Builder,
    ) -> CaptureResult<QuicPeer> {
        timeout(CONTROL_TIMEOUT, async {
            let RawQuicPeer {
                connection,
                worker,
                slot,
            } = self.raw_peer().await?;
            let (mut driver, requests) = builder
                .build(h3_quinn::Connection::new(connection.clone()))
                .await?;
            self.drivers.spawn(async move {
                let error = driver.wait_idle().await;
                if error.is_h3_no_error() {
                    return Ok(());
                }

                match &error {
                    ConnectionError::Remote(ConnectionErrorIncoming::Undefined(cause))
                        if matches!(
                            cause.downcast_ref::<quinn::ConnectionError>(),
                            Some(quinn::ConnectionError::LocallyClosed)
                        ) =>
                    {
                        Ok(())
                    }
                    _ => Err(error.into()),
                }
            });
            let mut settings = requests.peer_settings();
            settings.ready().await?;

            Ok(QuicPeer {
                connection,
                requests,
                worker,
                captured: Arc::clone(&self.captured),
                slot,
            })
        })
        .await?
    }

    pub(super) async fn raw_peer(&mut self) -> CaptureResult<RawQuicPeer> {
        timeout(CONTROL_TIMEOUT, async {
            let server = self.server.as_ref().ok_or("QUIC server was not acquired")?;
            let client = self.client.as_ref().ok_or("QUIC client was not acquired")?;
            let connecting = client.connect(server.local_addr()?, HOSTNAME)?;
            let incoming = server.accept().await.ok_or("QUIC listener stopped")?;
            assert!(incoming.remote_address().ip().is_loopback());
            // This exclusive acquisition does not await between reading and reserving the slot.
            let slot = self
                .captured
                .slots
                .lock()
                .map_err(|error| super::QuicObservationFailure {
                    boundary: "peer registration",
                    diagnostic: error.to_string(),
                })?
                .quic
                .len();
            let worker = spawn_origin_quic(&mut self.tasks, incoming, Arc::clone(&self.captured));
            let connection = connecting.await?;
            self.connections.push(connection.clone());

            Ok(RawQuicPeer {
                connection,
                worker,
                slot,
            })
        })
        .await?
    }

    pub(super) async fn finish(&mut self) -> TestResult {
        let dns = self.dns.as_mut().ok_or("DNS owner was not acquired")?;
        let capture = dns.take_capture()?;
        let tasks = mem::take(&mut self.tasks);
        let mut finish = Box::pin(finish_capture(Ok(()), tasks, capture));
        match timeout(GRACE_PERIOD + CONTROL_TIMEOUT, finish.as_mut()).await {
            Ok(result) => result,
            Err(primary) => {
                let backup = timeout(CONTROL_TIMEOUT, finish.as_mut()).await;
                let mut errors = vec![Box::new(primary) as Box<dyn Error + Send + Sync>];
                match backup {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error),
                    Err(error) => errors.push(error.into()),
                }
                capture_errors(errors)
            }
        }
    }

    pub(super) async fn observe_closed(&mut self) -> TestResult {
        let mut errors = Vec::new();
        loop {
            match timeout(CONTROL_TIMEOUT, self.drivers.join_next()).await {
                Ok(Some(Ok(Ok(())))) => {}
                Ok(Some(Ok(Err(error)))) => errors.push(error),
                Ok(Some(Err(error))) => errors.push(error.into()),
                Ok(None) => break,
                Err(error) => {
                    errors.push(error.into());
                    break;
                }
            }
        }
        for endpoint in [&self.server, &self.client].into_iter().flatten() {
            endpoint.close(0_u32.into(), b"control owner finished");
            if let Err(error) = timeout(CONTROL_TIMEOUT, endpoint.wait_idle()).await {
                errors.push(error.into());
            }
        }
        capture_errors(errors)
    }

    pub(super) async fn stop(&mut self) -> TestResult {
        for connection in &self.connections {
            connection.close(0_u32.into(), b"control backup");
        }
        for endpoint in [&self.server, &self.client].into_iter().flatten() {
            endpoint.close(0_u32.into(), b"control backup");
        }
        self.tasks.abort_all();
        self.drivers.abort_all();

        let mut errors = Vec::new();
        for tasks in [&mut self.tasks, &mut self.drivers] {
            loop {
                match timeout(CONTROL_TIMEOUT, tasks.join_next()).await {
                    Ok(Some(Ok(Ok(())))) => {}
                    Ok(Some(Ok(Err(error)))) => errors.push(error),
                    Ok(Some(Err(error))) if error.is_cancelled() => {}
                    Ok(Some(Err(error))) => errors.push(error.into()),
                    Ok(None) => break,
                    Err(error) => {
                        errors.push(error.into());
                        break;
                    }
                }
            }
        }
        if let Some(dns) = self.dns.as_mut() {
            if dns.task.is_some() {
                if let Err(error) = dns.stop().await {
                    errors.push(error);
                }
            }
        }
        for endpoint in [&self.server, &self.client].into_iter().flatten() {
            if let Err(error) = timeout(CONTROL_TIMEOUT, endpoint.wait_idle()).await {
                errors.push(error.into());
            }
        }
        self.connections.clear();
        self.server.take();
        self.client.take();
        capture_errors(errors)
    }
}
