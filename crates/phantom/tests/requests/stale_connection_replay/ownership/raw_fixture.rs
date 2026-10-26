use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::atomic::Ordering,
    task::{Context, Poll},
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, RetryPolicy};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    task::{Id, yield_now},
    time::timeout,
};
use tokio_btls::SslStream;

use super::super::{
    H1_ALPN, ReceivedRequest, TestIdentity, client_builder, raw_server, read_head, replaying_client,
};
use super::{Mode, Observation, TEST_TIMEOUT, TestResult};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::connection_peer::ConnectionPeer;
use crate::support::tunnel_proxy::finish_with_cleanup;

pub(super) type RawServer = ConnectionPeer<TestResult<(ReceivedRequest, ReceivedRequest)>>;

#[derive(Clone, Copy)]
pub(super) enum Protocol {
    Plain,
    Tls,
}

pub(super) struct RawFixture {
    server: Option<RawServer>,
    stream: Option<HeldSocket>,
    observation: Observation,
    client: Client,
    protocol: Protocol,
    address: SocketAddr,
    priming_caller: Option<TestResult>,
}

impl RawFixture {
    pub(super) async fn pending(protocol: Protocol) -> TestResult<Self> {
        Self::prepare(protocol, Mode::Healthy, false).await
    }

    pub(super) async fn completed_fault(protocol: Protocol) -> TestResult<Self> {
        Self::prepare(protocol, Mode::FailPrimeFlush, true).await
    }

    pub(super) async fn pending_client(protocol: Protocol) -> TestResult<Self> {
        Self::prepare(protocol, Mode::Healthy, true).await
    }

    async fn prepare(protocol: Protocol, mode: Mode, prime_with_client: bool) -> TestResult<Self> {
        let identity = match protocol {
            Protocol::Plain => None,
            Protocol::Tls => Some(TestIdentity::generate()?),
        };
        let client = match &identity {
            None => replaying_client()?,
            Some(identity) => client_builder(identity, true)
                .retry_policy(RetryPolicy::none().with_reused_connection_replay(true))
                .build()?,
        };
        let ssl = match (&identity, prime_with_client) {
            (Some(identity), false) => {
                let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
                connector.set_verify(SslVerifyMode::PEER);
                connector
                    .cert_store_mut()
                    .add_cert(X509::from_der(&identity.root_der)?)?;
                connector.set_alpn_protos(H1_ALPN)?;
                Some(connector.build().configure()?.into_ssl("127.0.0.1")?)
            }
            _ => None,
        };

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (control, observation) = Observation::control(mode);

        let server = match &identity {
            None => raw_server::spawn_replay(listener, Some(control)),
            Some(identity) => raw_server::spawn_negotiated(
                listener,
                identity.acceptor(H1_ALPN)?,
                identity.acceptor(H1_ALPN)?,
                Some(control),
            ),
        };
        let mut fixture = Self {
            server: Some(server),
            stream: None,
            observation,
            client,
            protocol,
            address,
            priming_caller: None,
        };

        let setup = async {
            if prime_with_client {
                let caller = timeout(TEST_TIMEOUT, fixture.waiting_caller())
                    .await
                    .map_err(|elapsed| {
                        FixtureDeadline::new(
                            "raw stale actual Client priming exceeded its deadline",
                            elapsed,
                        )
                    })?;

                match caller {
                    outcome @ Ok(()) => fixture.priming_caller = Some(outcome),
                    Err(original) => return Err(original),
                }
            } else {
                let tcp = timeout(TEST_TIMEOUT, TcpStream::connect(address))
                    .await
                    .map_err(|elapsed| {
                        FixtureDeadline::new("raw stale peer connect exceeded its deadline", elapsed)
                    })??;
                fixture.stream = Some(match ssl {
                    None => HeldSocket::Plain(tcp),
                    Some(ssl) => HeldSocket::Tls(SslStream::new(ssl, tcp)?),
                });

                if let Some(HeldSocket::Tls(stream)) = &mut fixture.stream {
                    timeout(TEST_TIMEOUT, Pin::new(&mut *stream).connect())
                        .await
                        .map_err(|elapsed| {
                            FixtureDeadline::new(
                                "raw stale trusted TLS handshake exceeded its deadline",
                                elapsed,
                            )
                        })??;

                    if stream.ssl().selected_alpn_protocol() != Some(&b"http/1.1"[..]) {
                        return Err("raw stale trusted TLS peer did not negotiate HTTP/1.1".into());
                    }
                }

                let stream = fixture.stream.as_mut().ok_or("raw stale held socket missing")?;

                stream
                    .write_all(b"GET /prime HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await?;
                stream.flush().await?;

                let response = timeout(TEST_TIMEOUT, read_head(stream))
                    .await
                    .map_err(|elapsed| {
                        FixtureDeadline::new(
                            "raw stale literal priming response exceeded its deadline",
                            elapsed,
                        )
                    })??;

                if response != b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" {
                    return Err("raw stale literal priming response changed".into());
                }
            }

            match mode {
                Mode::Healthy => fixture.observation.wait(
                    "raw stale actual post-prime read Pending prerequisite exceeded its deadline",
                    |state| state.primed && state.stale_read_pending && state.abort.is_some(),
                ).await?,
                Mode::FailPrimeFlush => {
                    fixture.observation.wait(
                        "raw stale consumed flush fault and destruction prerequisite exceeded its deadline",
                        |state| state.primed && state.fault_taken && state.destroyed,
                    ).await?;

                    fixture.wait_finished().await?;
                }
            }

            TestResult::Ok(())
        }
        .await;

        match setup {
            Ok(()) => Ok(fixture),
            Err(error) => {
                let cleanup = fixture.backup().await;
                finish_with_cleanup(Err(error), cleanup)
            }
        }
    }

    pub(super) fn take_server(&mut self) -> TestResult<RawServer> {
        self.server
            .take()
            .ok_or_else(|| "original raw stale server missing".into())
    }

    pub(super) fn take_priming_caller(&mut self) -> TestResult<TestResult> {
        self.priming_caller
            .take()
            .ok_or_else(|| "actual raw Client priming result missing".into())
    }

    pub(super) fn original_id(&self) -> TestResult<Id> {
        Ok(self
            .server
            .as_ref()
            .ok_or("original raw stale server missing")?
            .abort_handle()
            .id())
    }

    pub(super) fn abort_original(&self) -> TestResult {
        self.server
            .as_ref()
            .ok_or("original raw stale server missing")?
            .abort();
        Ok(())
    }

    pub(super) async fn wait_finished(&self) -> TestResult {
        timeout(TEST_TIMEOUT, async {
            while !self
                .server
                .as_ref()
                .ok_or("original raw stale server missing")?
                .is_finished()
            {
                yield_now().await;
            }

            TestResult::Ok(())
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "raw stale actual original finished prerequisite exceeded its deadline",
                elapsed,
            )
        })?
    }

    pub(super) async fn waiting_caller(&self) -> TestResult {
        let scheme = match self.protocol {
            Protocol::Plain => "http",
            Protocol::Tls => "https",
        };
        let url = format!("{scheme}://{}/prime", self.address);

        let response = match self.protocol {
            Protocol::Plain => {
                self.client
                    .get_with_protocol(HttpProtocol::Http1, &url)?
                    .send()
                    .await?
            }
            Protocol::Tls => self.client.get(&url)?.send().await?,
        };

        if response.status() != StatusCode::NO_CONTENT {
            return Err("actual waiting raw caller did not receive the priming status".into());
        }

        response.into_body().collect().await?;
        Ok(())
    }

    pub(super) async fn invalid_uri(&self) -> TestResult {
        let _response = self
            .client
            .get_with_protocol(HttpProtocol::Http1, "http://127.0.0.1/invalid uri")?
            .send()
            .await?;
        Ok(())
    }

    pub(super) async fn held_request(&self, address: SocketAddr) -> TestResult {
        self.client
            .get_with_protocol(
                HttpProtocol::Http1,
                &format!("http://{address}/held-deadline"),
            )?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;

        Ok(())
    }

    pub(super) async fn closed(
        &mut self,
        destruction_purpose: &'static str,
        socket_purpose: &'static str,
    ) -> TestResult {
        let stream = self
            .stream
            .as_mut()
            .ok_or("raw stale held socket missing")?;
        self.observation
            .closed(stream, destruction_purpose, socket_purpose)
            .await
    }

    pub(super) fn serving_cause(&self, error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
        self.observation.serving_cause(error)
    }

    pub(super) fn no_backup(&self) -> TestResult {
        self.observation.no_backup()
    }

    pub(super) async fn destroyed(&mut self, purpose: &'static str) -> TestResult {
        self.observation
            .wait(purpose, |state| state.destroyed)
            .await
    }

    pub(super) async fn backup(&mut self) -> TestResult {
        let abort = self
            .observation
            .state
            .borrow()
            .abort
            .clone()
            .ok_or("original raw stale abort handle missing")?;
        let requested = !abort.is_finished();

        self.observation
            .state
            .borrow()
            .backup_requested
            .store(true, Ordering::Release);

        if requested {
            abort.abort();
        }

        let joined = match self.server.take() {
            Some(mut server) => match timeout(TEST_TIMEOUT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "raw stale backup original join exceeded its deadline",
                    elapsed,
                )
                .into()),
            },
            // The canonical completion or its Drop has consumed this owner.
            None => Ok(()),
        };

        let primed = self.observation.state.borrow().primed;
        let closed = if primed && self.stream.is_some() {
            self.closed(
                "raw stale backup destruction exceeded its deadline",
                "raw stale backup socket closure exceeded its deadline",
            )
            .await
        } else {
            drop(self.stream.take());
            self.observation
                .wait(
                    "raw stale backup destruction exceeded its deadline",
                    |state| state.destroyed,
                )
                .await
        };

        finish_with_cleanup(joined, closed)
    }
}

enum HeldSocket {
    Plain(TcpStream),
    Tls(SslStream<TcpStream>),
}

impl AsyncRead for HeldSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for HeldSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}
