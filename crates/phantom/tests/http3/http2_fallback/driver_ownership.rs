use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    task::AbortHandle,
};
use tokio_btls::SslStream;

use super::*;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const READY_LIMIT: Duration = Duration::from_secs(5);
const DROP_LIMIT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct DriverObservation {
    pub(super) driver: Mutex<Option<AbortHandle>>,
    destroyed: AtomicBool,
    body_pending: AtomicBool,
    client_closed: AtomicBool,
}

impl DriverObservation {
    pub(super) fn publish(&self, driver: AbortHandle) -> TestResult<()> {
        match self.driver.lock() {
            Ok(mut observed) => {
                *observed = Some(driver);
                Ok(())
            }
            Err(poison) => {
                *poison.into_inner() = Some(driver);
                Err(io::Error::other("driver publication observation lock poisoned").into())
            }
        }
    }
}

pub(super) struct DriverLifetime(pub(super) Arc<DriverObservation>);

impl Drop for DriverLifetime {
    fn drop(&mut self) {
        self.0.destroyed.store(true, Ordering::SeqCst);
    }
}

pub(super) async fn body_data(
    body: &mut ::http2::RecvStream,
    received: &[u8],
    observation: &DriverObservation,
) -> Option<Result<Bytes, ::http2::Error>> {
    let next = body.data();
    tokio::pin!(next);
    poll_fn(|context| {
        let result = next.as_mut().poll(context);
        if result.is_pending() && received == b"payload" {
            observation.body_pending.store(true, Ordering::SeqCst);
        }

        result
    })
    .await
}

struct ObservedIo {
    stream: SslStream<TcpStream>,
    observation: Arc<DriverObservation>,
}

impl AsyncRead for ObservedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = bytes.filled().len();
        let has_capacity = bytes.remaining() != 0;
        let result = Pin::new(&mut self.stream).poll_read(context, bytes);
        let closed = match &result {
            Poll::Ready(Ok(())) => has_capacity && bytes.filled().len() == before,
            Poll::Ready(Err(error)) => tls_support::is_peer_gone(error),
            Poll::Pending => false,
        };
        if closed {
            self.observation.client_closed.store(true, Ordering::SeqCst);
        }

        result
    }
}

impl AsyncWrite for ObservedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

struct DriverBackup {
    observation: Arc<DriverObservation>,
    parent: Option<ConnectionPeer<TestResult<Received>>>,
    client: Option<ConnectionPeer<TestResult<()>>>,
}

impl DriverBackup {
    fn new() -> Self {
        Self {
            observation: Arc::new(DriverObservation::default()),
            parent: None,
            client: None,
        }
    }

    fn driver(&self) -> TestResult<Option<AbortHandle>> {
        Ok(self
            .observation
            .driver
            .lock()
            .map_err(|_| io::Error::other("driver lookup observation lock poisoned"))?
            .clone())
    }

    async fn finish(&mut self) -> TestResult<()> {
        let parent = match self.parent.take() {
            Some(parent) => parent.stop().await,
            None => Ok(()),
        };

        let (driver, observed): (_, TestResult<()>) = match self.observation.driver.lock() {
            Ok(observed) => (observed.clone(), Ok(())),
            Err(poison) => (
                poison.into_inner().clone(),
                Err(io::Error::other("driver backup observation lock poisoned").into()),
            ),
        };

        let nested: TestResult<()> = if let Some(driver) = driver {
            driver.abort();
            timeout(READY_LIMIT, async {
                while !driver.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(Into::into)
        } else {
            Ok(())
        };

        let client = match self.client.take() {
            Some(client) => client.stop().await,
            None => Ok(()),
        };

        finish_with_cleanup(
            finish_with_cleanup(parent, finish_with_cleanup(observed, nested)),
            client,
        )
    }
}

impl Drop for DriverBackup {
    fn drop(&mut self) {
        if let Some(parent) = &self.parent {
            parent.abort();
        }

        let driver = match self.observation.driver.lock() {
            Ok(observed) => observed.clone(),
            Err(poison) => poison.into_inner().clone(),
        };

        if let Some(driver) = driver {
            driver.abort();
        }
        if let Some(client) = &self.client {
            client.abort();
        }
    }
}

#[derive(Debug)]
struct DriverDropDeadline(Elapsed);

impl fmt::Display for DriverDropDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cancelled HTTP/2 serving retained its actual body driver")
    }
}

impl Error for DriverDropDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

enum ObservedContract {
    CompleteBody,
    ParentCancellation,
    ExplicitDriverAbort,
}

async fn exercise(contract: ObservedContract) -> TestResult<()> {
    let mut backup = DriverBackup::new();
    let result: TestResult<()> = async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H2_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;

        backup.parent = Some(ConnectionPeer::spawn(serve_http2_observed(
            listener,
            acceptor,
            Some(Arc::clone(&backup.observation)),
        )));

        let tcp = timeout(READY_LIMIT, TcpStream::connect(address)).await??;
        let mut stream = SslStream::new(ssl, tcp)?;
        timeout(READY_LIMIT, Pin::new(&mut stream).connect()).await??;
        if stream.ssl().selected_alpn_protocol() != Some(&b"h2"[..]) {
            return Err("trusted client did not negotiate HTTP/2".into());
        }

        let (mut requests, connection) = timeout(
            READY_LIMIT,
            ::http2::client::handshake(ObservedIo {
                stream,
                observation: Arc::clone(&backup.observation),
            }),
        )
        .await??;
        let observation = Arc::clone(&backup.observation);
        backup.client = Some(ConnectionPeer::spawn(async move {
            match connection.await {
                Ok(()) => Ok(()),
                Err(error) if error.is_io() && observation.client_closed.load(Ordering::SeqCst) => {
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }));

        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://127.0.0.1:{}/upload", address.port()))
            .body(())?;
        let (response, mut body) = requests.send_request(request, false)?;
        body.send_data(Bytes::from_static(b"payload"), false)?;
        timeout(READY_LIMIT, async {
            while !backup.observation.body_pending.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let driver = backup.driver()?.ok_or("body driver was not published")?;
        if driver.is_finished()
            || backup
                .client
                .as_ref()
                .is_none_or(ConnectionPeer::is_finished)
        {
            return Err("actual HTTP/2 drivers stopped before the pending-body observation".into());
        }

        match contract {
            ObservedContract::CompleteBody => {
                body.send_data(Bytes::new(), true)?;
                let response = timeout(READY_LIMIT, response).await??;
                if response.status() != StatusCode::NO_CONTENT {
                    return Err(
                        "canonical HTTP/2 serving changed its literal response status".into(),
                    );
                }
                drop((response, body, requests));

                let client = backup.client.take().ok_or("client owner absent")?;
                timeout(READY_LIMIT, client).await???;
                let parent = backup.parent.take().ok_or("serving owner absent")?;
                let received = timeout(READY_LIMIT, parent).await???;
                if received.method != Method::POST
                    || received.path != "/upload"
                    || received.body != Bytes::from_static(b"payload")
                {
                    return Err("canonical HTTP/2 serving changed the actual upload".into());
                }
            }
            ObservedContract::ParentCancellation | ObservedContract::ExplicitDriverAbort => {
                let mut parent = backup.parent.take().ok_or("serving owner absent")?;
                parent.abort();
                let joined = timeout(READY_LIMIT, &mut parent).await?;
                match joined {
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => return Err(error.into()),
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(_)) => {
                        return Err(
                            "actual serving parent completed instead of acknowledging cancellation"
                                .into(),
                        );
                    }
                }

                if matches!(contract, ObservedContract::ExplicitDriverAbort) {
                    driver.abort();
                }
                timeout(DROP_LIMIT, async {
                    while !backup.observation.destroyed.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .map_err(DriverDropDeadline)?;
                timeout(READY_LIMIT, async {
                    while !backup.observation.client_closed.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
                drop((response, body, requests));
            }
        }

        Ok(())
    }
    .await;
    let cleanup = backup.finish().await;
    finish_with_cleanup(result, cleanup)
}

#[tokio::test(flavor = "current_thread")]
async fn completed_http2_upload_keeps_its_canonical_wire_result() -> TestResult<()> {
    exercise(ObservedContract::CompleteBody).await
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_http2_serving_releases_its_actual_body_driver() -> TestResult<()> {
    exercise(ObservedContract::ParentCancellation).await
}

#[tokio::test(flavor = "current_thread")]
async fn explicitly_aborting_the_pending_body_driver_releases_its_socket() -> TestResult<()> {
    exercise(ObservedContract::ExplicitDriverAbort).await
}
