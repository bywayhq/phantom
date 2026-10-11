use std::{
    error::Error,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestError, RequestHeader};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::timeout,
};
use tokio_btls::SslStream;

use super::super::{H2_ALPN, TestIdentity, test_client, tls_support};
use super::{
    Control, IndependentServer, Observation, Requests, Server, State, TestResult, collect,
    collect_independent, spawn_server,
};
use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const FAILURE: &str = "injected session reuse serving read failure";

#[tokio::test]
async fn healthy_original_reuse_server_keeps_its_204_and_original_result() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.release_sender();
        let requests = backup.ordinary_result(Ok(())).await?;
        backup.closed().await?;
        assert_eq!(requests, vec![(1, "/first".to_owned())]);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_joins_the_original_reuse_server_and_closes_its_socket() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending().await?;
        backup
            .abort
            .as_ref()
            .ok_or("original reuse server witness missing")?
            .abort();
        let error = backup
            .ordinary_result(Ok(()))
            .await
            .err()
            .ok_or("aborted reuse server succeeded")?;
        backup.closed().await?;

        assert!(
            error
                .downcast_ref::<JoinError>()
                .is_some_and(JoinError::is_cancelled)
        );
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn completed_original_reuse_server_keeps_its_h2_io_kind_and_message() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, Some(read_failure())).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending().await?;
        backup.fail_read().await?;
        let error = backup
            .ordinary_result(Ok(()))
            .await
            .err()
            .ok_or("faulted reuse server succeeded")?;
        backup.closed().await?;
        retains_h2_cause(error.as_ref())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_original_reuse_owner_closes_its_pending_driver_before_backup()
-> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending().await?;
        drop(backup.server.take());
        backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_reuse_caller_failure_keeps_the_completed_original_server_cause() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, Some(read_failure())).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending().await?;
        backup.fail_read().await?;
        let caller = backup.invalid_header().await?;
        let kind = caller.kind();
        let error = backup
            .ordinary_result(Err(caller.into()))
            .await
            .err()
            .ok_or("invalid caller succeeded")?;
        backup.closed().await?;

        let errors = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("reuse caller discarded its original completed server cause")?;
        let caller = errors
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("original reuse caller type changed")?;
        assert_eq!(caller.kind(), kind);
        retains_h2_cause(errors.cleanup.as_ref())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn healthy_independent_clients_keep_two_original_h2_results() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Independent, None).await?;
    let primary = async {
        let first = test_client(&backup.identity, true)?;
        let second = test_client(&backup.identity, true)?;
        for (client, path) in [(&first, "/first"), (&second, "/second")] {
            let response = timeout(
                LIMIT,
                client
                    .get(
                        HttpProtocol::Http2,
                        &format!("https://{}{path}", backup.address),
                    )?
                    .send(),
            )
            .await??;
            assert_eq!(response.status(), 204);
            timeout(LIMIT, response.into_body().collect()).await??;
        }
        drop(first);
        drop(second);

        let results = backup.independent_result().await?;
        assert_eq!(
            results,
            [
                vec![(1, "/first".to_owned())],
                vec![(1, "/second".to_owned())]
            ]
        );
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_pending_second_accept_owner_closes_its_original_first_child() -> TestResult<()>
{
    let mut backup = Backup::start(Mode::Independent, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending_second().await?;
        drop(backup.server.take());
        backup.closed().await?;
        assert!(backup.observed.borrow().coordinator_destroyed);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn a_real_second_tls_accept_failure_closes_the_original_pending_first_child() -> TestResult<()>
{
    let mut backup = Backup::start(Mode::Independent, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending_second().await?;
        backup.bad_second_tls().await?;
        let error = backup
            .independent_result()
            .await
            .err()
            .ok_or("invalid second TLS peer was accepted")?;
        assert!(
            error.is::<btls::ssl::Error>(),
            "original accepted TLS input error changed"
        );
        backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn second_tls_acquisition_failure_keeps_the_completed_original_first_child_cause()
-> TestResult<()> {
    let mut backup = Backup::start(Mode::Independent, Some(read_failure())).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending_second().await?;
        backup.fail_read().await?;
        backup.bad_second_tls().await?;
        let error = backup
            .independent_result()
            .await
            .err()
            .ok_or("invalid second TLS peer was accepted")?;
        backup.closed().await?;

        let errors = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("second TLS accept discarded its original completed first child cause")?;
        assert!(
            errors.primary.is::<btls::ssl::Error>(),
            "original second TLS error changed"
        );
        retains_h2_cause(errors.cleanup.as_ref())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

enum Mode {
    Ordinary,
    Independent,
}

enum ServerTask {
    Ordinary(Server),
    Independent(IndependentServer),
}

impl ServerTask {
    fn abort_handle(&self) -> AbortHandle {
        match self {
            Self::Ordinary(server) => server.abort_handle(),
            Self::Independent(server) => server.abort_handle(),
        }
    }
}

struct Backup {
    identity: TestIdentity,
    address: SocketAddr,
    server: Option<ServerTask>,
    abort: Option<AbortHandle>,
    sender: Option<::http2::client::SendRequest<Bytes>>,
    driver: Option<ConnectionPeer<Result<(), ::http2::Error>>>,
    second_socket: Option<TcpStream>,
    observed: watch::Receiver<State>,
    arm: Option<oneshot::Sender<()>>,
}

impl Drop for Backup {
    fn drop(&mut self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
        for child in &self.observed.borrow().children {
            child.abort();
        }
    }
}

impl Backup {
    async fn start(mode: Mode, fault: Option<io::Error>) -> TestResult<Self> {
        Self::start_controlled(mode, fault, None, None).await
    }

    async fn start_controlled(
        mode: Mode,
        fault: Option<io::Error>,
        second_control: Option<Control>,
        collect_after: Option<oneshot::Receiver<()>>,
    ) -> TestResult<Self> {
        Self::start_observed(mode, fault, second_control, collect_after, None).await
    }

    async fn start_observed(
        mode: Mode,
        fault: Option<io::Error>,
        second_control: Option<Control>,
        collect_after: Option<oneshot::Receiver<()>>,
        second_accept_after: Option<oneshot::Receiver<()>>,
    ) -> TestResult<Self> {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (state, observed) = watch::channel(State::default());
        let (arm, armed) = oneshot::channel();
        let control = Control {
            observed: Observation(state),
            fault,
            armed,
        };
        let server = match mode {
            Mode::Ordinary => {
                ServerTask::Ordinary(spawn_server(listener, acceptor, 1, Some(control)))
            }
            Mode::Independent => ServerTask::Independent(super::spawn_independent_observed(
                listener,
                acceptor,
                Some(control),
                second_control,
                collect_after,
                second_accept_after,
            )),
        };
        let abort = server.abort_handle();
        Ok(Self {
            identity,
            address,
            server: Some(server),
            abort: Some(abort),
            sender: None,
            driver: None,
            second_socket: None,
            observed,
            arm: Some(arm),
        })
    }

    async fn raw_request(&mut self) -> TestResult<()> {
        open_raw_request(
            &self.identity,
            self.address,
            &mut self.sender,
            &mut self.driver,
        )
        .await
    }

    async fn pending(&mut self) -> TestResult<()> {
        timeout(LIMIT, self.observed.wait_for(|state| state.closed_pending)).await??;
        if self.sender.is_none() || self.driver.as_ref().is_none_or(ConnectionPeer::is_finished) {
            return Err(
                "original H2 client was not held live during the pending server poll".into(),
            );
        }

        let child = self.observed.borrow().children.first().cloned();
        let witness = child
            .as_ref()
            .or(self.abort.as_ref())
            .ok_or("original reuse worker witness missing")?;
        if witness.is_finished() {
            return Err("original reuse worker finished before its pending close poll".into());
        }
        Ok(())
    }

    async fn pending_second(&mut self) -> TestResult<()> {
        self.pending().await?;
        timeout(
            LIMIT,
            self.observed
                .wait_for(|state| state.second_accept_pending && state.children.len() == 1),
        )
        .await??;
        if self
            .abort
            .as_ref()
            .ok_or("original coordinator witness missing")?
            .is_finished()
        {
            return Err("original coordinator finished before its pending second accept".into());
        }
        Ok(())
    }

    async fn finished(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.observed.wait_for(|state| state.destroyed),
        )
        .await??;
        let child = self.observed.borrow().children.first().cloned();
        let witness = child
            .as_ref()
            .or(self.abort.as_ref())
            .ok_or("original reuse worker witness missing")?;
        timeout(LIMIT, async {
            while !witness.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn closed(&mut self) -> TestResult<()> {
        self.finished().await?;
        if let Some(driver) = self.driver.as_mut() {
            let joined = timeout(LIMIT, driver).await?;
            self.driver.take();
            let result = joined?;
            match result {
                Ok(()) => {}
                Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn fail_read(&mut self) -> TestResult<()> {
        self.arm
            .take()
            .ok_or("original serving fault gate missing")?
            .send(())
            .map_err(|_| "original serving fault gate closed")?;
        timeout(LIMIT, self.observed.wait_for(|state| state.fault_taken)).await??;
        self.finished().await
    }

    async fn bad_second_tls(&mut self) -> TestResult<()> {
        self.second_socket = Some(timeout(LIMIT, TcpStream::connect(self.address)).await??);
        let stream = self
            .second_socket
            .as_mut()
            .ok_or("actual second TLS input socket missing")?;
        timeout(LIMIT, stream.write_all(b"not a TLS record\r\n")).await??;
        timeout(
            LIMIT,
            self.observed.wait_for(|state| state.second_accept_failed),
        )
        .await??;
        Ok(())
    }

    async fn invalid_header(&self) -> TestResult<RequestError> {
        let client = test_client(&self.identity, true)?;
        timeout(
            LIMIT,
            client
                .get(
                    HttpProtocol::Http2,
                    &format!("https://{}/invalid", self.address),
                )?
                .header(RequestHeader::new("X-Uppercase", "rejected"))
                .send(),
        )
        .await?
        .err()
        .ok_or_else(|| "actual invalid H2 caller unexpectedly succeeded".into())
    }

    async fn ordinary_result(&mut self, caller: TestResult<()>) -> TestResult<Requests> {
        let Some(ServerTask::Ordinary(server)) = self.server.take() else {
            return Err("original ordinary reuse server missing".into());
        };
        timeout(LIMIT, collect(caller, server)).await?
    }

    async fn independent_result(&mut self) -> TestResult<[Requests; 2]> {
        let Some(ServerTask::Independent(server)) = self.server.take() else {
            return Err("original independent reuse coordinator missing".into());
        };
        timeout(LIMIT, collect_independent(Ok(()), server)).await?
    }

    fn release_sender(&mut self) {
        drop(self.sender.take());
    }

    async fn stop(&mut self) -> TestResult<()> {
        let requested = self
            .abort
            .as_ref()
            .is_some_and(|abort| !abort.is_finished());
        if requested && let Some(abort) = &self.abort {
            abort.abort();
        }
        let children = self.observed.borrow().children.clone();
        for child in &children {
            if !child.is_finished() {
                child.abort();
            }
        }
        self.release_sender();
        drop(self.second_socket.take());

        let server = match self.server.take() {
            Some(ServerTask::Ordinary(mut server)) => match timeout(LIMIT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            Some(ServerTask::Independent(mut server)) => match timeout(LIMIT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None => Ok(()),
        };
        let witnesses = timeout(LIMIT, async {
            while self
                .abort
                .as_ref()
                .is_some_and(|abort| !abort.is_finished())
                || children.iter().any(|child| !child.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(Into::into);
        let server = finish_with_cleanup(server, witnesses);

        let driver = if let Some(mut driver) = self.driver.take() {
            let requested = !driver.is_finished();
            if requested {
                driver.abort();
            }
            match timeout(LIMIT, &mut driver).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(error))) if error.get_io().is_some_and(tls_support::is_peer_gone) => {
                    Ok(())
                }
                Ok(Ok(Err(error))) => Err(error.into()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        } else {
            Ok(())
        };
        finish_with_cleanup(server, driver)
    }
}

fn read_failure() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, FAILURE)
}

fn retains_h2_cause(error: &(dyn Error + 'static)) -> TestResult<()> {
    let original = error
        .downcast_ref::<::http2::Error>()
        .ok_or("original H2 server error type changed")?;
    let io = original
        .get_io()
        .ok_or("original H2 server I/O cause missing")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), FAILURE);
    Ok(())
}

async fn open_raw_request(
    identity: &TestIdentity,
    address: SocketAddr,
    sender: &mut Option<::http2::client::SendRequest<Bytes>>,
    driver: &mut Option<ConnectionPeer<Result<(), ::http2::Error>>>,
) -> TestResult<()> {
    let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::PEER);
    connector
        .cert_store_mut()
        .add_cert(X509::from_der(&identity.root_der)?)?;
    connector.set_alpn_protos(H2_ALPN)?;
    let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;
    let tcp = timeout(LIMIT, TcpStream::connect(address)).await??;
    let mut stream = SslStream::new(ssl, tcp)?;
    timeout(LIMIT, Pin::new(&mut stream).connect()).await??;
    let (ready, connection) = timeout(
        LIMIT,
        ::http2::client::Builder::new().handshake::<_, Bytes>(stream),
    )
    .await??;
    *driver = Some(ConnectionPeer::spawn(connection));
    *sender = Some(timeout(LIMIT, ready.ready()).await??);

    let request = Request::builder().uri("https://127.0.0.1/first").body(())?;
    let (response, upload) = sender
        .as_mut()
        .ok_or("original raw H2 sender missing")?
        .send_request(request, true)?;
    drop(upload);
    let response = timeout(LIMIT, response).await??;
    assert_eq!(response.status(), 204);
    assert!(timeout(LIMIT, response.into_body().data()).await?.is_none());
    Ok(())
}

mod children;
