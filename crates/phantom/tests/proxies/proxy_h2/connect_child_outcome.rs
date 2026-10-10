//! Completed relay outcomes at the ordinary CONNECT caller cleanup boundary.

use std::{error::Error, io, net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, HttpProxy, Route};
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

use super::{
    H1_ALPN, H2Proxy, Reply, TaskProbe, TaskRole, TestIdentity, TestResult, accept_tls,
    client_builder, connection_tasks::stop_optional, read_head, relay_contract::Fault,
    relay_upstream, serve_connects_recorded,
};

const DEADLINE: Duration = Duration::from_secs(5);

pub(super) struct RelayReadObservation {
    pub(super) fault: Fault,
    pub(super) accepted: Option<oneshot::Sender<(Method, String, u16)>>,
    pub(super) completed: oneshot::Sender<Option<(io::ErrorKind, String)>>,
}

impl RelayReadObservation {
    pub(super) fn accepted(
        &mut self,
        method: Method,
        authority: String,
        status: u16,
    ) -> TestResult<()> {
        self.accepted
            .take()
            .ok_or("CONNECT observation was already sent")?
            .send((method, authority, status))
            .map_err(|_| io::Error::other("CONNECT observation receiver disappeared"))?;
        Ok(())
    }

    pub(super) async fn relay(
        self,
        read: impl AsyncRead + Unpin,
        send: ::http2::SendStream<Bytes>,
    ) -> TestResult<()> {
        // This seam injects a read fault; it is not an operating-system failure.
        let read = super::super::proxy_h2_multiplex::outcome_contract::ReadFailure {
            inner: read,
            fault: Some(self.fault),
        };
        let outcome = relay_upstream(read, send).await;
        let actual = outcome.as_ref().err().and_then(|error| {
            error
                .downcast_ref::<io::Error>()
                .map(|error| (error.kind(), error.to_string()))
        });
        let observation: TestResult<()> = self.completed.send(actual).map_err(|_| {
            io::Error::other("completed relay observation receiver disappeared").into()
        });
        finish_with_cleanup(outcome, observation)
    }
}

#[tokio::test]
async fn ordinary_caller_cleanup_keeps_its_completed_connect_relay_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let origin_acceptor = identity.acceptor(H1_ALPN)?;
    let (uri, root, proxy_acceptor, proxy_listener) = H2Proxy::bind().await?.into_parts()?;
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let fault = Fault::default();
    let (accepted, connect_observed) = oneshot::channel();
    let (completed, relay_completed) = oneshot::channel();
    let observation = RelayReadObservation {
        fault: fault.clone(),
        accepted: Some(accepted),
        completed,
    };

    let origin = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
        assert_eq!(
            timeout(DEADLINE, read_head(&mut stream)).await??,
            format!("GET /held HTTP/1.1\r\nHost: {origin_address}\r\n\r\n").as_bytes()
        );
        timeout(
            DEADLINE,
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        )
        .await??;
        std::future::pending::<()>().await;
        drop(stream);
        TestResult::<()>::Ok(())
    });
    let probe = TaskProbe::default();
    let relay_probe = probe.clone();
    let peer = probe.spawn(TaskRole::ProxyConnection, async move {
        let (tcp, _) = proxy_listener.accept().await?;
        serve_connects_recorded(
            tcp,
            &proxy_acceptor,
            vec![Reply::Tunnel(origin_address), Reply::Status(502)],
            Some(relay_probe),
            Some(observation),
        )
        .await
    });

    let prerequisites: TestResult<()> = async {
        let response = timeout(
            DEADLINE,
            client
                .get(
                    HttpProtocol::Http1,
                    &format!("https://{origin_address}/held"),
                )?
                .send(),
        )
        .await??;
        assert_eq!(response.status(), 200);
        assert_eq!(
            timeout(DEADLINE, response.into_body().collect())
                .await??
                .to_bytes(),
            "ok"
        );

        assert_eq!(
            timeout(DEADLINE, connect_observed).await??,
            (Method::CONNECT, origin_address.to_string(), 200)
        );
        assert!(
            !origin.is_finished(),
            "actual pooled origin was not held open"
        );
        assert!(
            !peer.is_finished(),
            "actual server did not await another CONNECT"
        );

        fault.enable()?;
        let actual = timeout(DEADLINE, relay_completed)
            .await??
            .ok_or("completed actual relay did not retain its injected I/O cause")?;
        assert_eq!(actual.0, io::ErrorKind::PermissionDenied);
        assert_eq!(actual.1, "controlled postexchange relay I/O");
        timeout(DEADLINE, async {
            while probe.live().contains(&TaskRole::RelayUpstream) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(fault.observations(), 1);
        assert!(probe.live().contains(&TaskRole::ProxyConnection));
        assert!(
            !peer.is_finished(),
            "relay completion also ended the serving owner"
        );
        Ok(())
    }
    .await;

    // Capture completion before stopping the real serving owner. Keep the client
    // live until all explicit cleanup has run, so client Drop cannot prove it.
    let reached_cleanup = prerequisites.is_ok();
    let primary: TestResult<()> = prerequisites.and_then(|()| {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "caller after literal CONNECT and origin response",
        )
        .into())
    });
    let observed = finish_with_cleanup(primary, stop_optional(Some(peer)).await);
    let cleanup = finish_with_cleanup(probe.backup().await, origin.stop().await);
    drop(client);
    if !reached_cleanup {
        return finish_with_cleanup(observed, cleanup);
    }

    let assertions: TestResult<()> = (|| {
        let error = observed
            .err()
            .ok_or("completed relay and caller failure became success")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("ordinary caller cleanup discarded its completed CONNECT relay failure")?;
        let primary = failures
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("caller primary lost its I/O type")?;
        assert_eq!(primary.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            primary.to_string(),
            "caller after literal CONNECT and origin response"
        );
        let relay = permission_denied(failures.cleanup.as_ref())
            .ok_or("completed relay cleanup lost its PermissionDenied cause")?;
        assert_eq!(relay.to_string(), "controlled postexchange relay I/O");
        Ok(())
    })();
    finish_with_cleanup(assertions, cleanup)
}

fn permission_denied<'a>(error: &'a (dyn Error + 'static)) -> Option<&'a io::Error> {
    if let Some(error) = error.downcast_ref::<io::Error>() {
        return (error.kind() == io::ErrorKind::PermissionDenied).then_some(error);
    }
    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return permission_denied(failures.primary.as_ref())
            .or_else(|| permission_denied(failures.cleanup.as_ref()));
    }
    error.source().and_then(permission_denied)
}
