use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseInfo};
use phantom_testkit::dns::DnsServer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    ORIGIN_NAME, Observed, PUBLIC_NAME, Replayed, TEST_ECH_KEYS, TestResult, client, ech_acceptor,
    ech_config, ech_config_list, https_rdata, spawn_observed_origin,
};
use crate::support::{
    ech::{origin_identity, record_server},
    tls::is_peer_gone,
    tunnel_proxy::ConnectionPeer,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct OriginObservation {
    pub(super) pending_handshake: Option<oneshot::Sender<()>>,
    destroyed: Option<oneshot::Sender<()>>,
}

impl Drop for OriginObservation {
    fn drop(&mut self) {
        if let Some(destroyed) = self.destroyed.take() {
            // The receiver may be cancelled while backup cleanup stops the worker.
            let _ = destroyed.send(());
        }
    }
}

pub(super) async fn observe_pending_handshake(
    handshake: impl Future<Output = TestResult<(Observed, SslStream<Replayed>)>>,
    pending: oneshot::Sender<()>,
) -> TestResult<(Observed, SslStream<Replayed>)> {
    let mut handshake = Box::pin(handshake);
    let mut pending = Some(pending);
    poll_fn(|context| {
        let result = handshake.as_mut().poll(context);
        if result.is_pending()
            && let Some(pending) = pending.take()
        {
            // Cancellation can close the controlling receiver before the worker.
            let _ = pending.send(());
        }

        result
    })
    .await
}

struct OriginBackup {
    abort: AbortHandle,
}

impl Drop for OriginBackup {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

struct DrivenOrigin {
    origin: ConnectionPeer<TestResult<Vec<Observed>>>,
    client: Client,
    dns: DnsServer,
    held_handshake: TcpStream,
    destroyed: oneshot::Receiver<()>,
    backup: OriginBackup,
}

enum StopOwner {
    Abandon,
    Abort,
}

#[tokio::test]
async fn abandoning_a_negotiated_origin_stops_its_actual_pending_handshake() -> TestResult<()> {
    observe_owner_destruction(StopOwner::Abandon).await
}

#[tokio::test]
async fn explicitly_aborting_a_negotiated_origin_destroys_its_actual_pending_handshake()
-> TestResult<()> {
    observe_owner_destruction(StopOwner::Abort).await
}

async fn observe_owner_destruction(stop: StopOwner) -> TestResult<()> {
    timeout(Duration::from_secs(12), async {
        let DrivenOrigin {
            origin,
            client,
            dns,
            mut held_handshake,
            mut destroyed,
            backup,
        } = driven_origin().await?;

        if matches!(stop, StopOwner::Abort) {
            backup.abort.abort();
        }

        drop(origin);
        let before_backup = timeout(CONTROL_TIMEOUT, &mut destroyed).await;
        let socket_closed = if matches!(&before_backup, Ok(Ok(()))) {
            Some(timeout(CONTROL_TIMEOUT, held_handshake.read(&mut [0_u8; 1])).await)
        } else {
            None
        };

        backup.abort.abort();
        if before_backup.is_err() {
            timeout(CONTROL_TIMEOUT, &mut destroyed).await??;
        }

        let destroyed_before_backup = match before_backup {
            Ok(result) => {
                result?;
                true
            }
            Err(_) => false,
        };
        assert!(
            destroyed_before_backup,
            "negotiated ECH origin outlived its abandoned owner during an active handshake"
        );

        let closed = socket_closed.ok_or("negotiated origin socket closure was not observed")??;
        match closed {
            Ok(0) => {}
            Err(error) if is_peer_gone(&error) => {}
            Ok(_) => return Err("negotiated origin sent unexpected data instead of closing".into()),
            Err(error) => return Err(error.into()),
        }

        drop(held_handshake);
        drop(client);
        drop(dns);
        Ok(())
    })
    .await?
}

async fn driven_origin() -> TestResult<DrivenOrigin> {
    let identity = origin_identity()?;
    let acceptor = ech_acceptor(&identity)?;
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let rdata = https_rdata(&ech_config_list(std::slice::from_ref(&config)));
    let dns = record_server(vec![rdata]).await?;
    let client = client(&identity, &dns)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (pending, wait_for_pending) = oneshot::channel();
    let (destroyed, wait_for_destruction) = oneshot::channel();
    let origin = spawn_observed_origin(
        listener,
        acceptor,
        2,
        Some(OriginObservation {
            pending_handshake: Some(pending),
            destroyed: Some(destroyed),
        }),
    );
    let backup = OriginBackup {
        abort: origin.abort_handle(),
    };

    let response = client
        .get_negotiated(&format!(
            "https://{ORIGIN_NAME}:{}/owner-ready",
            address.port()
        ))?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(
        response
            .extensions()
            .get::<ResponseInfo>()
            .map(ResponseInfo::protocol),
        Some(HttpProtocol::Http1)
    );
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

    let mut held_handshake = TcpStream::connect(address).await?;
    held_handshake.write_all(&[0x16]).await?;
    timeout(CONTROL_TIMEOUT, wait_for_pending).await??;

    Ok(DrivenOrigin {
        origin,
        client,
        dns,
        held_handshake,
        destroyed: wait_for_destruction,
        backup,
    })
}
