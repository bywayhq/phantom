use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseInfo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    H1_ALPN, ORIGIN_NAME, Observed, Opening, Origin, Replayed, TEST_ECH_KEYS, TestResult,
    ech_acceptor, origin_identity,
};
use crate::support::tls::is_peer_gone;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct OriginObservation {
    pub(super) pending_handshake: Option<oneshot::Sender<()>>,
    destroyed: Option<oneshot::Sender<()>>,
}

impl Drop for OriginObservation {
    fn drop(&mut self) {
        if let Some(destroyed) = self.destroyed.take() {
            // The receiver can disappear when the controlling test is cancelled.
            let _ = destroyed.send(());
        }
    }
}

pub(super) async fn observe_pending_handshake(
    handshake: impl Future<Output = TestResult<(Observed, Option<SslStream<Replayed>>)>>,
    pending: oneshot::Sender<()>,
) -> TestResult<(Observed, Option<SslStream<Replayed>>)> {
    let mut handshake = Box::pin(handshake);
    let mut pending = Some(pending);
    poll_fn(|context| {
        let result = handshake.as_mut().poll(context);
        if result.is_pending()
            && let Some(pending) = pending.take()
        {
            // Backup cleanup may cancel the receiver while this worker is stopping.
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
    origin: Origin,
    client: Client,
    held_handshake: TcpStream,
    destroyed: oneshot::Receiver<()>,
    backup: OriginBackup,
}

enum StopOwner {
    Abandon,
    Abort,
}

#[tokio::test]
async fn abandoning_an_origin_stops_its_actual_pending_handshake() -> TestResult<()> {
    observe_owner_destruction(StopOwner::Abandon).await
}

#[tokio::test]
async fn explicitly_aborting_an_origin_destroys_its_actual_pending_handshake() -> TestResult<()> {
    observe_owner_destruction(StopOwner::Abort).await
}

async fn observe_owner_destruction(stop: StopOwner) -> TestResult<()> {
    timeout(Duration::from_secs(12), async {
        let DrivenOrigin {
            origin,
            client,
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
            "exact ECH origin outlived its abandoned owner during an active handshake"
        );

        let closed = socket_closed.ok_or("origin socket closure was not observed")??;
        match closed {
            Ok(0) => {}
            Err(error) if is_peer_gone(&error) => {}
            Ok(_) => return Err("origin sent unexpected data instead of closing".into()),
            Err(error) => return Err(error.into()),
        }

        drop(held_handshake);
        drop(client);
        Ok(())
    })
    .await?
}

async fn driven_origin() -> TestResult<DrivenOrigin> {
    let identity = origin_identity()?;
    let acceptor = ech_acceptor(&identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])?;
    let client = Client::builder(Opening::profile(false))
        .add_root_certificate_der(identity.root_der.clone())
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?;
    let (pending, wait_for_pending) = oneshot::channel();
    let (destroyed, wait_for_destruction) = oneshot::channel();
    let origin = Origin::spawn_observed(
        acceptor,
        vec![Opening::Http1; 2],
        Some(OriginObservation {
            pending_handshake: Some(pending),
            destroyed: Some(destroyed),
        }),
    )
    .await?;
    let backup = OriginBackup {
        abort: origin.task.abort_handle(),
    };

    let response = client
        .get(
            HttpProtocol::Http1,
            &format!("https://{ORIGIN_NAME}:{}/owner-ready", origin.port),
        )?
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

    let mut held_handshake = TcpStream::connect(origin.address()).await?;
    held_handshake.write_all(&[0x16]).await?;
    timeout(CONTROL_TIMEOUT, wait_for_pending).await??;

    Ok(DrivenOrigin {
        origin,
        client,
        held_handshake,
        destroyed: wait_for_destruction,
        backup,
    })
}
