use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseInfo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{ORIGIN_NAME, Observed, QuicOrigin, TEST_ECH_KEYS, origin_identity, profile};
use crate::support::{
    ech::{Observed as HandshakeObserved, Replayed},
    tls::{TestResult, is_peer_gone},
    tunnel_proxy::connection_peer::finish_with_cleanup,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct OriginObservation {
    pub(super) quic: TaskObservation,
    pub(super) tcp: TcpObservation,
}

pub(super) struct TcpObservation {
    pub(super) parent: TaskObservation,
    pub(super) children: std::vec::IntoIter<HandshakeObservation>,
}

pub(super) struct TaskObservation {
    pub(super) started: watch::Sender<Option<AbortHandle>>,
    destroyed: watch::Sender<bool>,
}

impl TaskObservation {
    fn new() -> (Self, TaskControl) {
        let started = watch::Sender::new(None);
        let (destroyed, receiver) = watch::channel(false);
        (
            Self {
                started: started.clone(),
                destroyed,
            },
            TaskControl {
                started,
                destroyed: receiver,
            },
        )
    }
}

impl Drop for TaskObservation {
    fn drop(&mut self) {
        // Cancellation of the controlling test can remove its receiver.
        let _ = self.destroyed.send(true);
    }
}

pub(super) struct HandshakeObservation {
    pub(super) task: TaskObservation,
    pending: Option<oneshot::Sender<()>>,
}

pub(super) async fn observe_handshake(
    handshake: impl Future<Output = TestResult<(HandshakeObserved, Option<SslStream<Replayed>>)>>,
    observation: Option<&mut HandshakeObservation>,
) -> TestResult<(HandshakeObserved, Option<SslStream<Replayed>>)> {
    let Some(observation) = observation else {
        return handshake.await;
    };

    let mut handshake = Box::pin(handshake);
    let mut pending = observation.pending.take();
    poll_fn(|context| {
        let result = handshake.as_mut().poll(context);
        if result.is_pending()
            && let Some(pending) = pending.take()
        {
            // Backup cleanup may already have cancelled the controller.
            let _ = pending.send(());
        }

        result
    })
    .await
}

struct TaskControl {
    started: watch::Sender<Option<AbortHandle>>,
    destroyed: watch::Receiver<bool>,
}

impl TaskControl {
    fn handle(&self) -> TestResult<AbortHandle> {
        self.started
            .borrow()
            .as_ref()
            .cloned()
            .ok_or_else(|| "actual origin task handle was not published".into())
    }

    async fn finished(&mut self) -> TestResult<()> {
        let handle = self.handle()?;
        timeout(CONTROL_TIMEOUT, async {
            self.destroyed.wait_for(|destroyed| *destroyed).await?;
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }

            Ok::<_, watch::error::RecvError>(())
        })
        .await??;
        Ok(())
    }

    fn pending(&self) -> TestResult<()> {
        if self.handle()?.is_finished() || *self.destroyed.borrow() {
            return Err("held TCP handshake task was already destroyed".into());
        }

        Ok(())
    }
}

struct OriginBackup {
    // QUIC parent, TCP parent, successful prime, then both held TCP children.
    tasks: [TaskControl; 5],
}

impl OriginBackup {
    fn new() -> (Self, OriginObservation, [oneshot::Receiver<()>; 2]) {
        let (quic, quic_control) = TaskObservation::new();
        let (tcp, tcp_control) = TaskObservation::new();
        let (prime, prime_control) = TaskObservation::new();
        let (first, first_control) = TaskObservation::new();
        let (second, second_control) = TaskObservation::new();
        let (first_pending, first_receiver) = oneshot::channel();
        let (second_pending, second_receiver) = oneshot::channel();
        let children = vec![
            HandshakeObservation {
                task: prime,
                pending: None,
            },
            HandshakeObservation {
                task: first,
                pending: Some(first_pending),
            },
            HandshakeObservation {
                task: second,
                pending: Some(second_pending),
            },
        ]
        .into_iter();

        (
            Self {
                tasks: [
                    quic_control,
                    tcp_control,
                    prime_control,
                    first_control,
                    second_control,
                ],
            },
            OriginObservation {
                quic,
                tcp: TcpObservation {
                    parent: tcp,
                    children,
                },
            },
            [first_receiver, second_receiver],
        )
    }

    fn abort(&self) {
        for task in &self.tasks {
            if let Some(handle) = task.started.borrow().as_ref() {
                handle.abort();
            }
        }
    }

    async fn finished(&mut self, indices: &[usize]) -> TestResult<()> {
        for &index in indices {
            self.tasks[index].finished().await?;
        }

        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.abort();
        let mut outcome = Ok(());
        for task in &mut self.tasks {
            let acquired = task.started.borrow().is_some();
            if acquired {
                outcome = finish_with_cleanup(outcome, task.finished().await);
            }
        }

        outcome
    }
}

impl Drop for OriginBackup {
    fn drop(&mut self) {
        self.abort();
    }
}

enum StopOwner {
    Healthy,
    Abandon,
    Finish,
}

struct BeforeBackup {
    children: TestResult<()>,
    parents: TestResult<()>,
    sockets: Vec<TestResult<()>>,
    finished: Option<(Vec<Observed>, usize)>,
    _held_peers: Vec<TcpStream>,
    _client: Client,
}

#[tokio::test]
async fn finishing_a_tcp_origin_preserves_its_actual_http1_response() -> TestResult<()> {
    observe_owner_shutdown(StopOwner::Healthy).await
}

#[tokio::test]
async fn abandoning_an_origin_stops_its_actual_pending_tcp_children() -> TestResult<()> {
    observe_owner_shutdown(StopOwner::Abandon).await
}

#[tokio::test]
async fn finishing_an_origin_stops_its_actual_pending_tcp_children() -> TestResult<()> {
    observe_owner_shutdown(StopOwner::Finish).await
}

async fn observe_owner_shutdown(stop: StopOwner) -> TestResult<()> {
    let (mut backup, observation, pending) = OriginBackup::new();
    let outcome = match timeout(
        Duration::from_secs(12),
        drive_origin(stop, observation, pending, &mut backup),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => Err(error.into()),
    };
    let observed = finish_with_cleanup(outcome, backup.stop().await)?;

    assert!(
        observed.children.is_ok(),
        "actual TCP children outlived their origin before backup: {:?}",
        observed.children
    );
    observed.parents?;
    for socket in observed.sockets {
        socket?;
    }

    if let Some((quic, served)) = observed.finished {
        assert!(quic.is_empty());
        assert_eq!(served, 1);
    }

    Ok(())
}

async fn drive_origin(
    stop: StopOwner,
    observation: OriginObservation,
    mut pending: [oneshot::Receiver<()>; 2],
    backup: &mut OriginBackup,
) -> TestResult<BeforeBackup> {
    let identity = origin_identity()?;
    let origin =
        QuicOrigin::spawn_with_tcp_observed(&identity, 1, &TEST_ECH_KEYS[0], Some(observation))
            .await?;
    let client = Client::builder(profile(false))
        .add_root_certificate_der(identity.root_der.clone())
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?;

    let response = client
        .get(HttpProtocol::Http1, &origin.url("/tcp-owner-ready"))?
        .send()
        .await?;
    if response.status() != StatusCode::OK || response.version() != Version::HTTP_11 {
        return Err("origin did not serve the actual HTTP/1 prime".into());
    }

    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("actual HTTP/1 prime omitted response metadata")?;
    if info.protocol() != HttpProtocol::Http1 {
        return Err("actual HTTP/1 prime used another protocol".into());
    }

    if response.into_body().collect().await?.to_bytes().as_ref() != b"ok" {
        return Err("actual HTTP/1 prime returned another body".into());
    }
    backup.finished(&[2]).await?;

    let mut held_peers = Vec::new();
    if !matches!(stop, StopOwner::Healthy) {
        for (index, pending) in pending.iter_mut().enumerate() {
            let mut peer = timeout(
                CONTROL_TIMEOUT,
                TcpStream::connect((Ipv4Addr::LOCALHOST, origin.port)),
            )
            .await??;
            peer.write_all(&[0x16]).await?;
            timeout(CONTROL_TIMEOUT, pending).await??;
            backup.tasks[index + 3].pending()?;
            held_peers.push(peer);
        }
    }

    let finished = match stop {
        StopOwner::Abandon => {
            drop(origin);
            None
        }
        StopOwner::Healthy | StopOwner::Finish => {
            Some(timeout(CONTROL_TIMEOUT, origin.finish(0, 1)).await??)
        }
    };
    let children = if held_peers.is_empty() {
        backup.finished(&[2]).await
    } else {
        backup.finished(&[3, 4]).await
    };
    let parents = backup.finished(&[0, 1]).await;
    let mut sockets = Vec::new();
    if children.is_ok() {
        for peer in &mut held_peers {
            sockets.push(observe_socket_closed(peer).await);
        }
    }

    Ok(BeforeBackup {
        children,
        parents,
        sockets,
        finished,
        _held_peers: held_peers,
        _client: client,
    })
}

async fn observe_socket_closed(peer: &mut TcpStream) -> TestResult<()> {
    match timeout(CONTROL_TIMEOUT, peer.read(&mut [0_u8; 1])).await? {
        Ok(0) => Ok(()),
        Err(error) if is_peer_gone(&error) => Ok(()),
        Ok(_) => Err("held TCP peer received data instead of closing".into()),
        Err(error) => Err(error.into()),
    }
}
