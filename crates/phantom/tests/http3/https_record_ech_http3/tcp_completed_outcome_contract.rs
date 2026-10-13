use std::{
    future::poll_fn, net::Ipv4Addr, panic::resume_unwind, pin::Pin, sync::Arc, task::Poll,
    time::Duration,
};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseInfo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{oneshot, watch},
    task::{AbortHandle, Id, JoinError},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{ORIGIN_NAME, QuicOrigin, TEST_ECH_KEYS, origin_identity, profile};
use crate::support::{
    ech::{Observed as HandshakeObserved, Replayed},
    tls::{TestResult, is_peer_gone},
    tunnel_proxy::connection_peer::finish_with_cleanup,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

struct PanicMarker;

enum WorkerFault {
    Hold,
    Panic {
        release: oneshot::Receiver<()>,
        marker: Arc<PanicMarker>,
    },
}

pub(super) struct PendingWorker {
    pub(super) started: watch::Sender<Option<AbortHandle>>,
    pending: Option<oneshot::Sender<()>>,
    destroyed: Option<oneshot::Sender<()>>,
    fault: WorkerFault,
}

impl Drop for PendingWorker {
    fn drop(&mut self) {
        if let Some(destroyed) = self.destroyed.take() {
            // A failed controller may have already dropped its witness receiver.
            let _ = destroyed.send(());
        }
    }
}

pub(super) fn take_ready(
    receiver: &mut Option<oneshot::Receiver<PendingWorker>>,
) -> Option<PendingWorker> {
    match receiver.as_mut()?.try_recv() {
        Ok(worker) => {
            drop(receiver.take());
            Some(worker)
        }
        Err(oneshot::error::TryRecvError::Empty) => None,
        Err(oneshot::error::TryRecvError::Closed) => {
            drop(receiver.take());
            None
        }
    }
}

pub(super) async fn observe_handshake(
    handshake: impl Future<Output = TestResult<(HandshakeObserved, Option<SslStream<Replayed>>)>>,
    observation: Option<PendingWorker>,
) -> TestResult<(HandshakeObserved, Option<SslStream<Replayed>>)> {
    let Some(mut observation) = observation else {
        return handshake.await;
    };

    let mut handshake = Box::pin(handshake);
    poll_fn(|context| {
        let result = handshake.as_mut().poll(context);
        if result.is_pending() {
            if let Some(pending) = observation.pending.take() {
                // Backup may already have removed the controlling test.
                let _ = pending.send(());
            }

            if let WorkerFault::Panic { release, marker } = &mut observation.fault {
                match Pin::new(release).poll(context) {
                    Poll::Ready(Ok(())) => resume_unwind(Box::new(Arc::clone(marker))),
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err("controlled panic release closed".into()));
                    }
                    Poll::Pending => {}
                }
            }
        }

        result
    })
    .await
}

#[derive(Clone, Copy)]
enum CompletedExit {
    Healthy,
    Cancel,
    Panic,
}

struct Backup {
    tasks: Vec<AbortHandle>,
}

impl Backup {
    fn retain_origin(&mut self, origin: &QuicOrigin) {
        self.tasks.push(origin.task.abort_handle());
        if let Some(tcp) = &origin.tcp {
            self.tasks.push(tcp.task.abort_handle());
        }
    }

    async fn stop(&self) -> TestResult<()> {
        for task in &self.tasks {
            task.abort();
        }

        timeout(CONTROL_TIMEOUT, async {
            while self.tasks.iter().any(|task| !task.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        Ok(())
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

enum OwnerOutcome {
    Healthy { quic: usize, served: usize },
    Cancelled { task: Id },
    Panicked { task: Id, marker: Arc<PanicMarker> },
}

struct BeforeBackup {
    outcome: OwnerOutcome,
    child: Option<Id>,
    tasks_finished: bool,
    socket_closed: TestResult<()>,
    _peer: Option<TcpStream>,
    _client: Client,
}

#[tokio::test]
async fn an_empty_observation_preserves_the_actual_http1_prime() -> TestResult<()> {
    observe_completed_exit(CompletedExit::Healthy).await
}

#[tokio::test]
async fn finishing_an_origin_retains_its_completed_external_child_cancellation() -> TestResult<()> {
    observe_completed_exit(CompletedExit::Cancel).await
}

#[tokio::test]
async fn finishing_an_origin_retains_its_completed_child_panic_payload() -> TestResult<()> {
    observe_completed_exit(CompletedExit::Panic).await
}

async fn observe_completed_exit(exit: CompletedExit) -> TestResult<()> {
    let mut backup = Backup { tasks: Vec::new() };
    let marker = Arc::new(PanicMarker);
    let outcome = match timeout(
        Duration::from_secs(12),
        drive_completed_exit(exit, Arc::clone(&marker), &mut backup),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => Err(error.into()),
    };
    let observed = finish_with_cleanup(outcome, backup.stop().await)?;

    assert!(
        observed.tasks_finished,
        "observed origin tasks were not finished before backup"
    );

    observed.socket_closed?;

    match (exit, observed.outcome) {
        (CompletedExit::Healthy, OwnerOutcome::Healthy { quic, served }) => {
            assert_eq!(quic, 0);
            assert_eq!(served, 1);
            assert!(observed.child.is_none());
        }
        (CompletedExit::Cancel, OwnerOutcome::Cancelled { task }) => {
            assert_eq!(Some(task), observed.child);
        }
        (
            CompletedExit::Panic,
            OwnerOutcome::Panicked {
                task,
                marker: actual,
            },
        ) => {
            assert_eq!(Some(task), observed.child);
            assert!(
                Arc::ptr_eq(&actual, &marker),
                "owner replaced the exact panic marker"
            );
        }
        _ => return Err("origin discarded or changed its completed child failure".into()),
    }

    Ok(())
}

async fn drive_completed_exit(
    exit: CompletedExit,
    marker: Arc<PanicMarker>,
    backup: &mut Backup,
) -> TestResult<BeforeBackup> {
    let (observe, observation) = oneshot::channel();
    let identity = origin_identity()?;
    let origin = QuicOrigin::spawn_with_tcp_completed_observed(
        &identity,
        1,
        &TEST_ECH_KEYS[0],
        None,
        Some(observation),
    )
    .await?;
    backup.retain_origin(&origin);

    let client = Client::builder(profile(false))
        .add_root_certificate_der(identity.root_der.clone())
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?;
    let response = client
        .get(HttpProtocol::Http1, &origin.url("/completed-child-ready"))?
        .send()
        .await?;
    let protocol = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("actual HTTP/1 prime omitted response metadata")?
        .protocol();

    if response.status() != StatusCode::OK
        || response.version() != Version::HTTP_11
        || protocol != HttpProtocol::Http1
    {
        return Err("origin did not serve the actual HTTP/1 prime".into());
    }

    if response.into_body().collect().await?.to_bytes().as_ref() != b"ok" {
        return Err("actual HTTP/1 prime returned another body".into());
    }

    let mut child = None;
    let mut held = None;
    if !matches!(exit, CompletedExit::Healthy) {
        let (started, mut actual_task) = watch::channel(None);
        let (pending, became_pending) = oneshot::channel();
        let (destroyed, was_destroyed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let fault = match exit {
            CompletedExit::Panic => WorkerFault::Panic {
                release: released,
                marker,
            },
            CompletedExit::Cancel => WorkerFault::Hold,
            CompletedExit::Healthy => return Err("healthy control requested a held child".into()),
        };
        observe
            .send(PendingWorker {
                started,
                pending: Some(pending),
                destroyed: Some(destroyed),
                fault,
            })
            .map_err(|_| "healthy prime discarded the still-empty worker observation")?;

        let mut peer = timeout(
            CONTROL_TIMEOUT,
            TcpStream::connect((Ipv4Addr::LOCALHOST, origin.port)),
        )
        .await??;
        peer.write_all(&[0x16]).await?;
        let handle = timeout(CONTROL_TIMEOUT, actual_task.wait_for(Option::is_some))
            .await??
            .as_ref()
            .cloned()
            .ok_or("actual child AbortHandle was not published")?;
        backup.tasks.push(handle.clone());
        timeout(CONTROL_TIMEOUT, became_pending).await??;

        if handle.is_finished() {
            return Err("actual pending TCP child had already finished".into());
        }

        match exit {
            CompletedExit::Cancel => handle.abort(),
            CompletedExit::Panic => release
                .send(())
                .map_err(|_| "actual pending panic gate closed")?,
            CompletedExit::Healthy => return Err("healthy control requested a child fault".into()),
        }
        timeout(CONTROL_TIMEOUT, was_destroyed).await??;
        timeout(CONTROL_TIMEOUT, async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        child = Some(handle.id());
        held = Some(peer);
    }

    let result = timeout(CONTROL_TIMEOUT, origin.finish(0, 1)).await?;
    let outcome = match result {
        Ok((quic, served)) => OwnerOutcome::Healthy {
            quic: quic.len(),
            served,
        },
        Err(error) => {
            let error = error
                .downcast::<JoinError>()
                .map_err(|error| format!("owner changed the actual child JoinError: {error}"))?;
            let task = error.id();
            if error.is_cancelled() {
                OwnerOutcome::Cancelled { task }
            } else {
                if !error.is_panic() {
                    return Err("actual child failure was neither cancellation nor panic".into());
                }

                let payload = error.try_into_panic().map_err(|error| {
                    format!("child failure was neither cancellation nor panic: {error}")
                })?;
                let marker = payload
                    .downcast::<Arc<PanicMarker>>()
                    .map_err(|_| "owner changed the typed child panic payload")?;
                OwnerOutcome::Panicked {
                    task,
                    marker: *marker,
                }
            }
        }
    };

    let tasks_finished = backup.tasks.iter().all(AbortHandle::is_finished);
    let socket_closed = match held.as_mut() {
        Some(peer) => observe_socket_closed(peer).await,
        None => Ok(()),
    };

    Ok(BeforeBackup {
        outcome,
        child,
        tasks_finished,
        socket_closed,
        _peer: held,
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
