use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, mpsc},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::{Instant, timeout_at},
};

use super::super::super::EntryConnections;
use crate::session::prune_timer::PruneTimer;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
pub(super) const WAIT: Duration = Duration::from_secs(10);

pub(super) struct PruneRace {
    tasks: JoinSet<TestResult>,
    release_lock: Option<mpsc::Sender<()>>,
    release_peer: Option<oneshot::Sender<()>>,
}

impl PruneRace {
    pub(super) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            release_lock: None,
            release_peer: None,
        }
    }

    pub(super) async fn origin(
        &mut self,
        reconnects: bool,
    ) -> TestResult<(SocketAddr, oneshot::Receiver<()>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (closed, observed_close) = oneshot::channel();
        let (release, released) = oneshot::channel();
        self.release_peer = Some(release);
        self.tasks.spawn(async move {
            let (mut priming, _) = listener.accept().await?;
            let head = read_head(&mut priming).await?;
            if !head.starts_with(b"GET /prime HTTP/1.1\r\n") {
                return Err("actual origin did not receive the literal priming path".into());
            }

            priming
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            priming.flush().await?;
            let mut byte = [0_u8; 1];
            match priming.read(&mut byte).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    ) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("expired priming socket carried another request".into()),
            }

            closed
                .send(())
                .map_err(|()| io::Error::other("expired-socket observer dropped"))?;
            if reconnects {
                let (mut held, _) = listener.accept().await?;
                let head = read_head(&mut held).await?;
                if !head.starts_with(b"GET /held HTTP/1.1\r\n") {
                    return Err("actual origin did not receive the literal held path".into());
                }

                held.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                    .await?;
                held.flush().await?;
                released.await?;
                drop(held);
            }

            Ok(())
        });
        Ok((address, observed_close))
    }

    pub(super) async fn sweep(
        &mut self,
        timer: Arc<PruneTimer>,
        barrier: Arc<EntryConnections>,
    ) -> TestResult<oneshot::Receiver<()>> {
        let (release, released) = mpsc::channel();
        let (locked, observed_lock) = oneshot::channel();
        self.release_lock = Some(release);
        self.tasks.spawn_blocking(move || {
            let guard = barrier.lock();
            locked
                .send(())
                .map_err(|()| io::Error::other("pool-lock observer dropped"))?;
            released.recv_timeout(WAIT)?;
            drop(guard);
            Ok(())
        });
        observed_lock.await?;

        let (swept, observed_sweep) = oneshot::channel();
        self.tasks.spawn_blocking(move || {
            timer.fire();
            swept
                .send(())
                .map_err(|()| io::Error::other("prune-completion observer dropped"))?;
            Ok(())
        });
        Ok(observed_sweep)
    }

    pub(super) fn resume(&mut self) -> TestResult {
        if let Some(release) = self.release_lock.take() {
            release.send(())?;
        }

        Ok(())
    }

    pub(super) async fn finish(mut self, outcome: TestResult) -> TestResult {
        let mut outcome = combine(outcome, self.resume());
        if let Some(release) = self.release_peer.take() {
            // A prime-only worker may already have returned; its original
            // result is collected below regardless of this stop signal.
            let _ = release.send(());
        }

        let deadline = Instant::now() + WAIT;
        while !self.tasks.is_empty() {
            match timeout_at(deadline, self.tasks.join_next()).await {
                Ok(Some(Ok(result))) => outcome = combine(outcome, result),
                Ok(Some(Err(error))) => outcome = combine(outcome, Err(error.into())),
                Ok(None) => break,
                Err(elapsed) => {
                    outcome = combine(outcome, Err(elapsed.into()));
                    self.tasks.abort_all();
                    break;
                }
            }
        }

        if !self.tasks.is_empty() {
            let deadline = Instant::now() + WAIT;
            while !self.tasks.is_empty() {
                match timeout_at(deadline, self.tasks.join_next()).await {
                    Ok(Some(Ok(result))) => outcome = combine(outcome, result),
                    Ok(Some(Err(error))) => outcome = combine(outcome, Err(error.into())),
                    Ok(None) => break,
                    Err(elapsed) => {
                        outcome = combine(outcome, Err(elapsed.into()));
                        break;
                    }
                }
            }
        }

        outcome
    }
}

impl Drop for PruneRace {
    fn drop(&mut self) {
        if let Some(release) = self.release_lock.take() {
            // Drop cannot report cleanup; explicit finish collects results.
            let _ = release.send(());
        }

        if let Some(release) = self.release_peer.take() {
            let _ = release.send(());
        }

        self.tasks.abort_all();
    }
}

async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "prune race request head exceeded bound",
            ));
        }

        head.push(stream.read_u8().await?);
    }

    Ok(head)
}

fn combine(primary: TestResult, cleanup: TestResult) -> TestResult {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Box::new(PruneFailures { primary, cleanup })),
    }
}

#[derive(Debug)]
struct PruneFailures {
    primary: Box<dyn Error + Send + Sync>,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for PruneFailures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; prune race cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for PruneFailures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}
