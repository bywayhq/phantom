use std::{error::Error, fmt, future::Future, io};

use tokio::{sync::watch, task::JoinSet};

use super::{TestResult, finish_with_cleanup};

pub(super) enum PumpEnd {
    InputEnded,
    PeerClosed,
    OutputEnded,
}

#[derive(Debug)]
pub(super) struct UnexpectedReset(pub(super) ::http2::Reason);

impl fmt::Display for UnexpectedReset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unexpected CONNECT-UDP response reset: {}",
            self.0
        )
    }
}

impl Error for UnexpectedReset {}

pub(super) async fn stopped(receiver: &mut watch::Receiver<bool>) -> TestResult<()> {
    loop {
        if *receiver.borrow_and_update() {
            return Ok(());
        }

        receiver.changed().await?;
    }
}

pub(super) fn peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

pub(super) fn h2_peer_closed(error: &::http2::Error) -> bool {
    error.get_io().is_some_and(peer_gone)
        || (error.is_remote()
            && ((error.is_reset() && error.reason() == Some(::http2::Reason::CANCEL))
                || (error.is_go_away() && error.reason() == Some(::http2::Reason::NO_ERROR))))
}

/// The two or three protocol pumps stay owned while the inline UDP relay runs.
pub(super) async fn relay(
    mut pumps: JoinSet<TestResult<PumpEnd>>,
    future: impl Future<Output = TestResult<()>>,
    mut stopping: watch::Receiver<bool>,
) -> TestResult<()> {
    tokio::pin!(future);
    let primary = loop {
        tokio::select! {
            biased;
            result = &mut future => break result,
            completed = pumps.join_next(), if !pumps.is_empty() => {
                match completed {
                    Some(Ok(Ok(PumpEnd::InputEnded | PumpEnd::OutputEnded))) => {}
                    Some(Ok(Ok(PumpEnd::PeerClosed))) => break Ok(()),
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(error.into()),
                    None => break Err("MASQUE relay pump disappeared".into()),
                }
            }
            stopped = stopped(&mut stopping) => break stopped,
        }
    };

    // Only cancellations requested here are normal cleanup. Already-completed
    // protocol or I/O errors still arrive unchanged through join_next.
    pumps.abort_all();
    let mut cleanup = Ok(());
    while let Some(completed) = pumps.join_next().await {
        let result = match completed {
            Ok(result) => result.map(|_| ()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        };
        cleanup = finish_with_cleanup(cleanup, result);
    }

    finish_with_cleanup(primary, cleanup)
}
