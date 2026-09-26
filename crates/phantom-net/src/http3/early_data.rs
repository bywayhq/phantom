//! Early (0-RTT) data state for one QUIC connection.

use std::future::Future;

use tokio::sync::{oneshot, watch};

use super::{Http3Error, Http3ErrorKind};

/// How the server answered a connection's early data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EarlyDataOutcome {
    /// The handshake completed, the server accepted the early data, and the
    /// handshake metadata passed the checks a normal connection applies.
    Accepted,
    /// The handshake completed without the early data. The server processed
    /// none of it (RFC 9001, section 4.6.2), and Quinn discarded every stream
    /// opened before the handshake. HTTP/3 then started again on the same
    /// connection, from the completed handshake's metadata and without the
    /// remembered SETTINGS, so requests can be sent on it again, as Chromium
    /// sends them.
    Rejected,
    /// The server accepted the early data, but the completed handshake
    /// carried metadata a normal connection would have refused before its
    /// first request. The connection was closed.
    Invalid(InvalidHandshake),
    /// The connection closed before its handshake completed. The server may
    /// have processed early data it received.
    Failed,
}

/// Handshake metadata an early-data connection could check only after it
/// had sent its first requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InvalidHandshake {
    /// The TLS metadata was missing or did not name the `h3` ALPN.
    Alpn,
    /// The peer's ALPS carried a malformed `ACCEPT_CH` frame or frame header.
    Alps,
    /// The peer's ALPS SETTINGS were invalid or conflicted with its
    /// control-stream SETTINGS.
    AlpsSettings,
}

impl InvalidHandshake {
    /// The error a normal connection reports for the same metadata.
    pub(super) const fn error(self) -> Http3Error {
        match self {
            Self::Alpn => Http3Error::without_source(
                Http3ErrorKind::Handshake,
                "QUIC TLS did not negotiate the required `h3` ALPN",
            ),
            Self::Alps => Http3Error::without_source(
                Http3ErrorKind::Protocol,
                "peer HTTP/3 ALPS metadata is invalid",
            ),
            Self::AlpsSettings => Http3Error::without_source(
                Http3ErrorKind::Protocol,
                "peer HTTP/3 application settings are invalid",
            ),
        }
    }
}

/// The pending or settled answer to a connection's early data.
#[derive(Clone)]
pub(super) struct EarlyData {
    outcome: watch::Receiver<Option<EarlyDataOutcome>>,
}

/// Publishes a connection's early-data answer to its [`EarlyData`].
pub(super) struct EarlyDataAnswer {
    sender: watch::Sender<Option<EarlyDataOutcome>>,
    #[cfg(test)]
    hold: Option<std::sync::Arc<tokio::sync::Semaphore>>,
}

impl EarlyData {
    /// Returns the unsettled answer and the handle that settles it.
    pub(super) fn channel() -> (EarlyDataAnswer, Self) {
        let (sender, outcome) = watch::channel(None);
        (
            EarlyDataAnswer {
                sender,
                #[cfg(test)]
                hold: None,
            },
            Self { outcome },
        )
    }

    /// Returns a receiver of the published answer, `None` until it settles.
    pub(super) fn subscribe(&self) -> watch::Receiver<Option<EarlyDataOutcome>> {
        self.outcome.clone()
    }

    /// Returns the answer if the handshake has ended.
    pub(super) fn settled(&self) -> Option<EarlyDataOutcome> {
        *self.outcome.borrow()
    }

    /// Waits for the handshake to end and returns the answer.
    pub(super) async fn outcome(&self) -> EarlyDataOutcome {
        let mut outcome = self.outcome.clone();
        match outcome.wait_for(Option::is_some).await {
            Ok(settled) => settled.unwrap_or(EarlyDataOutcome::Failed),
            Err(_) => EarlyDataOutcome::Failed,
        }
    }
}

impl EarlyDataAnswer {
    /// Publishes an answer known without waiting, as when the server
    /// rejected the early data before the early session had started.
    pub(super) fn publish(self, outcome: EarlyDataOutcome) {
        let _ = self.sender.send(Some(outcome));
    }

    /// Makes the connection take a permit from `hold` after Quinn's answer
    /// arrives and before the handshake metadata is checked or HTTP/3 starts
    /// again, for tests of requests sent in between.
    #[cfg(test)]
    pub(super) fn with_test_hold(
        mut self,
        hold: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    ) -> Self {
        self.hold = hold;
        self
    }

    /// Records the server's answer once the connection driver reports it at
    /// handshake end.
    ///
    /// When the server accepted the early data, `complete` checks and applies
    /// the handshake metadata before the answer is published, so a request
    /// that sees an accepted outcome also sees the peer's ALPS. When it
    /// rejected the early data, `restart` checks the same metadata and starts
    /// HTTP/3 again on the connection before the answer is published, so a
    /// request that sees a rejected outcome sends on the new session.
    pub(super) fn spawn<F, C, R, S>(
        self,
        connection: quinn::Connection,
        answer: oneshot::Receiver<bool>,
        complete: F,
        restart: R,
    ) where
        F: FnOnce() -> C + Send + 'static,
        C: Future<Output = EarlyDataOutcome> + Send,
        R: FnOnce() -> S + Send + 'static,
        S: Future<Output = EarlyDataOutcome> + Send,
    {
        let Self {
            sender,
            #[cfg(test)]
            hold,
        } = self;
        drop(tokio::spawn(async move {
            let answer = answer.await;
            #[cfg(test)]
            if let Some(hold) = &hold {
                let _ = hold.acquire().await;
            }
            let outcome = match answer {
                Ok(true) => complete().await,
                Ok(false) if connection.close_reason().is_none() => restart().await,
                Ok(false) | Err(_) => EarlyDataOutcome::Failed,
            };
            let _ = sender.send(Some(outcome));
        }));
    }
}
