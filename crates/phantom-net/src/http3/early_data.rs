//! Early (0-RTT) data state for one QUIC connection.

use tokio::sync::watch;

/// How the server answered a connection's early data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EarlyDataOutcome {
    /// The handshake completed and the server accepted the early data.
    Accepted,
    /// The handshake completed without the early data. The server processed
    /// none of it (RFC 9001, section 4.6.2), and Quinn reset every stream
    /// opened before the handshake.
    Rejected,
    /// The connection closed before its handshake completed. The server may
    /// have processed early data it received.
    Failed,
}

/// The pending or settled answer to a connection's early data.
#[derive(Clone)]
pub(super) struct EarlyData {
    outcome: watch::Receiver<Option<EarlyDataOutcome>>,
}

impl EarlyData {
    /// Records the server's answer once `accepted` resolves at handshake end.
    pub(super) fn spawn(connection: quinn::Connection, accepted: quinn::ZeroRttAccepted) -> Self {
        let (sender, outcome) = watch::channel(None);
        tokio::spawn(async move {
            let outcome = if accepted.await {
                EarlyDataOutcome::Accepted
            } else if connection.close_reason().is_none() {
                EarlyDataOutcome::Rejected
            } else {
                EarlyDataOutcome::Failed
            };
            let _ = sender.send(Some(outcome));
        });
        Self { outcome }
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
