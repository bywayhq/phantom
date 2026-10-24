//! A connected HTTP/1.1 Upgrade whose request has not been sent.

use std::fmt;

use tracing::{Instrument, Span};

use super::{Http1TlsError, Http1UpgradeOutcome, OperationOutcome, PreparedGet};
use crate::{tcp::ProfileTcpStream, tls::TlsStream};

/// A validated Upgrade GET and its connected origin transport.
///
/// Dropping this opening closes its transport without sending the GET.
/// Use [`Self::send`] after separately retaining any slower connection.
pub struct Http1UpgradeOpening {
    stream: OpeningStream,
    prepared: PreparedGet,
    span: Span,
    outcome: OperationOutcome,
    strategy: super::Http1WriteStrategy,
}

pub(super) enum OpeningStream {
    Plaintext(ProfileTcpStream),
    Connected(crate::connection_leg::ConnectionLeg),
    Tls(TlsStream<ProfileTcpStream>),
    ProxyTls(TlsStream<crate::connection_leg::ConnectionLeg>),
}

impl fmt::Debug for Http1UpgradeOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1UpgradeOpening")
            .field(
                "encrypted",
                &matches!(
                    self.stream,
                    OpeningStream::Tls(_) | OpeningStream::ProxyTls(_)
                ),
            )
            .finish_non_exhaustive()
    }
}

impl Http1UpgradeOpening {
    pub(super) fn new(
        strategy: super::Http1WriteStrategy,
        stream: OpeningStream,
        prepared: PreparedGet,
        span: Span,
        outcome: OperationOutcome,
    ) -> Self {
        Self {
            stream,
            prepared,
            span,
            outcome,
            strategy,
        }
    }

    /// Sends the prepared GET and waits for its Upgrade or rejection response.
    ///
    /// # Errors
    ///
    /// Returns the existing TLS, response framing and HTTP/1 exchange errors.
    pub async fn send(self) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        let Self {
            stream,
            prepared,
            span,
            outcome,
            strategy,
        } = self;
        let result = async move {
            match stream {
                OpeningStream::Connected(stream) => {
                    super::tls::send_plaintext_tunnel_upgrade(strategy, stream, prepared).await
                }
                OpeningStream::Plaintext(stream) => {
                    super::tls::send_plaintext_tunnel_upgrade(strategy, stream, prepared).await
                }
                OpeningStream::Tls(stream) => {
                    super::tls::upgrade_over_tls(strategy, stream, prepared).await
                }
                OpeningStream::ProxyTls(stream) => {
                    super::tls::upgrade_over_tls(strategy, stream, prepared).await
                }
            }
        }
        .instrument(span)
        .await;
        outcome.finish(super::tls::upgrade_outcome(&result));
        result
    }
}
