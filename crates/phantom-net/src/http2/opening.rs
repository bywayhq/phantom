//! A connected WebSocket opening whose request has not been sent.

use std::fmt;

use phantom_profile::Http2Settings;

use super::{Http2Connection, Http2ExtendedConnectOutcome, Http2TlsError};
use crate::request::{OriginForm, RequestHeader};

/// A dedicated HTTP/2 connection and its validated extended CONNECT request.
///
/// The connection may still be settling TLS early data or awaiting peer
/// SETTINGS. No CONNECT HEADERS are sent until [`Self::send`]. Dropping the
/// opening releases its connection handle without sending the request.
#[must_use = "send or deliberately drop the connected opening"]
pub struct Http2ExtendedConnectOpening {
    connection: Http2Connection,
    settings: Http2Settings,
    authority: String,
    target: OriginForm,
    headers: Vec<RequestHeader>,
}

impl Http2ExtendedConnectOpening {
    pub(super) fn new(
        connection: Http2Connection,
        settings: Http2Settings,
        authority: String,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Self {
        Self {
            connection,
            settings,
            authority,
            target,
            headers,
        }
    }

    /// Returns the actual connected session without sending the opening.
    #[must_use]
    pub fn connection(&self) -> &Http2Connection {
        &self.connection
    }

    /// Sends the validated extended CONNECT after handshake and peer admission.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] for failed TLS early data, unsupported peer
    /// extended CONNECT, or stream failure. A non-success response is returned
    /// with its streaming body in [`Http2ExtendedConnectOutcome::Rejected`].
    pub async fn send(self) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        self.connection
            .send_extended_connect_with_settings(
                &self.settings,
                &self.authority,
                self.target,
                self.headers,
            )
            .await
            .map_err(|error| {
                self.connection
                    .early_data_failure()
                    .unwrap_or_else(|| error.into())
            })
    }
}

impl fmt::Debug for Http2ExtendedConnectOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2ExtendedConnectOpening")
            .field("connection", &self.connection)
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}
