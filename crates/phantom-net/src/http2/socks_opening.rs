//! A completed SOCKS tunnel whose origin protocol belongs to its claimant.

use super::{Http2Connection, Http2TlsConnector, Http2TlsError};
use crate::tcp::ProfileTcpStream;
use std::fmt;

/// A completed SOCKS tunnel that has sent no origin TLS or application bytes.
///
/// The original connector, target name and authenticated route are fixed when
/// this opening is created. Dropping it closes that tunnel. Claiming it never
/// repeats SOCKS authentication or changes the route.
pub struct Http2SocksOpening {
    state: Box<OpeningState>,
}
struct OpeningState {
    stream: ProfileTcpStream,
    connector: Http2TlsConnector,
    server_name: Box<str>,
}
impl fmt::Debug for Http2SocksOpening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2SocksOpening").finish_non_exhaustive()
    }
}
impl Http2SocksOpening {
    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http2TlsConnector,
        server_name: Box<str>,
    ) -> Self {
        Self {
            state: Box::new(OpeningState {
                stream,
                connector,
                server_name,
            }),
        }
    }

    /// Starts the ordinary origin protocol on this tunnel, without a request.
    ///
    /// # Errors
    ///
    /// Returns the original connector's TLS, ALPN and protocol errors.
    pub async fn finish(self) -> Result<Http2Connection, Http2TlsError> {
        let OpeningState {
            stream,
            connector,
            server_name,
        } = *self.state;
        connector.finish_socks_opening(stream, &server_name).await
    }

    /// Prepares verified extended CONNECT without sending WebSocket HEADERS.
    ///
    /// # Errors
    ///
    /// Invalid fields fail before origin TLS. Otherwise returns the existing
    /// origin TLS, ALPN and extended-CONNECT setup errors.
    pub async fn finish_extended_connect(
        self,
        authority: &str,
        target: crate::request::OriginForm,
        headers: Vec<crate::request::RequestHeader>,
    ) -> Result<crate::http2::Http2ExtendedConnectOpening, crate::http2::Http2TlsError> {
        let OpeningState {
            stream,
            connector,
            server_name,
        } = *self.state;
        connector
            .finish_socks_extended_connect(stream, &server_name, authority, target, headers)
            .await
    }
}
