//! A completed SOCKS tunnel whose origin protocol belongs to its claimant.

use super::{Http1Connection, Http1TlsConnector, Http1TlsError};
use crate::tcp::ProfileTcpStream;
use std::fmt;

/// A completed SOCKS tunnel that has sent no origin TLS or application bytes.
///
/// The original connector, target name and authenticated route are fixed when
/// this opening is created. Dropping it closes that tunnel. Claiming it never
/// repeats SOCKS authentication or changes the route.
pub struct Http1SocksOpening {
    state: Box<OpeningState>,
}
struct OpeningState {
    stream: ProfileTcpStream,
    connector: Http1TlsConnector,
    server_name: Option<Box<str>>,
}
impl fmt::Debug for Http1SocksOpening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http1SocksOpening").finish_non_exhaustive()
    }
}
impl Http1SocksOpening {
    pub(super) fn new(
        stream: ProfileTcpStream,
        connector: Http1TlsConnector,
        server_name: Option<Box<str>>,
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
    pub async fn finish(self) -> Result<Http1Connection, Http1TlsError> {
        let OpeningState {
            stream,
            connector,
            server_name,
        } = *self.state;
        connector
            .finish_socks_opening(stream, server_name.as_deref())
            .await
    }

    /// Prepares this claimant's Upgrade without sending its GET.
    ///
    /// # Errors
    ///
    /// Invalid ALPN or fields fail before origin TLS. Otherwise returns the
    /// existing origin TLS and HTTP/1 setup errors.
    pub async fn finish_upgrade(
        self,
        protocols: &[Box<[u8]>],
        target: crate::request::OriginForm,
        headers: Vec<crate::request::RequestHeader>,
    ) -> Result<crate::http1::Http1UpgradeOpening, crate::http1::Http1TlsError> {
        let OpeningState {
            stream,
            connector,
            server_name,
        } = *self.state;
        connector
            .with_alpn_protocols(protocols)?
            .finish_socks_upgrade(stream, server_name.as_deref(), target, headers)
            .await
    }
}
