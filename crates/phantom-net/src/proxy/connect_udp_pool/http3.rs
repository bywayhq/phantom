//! CONNECT-UDP stream setup on a route-owned isolated QUIC session.

use std::{net::SocketAddr, sync::Arc};

use http::Request;
use quinn::AsyncUdpSocket;
use tracing::Span;

use super::{Acquisition, ConnectUdpProxyPool, OuterSession, PoolKey};
use crate::http3::{
    ConnectUdpError, ConnectUdpErrorKind, Http3Connector,
    connect_udp::{self, OpenOutcome},
};

impl ConnectUdpProxyPool {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_http3(
        &self,
        key: PoolKey,
        initiator: &Http3Connector,
        proxy: &Http3Connector,
        host: &str,
        port: u16,
        anonymous: Request<()>,
        authenticated: Option<Request<()>>,
        span: Span,
    ) -> Result<(Arc<dyn AsyncUdpSocket>, SocketAddr), ConnectUdpError> {
        let mut acquisition = self.acquire(key).await?;
        let mut challenged = false;
        loop {
            match acquisition {
                Acquisition::Reuse {
                    session: OuterSession::Http3(outer),
                    authenticated: uses_credentials,
                    lease,
                } => {
                    // A validated challenge permits one fresh authenticated
                    // setup, never another anonymous request on a raced session.
                    if challenged && !uses_credentials {
                        acquisition = lease.retry().await?;
                        continue;
                    }
                    let request = if uses_credentials {
                        authenticated.clone().ok_or_else(missing_credentials)?
                    } else {
                        anonymous.clone()
                    };
                    connect_udp::record_attempts(&span, challenged);
                    match connect_udp::open(
                        outer,
                        request,
                        span.clone(),
                        !uses_credentials && authenticated.is_some(),
                    )
                    .await
                    .map_err(|error| {
                        if uses_credentials {
                            authentication_error(error)
                        } else {
                            error
                        }
                    })? {
                        OpenOutcome::Tunnel(socket, remote) => {
                            socket.retain_lease(lease);
                            return Ok((socket, remote));
                        }
                        OpenOutcome::Retry => {
                            challenged = true;
                            acquisition = lease.retry().await?;
                        }
                    }
                }
                Acquisition::Setup(setup) => {
                    let proxy = setup.http3_connector(proxy)?;
                    let mut established = None;
                    let result = async {
                        let mut outer = dial_outer(initiator, &proxy, host, port).await?;
                        established = Some(outer.clone());
                        let request = if challenged {
                            authenticated.clone().ok_or_else(missing_credentials)?
                        } else {
                            anonymous.clone()
                        };
                        connect_udp::record_attempts(&span, challenged);
                        let first = connect_udp::open(
                            outer.clone(),
                            request,
                            span.clone(),
                            !challenged && authenticated.is_some(),
                        )
                        .await?;
                        let (socket, remote, uses_credentials) = match first {
                            OpenOutcome::Tunnel(socket, remote) => (socket, remote, challenged),
                            OpenOutcome::Retry => {
                                // Authorization is permitted by this validated challenge,
                                // and its retry opens a fresh outer connection.
                                let request =
                                    authenticated.clone().ok_or_else(missing_credentials)?;
                                drop(outer);
                                established = None;
                                outer = dial_outer(initiator, &proxy, host, port).await?;
                                established = Some(outer.clone());
                                connect_udp::record_attempts(&span, true);
                                match connect_udp::open(outer.clone(), request, span.clone(), false)
                                    .await
                                {
                                    Ok(OpenOutcome::Tunnel(socket, remote)) => {
                                        (socket, remote, true)
                                    }
                                    Ok(OpenOutcome::Retry) => return Err(missing_credentials()),
                                    Err(error) => return Err(authentication_error(error)),
                                }
                            }
                        };
                        Ok((socket, remote, outer, uses_credentials))
                    }
                    .await;
                    match result {
                        Ok((socket, remote, outer, uses_credentials)) => {
                            socket.retain_lease(
                                setup.publish(OuterSession::Http3(outer), uses_credentials)?,
                            );
                            return Ok((socket, remote));
                        }
                        Err(error) => {
                            let error = if challenged {
                                authentication_error(error)
                            } else {
                                error
                            };
                            if let Some(outer) = established.filter(|outer| {
                                error.is_tunnel_reset() && proxy.can_reuse_now(outer)
                            }) {
                                // Keep a healthy outer after a stream reset without
                                // assuming that sent credentials were accepted.
                                drop(setup.publish(OuterSession::Http3(outer), false)?);
                            } else {
                                setup.fail(error.kind());
                            }
                            return Err(error);
                        }
                    }
                }
                Acquisition::Reuse { .. } => {
                    return Err(ConnectUdpError::new(
                        ConnectUdpErrorKind::Protocol,
                        "CONNECT-UDP pool protocol mismatch",
                    ));
                }
            }
        }
    }
}

fn missing_credentials() -> ConnectUdpError {
    ConnectUdpError::new(
        ConnectUdpErrorKind::Authentication,
        "CONNECT-UDP shared authentication requires validated credentials",
    )
}

fn authentication_error(error: ConnectUdpError) -> ConnectUdpError {
    if error.status() == Some(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED) {
        ConnectUdpError::authentication_rejected()
    } else {
        error
    }
}

async fn dial_outer(
    initiator: &Http3Connector,
    proxy: &Http3Connector,
    host: &str,
    port: u16,
) -> Result<crate::http3::Http3Connection, ConnectUdpError> {
    let offered_ticket = proxy.has_ticket_for(host);
    match initiator.connect_udp_outer(proxy, host, port).await {
        Err(error) if offered_ticket && error.kind() == ConnectUdpErrorKind::Handshake => {
            initiator
                .connect_udp_outer(&proxy.without_ticket_offers(), host, port)
                .await
        }
        result => result,
    }
}
