//! Complete SOCKS attempts and their quiet retained connection.
use super::{Socks4Error, Socks4ErrorKind, Socks5Error, Socks5ErrorKind};
use crate::{
    direct::Dialer,
    route::TcpRoute,
    tcp::{AddressFamilyMemory, ProfileTcpStream, SlowerProgress},
};
use phantom_profile::TcpBackupConnection;
use std::{
    error::Error as _, fmt, future::Future, io, pin::Pin, sync::Arc, task::Poll, time::Instant,
};
use targets::{OwnedRoute, Target};
mod scheduler;
mod targets;

#[derive(Debug)]
pub(crate) enum SocksConnectionError {
    Four(Socks4Error),
    Five(Socks5Error),
    AttemptTimeout(bool),
    BeforeConnect { four: bool, source: io::Error },
}
impl SocksConnectionError {
    fn retry_target(&self) -> bool {
        matches!(self, Self::Five(error) if error.is_target_specific_rejection())
            || matches!(self, Self::AttemptTimeout(_))
    }
    fn terminal(&self) -> bool {
        let source = match self {
            Self::Four(error) if error.kind() == Socks4ErrorKind::Connect => error.source(),
            Self::Five(error) if error.kind() == Socks5ErrorKind::Connect => error.source(),
            _ => return !self.retry_target(),
        };
        // Refusal/timeout ends this physical proxy walk. An already-started
        // complete sibling may still win, without advancing this target.
        // Configuration, DNS and feedback resource errors cannot be hidden by it.
        !source
            .and_then(|source| source.downcast_ref::<io::Error>())
            .is_some_and(crate::tcp::is_refusal_or_timeout)
    }
    pub(crate) fn into_leg(self) -> crate::connection_leg::ConnectionLegError {
        use crate::connection_leg::ConnectionLegError;
        match self {
            Self::Four(error) => ConnectionLegError::Socks4(error),
            Self::Five(error) => ConnectionLegError::Socks5(error),
            Self::BeforeConnect { four, source } => {
                if four {
                    ConnectionLegError::Socks4(Socks4Error::io(Socks4ErrorKind::Connect, source))
                } else {
                    ConnectionLegError::Socks5(Socks5Error::connect(source))
                }
            }
            Self::AttemptTimeout(four) => {
                let source = io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the complete SOCKS backup attempt timed out",
                );
                if four {
                    ConnectionLegError::Socks4(Socks4Error::io(
                        Socks4ErrorKind::Negotiation,
                        source,
                    ))
                } else {
                    ConnectionLegError::Socks5(Socks5Error::io(
                        Socks5ErrorKind::Negotiation,
                        source,
                    ))
                }
            }
        }
    }
}
impl From<Socks4Error> for SocksConnectionError {
    fn from(e: Socks4Error) -> Self {
        Self::Four(e)
    }
}
impl From<Socks5Error> for SocksConnectionError {
    fn from(e: Socks5Error) -> Self {
        Self::Five(e)
    }
}

/// All data a losing attempt uses is owned; secrets retain zeroizing storage.
struct Setup {
    route: OwnedRoute,
    tcp: Option<phantom_profile::TcpSettings>,
    source: Option<crate::SourceBinding>,
    resolver: Option<crate::host_resolver::HostResolver>,
    proxy_dns_feedback: phantom_profile::SocksProxyDnsFeedback,
}
impl Setup {
    fn dialer(&self) -> Dialer<'_> {
        Dialer {
            tcp: self.tcp,
            udp: None,
            source: self.source.as_ref(),
            resolver: self.resolver.as_ref(),
        }
    }
    async fn connect(
        &self,
        target: &Target,
        started: Instant,
    ) -> Result<ProfileTcpStream, SocksConnectionError> {
        let route = &self.route;
        let stream = crate::tcp::connect_socks_proxy_sequential(
            &route.proxy_host,
            route.proxy_port,
            self.dialer(),
            started,
            self.proxy_dns_feedback,
        )
        .await
        .map_err(|e| match e {
            crate::tcp::SocksProxyConnectError::BeforeConnect(e) => route.connect_error(e),
            crate::tcp::SocksProxyConnectError::Connect(e) => {
                tracing::debug!(error_kind=?e.kind(),"SOCKS physical proxy connect failed");
                route.physical_connect_error(e)
            }
        })?;
        route.establish(stream, target).await
    }
}

/// The losing logical attempt, polled alongside origin TLS without a task.
pub(crate) struct SocksSlower {
    progress: SlowerProgress,
    state: SlowerState,
}
enum SlowerState {
    Pending(Pin<Box<dyn Future<Output = Option<ProfileTcpStream>> + Send>>),
    Ready(Option<ProfileTcpStream>),
}
impl SocksSlower {
    fn new(walk: scheduler::Walk, setup: Arc<Setup>, memory: AddressFamilyMemory) -> Self {
        let progress = SlowerProgress::new();
        let signal = progress.clone();
        Self {
            progress,
            state: SlowerState::Pending(Box::pin(async move {
                let connected = walk.finish(setup).await.ok()?;
                connected.remember(&memory);
                signal.mark_connected();
                Some(connected.stream)
            })),
        }
    }
    pub(crate) fn progress(&self) -> SlowerProgress {
        self.progress.clone()
    }
    pub(crate) async fn alongside<F: Future>(&mut self, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|cx| {
            if let SlowerState::Pending(pending) = &mut self.state
                && let Poll::Ready(stream) = pending.as_mut().poll(cx)
            {
                self.state = SlowerState::Ready(stream);
            }
            future.as_mut().poll(cx)
        })
        .await
    }
    pub(crate) async fn finish(self) -> Option<ProfileTcpStream> {
        match self.state {
            SlowerState::Pending(future) => future.await,
            SlowerState::Ready(stream) => stream,
        }
    }
}
impl fmt::Debug for SocksSlower {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksSlower")
            .field("connected", &self.progress.has_connected())
            .finish_non_exhaustive()
    }
}

pub(crate) async fn connect_retaining(
    dialer: Dialer<'_>,
    route: TcpRoute<'_>,
    family: &AddressFamilyMemory,
    backup: TcpBackupConnection,
) -> Result<(ProfileTcpStream, Option<SocksSlower>), SocksConnectionError> {
    let route = OwnedRoute::new(&route)?;
    crate::tcp::check_settings(dialer.tcp.as_ref(), dialer.source)
        .map_err(|e| route.connect_error(e))?;
    tokio::runtime::Handle::try_current().map_err(|_| route.runtime_error())?;
    let started = Instant::now();
    let targets = route.resolve(dialer.resolver).await?;
    let setup = Arc::new(Setup {
        route,
        tcp: dialer.tcp,
        source: dialer.source.cloned(),
        resolver: dialer.resolver.cloned(),
        proxy_dns_feedback: backup.socks_proxy_dns_feedback,
    });
    scheduler::connect(setup, targets, family, backup, started).await
}

#[cfg(test)]
mod tests;
