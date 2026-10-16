//! Owned SOCKS route data and target selection; no target failure witness.
use super::{
    super::{
        Socks4Error, Socks4ErrorKind, Socks4UserId, Socks5Auth, Socks5Error, Socks5ErrorKind,
        socks4, socks5,
    },
    SocksConnectionError,
};
use crate::{
    host_resolver::{HostResolver, resolve_tcp},
    route::{Endpoint, Socks4Target, Socks5Target, TcpRoute},
    tcp::ProfileTcpStream,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub(super) enum Target {
    Address(SocketAddr),
    Remote(Box<str>, u16),
}
impl Target {
    pub(super) fn ipv6(&self) -> Option<bool> {
        match self {
            Self::Address(a) => Some(a.is_ipv6()),
            Self::Remote(..) => None,
        }
    }
}
enum Authentication {
    Four(Zeroizing<String>),
    FiveNone,
    Five(Zeroizing<String>, Zeroizing<String>),
}
pub(super) struct OwnedRoute {
    pub(super) proxy_host: Box<str>,
    pub(super) proxy_port: u16,
    target_host: Box<str>,
    target_port: u16,
    remote: bool,
    auth: Authentication,
}
impl OwnedRoute {
    pub(super) fn new(route: &TcpRoute<'_>) -> Result<Self, SocksConnectionError> {
        let (proxy, target, remote, auth) = match route {
            TcpRoute::Socks4 {
                proxy,
                target,
                user_id,
            } => {
                let (target, remote) = match target {
                    Socks4Target::LocalDns(t) => (*t, false),
                    Socks4Target::RemoteDns(t) => (*t, true),
                };
                socks4::validate_target(target)?;
                (
                    *proxy,
                    target,
                    remote,
                    Authentication::Four(Zeroizing::new(user_id.as_str().to_owned())),
                )
            }
            TcpRoute::Socks5 {
                proxy,
                target,
                auth,
            } => {
                let (target, remote) = match target {
                    Socks5Target::LocalDns(t) => (*t, false),
                    Socks5Target::RemoteDns(t) => (*t, true),
                };
                socks5::prepare_target(target.host, target.port)?;
                let auth = match auth.validate()? {
                    Socks5Auth::None => Authentication::FiveNone,
                    Socks5Auth::UsernamePassword { username, password } => Authentication::Five(
                        Zeroizing::new(username.to_owned()),
                        Zeroizing::new(password.to_owned()),
                    ),
                };
                (*proxy, target, remote, auth)
            }
            _ => return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget).into()),
        };
        Ok(Self {
            proxy_host: proxy.host.into(),
            proxy_port: proxy.port,
            target_host: target.host.into(),
            target_port: target.port,
            remote,
            auth,
        })
    }
    pub(super) fn four(&self) -> bool {
        matches!(self.auth, Authentication::Four(_))
    }
    pub(super) fn runtime_error(&self) -> SocksConnectionError {
        if self.four() {
            Socks4Error::new(Socks4ErrorKind::RuntimeUnavailable).into()
        } else {
            Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable).into()
        }
    }
    pub(super) fn connect_error(&self, source: io::Error) -> SocksConnectionError {
        SocksConnectionError::BeforeConnect {
            four: self.four(),
            source,
        }
    }
    pub(super) fn physical_connect_error(&self, source: io::Error) -> SocksConnectionError {
        if self.four() {
            Socks4Error::io(Socks4ErrorKind::Connect, source).into()
        } else {
            Socks5Error::connect(source).into()
        }
    }
    fn resolve_error(&self, e: io::Error) -> SocksConnectionError {
        if self.four() {
            Socks4Error::io(Socks4ErrorKind::Resolve, e).into()
        } else {
            Socks5Error::resolve(e).into()
        }
    }
    pub(super) async fn resolve(
        &self,
        resolver: Option<&HostResolver>,
    ) -> Result<Vec<Target>, SocksConnectionError> {
        if let Ok(ip) = self.target_host.parse::<IpAddr>() {
            return Ok(vec![Target::Address(SocketAddr::new(ip, self.target_port))]);
        }
        if self.remote {
            return Ok(vec![Target::Remote(
                self.target_host.clone(),
                self.target_port,
            )]);
        }
        let addresses = resolve_tcp(resolver, &self.target_host, self.target_port)
            .await
            .map_err(|e| self.resolve_error(e))?;
        let mut cursor = addresses.cursor();
        let mut targets = Vec::new();
        let mut saw_address = false;
        while let Some(candidate) = cursor.next() {
            let address = candidate.address();
            saw_address = true;
            // No logical target witness is ever reported by proxy/auth/TLS errors.
            if self.four() {
                if let IpAddr::V4(ip) = address.ip() {
                    socks4::validate_ipv4(ip.octets())?;
                    targets.push(Target::Address(address));
                    break;
                }
            } else if !targets
                .iter()
                .any(|t| matches!(t,Target::Address(old) if *old==address))
            {
                targets.push(Target::Address(address))
            }
        }
        if targets.is_empty() {
            if self.four() {
                return Err(Socks4Error::new(if saw_address {
                    Socks4ErrorKind::UnsupportedTarget
                } else {
                    Socks4ErrorKind::Resolve
                })
                .into());
            }
            return Err(Socks5Error::without_source(Socks5ErrorKind::Resolve).into());
        }
        Ok(targets)
    }
    pub(super) async fn establish(
        &self,
        stream: ProfileTcpStream,
        target: &Target,
    ) -> Result<ProfileTcpStream, SocksConnectionError> {
        match &self.auth {
            Authentication::Four(user) => {
                let endpoint = Endpoint {
                    host: &self.target_host,
                    port: self.target_port,
                };
                let encoded = match target {
                    Target::Address(SocketAddr::V4(a)) => (a.ip().octets(), None),
                    Target::Address(SocketAddr::V6(_)) => {
                        return Err(Socks4Error::new(Socks4ErrorKind::UnsupportedTarget).into());
                    }
                    Target::Remote(..) => socks4::encoded_address(endpoint)?,
                };
                socks4::establish(stream, self.target_port, encoded, Socks4UserId::new(user)?)
                    .await
                    .map_err(Into::into)
            }
            Authentication::FiveNone | Authentication::Five(..) => {
                let auth = match &self.auth {
                    Authentication::Five(u, p) => Socks5Auth::UsernamePassword {
                        username: u,
                        password: p,
                    },
                    _ => Socks5Auth::None,
                };
                match target {
                    Target::Address(a) => {
                        socks5::establish(stream, tokio_socks::TargetAddr::Ip(*a), auth).await
                    }
                    Target::Remote(name, port) => {
                        socks5::establish(stream, socks5::prepare_target(name, *port)?, auth).await
                    }
                }
                .map_err(Into::into)
            }
        }
    }
}
