//! Proxy negotiation and tunneled byte streams.

mod authentication;
mod connect_udp;
mod error;
mod http2_connect;
mod http_connect;
mod https_connect;
mod socks5;
mod socks5_udp;
mod tunnel;

pub use authentication::{HttpBasicCredentials, validate_basic_proxy_challenge};
pub(crate) use connect_udp::PreparedConnectUdp;
pub use error::{HttpConnectError, HttpConnectErrorKind};
pub use http_connect::{
    HttpConnectHeader, connect_http_tunnel, connect_http_tunnel_direct,
    connect_http_tunnel_direct_with_basic_auth,
};
pub use https_connect::{HttpsProxyConnector, HttpsProxyProtocol};
pub use socks5::{
    Socks5Auth, Socks5Error, Socks5ErrorKind, connect_socks5_tunnel_direct,
    connect_socks5_tunnel_direct_with_auth, connect_socks5_tunnel_local,
    connect_socks5_tunnel_local_with_auth,
};
pub(crate) use socks5_udp::{
    associate_socks5_udp_local_with_auth, associate_socks5_udp_remote_with_auth,
    prepare_socks5_udp_remote_target,
};
pub use tunnel::TunnelStream;

#[cfg(test)]
mod tests;
