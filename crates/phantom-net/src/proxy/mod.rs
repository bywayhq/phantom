//! Proxy negotiation and tunneled byte streams.

mod authentication;
mod error;
mod http_connect;
mod https_connect;
mod socks5;
mod tunnel;

pub use authentication::{HttpBasicCredentials, validate_basic_proxy_challenge};
pub use error::{HttpConnectError, HttpConnectErrorKind};
pub use http_connect::{
    HttpConnectHeader, connect_http_tunnel, connect_http_tunnel_direct,
    connect_http_tunnel_direct_with_basic_auth,
};
pub use https_connect::HttpsProxyConnector;
pub use socks5::{
    Socks5Auth, Socks5Error, Socks5ErrorKind, connect_socks5_tunnel_direct,
    connect_socks5_tunnel_direct_with_auth, connect_socks5_tunnel_local,
    connect_socks5_tunnel_local_with_auth,
};
pub use tunnel::TunnelStream;

#[cfg(test)]
mod tests;
