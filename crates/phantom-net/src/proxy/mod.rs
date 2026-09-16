//! Proxy negotiation and tunneled byte streams.

mod error;
mod http_connect;
mod socks5;
mod tunnel;

pub use error::{HttpConnectError, HttpConnectErrorKind};
pub use http_connect::{HttpConnectHeader, connect_http_tunnel, connect_http_tunnel_direct};
pub use socks5::{Socks5Error, Socks5ErrorKind, connect_socks5_tunnel_direct};
pub use tunnel::TunnelStream;

#[cfg(test)]
mod tests;
