//! HTTP proxy negotiation.

mod error;
mod http_connect;
mod tunnel;

pub use error::{HttpConnectError, HttpConnectErrorKind};
pub use http_connect::{HttpConnectHeader, connect_http_tunnel, connect_http_tunnel_direct};
pub use tunnel::TunnelStream;

#[cfg(test)]
mod tests;
