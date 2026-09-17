//! Network protocol implementations for Phantom.

mod accept_ch;
mod direct;
pub mod http1;
/// One-handshake HTTP/1.1 or HTTP/2 selection over TLS ALPN.
pub mod http1_or_2;
pub mod http2;
/// Direct HTTP/3 transactions over the BoringSSL-backed QUIC provider.
pub mod http3;
/// HTTP proxy negotiation and tunneled byte streams.
pub mod proxy;
pub mod request;
mod response;
mod shutdown_timer;
pub(crate) mod tls;

pub use response::{OrderedResponseHeaders, ResponseHeader};
pub use tls::ServerAuthentication;

#[cfg(test)]
mod tracing_test;
