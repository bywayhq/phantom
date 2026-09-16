//! Network protocol implementations for Phantom.

mod direct;
pub mod http1;
pub mod http2;
/// Direct HTTP/3 transactions over the BoringSSL-backed QUIC provider.
pub mod http3;
pub mod request;
mod shutdown_timer;
pub(crate) mod tls;

#[cfg(test)]
mod tracing_test;
