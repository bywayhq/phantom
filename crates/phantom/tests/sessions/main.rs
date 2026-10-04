//! Integration tests of `phantom-http`, one module per area of the public API.
//!
//! Covers name resolution, connection reuse, pooling, and negotiation across
//! requests.
//!
//! `support` holds the loopback servers and helpers that the crate's test
//! binaries share.

#[path = "../support/mod.rs"]
mod support;

mod dns_overrides;
mod early_data_server;
mod http2_connections;
mod http3_connections;
mod negotiated;
mod negotiated_parallel;
mod runtimes;
mod session;
mod session_http1;
mod session_http1_parallel;
mod session_http2_authority;
mod session_http2_idle;
mod session_http2_lifecycle;
mod session_http3;
mod session_tcp_early_data;
mod session_tls_resumption;
#[cfg(feature = "websocket")]
mod websocket_resumption;
