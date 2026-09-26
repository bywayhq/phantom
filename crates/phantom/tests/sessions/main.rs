//! `phantom-http` integration tests: name resolution, connection reuse, pooling, and negotiation across requests.
//!
//! Each module covers one area of the public API. `support` holds the loopback
//! servers and helpers that the crate's test binaries share.

#[path = "../support/mod.rs"]
mod support;

mod dns_overrides;
mod http2_connections;
mod negotiated;
mod negotiated_parallel;
mod session;
mod session_http1;
mod session_http1_parallel;
mod session_http2_authority;
mod session_http2_lifecycle;
mod session_http3;
mod session_tls_resumption;
