//! Deterministic wire-capture helpers used by Phantom tests.
//!
//! The crate captures protocol bytes without interpreting browser identity or
//! providing production networking abstractions.

/// Helpers for capturing an HTTP/2 client connection preface and initial frames.
pub mod http2;

/// Helpers for capturing TLS wire data.
pub mod tls;
