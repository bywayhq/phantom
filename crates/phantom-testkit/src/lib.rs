//! Deterministic wire-capture helpers used by Phantom tests.
//!
//! The crate captures protocol bytes without interpreting browser identity or
//! providing production networking abstractions.

/// Helpers for capturing TLS wire data.
pub mod tls;
