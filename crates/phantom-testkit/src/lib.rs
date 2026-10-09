//! Deterministic wire-capture helpers used by Phantom tests.
//!
//! Capture protocol bytes and compare retained request records in local tests.

#![doc = include_str!("../README.md")]

/// A scripted loopback DNS responder that records queries.
pub mod dns;

/// Sizes of async functions' futures, for tests that bound a call's stack use.
pub mod future_size;

/// Bounded HTTP/1 request heads and retained request expectations.
pub mod http1;

/// Helpers for capturing an HTTP/2 client connection preface and initial frames.
pub mod http2;

/// A loopback TCP port that refuses connections until a test listens on it.
pub mod tcp;

/// Helpers for capturing TLS wire data.
pub mod tls;

/// UDP sockets for loopback test peers that survive a Windows reserved port
/// block.
pub mod udp;
