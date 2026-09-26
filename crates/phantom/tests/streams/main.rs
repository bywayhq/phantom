//! `phantom-http` integration tests: WebSocket and server-sent event streams.
//!
//! Each module covers one area of the public API. `support` holds the loopback
//! servers and helpers that the crate's test binaries share.

#[path = "../support/mod.rs"]
mod support;

#[cfg(feature = "sse")]
mod sse;
#[cfg(feature = "sse")]
mod sse_browser_reconnect;
#[cfg(feature = "websocket")]
mod websocket;
#[cfg(feature = "websocket")]
mod websocket_http2;
#[cfg(feature = "websocket")]
mod websocket_http2_proxy;
#[cfg(feature = "websocket")]
mod websocket_profile;
#[cfg(feature = "websocket")]
mod websocket_trust;
