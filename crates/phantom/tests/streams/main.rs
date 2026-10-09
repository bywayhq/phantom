//! Integration tests of `phantom-http`, one module per area of the public API.
//!
//! Covers WebSocket and server-sent event streams.
//!
//! `support` holds the loopback servers and helpers that the crate's test
//! binaries share.

#[path = "../support.rs"]
mod support;

#[cfg(any(feature = "sse", feature = "websocket"))]
mod environment_routes;

#[cfg(feature = "sse")]
mod sse;
#[cfg(feature = "sse")]
mod sse_browser_reconnect;
#[cfg(feature = "websocket")]
mod websocket;
#[cfg(feature = "websocket")]
mod websocket_handshake;
#[cfg(feature = "websocket")]
mod websocket_http2;
#[cfg(feature = "websocket")]
mod websocket_http2_proxy;
#[cfg(feature = "websocket")]
mod websocket_http3;
#[cfg(feature = "websocket")]
mod websocket_profile;
#[cfg(feature = "websocket")]
mod websocket_trust;
