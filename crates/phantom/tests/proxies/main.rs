//! Integration tests of `phantom-http`, one module per area of the public API.
//!
//! Covers HTTP CONNECT, forwarding, and SOCKS5 proxy routes.
//!
//! `support` holds the loopback servers and helpers that the crate's test
//! binaries share.

#[path = "../support/mod.rs"]
mod support;

mod forward_proxy;
mod negotiated_proxy;
mod proxy;
mod proxy_credential_cache;
mod proxy_field_order;
mod proxy_h2;
mod proxy_h2_multiplex;
mod socks5;
mod socks5_local;
