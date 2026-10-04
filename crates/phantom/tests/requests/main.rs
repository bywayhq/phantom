//! Integration tests of `phantom-http`, one module per area of the public API.
//!
//! Covers one request through the public client: fields, bodies, redirects,
//! retries, and timeouts.
//!
//! `support` holds the loopback servers and helpers that the crate's test
//! binaries share.

#[path = "../support/mod.rs"]
mod support;

mod client;
mod client_certificates;
mod client_hints;
mod connection_retries;
mod content_coding;
#[cfg(feature = "cookies")]
mod cookie_crumbs;
#[cfg(feature = "cookies")]
mod cookies;
#[cfg(feature = "diagnostics")]
mod diagnostics;
mod direct_http;
mod expect_continue;
mod ping_failure_replay;
mod plaintext_templates;
mod redirects;
mod request_templates;
mod send_futures;
mod source_binding;
mod stale_connection_replay;
mod status_retry;
mod timeouts;
mod trust_anchor_orders;
mod unprocessed_replay;
