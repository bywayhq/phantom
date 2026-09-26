//! `phantom-http` integration tests: one request through the public client: fields, bodies, redirects, retries, and timeouts.
//!
//! Each module covers one area of the public API. `support` holds the loopback
//! servers and helpers that the crate's test binaries share.

#[path = "../support/mod.rs"]
mod support;

mod client;
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
mod plaintext_templates;
mod redirects;
mod request_templates;
mod stale_connection_replay;
mod status_retry;
mod timeouts;
mod unprocessed_replay;
