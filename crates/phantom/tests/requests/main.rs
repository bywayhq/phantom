//! Integration tests of `phantom-http`, one module per area of the public API.
//!
//! Covers one request through the public client: fields, bodies, redirects,
//! retries, and timeouts.
//!
//! `support` holds the loopback servers and helpers that the crate's test
//! binaries share.

#[path = "../support.rs"]
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
mod custom_connector;
mod destination_policy;
#[cfg(feature = "diagnostics")]
mod diagnostics;
mod direct_http;
#[cfg(feature = "https-records")]
mod doh;
mod error_context;
mod expect_continue;
#[cfg(feature = "fingerprint-import")]
mod fingerprint_import;
mod h2c;
mod h3_coalescing;
mod h3_received_order;
mod ping_failure_replay;
mod plaintext_templates;
mod prepared_bodies;
mod query_authorization;
mod raw_request;
mod redirects;
mod request_connections;
mod request_conveniences;
mod request_hooks;
mod request_templates;
mod request_timeline;
mod response_conveniences;
mod send_futures;
mod server_pinning;
mod source_binding;
mod stale_connection_replay;
mod status_retry;
mod timeouts;
mod tracing;
mod transfer;
mod trust_anchor_orders;
mod unprocessed_replay;
