//! Network protocol implementations for Phantom.
//!
//! This crate owns the concrete wire mechanisms behind the `phantom-http`
//! facade: TLS connectors built from typed profiles, ordered HTTP/1.1 and
//! HTTP/2 connections, one-handshake HTTP/1.1-or-HTTP/2 selection, HTTP/3
//! over direct QUIC, SOCKS5 UDP ASSOCIATE, or CONNECT-UDP, and HTTP CONNECT,
//! forward-proxy, and SOCKS5 routing. It owns no pools, redirects, cookies, or
//! retry policy; the facade supplies those.
//!
//! It is an internal crate with no stability guarantee. Applications should
//! depend on `phantom-http`. The optional `qlog` feature enables HTTP/3 qlog
//! output, and `keylog` enables NSS key logging on every TLS context; the
//! facade exposes both through its `diagnostics` feature. The optional
//! `https-records` feature adds [`dns`], HTTPS DNS record lookups, and the
//! resolver dependency they need.

mod accept_ch;
pub mod address_cache;
mod direct;
#[cfg(feature = "https-records")]
pub mod dns;
pub mod host_resolver;
pub mod http1;
/// One-handshake HTTP/1.1 or HTTP/2 selection over TLS ALPN.
pub mod http1_or_2;
pub mod http2;
/// HTTP/3 connections and transactions over the BoringSSL-backed QUIC provider,
/// on direct UDP, SOCKS5 UDP ASSOCIATE, or CONNECT-UDP.
pub mod http3;
/// HTTP proxy negotiation and tunneled byte streams.
pub mod proxy;
pub mod request;
mod response;
mod shutdown_timer;
pub mod tcp;
pub(crate) mod tls;

#[cfg(feature = "keylog")]
pub use phantom_quic_btls::{NssKeyLogReceiver, NssKeyLogSender, nss_key_log_channel};
pub use response::{OrderedResponseHeaders, ResponseHeader};
pub use tls::ServerAuthentication;

#[cfg(all(test, debug_assertions))]
mod connection_setup_futures;
#[cfg(test)]
mod tracing_test;
