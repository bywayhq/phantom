//! Network protocol implementations for Phantom.
//!
//! This crate owns the concrete wire mechanisms behind the `phantom-http`
//! facade: TLS connectors built from typed profiles, ordered HTTP/1.1 and
//! HTTP/2 connections, one-handshake HTTP/1.1-or-HTTP/2 selection, HTTP/3
//! over direct QUIC, SOCKS5 UDP ASSOCIATE, or CONNECT-UDP, and HTTP CONNECT,
//! forward-proxy, and SOCKS5 routing. It provides [`proxy::Http2ProxyPool`]
//! for connections to HTTP/2 proxies. The facade owns origin connection
//! pools, redirects, cookies, and retry policy.
//!
//! It is an internal crate with no stability guarantee. Applications should
//! depend on `phantom-http`. The optional `qlog` feature enables HTTP/3 qlog
//! output, and `keylog` enables NSS key logging on every TLS context; the
//! facade exposes both through its `diagnostics` feature. The optional
//! `https-records` feature adds `dns`, HTTPS DNS record lookups, and the
//! resolver dependency they need.
//!
//! Unsafe code stays in audited private modules. `socket_ffi` sets Windows port
//! randomization and platform interface binding. `system_dns_ffi` owns Windows
//! system resolution, DNS settings reads and configuration notifications.
//! Its safe API returns owned data and generation observations. Native pointers,
//! handles and callbacks stay private. Every unsafe block carries a `SAFETY`
//! comment required by `clippy::undocumented_unsafe_blocks`; the rest of
//! the crate denies `unsafe_code`.
//! `linux_dns_ffi` reads Linux native witnesses and owns file/network watches.

#![deny(unsafe_code)]

mod accept_ch;
pub mod address_cache;
mod attempt_budget;
mod authorization;
mod connection_leg;
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
#[cfg(all(feature = "https-records", target_os = "linux"))]
#[allow(unsafe_code, reason = "private Linux system DNS FFI boundary")]
mod linux_dns_ffi;
#[cfg(all(feature = "https-records", target_os = "macos"))]
#[allow(unsafe_code, reason = "private macOS system DNS FFI boundary")]
mod macos_dns_ffi;
/// HTTP proxy negotiation and tunneled byte streams.
pub mod proxy;
pub mod request;
mod response;
pub mod route;
mod session_tickets;
mod shutdown_timer;
// Raw libc, Winsock, IP Helper, and ntdll access is isolated here so safe code
// cannot grow new unsafe operations without crossing an explicit, reviewable
// module boundary. Linux and Android test builds compile it to run the Apple
// lookup, which their production builds never call.
#[cfg(any(
    target_vendor = "apple",
    windows,
    all(test, any(target_os = "android", target_os = "linux"))
))]
#[allow(unsafe_code, reason = "private socket FFI boundary")]
mod socket_ffi;
mod source_binding;
#[cfg(windows)]
#[allow(unsafe_code, reason = "private Windows system DNS FFI boundary")]
mod system_dns_ffi;
pub mod tcp;
pub(crate) mod tls;
mod udp;

pub use attempt_budget::{HttpAttemptBudget, HttpAttemptBudgetExhausted};
pub use authorization::{InvalidAuthorization, InvalidAuthorizationKind};
#[cfg(feature = "keylog")]
pub use phantom_quic_btls::{NssKeyLogReceiver, NssKeyLogSender, nss_key_log_channel};
pub use phantom_quic_btls::{QuicSessionRecordMetadata, QuicSessionStoreHeader};
pub use response::{OrderedResponseHeaders, ResponseHeader};
pub use session_tickets::{
    FrozenSessionTicketCache, PreparedSessionTicketReplacement, PreparedTcpSessionReplacement,
    RetiredSessionTicketPublications, RetiredSessionTicketReplacements,
    RetiredTcpSessionReplacements, SessionTicketCache, SessionTicketCacheOwner,
    SessionTicketGeneration, SessionTicketStoreExport, SessionTicketStoreHeader,
    TcpSessionExportRecord, TcpSessionRecordMetadata, TcpSessionStoreExport, TcpSessionStoreHeader,
};
#[doc(hidden)]
pub use shutdown_timer::run_after;
pub use source_binding::{InvalidSourceBinding, SourceBinding};
pub use tls::{
    ClientCertificate, ClientCertificateError, ClientCertificateErrorKind, EchFailure,
    ServerAuthentication, TlsError, TlsErrorKind, bundled_server_root_identity, draw_per_client,
};

#[cfg(all(test, debug_assertions))]
mod connection_setup_futures;
#[cfg(test)]
mod tracing_test;
