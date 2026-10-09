//! Send HTTP requests with a browser's connection settings and header order.
//!
//! Choose the settings with [`profile::ClientProfile`], then build a [`Client`].
//! The client keeps connections and state for later requests. You can choose
//! an exact protocol or let a negotiated request select one. Negotiated
//! requests can use HTTP/3 alternatives learned through discovery.
//! An exact HTTP/3 request can fall back to HTTP/2 when you enable
//! [`RetryPolicy::with_http2_fallback`]. Requests keep the route you selected.
//!
//! # Quick start
//!
//! ```no_run
//! use phantom::profile::browser::chrome;
//! use phantom::{Client, HttpProtocol, RequestHeader};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = chrome::v154_windows();
//! let client = Client::builder(profile).build()?;
//!
//! let response = client
//!     .get(HttpProtocol::Http2, "https://example.com/")?
//!     .header(RequestHeader::new("accept", "*/*"))
//!     .send()
//!     .await?;
//! println!("{}", response.status());
//! let body = response.into_body().collect_with_limit(1 << 20).await?;
//! println!("{} bytes", body.len());
//! # Ok(())
//! # }
//! ```
//!
//! Run requests in a Tokio runtime with I/O enabled. Enable timers for
//! timeouts and operations that wait on timers, such as HTTP/3 setup.
//! [`Client::get_negotiated`] lets a TLS handshake choose HTTP/1.1 or HTTP/2.
//! Composed browser profiles include HTTP/3 when their recipes support it.
//! Custom profiles add it through [`profile::Http3ClientSettings`].
//!
//! # Cargo features
//!
//! | Feature | Adds |
//! | --- | --- |
//! | `cookies` | `CookieJar` and client-owned cookie handling |
//! | `https-records` | HTTPS DNS lookups, HTTP/3 discovery, Encrypted Client Hello, and DNS queries with record TTLs |
//! | `sse` | Server-sent event streams and bounded reconnects |
//! | `websocket` | WebSocket over HTTP/1.1 Upgrade, or HTTP/2 or HTTP/3 extended CONNECT |
//! | `websocket-deflate` | Opt-in `permessage-deflate`; implies `websocket` |
//! | `serde` | `Serialize` and `Deserialize` for `CookieSnapshot` (with `cookies`) |
//! | `json` | Bounded typed-JSON requests and response reading |
//! | `full` | `cookies`, `https-records`, `json`, `serde`, `sse`, and `websocket-deflate` |
//! | `diagnostics` | TLS key logging and QUIC qlog files for debugging your own connections |
//! | `danger-disable-verification` | `ServerAuthentication::DangerDisabled`, which accepts any server certificate, for conformance testing |
//!
//! No feature is enabled by default. `full` leaves out `diagnostics`, because
//! a key log holds secrets that decrypt the client's traffic, and
//! `danger-disable-verification`, because it lets anyone on the path read and
//! change the connection.
//!
//! With `https-records`, `ClientBuilder::https_record_discovery` discovers
//! HTTP/3 endpoints. Profiles with `EchSettings::HttpsRecords` can use Encrypted
//! Client Hello from those records. Direct handshakes wait up to 50 ms for
//! that lookup. `AddressResolver::system_nameservers` sends DNS queries
//! that report record TTLs, the time each result can stay cached.
//!
//! # Public dependencies
//!
//! The client API uses `bytes` buffers, `http` request and response types,
//! and `http-body` streaming traits. SSE implements `futures-core::Stream`;
//! WebSocket implements that trait and `futures-sink::Sink`. The optional
//! JSON and cookie snapshot APIs use `serde` traits.
//!
//! Re-exported settings and transport types come from `phantom-profile` and
//! `phantom-net`. HTTP engine and TLS backend types stay behind those types
//! and their error source chains. Run the client in Tokio with I/O and the
//! timers its operations require.
//!
//! # Further reading
//!
//! The repository's `docs/` directory holds the documentation;
//! `docs/README.md` is its index. New to request fingerprinting? Start with
//! `docs/fingerprinting.md`. `docs/reference/coverage.md` is the detailed
//! support contract.
//!
//! Coding agents that use this crate should read `llms.txt` at the
//! repository root. A git dependency checks out the whole repository, so the
//! file matches the revision being built.

// Compile-check the Rust examples in the repository guides as doctests.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
struct ReadmeDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/getting-started.md")]
struct GettingStartedDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/client.md")]
struct ClientGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/responses.md")]
struct ResponsesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/profiles.md")]
struct ProfilesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/request-templates.md")]
struct RequestTemplatesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/request-bodies.md")]
struct RequestBodiesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/routes-and-proxies.md")]
struct RoutesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/socks-and-connect-udp.md")]
struct SocksGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/retries.md")]
struct RetriesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/http3.md")]
struct Http3GuideDoctests;

// The guide's HTTPS-record example needs the `https-records` feature.
#[cfg(all(doctest, feature = "https-records"))]
#[doc = include_str!("../../../docs/guides/http3-discovery.md")]
struct Http3DiscoveryGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/content-decoding.md")]
struct ContentDecodingGuideDoctests;

#[cfg(all(doctest, feature = "cookies"))]
#[doc = include_str!("../../../docs/guides/connections-and-state.md")]
struct ConnectionsGuideDoctests;

// The guide's own-queries example needs the `https-records` feature.
#[cfg(all(doctest, feature = "https-records"))]
#[doc = include_str!("../../../docs/guides/name-resolution.md")]
struct NameResolutionGuideDoctests;

#[cfg(all(doctest, feature = "cookies"))]
#[doc = include_str!("../../../docs/guides/cookies.md")]
struct CookiesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/redirects.md")]
struct RedirectsGuideDoctests;

#[cfg(all(doctest, feature = "cookies"))]
#[doc = include_str!("../../../docs/guides/coming-from-reqwest.md")]
struct ComingFromReqwestGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/troubleshooting.md")]
struct TroubleshootingGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/performance.md")]
struct PerformanceGuideDoctests;

#[cfg(all(doctest, feature = "sse"))]
#[doc = include_str!("../../../docs/guides/sse.md")]
struct SseGuideDoctests;

#[cfg(all(doctest, feature = "websocket"))]
#[doc = include_str!("../../../docs/guides/websocket.md")]
struct WebSocketGuideDoctests;

// The guide includes a compression example.
#[cfg(all(doctest, feature = "websocket-deflate"))]
#[doc = include_str!("../../../docs/guides/websocket-fields.md")]
struct WebSocketFieldsGuideDoctests;

mod authority;
mod body;
mod client;
mod content_coding;
#[cfg(feature = "diagnostics")]
mod diagnostics;
mod environment_proxy;
mod error;
mod link;
mod redirect;
mod request;
mod request_body;
mod request_slots;
mod response;
mod retry;
mod route;
mod session;
#[cfg(feature = "sse")]
mod sse;
mod timeout;
#[cfg(feature = "websocket")]
mod websocket;

pub use authority::RequestOrigin;
pub use body::ResponseBody;
pub use client::{Client, ClientBuilder, HttpProtocol};
pub use content_coding::{ContentCoding, ContentDecoding};
#[cfg(feature = "diagnostics")]
pub use diagnostics::KeyLog;
pub use environment_proxy::{EnvironmentProxies, EnvironmentProxyError, EnvironmentProxyErrorKind};
pub use error::{
    BuildError, BuildErrorKind, RequestError, RequestErrorKind, RequestReplayObservation,
};
/// The stream trait implemented by SSE streams and event sources.
#[cfg(feature = "sse")]
pub use futures_core::Stream;
pub use link::{Link, LinkParameter, LinkParseError, LinkParseErrorKind, parse_link_headers};
pub use redirect::RedirectPolicy;
pub use request::{PreparedRequestTemplate, RequestBuilder};
pub use request_body::{
    MultipartPart, PreparedBodyError, PreparedBodyErrorKind, PreparedRequestBody,
};
pub use request_slots::{RequestSlotError, RequestSlotErrorKind, RequestSlots};
#[cfg(feature = "json")]
pub use response::response_json;
pub use response::{
    ResponseInfo, ResponseReadError, ResponseReadErrorKind, StatusError, error_for_status,
    response_bytes, response_text,
};
pub use retry::{RetryPolicy, StatusRetry, StatusRetryError};
pub use route::{
    ConnectUdpProxy, ConnectUdpProxyConfigError, ConnectUdpProxyConfigErrorKind, HttpProxy,
    ProxyConfigError, ProxyConfigErrorKind, Route, Socks5DnsMode, Socks5Proxy,
    Socks5ProxyConfigError, Socks5ProxyConfigErrorKind,
};
pub use session::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot, AltSvcSnapshotEntry,
    AltSvcSnapshotError, AltSvcSnapshotErrorKind,
};
#[cfg(feature = "cookies")]
pub use session::{
    CookieError, CookieErrorKind, CookieJar, CookieLimits, CookieSameSite, CookieSnapshot,
    CookieSnapshotEntry, CookieSnapshotError, CookieSnapshotErrorKind, CookieSourceScheme,
};
#[cfg(feature = "sse")]
pub use sse::{
    SseError, SseErrorKind, SseEvent, SseEventSource, SseHeader, SseLimits, SseRequestBuilder,
    SseStream,
};
pub use timeout::{RequestTimeoutOverrides, RequestTimeouts, TimeoutOverride, TimeoutPhase};
#[cfg(feature = "websocket-deflate")]
pub use websocket::{
    NegotiatedPerMessageDeflate, PerMessageDeflate, PerMessageDeflateOfferParameter,
};
#[cfg(feature = "websocket")]
pub use websocket::{
    WebSocket, WebSocketCloseFrame, WebSocketError, WebSocketErrorKind, WebSocketHeader,
    WebSocketLimits, WebSocketMessage, WebSocketRequestBuilder, WebSocketRetryPolicy,
};

/// Policy for authenticating a TLS server certificate.
pub use phantom_net::ServerAuthentication;
/// Caller-supplied host name resolution for [`ClientBuilder::dns_resolver`].
pub use phantom_net::host_resolver::AddressResolver;
/// An ordered HTTP CONNECT field or destination-authority placeholder.
pub use phantom_net::proxy::HttpConnectHeader;
/// A TLS client certificate for [`ClientBuilder::client_certificate`] and
/// [`ClientBuilder::client_certificate_for`].
pub use phantom_net::{ClientCertificate, ClientCertificateError, ClientCertificateErrorKind};

/// Client-profile types used to configure observable wire behavior.
pub mod profile {
    pub use phantom_profile::quic::{
        GoogleConnectionOption, InvalidQuicTransportSettings, QuicAckFrequencyDraft,
        QuicConnectionIdLength, QuicTransportGrease, QuicTransportParameter,
        QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
        QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
    };
    pub use phantom_profile::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
        ClientHelloExtensionOrder, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, CookiePlacement, DnsCacheSettings, EchGreaseAead, EchGreasePayloadLength,
        EchGreaseSettings, EchSettings, Http1IdleTimeout, Http1Settings, Http2CookieCrumbs,
        Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding, Http2IdleTimeout,
        Http2IndexingLimit, Http2NameReference, Http2Priority, Http2ProxyConnections,
        Http2PseudoHeader, Http2RejectedConnect, Http2SensitiveProxyAuthorization, Http2Setting,
        Http2Settings, Http2StaticNameIndex, Http2StreamSettings, Http2TableSizeUpdates,
        Http2UnindexedMatch, Http3AltUsed, Http3ClientSettings, Http3CookieCrumbs,
        Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream, Http3QpackEncoding,
        Http3QpackStreamOrder, Http3RequestSettings, Http3Setting, Http3SettingOrder,
        Http3Settings, InvalidClientHintSettings, InvalidHttp1Settings, InvalidHttp2Settings,
        InvalidHttp3RequestSettings, InvalidHttp3Settings, InvalidProxyConnectTemplate,
        InvalidRequestTemplate, InvalidTcpSettings, InvalidTlsSettings, InvalidWebSocketSettings,
        NamedGroup, ProxyAuthorizationAttempt, ProxyConnectField, ProxyConnectTemplate,
        RequestField, RequestTemplate, SessionTicketOrder, SessionTickets, SignatureScheme,
        TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection, TcpBackupConnection,
        TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings,
        TlsSettings, TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder,
        TrustAnchorOrders, UdpSettings, UnknownCipherSuite, UrlTrust, ValidationErrorKind,
        WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
        WebSocketField, WebSocketNewConnection, WebSocketProxiedSession,
        WebSocketRefusedStreamRetry, WebSocketSettings,
    };

    /// Browser recipes and composed profiles grouped by brand and platform.
    pub use phantom_profile::browser;
}

/// HTTPS DNS record (RFC 9460) lookups used for HTTP/3 discovery.
///
/// See `ClientBuilder::https_record_discovery`. Requires the
/// `https-records` feature.
#[cfg(feature = "https-records")]
pub mod dns {
    pub use phantom_net::dns::{
        AliasRecord, EchCipherSuite, EchConfig, EchConfigExtension, EchConfigList,
        EchConfigListError, EchConfigListErrorKind, HttpsLookupError, HttpsLookupErrorKind,
        HttpsRecord, HttpsRecordAnswer, HttpsRecordError, HttpsRecordErrorKind, HttpsRecordLookup,
        HttpsRecordResolver, ServiceRecord, SvcParam, TargetName,
    };
}

/// An ordered request field preserving spelling, value bytes, and position.
pub use phantom_net::request::RequestHeader;
/// One declared request-trailer name retaining exact spelling and position.
pub use phantom_net::request::RequestTrailerName;
pub use phantom_net::{InvalidAuthorization, InvalidAuthorizationKind};

/// Lossless ordinary response-field order attached to each response.
pub use phantom_net::{OrderedResponseHeaders, ResponseHeader};

/// Shared byte buffer used for request and response bodies.
pub use bytes::Bytes;
/// HTTP request method accepted by [`Client::request`].
pub use http::Method;
/// HTTP response returned by [`RequestBuilder::send`].
pub use http::Response;
/// HTTP status accepted by [`StatusRetry`] and returned by [`Response::status`].
pub use http::StatusCode;
/// HTTP URI returned by [`ResponseInfo::effective_uri`].
pub use http::Uri;
