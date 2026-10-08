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
//! use phantom::profile::{chromium, ClientProfile};
//! use phantom::{Client, HttpProtocol, RequestHeader};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = ClientProfile::new(chromium::v154_tls())
//!     .with_http2(chromium::v154_http2())
//!     .with_client_hints(chromium::v154_windows_client_hints());
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
//! To use HTTP/3, add [`profile::Http3ClientSettings`] to the profile.
//!
//! # Cargo features
//!
//! | Feature | Adds |
//! | --- | --- |
//! | `cookies` | `CookieJar` and client-owned cookie handling |
//! | `https-records` | HTTPS DNS lookups, HTTP/3 discovery, Encrypted Client Hello, and DNS queries with record TTLs |
//! | `sse` | Server-sent event decoding and bounded reconnects |
//! | `websocket` | WebSocket over HTTP/1.1 Upgrade, or HTTP/2 or HTTP/3 extended CONNECT |
//! | `websocket-deflate` | Opt-in `permessage-deflate`; implies `websocket` |
//! | `serde` | `Serialize` and `Deserialize` for `CookieSnapshot` (with `cookies`) |
//! | `full` | `cookies`, `https-records`, `serde`, `sse`, and `websocket-deflate` |
//! | `diagnostics` | TLS key logging and QUIC qlog files for debugging your own connections |
//! | `danger-disable-verification` | `ServerAuthentication::DangerDisabled`, which accepts any server certificate, for conformance testing |
//!
//! No feature is enabled by default. `full` leaves out `diagnostics`, because
//! a key log holds secrets that decrypt the client's traffic, and
//! `danger-disable-verification`, because it lets anyone on the path read and
//! change the connection.
//!
//! With `https-records`, [`ClientBuilder::https_record_discovery`] discovers
//! HTTP/3 endpoints. Profiles with `ech_from_https_records` can use Encrypted
//! Client Hello from those records. Direct handshakes wait up to 50 ms for
//! that lookup. [`AddressResolver::system_nameservers`] sends DNS queries
//! that report record TTLs, the time each result can stay cached.
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
mod error;
mod redirect;
mod request;
mod response;
mod retry;
mod route;
mod session;
#[cfg(feature = "sse")]
mod sse;
mod timeout;
#[cfg(feature = "websocket")]
mod websocket;

pub use body::ResponseBody;
pub use client::{Client, ClientBuilder, HttpProtocol};
pub use content_coding::{ContentCoding, ContentDecoding};
#[cfg(feature = "diagnostics")]
pub use diagnostics::KeyLog;
pub use error::{BuildError, BuildErrorKind, RequestError, RequestErrorKind};
pub use redirect::RedirectPolicy;
pub use request::{PreparedRequestTemplate, RequestBuilder};
pub use response::ResponseInfo;
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
pub use timeout::{RequestTimeouts, TimeoutPhase};
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
        GoogleConnectionOption, InvalidQuicTransportSettings, QuicTransportGrease,
        QuicTransportParameter, QuicTransportParameterKind, QuicTransportParameterOrder,
        QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
    };
    pub use phantom_profile::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
        ClientHelloExtensionOrder, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, CookiePlacement, DnsCacheSettings, EchGreaseAead, EchGreasePayloadLength,
        Http1IdleTimeout, Http1Settings, Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings,
        Http2HuffmanCoding, Http2IdleTimeout, Http2IndexingLimit, Http2NameReference,
        Http2Priority, Http2ProxyConnections, Http2PseudoHeader, Http2RejectedConnect,
        Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
        Http2TableSizeUpdates, Http2UnindexedMatch, Http3AltUsed, Http3ClientSettings,
        Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream,
        Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings, Http3Setting,
        Http3SettingOrder, Http3Settings, InvalidClientHintSettings, InvalidHttp1Settings,
        InvalidHttp2Settings, InvalidHttp3RequestSettings, InvalidHttp3Settings,
        InvalidProxyConnectTemplate, InvalidRequestTemplate, InvalidTcpSettings,
        InvalidTlsSettings, InvalidWebSocketSettings, NamedGroup, ProxyAuthorizationAttempt,
        ProxyConnectField, ProxyConnectTemplate, RequestField, RequestTemplate, SessionTicketOrder,
        SignatureScheme, TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection,
        TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule,
        TcpPortRandomization, TcpSettings, TlsSettings, TlsVersion, TrustAnchorIds, UdpSettings,
        WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
        WebSocketField, WebSocketNewConnection, WebSocketProxiedSession,
        WebSocketRefusedStreamRetry, WebSocketSettings,
    };

    /// Chromium-family connection settings and request templates.
    pub mod chromium {
        pub use phantom_profile::chromium::{
            v154_cookie_placement, v154_dns_cache, v154_http1, v154_http2, v154_http3,
            v154_http3_request, v154_http3_tls, v154_macos_client_hints,
            v154_macos_fetch_no_store_template, v154_macos_fetch_template,
            v154_macos_navigation_template, v154_proxy_connect, v154_quic, v154_tcp, v154_tls,
            v154_udp, v154_websocket, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_fetch_template,
            v154_windows_navigation_template,
        };
    }

    /// Firefox connection settings and request templates.
    ///
    /// The HTTP/3 recipes build a Firefox 157 profile that can use HTTP/3:
    ///
    /// ```
    /// use phantom::profile::{ClientProfile, Http3ClientSettings, firefox};
    ///
    /// let profile = ClientProfile::new(firefox::v157_tls())
    ///     .with_http2(firefox::v157_http2())
    ///     .with_http3(Http3ClientSettings::new(
    ///         firefox::v157_http3_tls(),
    ///         firefox::v157_quic(),
    ///         firefox::v157_http3(),
    ///         firefox::v157_http3_request(),
    ///     ));
    /// assert!(profile.http3().is_some());
    /// ```
    pub mod firefox {
        pub use phantom_profile::firefox::{
            v157_cookie_placement, v157_dns_cache, v157_http1, v157_http2, v157_http3,
            v157_http3_request, v157_http3_tls, v157_macos_fetch_no_store_template,
            v157_macos_fetch_template, v157_macos_navigation_template, v157_proxy_connect,
            v157_quic, v157_tcp, v157_tls, v157_websocket, v157_windows_fetch_no_store_template,
            v157_windows_fetch_template, v157_windows_navigation_template,
        };
    }

    /// Brave connection settings and request templates.
    ///
    /// Brave 154 shares the Chromium H2, QUIC, H3, WebSocket, and proxy
    /// CONNECT recipes. Its TLS ClientHellos, client hints, and request
    /// headers differ.
    pub mod brave {
        pub use phantom_profile::brave::{
            v154_http3_tls, v154_tls, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_navigation_template,
        };
    }

    /// Opera connection settings and request templates.
    ///
    /// Opera 136 shares the Chromium TCP, UDP, HTTP/1.1 connection, address cache,
    /// H2, QUIC, H3, WebSocket, and proxy CONNECT recipes. Its TLS
    /// ClientHellos, client hints, and request identity differ.
    pub mod opera {
        pub use phantom_profile::opera::{
            v136_http3_tls, v136_macos_client_hints, v136_tls, v136_windows_client_hints,
            v136_windows_fetch_no_store_template, v136_windows_navigation_template,
        };
    }

    /// Microsoft Edge connection settings and request templates.
    ///
    /// Edge 154 shares the Chromium TCP, UDP, HTTP/1.1 connection, address cache,
    /// H2, QUIC, H3, WebSocket, and proxy CONNECT recipes. Its TLS
    /// ClientHellos, client hints, and request identity differ.
    pub mod edge {
        pub use phantom_profile::edge::{
            v154_http3_tls, v154_macos_client_hints, v154_tls, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_navigation_template,
        };
    }

    /// Brave for Android connection settings and request templates.
    ///
    /// For Brave 1.95.104 (Chromium 153) on Android 15 and 17 emulators.
    /// The TLS recipes and request-header differences equal desktop Brave's.
    /// The H2, QUIC, H3, and WebSocket recipes return the Chromium data.
    pub mod brave_android {
        pub use phantom_profile::brave_android::{
            v153_android_client_hints, v153_android_fetch_no_store_template,
            v153_android_navigation_template, v153_http2, v153_http3, v153_http3_request,
            v153_http3_tls, v153_quic, v153_tls, v153_websocket,
        };
    }

    /// Opera for Android TLS settings and client hints.
    ///
    /// For Opera 102 (Chromium 152) on an Android 17 emulator.
    pub mod opera_android {
        pub use phantom_profile::opera_android::{
            v102_android_client_hints, v102_android_client_hints_for_model, v102_tls,
        };
    }

    /// Firefox for Android TLS settings.
    ///
    /// For Firefox 156.0.1 on an Android 15 emulator. Its TLS ClientHello
    /// equals the desktop ClientHello that Firefox 156.0.1 and 157.0 send.
    pub mod firefox_android {
        pub use phantom_profile::firefox_android::v156_tls;
    }

    /// Chrome for Android connection settings and request templates.
    ///
    /// For Chrome 154 on an Android 17 emulator that reports a
    /// Pixel 7. The TLS, H2, QUIC, H3, and WebSocket recipes return the
    /// desktop Chromium data. The client hints and request identity differ.
    pub mod chrome_android {
        pub use phantom_profile::chrome_android::{
            v154_android_client_hints, v154_android_client_hints_for_model,
            v154_android_fetch_no_store_template, v154_android_navigation_template, v154_http2,
            v154_http3, v154_http3_request, v154_http3_tls, v154_quic, v154_tls, v154_websocket,
        };
    }

    /// Microsoft Edge for Android connection settings and request templates.
    ///
    /// For Edge 153 on an arm64 Android 17 emulator that reports a Pixel 7.
    /// The TLS recipes are desktop Edge's, which Edge 153 and 154 send alike.
    /// The H2, QUIC, and H3 recipes return the Chromium data. The client hints
    /// and request identity differ.
    pub mod edge_android {
        pub use phantom_profile::edge_android::{
            v153_android_client_hints, v153_android_client_hints_for_model,
            v153_android_fetch_no_store_template, v153_android_navigation_template, v153_http2,
            v153_http3, v153_http3_request, v153_http3_tls, v153_quic, v153_tls,
        };
    }
}

/// HTTPS DNS record (RFC 9460) lookups used for HTTP/3 discovery.
///
/// See [`ClientBuilder::https_record_discovery`]. Requires the
/// `https-records` feature.
#[cfg(feature = "https-records")]
pub mod dns {
    pub use phantom_net::dns::{
        AliasRecord, EchConfigList, HttpsLookupError, HttpsLookupErrorKind, HttpsRecord,
        HttpsRecordAnswer, HttpsRecordError, HttpsRecordErrorKind, HttpsRecordLookup,
        HttpsRecordResolver, ServiceRecord, SvcParam, TargetName,
    };
}

/// An ordered request field preserving spelling, value bytes, and position.
pub use phantom_net::request::RequestHeader;
/// One declared request-trailer name retaining exact spelling and position.
pub use phantom_net::request::RequestTrailerName;

/// Lossless ordinary response-field order attached to each response.
pub use phantom_net::{OrderedResponseHeaders, ResponseHeader};

/// HTTP request method accepted by [`Client::request`].
pub use http::Method;
