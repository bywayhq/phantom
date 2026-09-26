//! Public Phantom client facade.
//!
//! Phantom is an HTTP client whose observable TLS, HTTP/1.1, HTTP/2, QUIC, and
//! HTTP/3 behavior comes from a typed [`profile::ClientProfile`]. A [`Client`]
//! owns that profile plus bounded pools and cross-request state; each request
//! selects its protocol explicitly and never falls back to another protocol
//! or route.
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
//! Requests need a Tokio runtime with I/O and timers enabled.
//! [`Client::get_negotiated`] lets one direct TLS handshake choose HTTP/1.1 or
//! HTTP/2, and HTTP/3 needs [`profile::Http3ClientSettings`] on the profile.
//!
//! # Cargo features
//!
//! | Feature | Adds |
//! | --- | --- |
//! | `cookies` | `CookieJar` and client-owned cookie handling |
//! | `https-records` | The `dns` module, HTTP/3 discovery from HTTPS DNS records, and Encrypted Client Hello from them for profiles that set `ech_from_https_records`, whose direct handshakes wait up to 50 ms for the lookup |
//! | `sse` | Server-sent event decoding and bounded reconnects |
//! | `websocket` | WebSocket over HTTP/1.1 Upgrade or HTTP/2 extended CONNECT |
//! | `websocket-deflate` | Opt-in `permessage-deflate`; implies `websocket` |
//! | `serde` | `Serialize` and `Deserialize` for `CookieSnapshot` (with `cookies`) |
//! | `full` | All of the above |
//! | `diagnostics` | TLS key logging and QUIC qlog files for debugging your own connections |
//!
//! No feature is enabled by default. `full` leaves out `diagnostics`, because
//! a key log holds secrets that decrypt the client's traffic.
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

#[cfg(doctest)]
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
#[doc(hidden)]
pub use session::{Session, SessionBuilder};
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
        ClientProfile, CookiePlacement, DnsCacheSettings, EchGreaseAead, Http1Settings,
        Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
        Http2IndexingLimit, Http2NameReference, Http2Priority, Http2ProxyConnections,
        Http2PseudoHeader, Http2RejectedConnect, Http2Setting, Http2Settings, Http2StaticNameIndex,
        Http2TableSizeUpdates, Http2UnindexedMatch, Http3ClientSettings, Http3CookieCrumbs,
        Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream, Http3QpackEncoding,
        Http3QpackStreamOrder, Http3RequestSettings, Http3Setting, Http3SettingOrder,
        Http3Settings, InvalidClientHintSettings, InvalidHttp2Settings,
        InvalidHttp3RequestSettings, InvalidHttp3Settings, InvalidProxyConnectTemplate,
        InvalidRequestTemplate, InvalidTcpSettings, InvalidTlsSettings, InvalidWebSocketSettings,
        NamedGroup, ProxyAuthorizationAttempt, ProxyConnectField, ProxyConnectTemplate,
        RequestField, RequestTemplate, SignatureScheme, TcpAddressRacing, TcpKeepalive,
        TcpSettings, TlsSettings, TlsVersion, WebSocketConnectionPolicy, WebSocketDeflateParameter,
        WebSocketField, WebSocketNewConnection, WebSocketSettings,
    };

    /// Chromium-family recipes implemented by the public facade.
    pub mod chromium {
        pub use phantom_profile::chromium::{
            v154_cookie_placement, v154_dns_cache, v154_http1, v154_http2, v154_http3,
            v154_http3_request, v154_http3_tls, v154_macos_client_hints,
            v154_macos_fetch_no_store_template, v154_macos_navigation_template, v154_proxy_connect,
            v154_quic, v154_tcp, v154_tls, v154_websocket, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_navigation_template,
        };
    }

    /// Firefox recipes implemented by the public facade.
    pub mod firefox {
        pub use phantom_profile::firefox::{
            v156_cookie_placement, v156_dns_cache, v156_http1, v156_http2,
            v156_macos_fetch_no_store_template, v156_macos_navigation_template, v156_proxy_connect,
            v156_tcp, v156_tls, v156_websocket, v156_windows_fetch_no_store_template,
            v156_windows_navigation_template,
        };
    }

    /// Brave recipes implemented by the public facade.
    ///
    /// Brave 154 shares the Chromium H2, QUIC, H3, WebSocket, and proxy
    /// CONNECT recipes; its TLS ClientHellos, client hints, and request
    /// fields differ.
    pub mod brave {
        pub use phantom_profile::brave::{
            v154_http3_tls, v154_tls, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_navigation_template,
        };
    }

    /// Opera recipes implemented by the public facade.
    ///
    /// Opera 135 shares the Chromium H2, QUIC, H3, WebSocket, and proxy
    /// CONNECT recipes; only its TLS ClientHellos, client hints, and request
    /// identity differ.
    pub mod opera {
        pub use phantom_profile::opera::{
            v135_http3_tls, v135_macos_client_hints, v135_tls, v135_windows_client_hints,
            v135_windows_fetch_no_store_template, v135_windows_navigation_template,
        };
    }

    /// Microsoft Edge recipes implemented by the public facade.
    ///
    /// Edge 154 shares the Chromium H2, QUIC, H3, WebSocket, and proxy
    /// CONNECT recipes; only its TLS ClientHellos, client hints, and request
    /// identity differ.
    pub mod edge {
        pub use phantom_profile::edge::{
            v154_http3_tls, v154_macos_client_hints, v154_tls, v154_windows_client_hints,
            v154_windows_fetch_no_store_template, v154_windows_navigation_template,
        };
    }

    /// Brave for Android recipes implemented by the public facade.
    ///
    /// Captured from Brave 1.95.104 (Chromium 153) on Android 15 and 17 emulators.
    /// The TLS recipes and request-field differences equal desktop Brave's;
    /// the H2, QUIC, H3, and WebSocket recipes return the Chromium data.
    pub mod brave_android {
        pub use phantom_profile::brave_android::{
            v153_android_client_hints, v153_android_fetch_no_store_template,
            v153_android_navigation_template, v153_http2, v153_http3, v153_http3_request,
            v153_http3_tls, v153_quic, v153_tls, v153_websocket,
        };
    }

    /// Opera for Android recipes implemented by the public facade.
    ///
    /// Captured from Opera 102 (Chromium 152) on an Android 17 emulator. Opera
    /// for Android takes no switches, so only its TLS ClientHello and client
    /// hints are captured.
    pub mod opera_android {
        pub use phantom_profile::opera_android::{
            v102_android_client_hints, v102_android_client_hints_for_model, v102_tls,
        };
    }

    /// Firefox for Android recipes implemented by the public facade.
    ///
    /// Captured from Firefox 156.0.1 on an Android 15 emulator. Only the TLS
    /// ClientHello is captured; it equals desktop Firefox 156's.
    pub mod firefox_android {
        pub use phantom_profile::firefox_android::v156_tls;
    }

    /// Chrome for Android recipes implemented by the public facade.
    ///
    /// Captured from Chrome 154 on an Android 17 emulator that reports a
    /// Pixel 7. The TLS, H2, QUIC, H3, and WebSocket recipes return the
    /// desktop Chromium data, which the Android captures equal; the client
    /// hints and request identity differ.
    pub mod chrome_android {
        pub use phantom_profile::chrome_android::{
            v154_android_client_hints, v154_android_client_hints_for_model,
            v154_android_fetch_no_store_template, v154_android_navigation_template, v154_http2,
            v154_http3, v154_http3_request, v154_http3_tls, v154_quic, v154_tls, v154_websocket,
        };
    }

    /// Microsoft Edge for Android recipes implemented by the public facade.
    ///
    /// Captured from Edge 153 on an arm64 Android 17 emulator that reports a
    /// Pixel 7. The TLS recipes are desktop Edge's TLS recipes, which Edge 153
    /// and 154 send alike, and the H2, QUIC, and H3 recipes return the
    /// Chromium data; the client hints and request identity differ.
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
