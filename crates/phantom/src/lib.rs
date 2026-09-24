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
#[doc = include_str!("../../../docs/guides/profiles.md")]
struct ProfilesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/routes-and-proxies.md")]
struct RoutesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/retries.md")]
struct RetriesGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/http3.md")]
struct Http3GuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/content-decoding.md")]
struct ContentDecodingGuideDoctests;

#[cfg(all(doctest, feature = "cookies"))]
#[doc = include_str!("../../../docs/guides/connections-and-state.md")]
struct ConnectionsGuideDoctests;

#[cfg(all(doctest, feature = "cookies"))]
#[doc = include_str!("../../../docs/guides/coming-from-reqwest.md")]
struct ComingFromReqwestGuideDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/guides/troubleshooting.md")]
struct TroubleshootingGuideDoctests;

#[cfg(all(doctest, feature = "sse"))]
#[doc = include_str!("../../../docs/guides/sse.md")]
struct SseGuideDoctests;

// The WebSocket guide includes a compression example.
#[cfg(all(doctest, feature = "websocket-deflate"))]
#[doc = include_str!("../../../docs/guides/websocket.md")]
struct WebSocketGuideDoctests;

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
    WebSocketLimits, WebSocketMessage, WebSocketRequestBuilder,
};

/// Policy for authenticating a TLS server certificate.
pub use phantom_net::ServerAuthentication;
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
        ClientProfile, CookiePlacement, EchGreaseAead, Http1Settings, Http2HpackSettings,
        Http2HuffmanCoding, Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings,
        Http2StaticNameIndex, Http3ClientSettings, Http3PseudoHeader, Http3QpackDecoderStream,
        Http3QpackEncoding, Http3RequestSettings, Http3Setting, Http3SettingOrder, Http3Settings,
        InvalidClientHintSettings, InvalidHttp2Settings, InvalidHttp3RequestSettings,
        InvalidHttp3Settings, InvalidRequestTemplate, InvalidTcpSettings, InvalidTlsSettings,
        InvalidWebSocketSettings, NamedGroup, RequestField, RequestTemplate, SignatureScheme,
        TcpAddressRacing, TcpKeepalive, TcpSettings, TlsSettings, TlsVersion,
        WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketField,
        WebSocketNewConnection, WebSocketSettings,
    };

    /// Chromium-family recipes implemented by the public facade.
    pub mod chromium {
        pub use phantom_profile::chromium::{
            v154_cookie_placement, v154_http1, v154_http2, v154_http3, v154_http3_request,
            v154_http3_tls, v154_quic, v154_tcp, v154_tls, v154_websocket,
            v154_windows_client_hints, v154_windows_fetch_no_store_template,
            v154_windows_navigation_template,
        };
    }

    /// Firefox recipes implemented by the public facade.
    pub mod firefox {
        pub use phantom_profile::firefox::{
            v156_cookie_placement, v156_http1, v156_http2, v156_tcp, v156_tls, v156_websocket,
            v156_windows_fetch_no_store_template, v156_windows_navigation_template,
        };
    }

    /// Microsoft Edge recipes implemented by the public facade.
    ///
    /// Edge 153 shares the Chromium H2, QUIC, and H3 recipes; only its TLS
    /// ClientHellos, client hints, and request identity differ.
    pub mod edge {
        pub use phantom_profile::edge::{
            v153_http3_tls, v153_tls, v153_windows_client_hints,
            v153_windows_fetch_no_store_template, v153_windows_navigation_template,
        };
    }
}

/// An ordered request field preserving spelling, value bytes, and position.
pub use phantom_net::request::RequestHeader;
/// One declared request-trailer name retaining exact spelling and position.
pub use phantom_net::request::RequestTrailerName;

/// Lossless ordinary response-field order attached to each response.
pub use phantom_net::{OrderedResponseHeaders, ResponseHeader};

/// HTTP request method accepted by [`Client::request`].
pub use http::Method;
