#![doc = include_str!("docs/overview.md")]

/// Shared byte buffer used for request and response bodies.
pub use bytes::Bytes;
/// The stream trait implemented by SSE streams and event sources.
#[cfg(feature = "sse")]
pub use futures_core::Stream;
/// HTTP request method accepted by [`Client::request`].
pub use http::Method;
/// HTTP response returned by [`RequestBuilder::send`].
pub use http::Response;
/// HTTP status accepted by [`StatusRetry`] and returned by [`Response::status`].
pub use http::StatusCode;
/// HTTP URI returned by [`ResponseInfo::effective_uri`].
pub use http::Uri;
/// Caller-supplied host name resolution for [`ClientBuilder::dns_resolver`].
pub use phantom_net::host_resolver::{
    AddressAnswer, AddressNegative, AddressNegativeKind, AddressResolver, DnsConfigurationToken,
};
/// An ordered HTTP CONNECT field or destination-authority placeholder.
pub use phantom_net::proxy::{
    DigestAuthError, DigestPolicy, HttpConnectHeader, HttpDigestCredentials,
};
/// An ordered request field preserving spelling, value bytes, and position.
pub use phantom_net::request::RequestHeader;
/// One declared request-trailer name retaining exact spelling and position.
pub use phantom_net::request::RequestTrailerName;
/// A TLS client certificate for [`ClientBuilder::client_certificate`] and
/// [`ClientBuilder::client_certificate_for`].
pub use phantom_net::{ClientCertificate, ClientCertificateError, ClientCertificateErrorKind};
pub use phantom_net::{
    ConnectionEndpointScope, RequestConnection, RequestDiagnostics, RequestTimeline,
    RequestTimelineOutcome, RequestTiming, RequestTimingOutcome, RequestTimingPhase,
    TlsConnectionInfo, TlsConnectionState,
};
pub use phantom_net::{HttpAttemptBudget, HttpAttemptBudgetExhausted};
pub use phantom_net::{InvalidAuthorization, InvalidAuthorizationKind};
/// Policy for authenticating a TLS server certificate.
pub use phantom_net::{InvalidServerSpkiPins, ServerAuthentication, ServerSpkiPins};
/// Lossless ordinary response-field order attached to each response.
pub use phantom_net::{OrderedResponseHeaders, ResponseHeader};

#[cfg(feature = "https-records")]
pub use alt_svc_https_policy::AltSvcHttpsPolicy;
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
pub use header_hook::{HeaderHookContext, HeaderHookError};
pub use link::{Link, LinkParameter, LinkParseError, LinkParseErrorKind, parse_link_headers};
pub use redirect::{RedirectHistory, RedirectHop, RedirectPolicy};
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
    ProxyConfigError, ProxyConfigErrorKind, Route, Socks4DnsMode, Socks4Proxy,
    Socks4ProxyConfigError, Socks4ProxyConfigErrorKind, Socks5DnsMode, Socks5Proxy,
    Socks5ProxyConfigError, Socks5ProxyConfigErrorKind,
};
pub use session::{
    AltSvcBrokenBackoff, AltSvcOriginDelay, AltSvcPolicy, AltSvcRace, AltSvcRttDelay,
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, AltSvcSnapshotErrorKind,
    SessionTicketError, SessionTicketErrorKind, SessionTicketSnapshot,
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

// Compile-check the README Rust example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../../../README.md")]
struct ReadmeDoctests;

#[cfg(feature = "https-records")]
mod alt_svc_https_policy;
mod authority;
mod base_url;
mod body;
mod client;
mod content_coding;
#[cfg(feature = "diagnostics")]
mod diagnostics;
#[cfg(feature = "https-records")]
mod doh;
mod environment_proxy;
mod error;
mod header_hook;
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

pub mod guide;

/// Client-profile types used to configure observable wire behavior.
///
/// See [Browser profiles](crate::guide::browser_profiles) to choose connection
/// settings and request templates.
pub mod profile {
    pub use phantom_profile::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
        ClientHelloExtensionOrder, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, CookiePlacement, DnsAddressFailurePolicy, DnsCacheSettings, EchGreaseAead,
        EchGreasePayloadLength, EchGreaseSettings, EchSettings, GoogleConnectionOption,
        Http1IdleTimeout, Http1Settings, Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings,
        Http2HuffmanCoding, Http2IdleTimeout, Http2IndexingLimit, Http2NameReference,
        Http2Priority, Http2ProxyConnections, Http2PseudoHeader, Http2RejectedConnect,
        Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
        Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch, Http3AltUsed,
        Http3ClientSettings, Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream,
        Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings,
        Http3Setting, Http3SettingOrder, Http3Settings, InvalidClientHintSettings,
        InvalidHttp1Settings, InvalidHttp2Settings, InvalidHttp3RequestSettings,
        InvalidHttp3Settings, InvalidProxyConnectTemplate, InvalidQuicTransportSettings,
        InvalidRequestTemplate, InvalidTcpSettings, InvalidTlsSettings, InvalidWebSocketSettings,
        NamedGroup, ProxyAuthorizationAttempt, ProxyConnectField, ProxyConnectTemplate,
        QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportGrease, QuicTransportParameter,
        QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
        QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation, RequestField, RequestTemplate,
        SessionTicketOrder, SessionTickets, SignatureScheme, SystemDnsTtlPolicy, TcpAddressAdvance,
        TcpAddressRacing, TcpAddressSelection, TcpBackupConnection, TcpKeepalive,
        TcpKeepalivePolicy, TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings, TlsSettings,
        TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder, TrustAnchorOrders,
        UdpSettings, UnknownCipherSuite, UrlTrust, ValidationErrorKind, WebSocketConnectionPolicy,
        WebSocketDeflateParameter, WebSocketEmptyMessageCompression, WebSocketField,
        WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
        WebSocketSettings,
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
    pub use crate::doh::{
        DnsOverHttps, DnsOverHttpsBuilder, DohAddressFamilies, DohBuildError, DohBuildErrorKind,
        DohConfiguration, DohMethod,
    };
    #[cfg(target_os = "linux")]
    pub use phantom_net::dns::chromium_linux_resolvers;
    #[cfg(target_os = "macos")]
    pub use phantom_net::dns::chromium_macos_resolvers;
    #[cfg(windows)]
    pub use phantom_net::dns::chromium_windows_resolvers;
    pub use phantom_net::dns::{
        AliasRecord, EchCipherSuite, EchConfig, EchConfigExtension, EchConfigList,
        EchConfigListError, EchConfigListErrorKind, HttpsLookupError, HttpsLookupErrorKind,
        HttpsRecord, HttpsRecordAnswer, HttpsRecordError, HttpsRecordErrorKind, HttpsRecordLookup,
        HttpsRecordResolver, ServiceRecord, SvcParam, TargetName,
    };
}

#[cfg(feature = "fingerprint-import")]
/// Inspect, export, import and name complete custom profiles.
///
/// Imported settings carry no catalog identity or browser validation claim.
pub mod fingerprint;
