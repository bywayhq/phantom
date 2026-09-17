//! Public Phantom client facade.

mod authority;
mod body;
mod client;
mod error;
mod redirect;
mod request;
mod response;
mod route;
mod session;
#[cfg(feature = "sse")]
mod sse;
#[cfg(feature = "websocket")]
mod websocket;

pub use body::ResponseBody;
pub use client::{Client, ClientBuilder, HttpProtocol};
pub use error::{BuildError, BuildErrorKind, RequestError, RequestErrorKind};
pub use redirect::RedirectPolicy;
pub use request::RequestBuilder;
pub use response::ResponseInfo;
pub use route::{
    HttpProxy, ProxyConfigError, ProxyConfigErrorKind, Route, Socks5DnsMode, Socks5Proxy,
    Socks5ProxyConfigError, Socks5ProxyConfigErrorKind,
};
#[cfg(feature = "cookies")]
pub use session::{CookieError, CookieErrorKind, CookieJar, CookieLimits};
#[doc(hidden)]
pub use session::{Session, SessionBuilder};
#[cfg(feature = "sse")]
pub use sse::{
    SseError, SseErrorKind, SseEvent, SseEventSource, SseLimits, SseRequestBuilder, SseStream,
};
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
        AlpsSettings, CertificateCompression, CipherSuite, ClientFamily, ClientHelloExtension,
        ClientHelloExtensionOrder, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, EmptyClientVersion, Http2Priority, Http2PseudoHeader, Http2Setting,
        Http2Settings, Http3ClientSettings, Http3PseudoHeader, Http3QpackDecoderStream,
        Http3QpackEncoding, Http3RequestSettings, Http3Setting, Http3SettingOrder, Http3Settings,
        InvalidClientHintSettings, InvalidHttp2Settings, InvalidHttp3RequestSettings,
        InvalidHttp3Settings, InvalidProfileId, InvalidTlsSettings, NamedGroup, Platform,
        ProfileId, ProfileMetadata, SignatureScheme, TlsSettings, TlsVersion,
    };

    /// Chromium-family recipes implemented by the public facade.
    pub mod chromium {
        pub use phantom_profile::chromium::{
            v152_macos_client_hints, v152_macos_http2, v152_macos_http3, v152_macos_http3_request,
            v152_macos_http3_tls, v152_macos_quic, v152_macos_tls,
        };
    }

    /// Firefox recipes implemented by the public facade.
    pub mod firefox {
        pub use phantom_profile::firefox::{v154_macos_http2, v154_macos_tls};
    }

    /// Safari recipes implemented by the public facade.
    pub mod safari {
        pub use phantom_profile::safari::v18_5_macos_tls;
    }
}

/// An ordered request field preserving spelling, value bytes, and position.
pub use phantom_net::request::RequestHeader;

/// Lossless ordinary response-field order attached to each response.
pub use phantom_net::{OrderedResponseHeaders, ResponseHeader};

/// HTTP request method accepted by [`Client::request`].
pub use http::Method;
