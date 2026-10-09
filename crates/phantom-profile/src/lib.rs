//! Browser recipes and typed settings for Phantom connections.
//!
//! Public settings fields let you combine recipe components and change the
//! values you need. Call each changed settings type's `validate` method when
//! it has one before passing it to a transport. Backend and host checks can
//! still reject a structurally valid configuration.
//!
//! Adding or removing a required public field is a breaking API change.
//! Before version 1.0, such changes require a minor release. Policy enums
//! marked `non_exhaustive` require a catch-all match arm. A transport must
//! reject an unknown policy instead of choosing an implicit behavior.
//!
//! Settings equality compares stored values, including the order of lists.
//! It does not prove that two settings produce the same connection bytes.
//! Clone, Debug, Eq, Send, and Sync apply where each type implements them.
//! Validation errors in this crate support these traits too. Network errors
//! can carry runtime or backend sources and are outside this contract.
//! Defaults, builders, and Hash are provided only by types that implement
//! them.

pub mod browser;

pub mod client_hints;
pub mod cookie;
pub mod dns_cache;
pub mod http1;
pub mod http2;
pub mod http3;
pub mod proxy_connect;
pub mod quic;
pub mod request_template;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod websocket;

mod client;
mod url_trust;
mod validation;

pub use client::{ClientProfile, Http3ClientSettings};
pub use client_hints::{
    ClientHint, ClientHintDelivery, ClientHintSettings, InvalidClientHintSettings,
};
pub use cookie::CookiePlacement;
pub use dns_cache::DnsCacheSettings;
pub use http1::{Http1IdleTimeout, Http1Settings, InvalidHttp1Settings};
pub use http2::{
    Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
    Http2IdleTimeout, Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader,
    Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
    Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch, InvalidHttp2Settings,
};
pub use http3::{
    Http3AltUsed, Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream,
    Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings,
    Http3Setting, Http3SettingOrder, Http3Settings, InvalidHttp3RequestSettings,
    InvalidHttp3Settings,
};
pub use proxy_connect::{
    Http2ProxyConnections, Http2RejectedConnect, InvalidProxyConnectTemplate, ProxyConnectField,
    ProxyConnectTemplate,
};
pub use request_template::{
    InvalidRequestTemplate, ProxyAuthorizationAttempt, RequestField, RequestTemplate,
};
pub use tcp::{
    InvalidTcpSettings, TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection,
    TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy, TcpKeepaliveSchedule,
    TcpPortRandomization, TcpSettings,
};
pub use tls::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, EchGreaseAead, EchGreasePayloadLength, EchGreaseSettings,
    EchSettings, InvalidTlsSettings, NamedGroup, SessionTicketOrder, SessionTickets,
    SignatureScheme, TlsSettings, TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder,
    TrustAnchorOrders, UnknownCipherSuite,
};
pub use udp::UdpSettings;
pub use url_trust::UrlTrust;
pub use validation::ValidationErrorKind;
pub use websocket::{
    InvalidWebSocketSettings, WebSocketConnectionPolicy, WebSocketDeflateParameter,
    WebSocketEmptyMessageCompression, WebSocketField, WebSocketNewConnection,
    WebSocketProxiedSession, WebSocketRefusedStreamRetry, WebSocketSettings,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_and_validation_errors_keep_their_public_traits() {
        fn settings<T: Clone + std::fmt::Debug + Eq + Send + Sync>() {}
        settings::<TcpSettings>();
        settings::<ClientHint>();
        settings::<ClientHintSettings>();
        settings::<TlsSettings>();
        settings::<Http2Settings>();
        settings::<Http2HpackSettings>();
        settings::<Http2StreamSettings>();
        settings::<Http3Settings>();
        settings::<Http3RequestSettings>();
        settings::<quic::QuicTransportSettings>();
        settings::<UrlTrust>();
        settings::<ValidationErrorKind>();

        fn error<T: Clone + std::fmt::Debug + Eq + std::error::Error + Send + Sync>() {}
        error::<InvalidTcpSettings>();
        error::<InvalidClientHintSettings>();
        error::<InvalidTlsSettings>();
        error::<InvalidHttp2Settings>();
        error::<InvalidHttp3Settings>();
        error::<InvalidHttp3RequestSettings>();
        error::<quic::InvalidQuicTransportSettings>();
        error::<InvalidHttp1Settings>();
        error::<InvalidProxyConnectTemplate>();
        error::<InvalidRequestTemplate>();
        error::<InvalidWebSocketSettings>();
        error::<UnknownCipherSuite>();
    }
}
