//! Browser recipes and typed settings for Phantom connections.

pub mod brave;
pub mod brave_android;
pub mod chrome_android;
pub mod chromium;
pub mod client_hints;
pub mod cookie;
pub mod dns_cache;
pub mod edge;
pub mod edge_android;
pub mod firefox;
pub mod firefox_android;
pub mod http1;
pub mod http2;
pub mod http3;
pub mod opera;
pub mod opera_android;
pub mod proxy_connect;
pub mod quic;
pub mod request_template;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod websocket;

mod client;

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
    ClientHelloExtensionOrder, EchGreaseAead, EchGreasePayloadLength, InvalidTlsSettings,
    NamedGroup, SessionTicketOrder, SignatureScheme, TlsSettings, TlsVersion, TrustAnchorIds,
};
pub use udp::UdpSettings;
pub use websocket::{
    InvalidWebSocketSettings, WebSocketConnectionPolicy, WebSocketDeflateParameter,
    WebSocketEmptyMessageCompression, WebSocketField, WebSocketNewConnection,
    WebSocketProxiedSession, WebSocketRefusedStreamRetry, WebSocketSettings,
};
