//! Client-neutral profile wire settings.

pub mod brave;
pub mod brave_android;
pub mod chrome_android;
pub mod chromium;
pub mod client_hints;
pub mod cookie;
pub mod dns_cache;
pub mod edge;
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
pub mod websocket;

mod client;

pub use client::{ClientProfile, Http3ClientSettings};
pub use client_hints::{
    ClientHint, ClientHintDelivery, ClientHintSettings, InvalidClientHintSettings,
};
pub use cookie::CookiePlacement;
pub use dns_cache::DnsCacheSettings;
pub use http1::Http1Settings;
pub use http2::{
    Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
    Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader, Http2Setting,
    Http2Settings, Http2StaticNameIndex, Http2TableSizeUpdates, Http2UnindexedMatch,
    InvalidHttp2Settings,
};
pub use http3::{
    Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream,
    Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings, Http3Setting,
    Http3SettingOrder, Http3Settings, InvalidHttp3RequestSettings, InvalidHttp3Settings,
};
pub use proxy_connect::{
    Http2ProxyConnections, Http2RejectedConnect, InvalidProxyConnectTemplate, ProxyConnectField,
    ProxyConnectTemplate,
};
pub use request_template::{
    InvalidRequestTemplate, ProxyAuthorizationAttempt, RequestField, RequestTemplate,
};
pub use tcp::{InvalidTcpSettings, TcpAddressRacing, TcpKeepalive, TcpSettings};
pub use tls::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, EchGreaseAead, InvalidTlsSettings, NamedGroup, SignatureScheme,
    TlsSettings, TlsVersion,
};
pub use websocket::{
    InvalidWebSocketSettings, WebSocketConnectionPolicy, WebSocketDeflateParameter,
    WebSocketEmptyMessageCompression, WebSocketField, WebSocketNewConnection,
    WebSocketRefusedStreamRetry, WebSocketSettings,
};
