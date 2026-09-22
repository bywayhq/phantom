//! Client-neutral profile identity, provenance, and wire settings.

pub mod chromium;
pub mod client_hints;
pub mod cookie;
pub mod edge;
pub mod firefox;
pub mod http2;
pub mod http3;
pub mod quic;
pub mod safari;
pub mod tls;
pub mod websocket;

mod client;
mod identity;

pub use client::{ClientProfile, Http3ClientSettings};
pub use client_hints::{
    ClientHint, ClientHintDelivery, ClientHintSettings, InvalidClientHintSettings,
};
pub use cookie::CookiePlacement;
pub use http2::{
    Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings, InvalidHttp2Settings,
};
pub use http3::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoding, Http3RequestSettings,
    Http3Setting, Http3SettingOrder, Http3Settings, InvalidHttp3RequestSettings,
    InvalidHttp3Settings,
};
pub use identity::{
    ClientFamily, EmptyClientVersion, InvalidProfileId, Platform, ProfileId, ProfileMetadata,
};
pub use tls::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, EchGreaseAead, InvalidTlsSettings, NamedGroup, SignatureScheme,
    TlsSettings, TlsVersion,
};
pub use websocket::{
    InvalidWebSocketSettings, WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketField,
    WebSocketNewConnection, WebSocketSettings,
};
