//! Client-neutral profile identity, provenance, and wire settings.

pub mod chromium;
pub mod firefox;
pub mod http2;
pub mod http3;
pub mod quic;
pub mod safari;
pub mod tls;

mod client;
mod identity;

pub use client::{ClientProfile, Http3ClientSettings};
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
    ClientHelloExtensionOrder, InvalidTlsSettings, NamedGroup, SignatureScheme, TlsSettings,
    TlsVersion,
};
