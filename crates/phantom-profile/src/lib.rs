//! Client-neutral profile identity, provenance, and wire settings.

pub mod chromium;
pub mod firefox;
pub mod http2;
pub mod safari;
pub mod tls;

mod identity;

pub use http2::{
    Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings, InvalidHttp2Settings,
};
pub use identity::{
    ClientFamily, EmptyClientVersion, InvalidProfileId, Platform, ProfileId, ProfileMetadata,
};
pub use tls::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, InvalidTlsSettings, NamedGroup, SignatureScheme, TlsSettings,
    TlsVersion,
};
