//! Public Phantom client facade.

mod body;
mod client;
mod error;
mod request;

pub use body::ResponseBody;
pub use client::{Client, ClientBuilder, HttpProtocol};
pub use error::{BuildError, BuildErrorKind, RequestError, RequestErrorKind};
pub use request::RequestBuilder;

/// Client-profile types used to configure observable wire behavior.
pub mod profile {
    pub use phantom_profile::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientFamily, ClientHelloExtension,
        ClientHelloExtensionOrder, ClientProfile, EmptyClientVersion, Http2Priority,
        Http2PseudoHeader, Http2Setting, Http2Settings, InvalidHttp2Settings, InvalidProfileId,
        InvalidTlsSettings, NamedGroup, Platform, ProfileId, ProfileMetadata, SignatureScheme,
        TlsSettings, TlsVersion,
    };

    /// Chromium-family recipes implemented by the public facade.
    pub mod chromium {
        pub use phantom_profile::chromium::{v152_macos_http2, v152_macos_tls};
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
