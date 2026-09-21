//! Wire settings retained from Firefox browser observations.

use crate::{
    http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings},
    tls::{
        CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
        EchGreaseAead, NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
    },
};

/// Returns TLS settings captured from Firefox 154.0 on macOS 15.5 and Windows 11.
///
/// Captures on both platforms (Windows 11 build 26200) match this recipe on
/// every compared field, so the name carries no platform.
///
/// The fixed extension order and exact ECH GREASE payload length retain the
/// stable wire shape observed across the local captures. Firefox picks its ECH
/// GREASE AEAD per connection from AES-128-GCM and ChaCha20-Poly1305 with equal
/// probability; this recipe lists both, so each connection draws one the same
/// way. The delegated-credential vector includes legacy
/// ECDSA-SHA1 because Firefox advertised it; TLS 1.3 authentication cannot
/// select that legacy scheme. The returned value is an ordinary owned
/// [`TlsSettings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::RsaAes256CbcSha,
        ],
        groups: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
            NamedGroup::Ffdhe2048,
            NamedGroup::Ffdhe3072,
        ],
        key_shares: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
        ],
        signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::RsaPkcs1Sha1,
        ],
        delegated_credential_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ],
        session_tickets: true,
        record_size_limit: Some(16_385),
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::Fixed(vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ExtendedMasterSecret,
            ClientHelloExtension::RenegotiationInfo,
            ClientHelloExtension::SupportedGroups,
            ClientHelloExtension::EcPointFormats,
            ClientHelloExtension::SessionTicket,
            ClientHelloExtension::Alpn,
            ClientHelloExtension::StatusRequest,
            ClientHelloExtension::DelegatedCredential,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::RecordSizeLimit,
            ClientHelloExtension::CertificateCompression,
            ClientHelloExtension::EncryptedClientHello,
        ]),
        ech_grease: true,
        ech_grease_payload_length: Some(239),
        ech_grease_aeads: vec![EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305],
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

/// Returns HTTP/2 settings observed from Firefox 154.0 on macOS 15.5 and Windows 11.
///
/// Captures on both platforms (Windows 11 build 26200) match this recipe on
/// every compared field, so the name carries no platform.
///
/// The initial SETTINGS and connection window come from the retained local raw
/// startup-frame capture. Pseudo-header order and request priority come from
/// matching supplemental Peet and Pingly observations; the local capture ends
/// before a request HEADERS frame. The returned value is an ordinary owned
/// [`Http2Settings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ],
        initial_connection_window_size: 12_582_912,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ],
        extended_connect_pseudo_header_order: None,
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
    }
}

/// Returns TLS settings captured from Firefox 156.0 on Windows 11.
///
/// Captured from Firefox 156.0 (Windows 11 build 26200) in twelve fresh
/// processes. It reuses [`v154_tls`] and changes only the two fields that
/// differ from Firefox 154: the supported groups no longer offer FFDHE-2048 or
/// FFDHE-3072, and the ECH GREASE payload is 240 bytes instead of 239. Every
/// other compared field, including the fixed extension order, matches 154.
/// Firefox still picks its ECH GREASE AEAD per connection from AES-128-GCM and
/// ChaCha20-Poly1305; this recipe keeps both choices from [`v154_tls`]. The
/// returned value is an ordinary owned [`TlsSettings`].
#[must_use]
pub fn v156_tls() -> TlsSettings {
    let mut settings = v154_tls();
    settings.groups = vec![
        NamedGroup::X25519MlKem768,
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
        NamedGroup::Secp521r1,
    ];
    settings.ech_grease_payload_length = Some(240);
    settings
}

/// Returns HTTP/2 settings observed from Firefox 156.0 on Windows 11.
///
/// Firefox 156.0 (Windows 11 build 26200) matches [`v154_http2`] on every
/// compared field, so this returns that recipe unchanged. The initial
/// SETTINGS, connection window, request pseudo-header order, and HEADERS
/// priority come from the retained local H2 session captures of the WebSocket
/// fixture set, three fresh-profile runs.
#[must_use]
pub fn v156_http2() -> Http2Settings {
    v154_http2()
}

// Compatibility aliases for the names used before the Windows parity
// captures showed these transport recipes are platform-independent.

/// Compatibility alias for [`v154_tls`].
#[doc(hidden)]
#[must_use]
pub fn v154_macos_tls() -> TlsSettings {
    v154_tls()
}

/// Compatibility alias for [`v154_http2`].
#[doc(hidden)]
#[must_use]
pub fn v154_macos_http2() -> Http2Settings {
    v154_http2()
}

#[cfg(test)]
mod tests;
