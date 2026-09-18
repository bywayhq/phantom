//! Wire settings retained from Firefox browser observations.

use crate::{
    http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings},
    tls::{
        CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
        NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
    },
};

/// Returns TLS settings captured from Firefox 154.0 on macOS 15.5.
///
/// The fixed extension order and exact ECH GREASE payload length retain the
/// stable wire shape observed across the local captures. The delegated-
/// credential vector includes legacy ECDSA-SHA1 because Firefox advertised it;
/// TLS 1.3 authentication cannot select that legacy scheme. The returned value
/// is an ordinary owned [`TlsSettings`], so callers can customize it before
/// constructing a transport.
#[must_use]
pub fn v154_macos_tls() -> TlsSettings {
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
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

/// Returns HTTP/2 settings observed from Firefox 154.0 on macOS 15.5.
///
/// The initial SETTINGS and connection window come from the retained local raw
/// startup-frame capture. Pseudo-header order and request priority come from
/// matching supplemental Peet and Pingly observations; the local capture ends
/// before a request HEADERS frame. The returned value is an ordinary owned
/// [`Http2Settings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_macos_http2() -> Http2Settings {
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

#[cfg(test)]
mod tests;
