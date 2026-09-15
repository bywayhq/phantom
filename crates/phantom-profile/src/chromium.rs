//! Wire settings retained from Chromium-family browser observations.

use crate::{
    http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings},
    tls::{
        AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtensionOrder, NamedGroup,
        SignatureScheme, TlsSettings, TlsVersion,
    },
};

const V152_MACOS_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0xd6, 0x79, 0x09, 0x06],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0xd6, 0x79, 0x09, 0x02],
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0xd6, 0x79, 0x09, 0x0e],
    &[0xd6, 0x79, 0x09, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0xd6, 0x79, 0x09, 0x03],
    &[0xd6, 0x79, 0x09, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0xd6, 0x79, 0x09, 0x0b],
];

/// Returns TLS settings captured from Chrome 152.0.7977.83 on macOS 15.5.
///
/// The returned value is an ordinary owned [`TlsSettings`], so callers can
/// customize it before constructing a transport. Its wire-relevant defaults
/// are checked against the retained ClientHello fixture in `phantom-net`.
#[must_use]
pub fn v152_macos_tls() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
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
        ],
        key_shares: vec![NamedGroup::X25519MlKem768, NamedGroup::X25519],
        signature_schemes: vec![
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha512,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: Some(AlpsSettings {
            protocol: Box::from(&b"h2"[..]),
            settings: Box::default(),
            use_new_codepoint: true,
        }),
        certificate_compression: vec![CertificateCompression::Brotli],
        session_tickets: true,
        record_size_limit: None,
        requested_trust_anchor_ids: Some(
            V152_MACOS_TRUST_ANCHOR_IDS
                .iter()
                .map(|id| Box::from(*id))
                .collect(),
        ),
        grease: true,
        grease_signature_algorithms: true,
        extension_order: ClientHelloExtensionOrder::Permuted,
        ech_grease: true,
        ech_grease_payload_length: None,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

/// Returns HTTP/2 settings observed from Chrome 152.0.7977.83 on macOS 15.5.
///
/// The initial SETTINGS and connection window are checked against a retained
/// raw startup-frame capture. Pseudo-header order and request priority come
/// from a supplemental Pingly observation. The returned value is an ordinary
/// owned [`Http2Settings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v152_macos_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(6_291_456),
            Http2Setting::MaxHeaderListSize(262_144),
        ],
        initial_connection_window_size: 15_728_640,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Path,
        ],
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 256,
            exclusive: true,
        }),
    }
}

#[cfg(test)]
mod tests;
