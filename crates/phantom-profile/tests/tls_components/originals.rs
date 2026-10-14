// Independent original factories at f3b18c9a6e21876ad180bb23ec335bc534644f29.
// Private original constructors are replaced only with checked public equivalents.

use phantom_profile::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, EchGreaseAead, EchGreasePayloadLength, EchGreaseSettings,
    EchSettings, InvalidTlsSettings, NamedGroup, SessionTicketOrder, SessionTickets,
    SignatureScheme, TlsSettings, TlsVersion, TlsVersionRange, TrustAnchorIds, TrustAnchorOrder,
};

const V154_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0f],
];

pub(super) fn chrome_tcp() -> Result<TlsSettings, InvalidTlsSettings> {
    Ok(TlsSettings {
        versions: TlsVersionRange::TLS12_TO_TLS13,
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
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: Some(AlpsSettings {
            protocol: Box::from(&b"h2"[..]),
            settings: Box::default(),
            use_new_codepoint: true,
        }),
        certificate_compression: vec![CertificateCompression::Brotli],
        session_tickets: SessionTickets::enabled(2)?,
        session_ticket_order: SessionTicketOrder::NewestFirst,
        session_ticket_extension_when_resuming: true,
        tcp_early_data: false,
        record_size_limit: None,
        tls12_extensions_in_tls13_client_hello: false,
        requested_trust_anchor_ids: Some(trust_anchor_ids(V154_TRUST_ANCHOR_IDS)?),
        grease: true,
        grease_signature_algorithms: true,
        extension_order: ClientHelloExtensionOrder::Permuted,
        ech: EchSettings::HttpsRecords(EchGreaseSettings::backend_default()),
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
        close_notify: false,
    })
}

pub(super) fn chrome_quic() -> Result<TlsSettings, InvalidTlsSettings> {
    let mut settings = chrome_tcp()?;
    settings.versions = TlsVersionRange::only(TlsVersion::Tls13);
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ];
    settings.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPkcs1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::RsaPssRsaeSha384,
        SignatureScheme::RsaPkcs1Sha384,
        SignatureScheme::RsaPssRsaeSha512,
        SignatureScheme::RsaPkcs1Sha512,
        SignatureScheme::RsaPkcs1Sha1,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h3"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });
    settings.grease = false;
    settings.grease_signature_algorithms = false;
    settings.request_ocsp_staple = false;
    settings.request_signed_certificate_timestamps = false;
    Ok(settings)
}

pub(super) fn firefox_tcp() -> Result<TlsSettings, InvalidTlsSettings> {
    Ok(TlsSettings {
        versions: TlsVersionRange::TLS12_TO_TLS13,
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
        session_tickets: SessionTickets::enabled(10)?,
        session_ticket_order: SessionTicketOrder::OldestConnectionFirst,
        session_ticket_extension_when_resuming: false,
        tcp_early_data: true,
        record_size_limit: Some(16_385),
        tls12_extensions_in_tls13_client_hello: true,
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
            ClientHelloExtension::EarlyData,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::RecordSizeLimit,
            ClientHelloExtension::CertificateCompression,
            ClientHelloExtension::EncryptedClientHello,
        ]),
        ech: EchSettings::Grease(firefox_ech_grease()?),
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
        close_notify: true,
    })
}

pub(super) fn firefox_quic() -> Result<TlsSettings, InvalidTlsSettings> {
    let mut settings = firefox_tcp()?;
    settings.versions = TlsVersionRange::only(TlsVersion::Tls13);
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Chacha20Poly1305Sha256,
        CipherSuite::Aes256GcmSha384,
    ];
    settings.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::EcdsaSecp521r1Sha512,
        SignatureScheme::EcdsaSha1,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPssRsaeSha384,
        SignatureScheme::RsaPssRsaeSha512,
        SignatureScheme::RsaPkcs1Sha256,
        SignatureScheme::RsaPkcs1Sha384,
        SignatureScheme::RsaPkcs1Sha512,
        SignatureScheme::RsaPkcs1Sha1,
    ];
    settings.certificate_compression = vec![
        CertificateCompression::Zlib,
        CertificateCompression::Zstd,
        CertificateCompression::Brotli,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.request_signed_certificate_timestamps = false;
    settings.extension_order = ClientHelloExtensionOrder::PermutedWithTail(vec![
        ClientHelloExtension::QuicTransportParameters,
        ClientHelloExtension::EncryptedClientHello,
    ]);
    // QUIC early data follows `v157_quic`; this field covers TCP only.
    settings.tcp_early_data = false;
    Ok(settings)
}

fn trust_anchor_ids(ids: &[&[u8]]) -> Result<TrustAnchorIds, InvalidTlsSettings> {
    Ok(TrustAnchorIds::Fixed(TrustAnchorOrder::new(
        ids.iter().map(|id| Box::from(*id)).collect(),
    )?))
}

fn firefox_ech_grease() -> Result<EchGreaseSettings, InvalidTlsSettings> {
    EchGreaseSettings::new(
        EchGreasePayloadLength::FromClientHello {
            maximum_name_length: 100,
        },
        vec![EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305],
    )
}
