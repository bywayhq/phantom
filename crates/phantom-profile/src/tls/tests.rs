use std::error::Error;

use super::*;

fn minimal_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![CipherSuite::Aes128GcmSha256],
        groups: vec![NamedGroup::X25519],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        alpn_protocols: vec![Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: true,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

#[test]
fn tls_12_does_not_require_key_shares() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;
    settings.key_shares.clear();

    settings.validate()?;
    Ok(())
}

#[test]
fn tls_12_rejects_key_shares() {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("key_shares")
    );
}

#[test]
fn tls_12_rejects_ech_grease() {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;
    settings.key_shares.clear();
    settings.ech_grease = true;

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease")
    );
}

#[test]
fn tls_12_rejects_alps() {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;
    settings.key_shares.clear();
    settings.alps = Some(AlpsSettings {
        protocol: Box::from(&b"http/1.1"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });

    let error = settings.validate().err();
    assert_eq!(error.as_ref().map(InvalidTlsSettings::field), Some("alps"));
}

#[test]
fn alps_settings_must_fit_the_tls_vector() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.alpn_protocols = vec![Box::from(&b"h2"[..])];
    settings.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h2"[..]),
        settings: vec![0; u16::MAX as usize].into_boxed_slice(),
        use_new_codepoint: true,
    });

    settings.validate()?;
    settings
        .alps
        .as_mut()
        .ok_or("test profile omitted ALPS")?
        .settings = vec![0; u16::MAX as usize + 1].into_boxed_slice();

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("alps.settings")
    );
    Ok(())
}

#[test]
fn tls_12_rejects_requested_trust_anchors() {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;
    settings.key_shares.clear();
    settings.requested_trust_anchor_ids = Some(Vec::new());

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("requested_trust_anchor_ids")
    );
}

#[test]
fn tls_12_rejects_certificate_compression() {
    let mut settings = minimal_settings();
    settings.max_version = TlsVersion::Tls12;
    settings.key_shares.clear();
    settings.certificate_compression = vec![CertificateCompression::Zlib];

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("certificate_compression")
    );
}

#[test]
fn certificate_compression_accepts_unique_order_and_rejects_duplicates()
-> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.certificate_compression = vec![
        CertificateCompression::Zlib,
        CertificateCompression::Brotli,
        CertificateCompression::Zstd,
    ];
    settings.validate()?;

    settings
        .certificate_compression
        .push(CertificateCompression::Zlib);
    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("certificate_compression")
    );
    Ok(())
}

#[test]
fn fixed_extension_order_must_be_nonempty_and_unique() {
    for extensions in [
        Vec::new(),
        vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ServerName,
        ],
    ] {
        let mut settings = minimal_settings();
        settings.extension_order = ClientHelloExtensionOrder::Fixed(extensions);
        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("extension_order")
        );
    }
}

#[test]
fn trust_anchor_ids_may_be_omitted_or_explicitly_empty() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = Some(Vec::new());

    settings.validate()?;
    settings.requested_trust_anchor_ids = None;
    settings.validate()?;
    Ok(())
}

#[test]
fn trust_anchor_ids_must_be_nonempty_and_fit_one_byte_lengths() {
    let invalid_ids = [Box::default(), vec![0; 256].into_boxed_slice()];

    for id in invalid_ids {
        let mut settings = minimal_settings();
        settings.requested_trust_anchor_ids = Some(vec![id]);
        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchor_ids")
        );
    }
}

#[test]
fn trust_anchor_id_list_must_fit_the_extension_body() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    let mut ids = (0..u8::MAX)
        .map(|_| vec![0; u8::MAX as usize].into_boxed_slice())
        .collect::<Vec<_>>();
    ids.push(vec![0; 252].into_boxed_slice());
    settings.requested_trust_anchor_ids = Some(ids.clone());

    settings.validate()?;
    ids.push(Box::from(&b"x"[..]));
    settings.requested_trust_anchor_ids = Some(ids);

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("requested_trust_anchor_ids")
    );
    Ok(())
}
