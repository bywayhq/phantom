use std::error::Error;

use super::*;

#[test]
fn tls_versions_round_trip_protocol_identifiers() {
    for version in [
        TlsVersion::Tls10,
        TlsVersion::Tls11,
        TlsVersion::Tls12,
        TlsVersion::Tls13,
    ] {
        assert_eq!(
            TlsVersion::from_protocol_id(version.protocol_id()),
            Some(version)
        );
    }
    assert_eq!(TlsVersion::from_protocol_id(0x7f17), None);
}

#[test]
fn cipher_suites_round_trip_iana_identifiers() {
    for suite in [
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
        CipherSuite::EcdheEcdsaAes128CbcSha,
        CipherSuite::EcdheEcdsaAes256CbcSha,
        CipherSuite::EcdheEcdsa3DesEdeCbcSha,
        CipherSuite::EcdheRsa3DesEdeCbcSha,
        CipherSuite::RsaAes128GcmSha256,
        CipherSuite::RsaAes256GcmSha384,
        CipherSuite::RsaAes128CbcSha,
        CipherSuite::RsaAes256CbcSha,
        CipherSuite::Rsa3DesEdeCbcSha,
    ] {
        assert_eq!(CipherSuite::from_iana_id(suite.iana_id()), Some(suite));
    }
    assert_eq!(CipherSuite::from_iana_id(0x0a0a), None);
}

fn minimal_settings() -> TlsSettings {
    TlsSettings {
        versions: crate::TlsVersionRange::TLS12_TO_TLS13,
        cipher_suites: vec![CipherSuite::Aes128GcmSha256],
        groups: vec![NamedGroup::X25519],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: crate::tls::TWO_SESSION_TICKETS,
        session_ticket_order: SessionTicketOrder::NewestFirst,
        session_ticket_extension_when_resuming: true,
        tcp_early_data: false,
        record_size_limit: None,
        tls12_extensions_in_tls13_client_hello: false,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech: crate::EchSettings::Disabled,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
        close_notify: true,
    }
}

#[test]
fn delegated_credential_advertisement_accepts_ordered_ecdsa_schemes() -> Result<(), Box<dyn Error>>
{
    let mut settings = minimal_settings();
    settings.delegated_credential_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::EcdsaSecp521r1Sha512,
        SignatureScheme::EcdsaSha1,
    ];

    settings.validate()?;
    Ok(())
}

#[test]
fn delegated_credential_advertisement_requires_tls_13() {
    let mut settings = minimal_settings();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
    settings.key_shares.clear();
    settings.delegated_credential_schemes = vec![SignatureScheme::EcdsaSecp256r1Sha256];

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("delegated_credential_schemes")
    );
}

#[test]
fn delegated_credential_advertisement_rejects_rsae_schemes() {
    let mut settings = minimal_settings();
    settings.delegated_credential_schemes = vec![SignatureScheme::RsaPssRsaeSha256];

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("delegated_credential_schemes")
    );
}

#[test]
fn record_size_limit_accepts_wire_boundaries() -> Result<(), Box<dyn Error>> {
    for limit in [64, 16_385] {
        let mut settings = minimal_settings();
        settings.record_size_limit = Some(limit);
        settings.validate()?;
    }
    Ok(())
}

#[test]
fn record_size_limit_rejects_values_outside_the_wire_range() {
    for limit in [0, 63, 16_386] {
        let mut settings = minimal_settings();
        settings.record_size_limit = Some(limit);
        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("record_size_limit")
        );
    }
}

#[test]
fn session_tickets_per_origin_must_be_between_one_and_ten() -> Result<(), Box<dyn Error>> {
    for limit in [1, 10] {
        let mut settings = minimal_settings();
        settings.session_tickets = SessionTickets::enabled(limit)?;
        assert_eq!(SessionTickets::try_from(limit)?, settings.session_tickets);
        assert!(settings.session_tickets.is_enabled());
        assert_eq!(
            settings
                .session_tickets
                .tcp_per_origin_limit()
                .map(NonZeroU8::get),
            Some(limit)
        );
        settings.validate()?;
    }
    for limit in [0, 11, u8::MAX] {
        let error = SessionTickets::enabled(limit).err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("session_tickets.tcp_per_origin")
        );
        assert_eq!(SessionTickets::try_from(limit).err(), error);
    }
    Ok(())
}

#[test]
fn disabled_session_tickets_have_no_tcp_limit() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.session_tickets = SessionTickets::disabled();
    assert!(!settings.session_tickets.is_enabled());
    assert_eq!(settings.session_tickets.tcp_per_origin_limit(), None);
    settings.validate()?;
    Ok(())
}

#[test]
fn tls_version_ranges_preserve_endpoints_and_reject_reversal() -> Result<(), InvalidTlsSettings> {
    let versions = [
        TlsVersion::Tls10,
        TlsVersion::Tls11,
        TlsVersion::Tls12,
        TlsVersion::Tls13,
    ];
    for min in versions {
        for max in versions {
            if min <= max {
                let range = TlsVersionRange::new(min, max)?;
                assert_eq!(range.min(), min);
                assert_eq!(range.max(), max);
                assert_eq!(TlsVersionRange::try_from((min, max))?, range);
            } else {
                assert_eq!(
                    TlsVersionRange::new(min, max)
                        .err()
                        .as_ref()
                        .map(InvalidTlsSettings::field),
                    Some("version range")
                );
            }
        }
        assert_eq!(TlsVersionRange::only(min).min(), min);
        assert_eq!(TlsVersionRange::only(min).max(), min);
        assert_eq!(TlsVersionRange::from(min), TlsVersionRange::only(min));
    }
    assert_eq!(
        TlsVersionRange::TLS12_TO_TLS13,
        TlsVersionRange::new(TlsVersion::Tls12, TlsVersion::Tls13)?
    );
    Ok(())
}

#[test]
fn checked_tls_values_support_copy_hash_and_thread_sharing() {
    fn assert_traits<T: Clone + Copy + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync>() {}
    assert_traits::<TlsVersionRange>();
    assert_traits::<SessionTickets>();
}

#[test]
fn tcp_ticket_retention_follows_the_resumption_captures() {
    for settings in [
        crate::browser::chrome::v154_tcp_tls(),
        crate::browser::edge::v154_tcp_tls(),
        crate::browser::brave::v154_tcp_tls(),
        crate::browser::opera::v136_tcp_tls(),
        crate::browser::chrome::v154_android_tcp_tls(),
        crate::browser::edge::v153_android_tcp_tls(),
        crate::browser::brave::v153_android_tcp_tls(),
        crate::browser::opera::v102_android_tcp_tls(),
    ] {
        assert_eq!(
            settings
                .session_tickets
                .tcp_per_origin_limit()
                .map(NonZeroU8::get),
            Some(2)
        );
        assert_eq!(
            settings.session_ticket_order,
            SessionTicketOrder::NewestFirst
        );
        assert!(settings.session_ticket_extension_when_resuming);
    }
    for (firefox, order) in [
        (
            crate::browser::firefox::v157_tcp_tls(),
            SessionTicketOrder::OldestConnectionFirst,
        ),
        (
            crate::browser::firefox::v156_android_tcp_tls(),
            SessionTicketOrder::OldestFirst,
        ),
    ] {
        assert_eq!(
            firefox
                .session_tickets
                .tcp_per_origin_limit()
                .map(NonZeroU8::get),
            Some(10)
        );
        assert_eq!(firefox.session_ticket_order, order);
        assert!(!firefox.session_ticket_extension_when_resuming);
    }
}

#[test]
fn only_the_firefox_recipe_sends_early_data_over_tcp() {
    for settings in [
        crate::browser::chrome::v154_tcp_tls(),
        crate::browser::chrome::v154_quic_tls(),
        crate::browser::chrome::v154_android_tcp_tls(),
        crate::browser::chrome::v154_android_quic_tls(),
        crate::browser::edge::v154_tcp_tls(),
        crate::browser::edge::v154_quic_tls(),
        crate::browser::edge::v153_android_tcp_tls(),
        crate::browser::edge::v153_android_quic_tls(),
        crate::browser::brave::v154_tcp_tls(),
        crate::browser::brave::v154_quic_tls(),
        crate::browser::brave::v153_android_tcp_tls(),
        crate::browser::brave::v153_android_quic_tls(),
        crate::browser::opera::v136_tcp_tls(),
        crate::browser::opera::v136_quic_tls(),
        crate::browser::opera::v102_android_tcp_tls(),
    ] {
        assert!(!settings.tcp_early_data);
    }
    assert!(crate::browser::firefox::v157_tcp_tls().tcp_early_data);
    assert!(crate::browser::firefox::v156_android_tcp_tls().tcp_early_data);
}

#[test]
fn tcp_early_data_requires_session_tickets_and_tls_13() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.tcp_early_data = true;
    settings.validate()?;

    settings.session_tickets = crate::SessionTickets::disabled();
    assert_eq!(
        settings
            .validate()
            .err()
            .as_ref()
            .map(InvalidTlsSettings::field),
        Some("tcp_early_data")
    );

    settings.session_tickets = crate::SessionTickets::enabled(2)?;
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
    settings.key_shares.clear();
    assert_eq!(
        settings
            .validate()
            .err()
            .as_ref()
            .map(InvalidTlsSettings::field),
        Some("tcp_early_data")
    );
    Ok(())
}

#[test]
fn tls_12_does_not_require_key_shares() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
    settings.key_shares.clear();

    settings.validate()?;
    Ok(())
}

#[test]
fn tls_12_rejects_key_shares() {
    let mut settings = minimal_settings();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("key_shares")
    );
}

#[test]
fn tls_12_rejects_ech_grease() {
    for ech in [
        EchSettings::Grease(EchGreaseSettings::backend_default()),
        EchSettings::HttpsRecords(EchGreaseSettings::backend_default()),
    ] {
        let mut settings = minimal_settings();
        settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
        settings.key_shares.clear();
        settings.ech = ech;
        let error = settings.validate().err();
        assert_eq!(error.as_ref().map(InvalidTlsSettings::field), Some("ech"));
    }
}

#[test]
fn ech_modes_keep_grease_options_only_when_enabled() -> Result<(), InvalidTlsSettings> {
    let grease = EchGreaseSettings::new(
        EchGreasePayloadLength::Exact(239),
        vec![EchGreaseAead::Aes256Gcm],
    )?;
    assert!(EchSettings::Disabled.grease().is_none());
    assert!(!EchSettings::Disabled.uses_https_records());
    for ech in [
        EchSettings::Grease(grease.clone()),
        EchSettings::HttpsRecords(grease.clone()),
    ] {
        assert_eq!(ech.grease(), Some(&grease));
        let mut settings = minimal_settings();
        settings.ech = ech;
        settings.validate()?;
    }
    assert!(!EchSettings::Grease(grease.clone()).uses_https_records());
    assert!(EchSettings::HttpsRecords(grease).uses_https_records());
    Ok(())
}

#[test]
fn ech_value_types_are_hashable_send_and_sync() {
    fn assert_traits<T: Clone + std::fmt::Debug + Eq + std::hash::Hash + Send + Sync>() {}
    assert_traits::<EchGreaseSettings>();
    assert_traits::<EchSettings>();
}

#[test]
fn only_the_desktop_chromium_recipes_use_ech_from_https_records() {
    assert!(
        crate::browser::chrome::v154_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::chrome::v154_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::edge::v154_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::edge::v154_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::brave::v154_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::brave::v154_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::opera::v136_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        crate::browser::opera::v136_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::opera::v102_android_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::chrome::v154_android_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::chrome::v154_android_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::edge::v153_android_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::edge::v153_android_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::brave::v153_android_tcp_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::brave::v153_android_quic_tls()
            .ech
            .uses_https_records()
    );
    assert!(
        !crate::browser::firefox::v157_tcp_tls()
            .ech
            .uses_https_records()
    );
}

#[test]
fn ech_grease_aead_ids_match_rfc_9180() {
    assert_eq!(EchGreaseAead::Aes128Gcm.hpke_id(), 0x0001);
    assert_eq!(EchGreaseAead::Aes256Gcm.hpke_id(), 0x0002);
    assert_eq!(EchGreaseAead::ChaCha20Poly1305.hpke_id(), 0x0003);
}

#[test]
fn ech_grease_aead_choices_must_not_repeat() {
    let error = EchGreaseSettings::new(
        EchGreasePayloadLength::BackendDefault,
        vec![
            EchGreaseAead::Aes128Gcm,
            EchGreaseAead::ChaCha20Poly1305,
            EchGreaseAead::Aes128Gcm,
        ],
    )
    .err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_aeads")
    );
}

#[test]
fn every_distinct_ech_grease_aead_choice_is_valid() -> Result<(), InvalidTlsSettings> {
    let aeads = vec![
        EchGreaseAead::ChaCha20Poly1305,
        EchGreaseAead::Aes256Gcm,
        EchGreaseAead::Aes128Gcm,
    ];
    let grease = EchGreaseSettings::new(EchGreasePayloadLength::BackendDefault, aeads.clone())?;
    assert_eq!(grease.aeads(), aeads);
    let mut settings = minimal_settings();
    settings.ech = EchSettings::Grease(grease);
    settings.validate()
}

#[test]
fn exact_ech_grease_payload_length_must_be_nonzero() {
    let error = EchGreaseSettings::new(EchGreasePayloadLength::Exact(0), Vec::new()).err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );
}

#[test]
fn exact_ech_grease_payload_and_framing_must_fit_the_extension_body()
-> Result<(), InvalidTlsSettings> {
    for length in [1, MAX_ECH_GREASE_PAYLOAD_LENGTH] {
        let grease = EchGreaseSettings::new(EchGreasePayloadLength::Exact(length), Vec::new())?;
        assert_eq!(
            grease.payload_length(),
            EchGreasePayloadLength::Exact(length)
        );
    }
    let error = EchGreaseSettings::new(
        EchGreasePayloadLength::Exact(MAX_ECH_GREASE_PAYLOAD_LENGTH + 1),
        Vec::new(),
    )
    .err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );
    Ok(())
}

#[test]
fn ech_grease_payload_from_the_client_hello_preserves_the_name_bound()
-> Result<(), InvalidTlsSettings> {
    for maximum_name_length in [0, 100, u8::MAX] {
        let payload = EchGreasePayloadLength::FromClientHello {
            maximum_name_length,
        };
        let grease = EchGreaseSettings::new(payload, Vec::new())?;
        assert_eq!(grease.payload_length(), payload);
        let mut settings = minimal_settings();
        settings.ech = EchSettings::Grease(grease);
        settings.validate()?;
    }
    let default = EchGreaseSettings::backend_default();
    assert_eq!(
        default.payload_length(),
        EchGreasePayloadLength::BackendDefault
    );
    assert!(default.aeads().is_empty());
    assert_eq!(
        EchGreaseSettings::new(EchGreasePayloadLength::BackendDefault, Vec::new())?,
        default
    );
    Ok(())
}

#[test]
fn ech_grease_padding_uses_an_ip_literal_without_brackets() {
    for (server_name, host) in [
        ("127.0.0.1", Some("127.0.0.1")),
        ("::1", Some("::1")),
        ("[::1]", Some("::1")),
        ("::ffff:127.0.0.1", Some("::ffff:127.0.0.1")),
        ("[::ffff:127.0.0.1]", Some("::ffff:127.0.0.1")),
        ("server.phantom.test", None),
        ("[server.phantom.test]", None),
        ("127.0.0.1.nip.io", None),
    ] {
        assert_eq!(
            EchGreasePayloadLength::ip_literal_host(server_name),
            host,
            "{server_name}"
        );
    }
}

#[test]
fn tls_12_rejects_alps() {
    let mut settings = minimal_settings();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
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
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
    settings.key_shares.clear();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(TrustAnchorOrder::empty()));

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("requested_trust_anchor_ids")
    );
}

#[test]
fn tls_12_rejects_certificate_compression() {
    let mut settings = minimal_settings();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls12);
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
fn fixed_extension_order_and_tail_must_be_nonempty_and_unique() {
    for extensions in [
        Vec::new(),
        vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ServerName,
        ],
    ] {
        for order in [
            ClientHelloExtensionOrder::Fixed(extensions.clone()),
            ClientHelloExtensionOrder::PermutedWithTail(extensions.clone()),
        ] {
            let mut settings = minimal_settings();
            settings.extension_order = order;
            let error = settings.validate().err();
            assert_eq!(
                error.as_ref().map(InvalidTlsSettings::field),
                Some("extension_order")
            );
        }
    }
}

#[test]
fn permuted_extension_order_accepts_a_quic_tail() -> Result<(), InvalidTlsSettings> {
    let mut settings = minimal_settings();
    settings.extension_order = ClientHelloExtensionOrder::PermutedWithTail(vec![
        ClientHelloExtension::QuicTransportParameters,
        ClientHelloExtension::EncryptedClientHello,
    ]);
    settings.validate()
}

#[test]
fn trust_anchor_ids_may_be_omitted_or_explicitly_empty() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    let empty = TrustAnchorOrder::new(Vec::new())?;
    assert_eq!(empty, TrustAnchorOrder::empty());
    assert!(empty.as_ref().is_empty());
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(empty));
    settings.validate()?;
    settings.requested_trust_anchor_ids = None;
    settings.validate()?;
    Ok(())
}

#[test]
fn trust_anchor_ids_must_be_nonempty_and_fit_one_byte_lengths() -> Result<(), Box<dyn Error>> {
    for id in [Box::default(), vec![0; 256].into_boxed_slice()] {
        let error = TrustAnchorOrder::new(vec![id]).err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchor_ids")
        );
    }
    let ids = vec![Box::from(&b"x"[..]), vec![0; 255].into_boxed_slice()];
    let order = TrustAnchorOrder::try_from(ids.clone())?;
    assert_eq!(order.as_slice(), ids);
    assert_eq!(order.as_ref(), ids);
    Ok(())
}

#[test]
fn trust_anchor_id_list_must_fit_the_extension_body() -> Result<(), Box<dyn Error>> {
    let mut ids = (0..u8::MAX)
        .map(|_| vec![0; 255].into_boxed_slice())
        .collect::<Vec<_>>();
    ids.push(vec![0; 252].into_boxed_slice());
    let order = TrustAnchorOrder::new(ids.clone())?;
    assert_eq!(
        order
            .as_slice()
            .iter()
            .map(|id| id.len() + 1)
            .sum::<usize>(),
        65533
    );
    ids[255] = vec![0; 253].into_boxed_slice();
    let error = TrustAnchorOrder::new(ids).err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("requested_trust_anchor_ids")
    );
    Ok(())
}

fn orders(lists: &[&[&[u8]]]) -> Result<TrustAnchorOrders, InvalidTlsSettings> {
    let orders = lists
        .iter()
        .map(|ids| TrustAnchorOrder::new(ids.iter().map(|id| Box::from(*id)).collect()))
        .collect::<Result<Vec<_>, _>>()?;
    TrustAnchorOrders::new(orders)
}

#[test]
fn drawn_trust_anchor_orders_must_list_the_same_ids() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    let same = orders(&[&[b"a", b"b", b"c"], &[b"c", b"a", b"b"]])?;
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(same.clone()));
    settings.validate()?;
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(same));
    settings.validate()?;
    for lists in [
        &[][..],
        &[
            &[b"a".as_slice(), b"b".as_slice()][..],
            &[b"a".as_slice(), b"c".as_slice()][..],
        ][..],
        &[
            &[b"a".as_slice(), b"b".as_slice()][..],
            &[b"a".as_slice()][..],
        ][..],
        &[
            &[b"a".as_slice(), b"a".as_slice()][..],
            &[b"a".as_slice(), b"b".as_slice()][..],
        ][..],
        &[&[b"".as_slice()][..]][..],
    ] {
        let error = orders(lists).err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchor_ids")
        );
    }
    Ok(())
}

#[test]
fn checked_orders_keep_repeated_ids_candidates_and_empty_orders() -> Result<(), Box<dyn Error>> {
    let listed = orders(&[
        &[b"b", b"a", b"a"],
        &[b"a", b"b", b"a"],
        &[b"b", b"a", b"a"],
    ])?;
    assert_eq!(listed.as_slice().len(), 3);
    assert_eq!(
        listed.as_ref()[0].as_ref(),
        &[
            Box::from(&b"b"[..]),
            Box::from(&b"a"[..]),
            Box::from(&b"a"[..])
        ]
    );
    assert_eq!(listed.as_slice()[0], listed.as_slice()[2]);
    let copied = TrustAnchorOrders::try_from(listed.as_slice().to_vec())?;
    assert_eq!(copied, listed);
    let empty = orders(&[&[], &[]])?;
    assert_eq!(empty.as_slice().len(), 2);
    assert!(
        empty
            .as_slice()
            .iter()
            .all(|order| order.as_slice().is_empty())
    );
    Ok(())
}

#[test]
fn trust_anchor_order_draw_divides_the_random_range_evenly() -> Result<(), Box<dyn Error>> {
    let ids =
        TrustAnchorIds::PerConnection(orders(&[&[b"a", b"b"], &[b"b", b"a"], &[b"a", b"b"]])?);
    // The first random value selecting order k is ceil(k * 2^64 / 3).
    let first = |k: u128| u64::try_from((k << 64).div_ceil(3));
    let (second, third) = (first(1)?, first(2)?);
    for (random, index) in [
        (0, 0),
        (second - 1, 0),
        (second, 1),
        (third - 1, 1),
        (third, 2),
        (u64::MAX, 2),
    ] {
        let selected = ids.select(random).ok_or("no selected order")?;
        assert!(std::ptr::eq(selected, &ids.orders()[index]));
    }
    let fixed = TrustAnchorIds::Fixed(TrustAnchorOrder::new(vec![Box::from(&b"x"[..])])?);
    assert_eq!(fixed.orders().len(), 1);
    assert_eq!(fixed.select(u64::MAX), Some(&fixed.orders()[0]));
    Ok(())
}

#[test]
fn per_client_draw_fixes_only_a_per_client_order() -> Result<(), Box<dyn Error>> {
    let lists = orders(&[&[b"a", b"b"], &[b"b", b"a"]])?;
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(lists.clone()));
    let mut draws = 0;
    settings
        .draw_per_client(|| {
            draws += 1;
            Ok::<_, ()>(u64::MAX)
        })
        .map_err(|()| "draw failed")?;
    assert_eq!(draws, 1);
    assert_eq!(
        settings.requested_trust_anchor_ids,
        Some(TrustAnchorIds::Fixed(lists.as_slice()[1].clone()))
    );
    for ids in [
        None,
        Some(TrustAnchorIds::Fixed(lists.as_slice()[0].clone())),
        Some(TrustAnchorIds::PerConnection(lists)),
    ] {
        settings.requested_trust_anchor_ids = ids.clone();
        assert_eq!(
            settings.draw_per_client(|| Err("random was called")),
            Ok(())
        );
        assert_eq!(settings.requested_trust_anchor_ids, ids);
    }
    Ok(())
}

#[test]
fn one_empty_candidate_still_draws_once_per_client() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(orders(&[&[]])?));
    let mut draws = 0;
    settings
        .draw_per_client(|| {
            draws += 1;
            Ok::<_, ()>(0)
        })
        .map_err(|()| "draw failed")?;
    assert_eq!(draws, 1);
    assert_eq!(
        settings.requested_trust_anchor_ids,
        Some(TrustAnchorIds::Fixed(TrustAnchorOrder::empty()))
    );
    settings.validate()?;
    Ok(())
}

#[test]
fn failed_per_client_draw_returns_the_error_and_keeps_the_list() -> Result<(), Box<dyn Error>> {
    let ids = Some(TrustAnchorIds::PerClient(orders(&[
        &[b"a", b"b"],
        &[b"b", b"a"],
    ])?));
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = ids.clone();
    assert_eq!(
        settings.draw_per_client(|| Err("no entropy")),
        Err("no entropy")
    );
    assert_eq!(settings.requested_trust_anchor_ids, ids);
    Ok(())
}

#[test]
fn trust_anchor_values_are_send_sync_and_hashable() -> Result<(), Box<dyn Error>> {
    fn check<T: Send + Sync + std::hash::Hash>() {}
    check::<TrustAnchorOrder>();
    check::<TrustAnchorOrders>();
    check::<TrustAnchorIds>();
    let a = orders(&[&[b"a", b"b"], &[b"b", b"a"]])?;
    let mut values = std::collections::HashSet::new();
    assert!(values.insert(a.clone()));
    assert!(!values.insert(a));
    assert!(values.insert(orders(&[&[b"b", b"a"], &[b"a", b"b"]])?));
    Ok(())
}

#[test]
fn static_id_checks_match_checked_constructor_bounds() {
    let exact = vec![0_u8; 255];
    let too_long = vec![0_u8; 256];
    assert!(TrustAnchorOrder::valid_recipe_ids(&[]));
    assert!(TrustAnchorOrder::valid_recipe_ids(&[&exact]));
    assert!(!TrustAnchorOrder::valid_recipe_ids(&[&[]]));
    assert!(!TrustAnchorOrder::valid_recipe_ids(&[&too_long]));
    let tail = vec![0_u8; 252];
    let mut ids = vec![exact.as_slice(); 255];
    ids.push(&tail);
    assert!(TrustAnchorOrder::valid_recipe_ids(&ids));
    ids.push(b"x");
    assert!(!TrustAnchorOrder::valid_recipe_ids(&ids));
}
