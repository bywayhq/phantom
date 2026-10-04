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
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![CipherSuite::Aes128GcmSha256],
        groups: vec![NamedGroup::X25519],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: true,
        session_tickets_per_origin: 2,
        session_ticket_order: SessionTicketOrder::NewestFirst,
        session_ticket_extension_when_resuming: true,
        tcp_early_data: false,
        record_size_limit: None,
        tls12_extensions_in_tls13_client_hello: false,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: EchGreasePayloadLength::BackendDefault,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
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
    settings.max_version = TlsVersion::Tls12;
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
        settings.session_tickets_per_origin = limit;
        settings.validate()?;
    }
    for limit in [0, 11] {
        let mut settings = minimal_settings();
        settings.session_tickets_per_origin = limit;
        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("session_tickets_per_origin")
        );
        settings.session_tickets = false;
        settings.validate()?;
    }
    Ok(())
}

#[test]
fn tcp_ticket_retention_follows_the_resumption_captures() {
    for settings in [
        crate::chromium::v154_tls(),
        crate::edge::v154_tls(),
        crate::brave::v154_tls(),
        crate::opera::v136_tls(),
        crate::chrome_android::v154_tls(),
        crate::edge_android::v153_tls(),
        crate::brave_android::v153_tls(),
        crate::opera_android::v102_tls(),
    ] {
        assert_eq!(settings.session_tickets_per_origin, 2);
        assert_eq!(
            settings.session_ticket_order,
            SessionTicketOrder::NewestFirst
        );
        assert!(settings.session_ticket_extension_when_resuming);
    }
    for (firefox, order) in [
        (
            crate::firefox::v157_tls(),
            SessionTicketOrder::OldestConnectionFirst,
        ),
        (
            crate::firefox_android::v156_tls(),
            SessionTicketOrder::OldestFirst,
        ),
    ] {
        assert_eq!(firefox.session_tickets_per_origin, 10);
        assert_eq!(firefox.session_ticket_order, order);
        assert!(!firefox.session_ticket_extension_when_resuming);
    }
}

#[test]
fn only_the_firefox_recipe_sends_early_data_over_tcp() {
    for settings in [
        crate::chromium::v154_tls(),
        crate::chromium::v154_http3_tls(),
        crate::chrome_android::v154_tls(),
        crate::chrome_android::v154_http3_tls(),
        crate::edge::v154_tls(),
        crate::edge::v154_http3_tls(),
        crate::edge_android::v153_tls(),
        crate::edge_android::v153_http3_tls(),
        crate::brave::v154_tls(),
        crate::brave::v154_http3_tls(),
        crate::brave_android::v153_tls(),
        crate::brave_android::v153_http3_tls(),
        crate::opera::v136_tls(),
        crate::opera::v136_http3_tls(),
        crate::opera_android::v102_tls(),
    ] {
        assert!(!settings.tcp_early_data);
    }
    assert!(crate::firefox::v157_tls().tcp_early_data);
    assert!(crate::firefox_android::v156_tls().tcp_early_data);
}

#[test]
fn tcp_early_data_requires_session_tickets_and_tls_13() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.tcp_early_data = true;
    settings.validate()?;

    settings.session_tickets = false;
    assert_eq!(
        settings
            .validate()
            .err()
            .as_ref()
            .map(InvalidTlsSettings::field),
        Some("tcp_early_data")
    );

    settings.session_tickets = true;
    settings.max_version = TlsVersion::Tls12;
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
fn ech_from_https_records_requires_ech_grease() {
    let mut settings = minimal_settings();
    settings.ech_from_https_records = true;

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_from_https_records")
    );

    settings.ech_grease = true;
    assert!(settings.validate().is_ok());
}

#[test]
fn only_the_desktop_chromium_recipes_use_ech_from_https_records() {
    assert!(crate::chromium::v154_tls().ech_from_https_records);
    assert!(crate::chromium::v154_http3_tls().ech_from_https_records);
    assert!(crate::edge::v154_tls().ech_from_https_records);
    assert!(crate::edge::v154_http3_tls().ech_from_https_records);
    assert!(crate::brave::v154_tls().ech_from_https_records);
    assert!(crate::brave::v154_http3_tls().ech_from_https_records);
    assert!(crate::opera::v136_tls().ech_from_https_records);
    assert!(crate::opera::v136_http3_tls().ech_from_https_records);
    assert!(!crate::opera_android::v102_tls().ech_from_https_records);
    assert!(!crate::chrome_android::v154_tls().ech_from_https_records);
    assert!(!crate::chrome_android::v154_http3_tls().ech_from_https_records);
    assert!(!crate::edge_android::v153_tls().ech_from_https_records);
    assert!(!crate::edge_android::v153_http3_tls().ech_from_https_records);
    assert!(!crate::brave_android::v153_tls().ech_from_https_records);
    assert!(!crate::brave_android::v153_http3_tls().ech_from_https_records);
    assert!(!crate::firefox::v157_tls().ech_from_https_records);
}

#[test]
fn ech_grease_aead_ids_match_rfc_9180() {
    assert_eq!(EchGreaseAead::Aes128Gcm.hpke_id(), 0x0001);
    assert_eq!(EchGreaseAead::Aes256Gcm.hpke_id(), 0x0002);
    assert_eq!(EchGreaseAead::ChaCha20Poly1305.hpke_id(), 0x0003);
}

#[test]
fn ech_grease_aead_choices_require_ech_grease() {
    let mut settings = minimal_settings();
    settings.ech_grease_aeads = vec![EchGreaseAead::ChaCha20Poly1305];

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_aeads")
    );
}

#[test]
fn ech_grease_aead_choices_must_not_repeat() {
    let mut settings = minimal_settings();
    settings.ech_grease = true;
    settings.ech_grease_aeads = vec![
        EchGreaseAead::Aes128Gcm,
        EchGreaseAead::ChaCha20Poly1305,
        EchGreaseAead::Aes128Gcm,
    ];

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_aeads")
    );
}

#[test]
fn every_distinct_ech_grease_aead_choice_is_valid() -> Result<(), InvalidTlsSettings> {
    let mut settings = minimal_settings();
    settings.ech_grease = true;
    settings.ech_grease_aeads = vec![
        EchGreaseAead::ChaCha20Poly1305,
        EchGreaseAead::Aes256Gcm,
        EchGreaseAead::Aes128Gcm,
    ];

    settings.validate()
}

#[test]
fn exact_ech_grease_payload_length_requires_ech_grease() {
    let mut settings = minimal_settings();
    settings.ech_grease_payload_length = EchGreasePayloadLength::Exact(239);

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );
}

#[test]
fn exact_ech_grease_payload_length_must_be_nonzero() {
    let mut settings = minimal_settings();
    settings.ech_grease = true;
    settings.ech_grease_payload_length = EchGreasePayloadLength::Exact(0);

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );
}

#[test]
fn exact_ech_grease_payload_and_framing_must_fit_the_extension_body() {
    let mut settings = minimal_settings();
    settings.ech_grease = true;
    settings.ech_grease_payload_length =
        EchGreasePayloadLength::Exact(MAX_ECH_GREASE_PAYLOAD_LENGTH + 1);

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );
}

#[test]
fn ech_grease_payload_from_the_client_hello_requires_ech_grease() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    settings.ech_grease_payload_length = EchGreasePayloadLength::FromClientHello {
        maximum_name_length: 100,
    };
    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("ech_grease_payload_length")
    );

    settings.ech_grease = true;
    for maximum_name_length in [0, 100, u8::MAX] {
        settings.ech_grease_payload_length = EchGreasePayloadLength::FromClientHello {
            maximum_name_length,
        };
        settings.validate()?;
    }
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
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(Vec::new()));

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
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(Vec::new()));

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
        settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(vec![id]));
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
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(ids.clone()));

    settings.validate()?;
    ids.push(Box::from(&b"x"[..]));
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(ids));

    let error = settings.validate().err();
    assert_eq!(
        error.as_ref().map(InvalidTlsSettings::field),
        Some("requested_trust_anchor_ids")
    );
    Ok(())
}

fn orders(lists: &[&[&[u8]]]) -> Vec<Vec<Box<[u8]>>> {
    lists
        .iter()
        .map(|ids| ids.iter().map(|id| Box::from(*id)).collect())
        .collect()
}

#[test]
fn drawn_trust_anchor_orders_must_list_the_same_ids() -> Result<(), Box<dyn Error>> {
    let mut settings = minimal_settings();
    let same = orders(&[&[b"a", b"b", b"c"], &[b"c", b"a", b"b"]]);
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(same.clone()));
    settings.validate()?;
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(same));
    settings.validate()?;

    for ids in [
        TrustAnchorIds::PerClient(Vec::new()),
        TrustAnchorIds::PerConnection(Vec::new()),
        TrustAnchorIds::PerClient(orders(&[&[b"a", b"b"], &[b"a", b"c"]])),
        TrustAnchorIds::PerConnection(orders(&[&[b"a", b"b"], &[b"a"]])),
        TrustAnchorIds::PerConnection(orders(&[&[b"a", b"a"], &[b"a", b"b"]])),
        TrustAnchorIds::PerClient(orders(&[&[b""]])),
    ] {
        settings.requested_trust_anchor_ids = Some(ids);
        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchor_ids")
        );
    }
    Ok(())
}

#[test]
fn trust_anchor_order_draw_divides_the_random_range_evenly() {
    let ids = TrustAnchorIds::PerConnection(orders(&[&[b"a", b"b"], &[b"b", b"a"], &[b"a", b"b"]]));
    // The first `random` that selects order `k` is ceil(k * 2^64 / 3).
    let first = |k: u128| u64::try_from((k << 64).div_ceil(3));
    let (second, third) = (first(1).unwrap_or(0), first(2).unwrap_or(0));
    let selected = |random| ids.select(random).map(<[_]>::to_vec);
    let order = |index: usize| Some(ids.orders()[index].clone());
    assert_eq!(selected(0), order(0));
    assert_eq!(selected(second - 1), order(0));
    assert_eq!(selected(second), order(1));
    assert_eq!(selected(third - 1), order(1));
    assert_eq!(selected(third), order(2));
    assert_eq!(selected(u64::MAX), order(2));

    let fixed = TrustAnchorIds::Fixed(orders(&[&[b"x"]]).remove(0));
    assert_eq!(fixed.orders().len(), 1);
    assert_eq!(fixed.select(u64::MAX), Some(&fixed.orders()[0][..]));
    assert_eq!(TrustAnchorIds::PerClient(Vec::new()).select(0), None);
}

#[test]
fn per_client_draw_fixes_only_a_per_client_order() {
    let lists = orders(&[&[b"a", b"b"], &[b"b", b"a"]]);
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = Some(TrustAnchorIds::PerClient(lists.clone()));
    assert_eq!(settings.draw_per_client(|| Ok::<_, ()>(u64::MAX)), Ok(()));
    assert_eq!(
        settings.requested_trust_anchor_ids,
        Some(TrustAnchorIds::Fixed(lists[1].clone()))
    );

    // Nothing is drawn, so `random` is not called; an invalid per-client list
    // stays for validation to reject.
    for ids in [
        None,
        Some(TrustAnchorIds::Fixed(lists[0].clone())),
        Some(TrustAnchorIds::PerConnection(lists)),
        Some(TrustAnchorIds::PerClient(orders(&[
            &[b"a", b"b"],
            &[b"a", b"c"],
        ]))),
        Some(TrustAnchorIds::PerClient(Vec::new())),
    ] {
        settings.requested_trust_anchor_ids = ids.clone();
        assert_eq!(
            settings.draw_per_client(|| Err("random was called")),
            Ok(())
        );
        assert_eq!(settings.requested_trust_anchor_ids, ids);
    }
}

#[test]
fn failed_per_client_draw_returns_the_error_and_keeps_the_list() {
    let ids = Some(TrustAnchorIds::PerClient(orders(&[
        &[b"a", b"b"],
        &[b"b", b"a"],
    ])));
    let mut settings = minimal_settings();
    settings.requested_trust_anchor_ids = ids.clone();
    assert_eq!(
        settings.draw_per_client(|| Err("no entropy")),
        Err("no entropy")
    );
    assert_eq!(settings.requested_trust_anchor_ids, ids);
}
