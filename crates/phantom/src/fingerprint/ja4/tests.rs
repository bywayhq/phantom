use super::*;
use phantom_profile::browser::chrome;

fn raw(hello: &ClientHelloSummary, format: Ja4RawFormat) -> String {
    fn list(ids: &[u16]) -> String {
        ids.iter()
            .map(|id| format!("{id:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    }
    let mut ciphers = normalized(hello.cipher_suites());
    let mut extensions = normalized(hello.extension_types());
    let header = format!(
        "t13d{:02}{:02}{}",
        ciphers.len(),
        extensions.len(),
        alpn_tag(hello)
    );
    if format == Ja4RawFormat::Sorted {
        ciphers.sort_unstable();
        extensions.retain(|id| !matches!(id, 0 | 16));
        extensions.sort_unstable();
    }
    format!(
        "{header}_{}_{}_{}",
        list(&ciphers),
        list(&extensions),
        list(&normalized(hello.signature_algorithms()))
    )
}

#[test]
fn original_ja4_applies_order_while_sorted_ja4_retains_base_order() {
    let base = chrome::v154_windows();
    let mut desired = base.tls().clone();
    desired.cipher_suites.swap(0, 1);
    let hello = preview(&desired, "import.invalid").expect("preview");
    for format in [Ja4RawFormat::Original, Ja4RawFormat::Sorted] {
        let input = raw(&hello, format);
        let imported = import_ja4_profile(&input, format, &base).expect("import");
        let expected = if format == Ja4RawFormat::Original {
            &desired.cipher_suites
        } else {
            &base.tls().cipher_suites
        };
        assert_eq!(&imported.profile().tls().cipher_suites, expected);
        assert_eq!(imported.profile().tls().groups, base.tls().groups);
        assert_eq!(
            imported
                .supplemented_fields()
                .any(|field| field == "tls.extension_order"),
            format == Ja4RawFormat::Sorted
        );
    }
}

#[test]
fn hashes_transport_mismatches_and_missing_payload_information_fail_precisely() {
    let base = chrome::v154_windows();
    let hello = preview(base.tls(), "import.invalid").expect("preview");
    let input = raw(&hello, Ja4RawFormat::Original);
    for (input, kind, field) in [
        (
            "t13d1516h2_8daaf6152771_b186095e22b6".into(),
            Kind::LossyDescription,
            "ja4",
        ),
        (
            input.replacen('t', "q", 1),
            Kind::UnsupportedSetting,
            "ja4.transport",
        ),
        (
            input.replacen("t13", "t12", 1),
            Kind::UnsupportedSetting,
            "ja4.version",
        ),
        (
            input.replacen("h2", "h1", 1),
            Kind::UnsupportedSetting,
            "ja4.alpn",
        ),
        (
            input.replacen("1301", "ffff", 1),
            Kind::UnsupportedSetting,
            "tls.cipher_suites",
        ),
    ] {
        let error = import_ja4_profile(&input, Ja4RawFormat::Original, &base).expect_err("reject");
        assert_eq!((error.kind(), error.field()), (kind, field));
    }
    assert_eq!(
        hex_list("000a,000a", "ja4.extensions")
            .expect_err("duplicate")
            .kind(),
        Kind::DuplicateField
    );
    assert_eq!(
        hex_list("0a0a", "ja4.extensions")
            .expect_err("grease")
            .kind(),
        Kind::InvalidValue
    );
    assert_eq!(
        hex_list("a", "ja4.extensions").expect_err("width").kind(),
        Kind::MalformedDescription
    );
}

#[test]
fn alpn_abbreviation_handles_binary_and_single_byte_identifiers() {
    let mut settings = chrome::v154_windows().tls().clone();
    settings.alps = None;
    for (protocol, expected) in [
        (vec![b'x'], "xx"),
        (vec![0xab, 0xcd], "ad"),
        (vec![0x20, b'a'], "21"),
    ] {
        settings.alpn_protocols = vec![protocol.into_boxed_slice()];
        assert_eq!(
            alpn_tag(&preview(&settings, "import.invalid").expect("preview")),
            expected
        );
    }
}
