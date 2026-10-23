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
    let hello =
        preview(&desired, "import.invalid").unwrap_or_else(|error| panic!("preview: {error}"));
    for format in [Ja4RawFormat::Original, Ja4RawFormat::Sorted] {
        let input = raw(&hello, format);
        let imported = import_ja4_profile(&input, format, &base)
            .unwrap_or_else(|error| panic!("import: {error}"));
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
fn retained_safari_signature_repetitions_survive_both_raw_ja4_formats()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use phantom_profile::catalog::profile;

    // FoxIO JA4 at 820ec301a930ae3d92a80afd8fc4d3f1abb73b9d keeps
    // signature algorithms in their observed order in both raw formats.
    let original = concat!(
        "t13d2013h2_",
        "1302,1303,1301,c02c,c02b,cca9,c030,c02f,cca8,c00a,c009,c014,c013,",
        "009d,009c,0035,002f,c008,c012,000a_",
        "0000,0017,ff01,000a,000b,0010,0005,000d,0012,0033,002d,002b,001b_",
        "0403,0804,0401,0503,0805,0805,0501,0806,0601,0201"
    );
    let sorted = concat!(
        "t13d2013h2_",
        "000a,002f,0035,009c,009d,1301,1302,1303,c008,c009,c00a,c012,c013,",
        "c014,c02b,c02c,c02f,c030,cca8,cca9_",
        "0005,000a,000b,000d,0012,0017,001b,002b,002d,0033,ff01_",
        "0403,0804,0401,0503,0805,0805,0501,0806,0601,0201"
    );
    let expected = [1027, 2052, 1025, 1283, 2053, 2053, 1281, 2054, 1537, 513];
    for (selector, bytes) in [
        (
            "safari-26-macos",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../phantom-profile/tests/fixtures/peers/",
                "curl-impersonate-2.2.3-safari2601/run-1/connection-0.hello.bin"
            ))
            .as_slice(),
        ),
        (
            "safari-26-ios",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../phantom-profile/tests/fixtures/peers/",
                "wreq-util-5715529-safari-ios-26/run-1/connection-0.hello.bin"
            ))
            .as_slice(),
        ),
    ] {
        let captured = ClientHelloSummary::from_handshake_bytes(bytes)?;
        assert_eq!(captured.signature_algorithms(), expected);
        let base = profile(selector)?.instantiate(&[])?;
        for (format, input) in [
            (Ja4RawFormat::Original, original),
            (Ja4RawFormat::Sorted, sorted),
        ] {
            assert_eq!(raw(&captured, format), input);
            let imported = import_ja4_profile(input, format, &base)?;
            assert_eq!(
                imported.profile().tls().signature_schemes,
                base.tls().signature_schemes
            );
            let generated = preview(imported.profile().tls(), "import.invalid")?;
            assert_eq!(generated.signature_algorithms(), expected);
            assert_eq!(raw(&generated, format), input);
        }
    }
    Ok(())
}

#[test]
fn cipher_and_extension_repetitions_remain_invalid_in_both_raw_formats()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let base = chrome::v154_windows();
    let hello = preview(base.tls(), "import.invalid")?;
    for format in [Ja4RawFormat::Original, Ja4RawFormat::Sorted] {
        let input = raw(&hello, format);
        for (section, field) in [(1, "ja4.ciphers"), (2, "ja4.extensions")] {
            let mut parts = input.split('_').map(str::to_owned).collect::<Vec<_>>();
            let first = parts[section].split(',').next().ok_or("empty list")?;
            parts[section] = format!("{},{}", parts[section], first);
            let error = import_ja4_profile(&parts.join("_"), format, &base)
                .err()
                .ok_or("accepted repeated cipher or extension")?;
            assert_eq!((error.kind(), error.field()), (Kind::DuplicateField, field));
        }
    }
    Ok(())
}

#[test]
fn repeated_signatures_keep_the_identifier_bound_and_syntax_checks()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let limit = vec!["0805"; 256].join(",");
    assert_eq!(hex_values(&limit, "ja4.signatures")?, vec![0x0805; 256]);

    let base = chrome::v154_windows();
    let hello = preview(base.tls(), "import.invalid")?;
    let input = raw(&hello, Ja4RawFormat::Original);
    let (prefix, _) = input.rsplit_once('_').ok_or("missing signatures")?;
    for (signatures, kind) in [
        (format!("{limit},0805"), Kind::TooLarge),
        ("0805,0a0a".into(), Kind::InvalidValue),
        ("0805,805".into(), Kind::MalformedDescription),
        ("0805,gggg".into(), Kind::MalformedDescription),
    ] {
        let error = import_ja4_profile(
            &format!("{prefix}_{signatures}"),
            Ja4RawFormat::Original,
            &base,
        )
        .err()
        .ok_or("accepted invalid signatures")?;
        assert_eq!((error.kind(), error.field()), (kind, "ja4.signatures"));
    }
    Ok(())
}

#[test]
fn hashes_transport_mismatches_and_missing_payload_information_fail_precisely() {
    let base = chrome::v154_windows();
    let hello =
        preview(base.tls(), "import.invalid").unwrap_or_else(|error| panic!("preview: {error}"));
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
        let error = import_ja4_profile(&input, Ja4RawFormat::Original, &base)
            .err()
            .unwrap_or_else(|| panic!("reject"));
        assert_eq!((error.kind(), error.field()), (kind, field));
    }
    assert_eq!(
        hex_list("000a,000a", "ja4.extensions")
            .err()
            .unwrap_or_else(|| panic!("duplicate"))
            .kind(),
        Kind::DuplicateField
    );
    assert_eq!(
        hex_list("0a0a", "ja4.extensions")
            .err()
            .unwrap_or_else(|| panic!("grease"))
            .kind(),
        Kind::InvalidValue
    );
    assert_eq!(
        hex_list("a", "ja4.extensions")
            .err()
            .unwrap_or_else(|| panic!("width"))
            .kind(),
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
            alpn_tag(
                &preview(&settings, "import.invalid")
                    .unwrap_or_else(|error| panic!("preview: {error}"))
            ),
            expected
        );
    }
}
