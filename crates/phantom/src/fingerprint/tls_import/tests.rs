use super::*;
use phantom_profile::{
    ClientHelloExtensionOrder,
    browser::{chrome, firefox},
};

fn ja3(summary: &ClientHelloSummary) -> String {
    fn list(values: &[u16]) -> String {
        normalized(values)
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("-")
    }
    format!(
        "{},{},{},{},{}",
        summary.legacy_version(),
        list(summary.cipher_suites()),
        list(summary.extension_types()),
        list(summary.supported_groups()),
        summary
            .ec_point_formats()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    )
}

#[test]
fn ja3_applies_order_and_retains_explicit_payloads_and_other_layers() {
    for base in [chrome::v154_windows(), firefox::v157_windows()] {
        let mut desired = base.tls().clone();
        desired.cipher_suites.swap(0, 1);
        let hello =
            preview(&desired, "import.invalid").unwrap_or_else(|error| panic!("preview: {error}"));
        let input = ja3(&hello);
        let imported =
            import_ja3_profile(&input, &base).unwrap_or_else(|error| panic!("import: {error}"));
        Ja3::parse(&input)
            .unwrap_or_else(|error| panic!("parse: {error}"))
            .verify(
                &preview(imported.profile().tls(), "import.invalid")
                    .unwrap_or_else(|error| panic!("preview: {error}")),
            )
            .unwrap_or_else(|error| panic!("wire projection: {error}"));
        assert_eq!(
            imported.profile().tls().cipher_suites,
            desired.cipher_suites
        );
        assert_eq!(
            imported.profile().tls().alpn_protocols,
            base.tls().alpn_protocols
        );
        assert_eq!(imported.profile().http2(), base.http2());
        assert_eq!(imported.profile().http3(), base.http3());
        assert!(
            imported
                .supplemented_fields()
                .any(|field| field == "tls.versions")
        );
        assert!(
            imported
                .observed_fields()
                .any(|field| field == "tls.extension_order")
        );
    }
}

#[test]
fn client_hello_import_applies_decoded_fields_without_retaining_destination_or_keys() {
    let base = chrome::v154_windows();
    let mut desired = base.tls().clone();
    desired.cipher_suites.swap(0, 1);
    let bytes = phantom_net::preview_client_hello(&desired, "private.example")
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let imported = import_client_hello_profile(&bytes, &base)
        .unwrap_or_else(|error| panic!("import: {error}"));
    let summary = ClientHelloSummary::from_handshake_bytes(&bytes)
        .unwrap_or_else(|error| panic!("decode: {error}"));
    let actual = preview(imported.profile().tls(), "different.example")
        .unwrap_or_else(|error| panic!("preview: {error}"));
    assert_eq!(
        normalized(actual.cipher_suites()),
        normalized(summary.cipher_suites())
    );
    assert_eq!(
        normalized(actual.extension_types()),
        normalized(summary.extension_types())
    );
    assert_eq!(actual.alpn_protocols(), summary.alpn_protocols());
    assert!(
        !super::super::export::describe(imported.profile())
            .unwrap_or_else(|error| panic!("export: {error}"))
            .1
            .windows(b"private.example".len())
            .any(|window| window == b"private.example")
    );
    assert!(
        imported
            .supplemented_fields()
            .any(|field| field == "tls.ech")
    );
    assert!(
        !imported
            .supplemented_fields()
            .any(|field| field == "tls.versions")
    );
}

#[test]
fn hashes_malformed_lists_duplicates_and_unbounded_input_are_rejected() {
    let base = chrome::v154_windows();
    for (input, kind, field) in [
        ("a".repeat(32), Kind::LossyDescription, "ja3"),
        (
            "771,4865,0,29".into(),
            Kind::MalformedDescription,
            "ja3.point_formats",
        ),
        (
            "771,4865-4865,0,29,0".into(),
            Kind::DuplicateField,
            "ja3.ciphers",
        ),
        ("771,2570,0,29,0".into(), Kind::InvalidValue, "ja3.ciphers"),
        (
            "771,65535,0,29,0".into(),
            Kind::UnsupportedSetting,
            "tls.cipher_suites",
        ),
        (
            "771,4865,41,29,0".into(),
            Kind::UnsupportedSetting,
            "tls.extension_order",
        ),
        ("secret".repeat(6000), Kind::TooLarge, "ja3"),
    ] {
        let error = import_ja3_profile(&input, &base)
            .err()
            .unwrap_or_else(|| panic!("must reject"));
        assert_eq!((error.kind(), error.field()), (kind, field));
        assert!(!format!("{error:?}: {error}").contains("secret"));
    }
    assert_eq!(
        import_client_hello_profile(&vec![0; 65537], &base)
            .err()
            .unwrap_or_else(|| panic!("bound"))
            .kind(),
        Kind::TooLarge
    );
    assert_eq!(
        import_client_hello_profile(&[1, 0, 0, 0], &base)
            .err()
            .unwrap_or_else(|| panic!("malformed"))
            .kind(),
        Kind::MalformedDescription
    );
}

#[test]
fn missing_extensions_and_backend_point_formats_cannot_silently_pass() {
    let base = chrome::v154_windows();
    let summary =
        preview(base.tls(), "import.invalid").unwrap_or_else(|error| panic!("preview: {error}"));
    let mut observed = Ja3::from_summary(&summary);
    observed.extensions.retain(|id| *id != 5);
    let changed = observed
        .apply(base.tls())
        .unwrap_or_else(|error| panic!("settings: {error}"));
    assert_eq!(
        observed
            .verify(
                &preview(&changed, "import.invalid")
                    .unwrap_or_else(|error| panic!("preview: {error}"))
            )
            .err()
            .unwrap_or_else(|| panic!("extra extension"))
            .field(),
        "ja3.extensions"
    );
    observed = Ja3::from_summary(&summary);
    observed.points = vec![1];
    assert_eq!(
        observed
            .verify(&summary)
            .err()
            .unwrap_or_else(|| panic!("point format"))
            .field(),
        "ja3.point_formats"
    );
    assert!(matches!(
        changed.extension_order,
        ClientHelloExtensionOrder::Fixed(_)
    ));
}

#[test]
fn legacy_client_hello_keeps_the_base_minimum_version_as_a_supplement() {
    let mut settings = chrome::v154_windows().tls().clone();
    settings.versions = TlsVersionRange::new(TlsVersion::Tls10, TlsVersion::Tls12)
        .unwrap_or_else(|error| panic!("range: {error}"));
    settings.key_shares.clear();
    settings.ech = phantom_profile::EchSettings::Disabled;
    settings.requested_trust_anchor_ids = None;
    settings.certificate_compression.clear();
    settings.delegated_credential_schemes.clear();
    settings.tcp_early_data = false;
    settings.alpn_protocols = vec![vec![b'x'; 200].into_boxed_slice()];
    settings.alps = None;
    settings
        .validate()
        .unwrap_or_else(|error| panic!("legacy settings: {error}"));
    let base = ClientProfile::new(settings);
    let bytes = phantom_net::preview_client_hello(base.tls(), "import.invalid")
        .unwrap_or_else(|error| panic!("capture: {error}"));
    let captured = ClientHelloSummary::from_handshake_bytes(&bytes)
        .unwrap_or_else(|error| panic!("decode: {error}"));
    assert!(captured.extension_types().contains(&21));
    let imported = import_client_hello_profile(&bytes, &base)
        .unwrap_or_else(|error| panic!("import: {error}"));
    let ja3_imported = import_ja3_profile(&ja3(&captured), &base)
        .unwrap_or_else(|error| panic!("JA3 import: {error}"));
    assert_eq!(ja3_imported.profile().tls().versions, base.tls().versions);
    assert_eq!(imported.profile().tls().versions, base.tls().versions);
    assert!(
        imported
            .supplemented_fields()
            .any(|field| field == "tls.versions")
    );
    assert!(
        !imported
            .observed_fields()
            .any(|field| field == "tls.versions")
    );
}

#[test]
fn retained_chrome_client_hello_imports_without_inventing_browser_identity() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt"
    ));
    let record = fixture
        .lines()
        .find_map(|line| line.strip_prefix("record_0_hex="))
        .unwrap_or_else(|| panic!("record"));
    let bytes = record
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap_or_else(|error| panic!("hex: {error}"));
            u8::from_str_radix(text, 16).unwrap_or_else(|error| panic!("hex: {error}"))
        })
        .collect::<Vec<_>>();
    let imported = import_client_hello_profile(&bytes[5..], &chrome::v154_windows())
        .unwrap_or_else(|error| panic!("captured input: {error}"));
    let described = super::super::describe_profile(imported.profile())
        .unwrap_or_else(|error| panic!("description: {error}"));
    assert!(described.get("browser").is_none());
    assert!(
        imported
            .supplemented_fields()
            .any(|field| field == "tls.requested_trust_anchor_ids")
    );
}
