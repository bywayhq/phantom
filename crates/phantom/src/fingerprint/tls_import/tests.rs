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
        let hello = preview(&desired, "import.invalid").expect("preview");
        let input = ja3(&hello);
        let imported = import_ja3_profile(&input, &base).expect("import");
        Ja3::parse(&input)
            .expect("parse")
            .verify(&preview(imported.profile().tls(), "import.invalid").expect("preview"))
            .expect("wire projection");
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
    let bytes = phantom_net::preview_client_hello(&desired, "private.example").expect("capture");
    let imported = import_client_hello_profile(&bytes, &base).expect("import");
    let summary = ClientHelloSummary::from_handshake_bytes(&bytes).expect("decode");
    let actual = preview(imported.profile().tls(), "different.example").expect("preview");
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
            .expect("export")
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
        let error = import_ja3_profile(&input, &base).expect_err("must reject");
        assert_eq!((error.kind(), error.field()), (kind, field));
        assert!(!format!("{error:?}: {error}").contains("secret"));
    }
    assert_eq!(
        import_client_hello_profile(&vec![0; 65537], &base)
            .expect_err("bound")
            .kind(),
        Kind::TooLarge
    );
    assert_eq!(
        import_client_hello_profile(&[1, 0, 0, 0], &base)
            .expect_err("malformed")
            .kind(),
        Kind::MalformedDescription
    );
}

#[test]
fn missing_extensions_and_backend_point_formats_cannot_silently_pass() {
    let base = chrome::v154_windows();
    let summary = preview(base.tls(), "import.invalid").expect("preview");
    let mut observed = Ja3::from_summary(&summary);
    observed.extensions.retain(|id| *id != 5);
    let changed = observed.apply(base.tls()).expect("settings");
    assert_eq!(
        observed
            .verify(&preview(&changed, "import.invalid").expect("preview"))
            .expect_err("extra extension")
            .field(),
        "ja3.extensions"
    );
    observed = Ja3::from_summary(&summary);
    observed.points = vec![1];
    assert_eq!(
        observed.verify(&summary).expect_err("point format").field(),
        "ja3.point_formats"
    );
    assert!(matches!(
        changed.extension_order,
        ClientHelloExtensionOrder::Fixed(_)
    ));
}
