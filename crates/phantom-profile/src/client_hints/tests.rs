use super::{ClientHint, ClientHintDelivery, ClientHintSettings};

#[test]
fn accepts_ordered_default_and_negotiated_fields() {
    let settings = ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="152""#,
            ClientHintDelivery::Default,
        ),
        ClientHint::new("sec-ch-ua-arch", r#""arm""#, ClientHintDelivery::AcceptCh),
    ]);

    assert!(settings.validate().is_ok());
    assert_eq!(settings.hints()[0].name(), "sec-ch-ua");
    assert_eq!(settings.hints()[1].value(), br#""arm""#);
}

#[test]
fn rejects_invalid_duplicate_or_non_lowercase_names() {
    for (name, field) in [
        ("", "hints.name"),
        ("Sec-CH-UA", "hints.name"),
        ("sec ch ua", "hints.name"),
        ("1-client-hint", "hints.name"),
    ] {
        let settings = ClientHintSettings::new(vec![ClientHint::new(
            name,
            "value",
            ClientHintDelivery::Default,
        )]);
        let error = match settings.validate() {
            Ok(()) => panic!("invalid client-hint name was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.field(), field);
    }

    let duplicate = ClientHintSettings::new(vec![
        ClientHint::new("sec-ch-ua", "one", ClientHintDelivery::Default),
        ClientHint::new("sec-ch-ua", "two", ClientHintDelivery::AcceptCh),
    ]);
    let error = match duplicate.validate() {
        Ok(()) => panic!("duplicate client-hint name was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.field(), "hints.name");
}

#[test]
fn rejects_control_bytes_and_redacts_values() {
    let settings = ClientHintSettings::new(vec![ClientHint::new(
        "sec-ch-ua-arch",
        b"sentinel\r\nvalue",
        ClientHintDelivery::AcceptCh,
    )]);
    let error = match settings.validate() {
        Ok(()) => panic!("invalid client-hint value was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.field(), "hints.value");

    let hint = ClientHint::new(
        "sec-ch-ua-arch",
        "recognizable-secret",
        ClientHintDelivery::AcceptCh,
    );
    let debug = format!("{hint:?}");
    assert!(debug.contains("sec-ch-ua-arch"));
    assert!(!debug.contains("recognizable-secret"));
}
