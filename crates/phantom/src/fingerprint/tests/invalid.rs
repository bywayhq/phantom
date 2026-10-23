//! Rejected descriptions preserve error privacy and native causes.
use super::super::{FingerprintImportErrorKind as Kind, import_profile_json};
use super::profiles::{TestResult, document};
use serde_json::json;
use std::error::Error;

fn error(
    value: &serde_json::Value,
) -> Result<super::super::FingerprintImportError, Box<dyn Error>> {
    Ok(import_profile_json(&serde_json::to_vec(value)?)
        .err()
        .ok_or("unexpected success")?)
}

#[test]
fn missing_unknown_and_null_required_settings_are_explicit_errors() -> TestResult {
    let mut value = document(0)?;
    value["profile"]
        .as_object_mut()
        .ok_or("not an object")?
        .remove("tcp");
    assert_eq!(error(&value)?.kind(), Kind::MissingField);
    let mut value = document(0)?;
    value["profile"]["imagined_browser"] = json!(true);
    assert_eq!(error(&value)?.kind(), Kind::UnsupportedSetting);
    let mut value = document(0)?;
    value["profile"]["tls"] = json!(null);
    assert_eq!(error(&value)?.kind(), Kind::InvalidValue);
    let mut value = document(0)?;
    value["profile"]["tls"]["cipher_suites"] = json!(["unknown"]);
    assert_eq!(error(&value)?.kind(), Kind::UnsupportedSetting);
    Ok(())
}

#[test]
fn foreign_lossy_fingerprints_and_unknown_versions_are_not_completed() -> TestResult {
    for format in ["ja3", "ja3n", "ja4", "ja4_r", "ja4_ro"] {
        assert_eq!(
            error(&json!({"format":format,"hash":"secret"}))?.kind(),
            Kind::LossyDescription
        );
    }
    assert_eq!(
        error(&json!({"format":"foreign"}))?.kind(),
        Kind::UnsupportedFormat
    );
    let mut value = document(0)?;
    value["version"] = json!(2);
    assert_eq!(error(&value)?.kind(), Kind::UnsupportedFormat);
    assert_eq!(
        import_profile_json(b"0123456789abcdef")
            .err()
            .ok_or("accepted hash")?
            .kind(),
        Kind::MalformedJson
    );
    Ok(())
}

#[test]
fn native_validation_failure_retains_its_typed_cause() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["tls"]["session_tickets"]["tcp_per_origin"] = json!(11);
    let failure = error(&value)?;
    assert_eq!(failure.kind(), Kind::InvalidSettings);
    assert!(
        failure
            .source()
            .and_then(|cause| cause.downcast_ref::<phantom_profile::InvalidTlsSettings>())
            .is_some()
    );
    Ok(())
}

#[test]
fn diagnostics_do_not_echo_supplied_keys_values_or_documents() -> TestResult {
    let secret = "secret-do-not-log-872ef";
    let mut value = document(0)?;
    value["profile"][secret] = json!(secret);
    let failure = error(&value)?;
    assert!(!format!("{failure} {failure:?}").contains(secret));
    let mut value = document(0)?;
    value["profile"]["client_hints"]["hints"][0]["value"] =
        json!([115, 101, 99, 114, 101, 116, 10]);
    let failure = error(&value)?;
    assert_eq!(failure.kind(), Kind::InvalidSettings);
    assert!(!format!("{failure} {failure:?}").contains("secret"));
    if let Some(cause) = failure.source() {
        assert!(!cause.to_string().contains("secret"));
    }
    Ok(())
}

#[test]
fn duration_integer_and_native_quic_constraints_are_checked() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["http2"]["idle_ping_after"] = json!({"seconds":1,"nanoseconds":1000000000});
    assert_eq!(error(&value)?.kind(), Kind::InvalidValue);
    let mut value = document(0)?;
    value["profile"]["http3"]["quic_transport"]["wire_parameters"][0]["id_width"] =
        json!("unknown");
    assert_eq!(error(&value)?.kind(), Kind::UnsupportedSetting);
    let mut value = document(0)?;
    value["profile"]["http3"]["quic_transport"]["max_udp_payload_size"] = json!(1199);
    assert_eq!(error(&value)?.kind(), Kind::InvalidSettings);
    let mut value = document(0)?;
    value["profile"]["tls"]["alpn_protocols"] = json!([[256]]);
    assert_eq!(error(&value)?.kind(), Kind::InvalidValue);
    Ok(())
}

#[test]
fn partial_http3_and_injected_evidence_or_credentials_are_rejected() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["http3"]
        .as_object_mut()
        .ok_or("missing H3")?
        .remove("request");
    assert_eq!(error(&value)?.kind(), Kind::MissingField);
    for key in ["catalog_id", "evidence", "roots", "credentials"] {
        let mut value = document(0)?;
        value["profile"][key] = json!("secret");
        assert_eq!(error(&value)?.kind(), Kind::UnsupportedSetting);
    }
    Ok(())
}
// Every present native layer keeps its own validation authority.
#[test]
fn invalid_policies_in_each_present_layer_keep_native_error_types() -> TestResult {
    let index = super::profiles::PROFILES
        .iter()
        .position(|(id, _)| id.starts_with("chrome/") && id.contains("windows"))
        .ok_or("desktop fixture absent")?;
    let cases = [
        (
            "/profile/tcp/keepalive/idle",
            json!({"seconds":0,"nanoseconds":0}),
            "tcp",
        ),
        (
            "/profile/http1/idle_timeout",
            json!({"kind":"ClosedOnTimer","duration":{"seconds":65536,"nanoseconds":0}}),
            "http1",
        ),
        ("/profile/http2/streams/first_stream_id", json!(2), "http2"),
        (
            "/profile/http3/http3/initial_settings",
            json!([{"kind":"EnableWebTransportDraft02","value":true}]),
            "http3.http3",
        ),
        (
            "/profile/http3/request/pseudo_header_order",
            json!(["Method"]),
            "http3.request",
        ),
        (
            "/profile/websocket/handshake_timeout",
            json!({"seconds":0,"nanoseconds":0}),
            "websocket",
        ),
        (
            "/profile/proxy_connect/http2_fields",
            json!([{"kind":"FromRequest","name":"authorization"},{"kind":"ProxyAuthorization","name":"proxy-authorization"}]),
            "proxy_connect",
        ),
    ];
    for (pointer, replacement, field) in cases {
        let mut value = document(index)?;
        *value
            .pointer_mut(pointer)
            .ok_or("native fixture path absent")? = replacement;
        let failure = error(&value)?;
        assert_eq!(failure.kind(), Kind::InvalidSettings, "{pointer}");
        assert_eq!(failure.field(), field, "{pointer}");
        assert!(failure.source().is_some(), "{pointer}");
    }
    Ok(())
}

#[test]
fn imported_template_invalid_field_is_rejected_by_native_validator() -> TestResult {
    let mut value = document(0)?;
    value["profile"]["request_template"] = json!({"http1_fields":[{"variant":"Literal","name":"Cookie","value":"secret"}],"http2_fields":[],"http3_fields":null,"http2_priority":null,"requested_client_hint_placement":false,"restarts_for_connection_accept_ch":false});
    let failure = error(&value)?;
    assert_eq!(failure.kind(), Kind::InvalidSettings);
    assert!(
        failure
            .source()
            .and_then(|cause| cause.downcast_ref::<phantom_profile::InvalidRequestTemplate>())
            .is_some()
    );
    assert!(!format!("{failure} {failure:?}").contains("secret"));
    Ok(())
}

#[test]
fn websocket_cleartext_state_requires_a_known_explicit_policy() -> TestResult {
    let mut value = document(0)?;
    let connection = &mut value["profile"]["websocket"]["connection"];
    connection
        .as_object_mut()
        .ok_or("missing WebSocket policy")?
        .remove("cleartext_state");
    let failure = error(&value)?;
    assert_eq!(failure.kind(), Kind::MissingField);
    assert_eq!(failure.field(), "websocket.connection.cleartext_state");

    value["profile"]["websocket"]["connection"]["cleartext_state"] = json!("Unknown");
    let failure = error(&value)?;
    assert_eq!(failure.kind(), Kind::UnsupportedSetting);
    assert_eq!(failure.field(), "websocket.connection.cleartext_state");
    Ok(())
}
