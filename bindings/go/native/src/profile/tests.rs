use super::*;

fn value(command: Value, input: &[u8], capacity: usize) -> Result<(Value, Vec<u8>), Failure> {
    let (reply, output) = dispatch(
        &serde_json::to_vec(&command).map_err(|_| Failure::new("test_json"))?,
        input,
        capacity,
    );
    Ok((
        serde_json::from_slice(&reply).map_err(|_| Failure::new("test_json"))?,
        output,
    ))
}

fn create() -> Result<u64, Failure> {
    let (reply, _) = value(
        json!({"kind": "catalog", "identifier": "chrome/154.0.8037.97/windows-11-26200/r1"}),
        &[],
        0,
    )?;
    reply["value"]["id"]
        .as_u64()
        .ok_or_else(|| Failure::new("test_owner"))
}

fn release(id: u64) -> Result<(), Failure> {
    let (reply, _) = value(json!({"kind": "release", "profile": id}), &[], 0)?;
    assert!(reply.get("error").is_none());
    Ok(())
}

#[test]
fn catalog_roundtrips_use_core_settings_without_imported_identity() -> Result<(), Failure> {
    for definition in catalog::profiles() {
        let owner = ProfileState::catalog(definition.id().as_str(), None)?;
        let document = fingerprint::export_profile_json(&owner.settings)
            .map_err(|_| Failure::new("test_export"))?;
        let imported =
            fingerprint::import_profile_json(&document).map_err(|_| Failure::new("test_import"))?;
        assert_eq!(
            fingerprint::export_profile_json(&imported).map_err(|_| Failure::new("test_export"))?,
            document
        );
        let custom = ProfileState {
            settings: imported,
            definition: None,
        };
        assert!(custom.selected(Some("raw"))?.request_template().is_none());
        assert_eq!(
            custom
                .selected(Some("navigation"))
                .err()
                .map(|error| error.kind),
            Some("context_unavailable")
        );
        assert_eq!(
            custom
                .selected(Some("unknown"))
                .err()
                .map(|error| error.kind),
            Some("invalid_context")
        );
    }
    Ok(())
}

#[test]
fn registry_has_no_http_quota_and_never_reuses_ids() -> Result<(), Failure> {
    let ids = (0..80).map(|_| create()).collect::<Result<Vec<_>, _>>()?;
    let retained = get(ids[0])?;
    for id in &ids {
        release(*id)?;
    }
    assert_eq!(
        get(ids[0]).err().map(|error| error.kind),
        Some("profile_closed")
    );
    assert!(retained.selected(None).is_ok());
    let next = create()?;
    assert!(ids.iter().all(|id| *id < next));
    release(next)?;

    let mut exhausted = Registry {
        last: u64::MAX,
        owners: HashMap::new(),
    };
    let owner = ProfileState::catalog("chrome/154.0.8037.97/windows-11-26200/r1", None)?;
    assert_eq!(
        exhausted.insert(owner, None).err().map(|error| error.kind),
        Some("profile_id_exhausted")
    );
    assert!(exhausted.owners.is_empty());
    Ok(())
}

#[test]
fn export_probe_close_and_insufficient_output_are_explicit() -> Result<(), Failure> {
    let id = create()?;
    let command = json!({"kind": "export", "profile": id});
    let (probe, empty) = value(command.clone(), &[], 0)?;
    assert!(empty.is_empty());
    let size = probe["value"]["length"]
        .as_u64()
        .ok_or_else(|| Failure::new("test_length"))? as usize;
    let (copied, document) = value(command.clone(), &[], size)?;
    assert_eq!(copied["value"]["length"], probe["value"]["length"]);
    assert_eq!(document.len(), size);
    let (limited, empty) = value(command.clone(), &[], size - 1)?;
    assert_eq!(limited["error"]["kind"], "profile_output_limit");
    assert!(empty.is_empty());
    release(id)?;
    let (closed, empty) = value(command, &[], size)?;
    assert_eq!(closed["error"]["kind"], "profile_closed");
    assert!(empty.is_empty());
    Ok(())
}

#[test]
fn commands_and_document_errors_are_strict_and_redacted() -> Result<(), Failure> {
    for command in [
        br#"{"kind":"import","extra":true}"#.as_slice(),
        br#"{"kind":"import"} {}"#,
        br#"{"kind":"release","profile":1,"secret":"hidden"}"#,
    ] {
        let (reply, output) = dispatch(command, &[], 0);
        assert_eq!(
            serde_json::from_slice::<Value>(&reply).map_err(|_| Failure::new("test_json"))?["error"]
                ["kind"],
            "invalid_command"
        );
        assert!(output.is_empty());
    }
    let (reply, _) = value(
        json!({"kind":"import"}),
        br#"{"format":"private-secret"}"#,
        0,
    )?;
    assert_eq!(reply["error"]["kind"], "profile_import_unsupported_format");
    assert_eq!(reply["error"]["field"], "format");
    assert!(!reply.to_string().contains("private-secret"));
    Ok(())
}

#[test]
fn captured_handshake_import_keeps_owned_settings_and_exact_field_report() -> Result<(), Failure> {
    let capture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt"
    ));
    let record = capture
        .lines()
        .find_map(|line| line.strip_prefix("record_0_hex="))
        .ok_or_else(|| Failure::new("test_capture"))?;
    let record = record
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| Failure::new("test_hex"))?;
            u8::from_str_radix(text, 16).map_err(|_| Failure::new("test_hex"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let base = create()?;
    let retained = get(base)?;
    let before = fingerprint::export_profile_json(&retained.settings)
        .map_err(|_| Failure::new("test_export"))?;
    let (reply, output) = value(
        json!({"kind":"import_client_hello", "base":base}),
        &record[5..],
        0,
    )?;
    assert!(output.is_empty());
    assert_eq!(reply["value"]["catalog_id"], Value::Null);
    let observed = reply["value"]["observed_fields"]
        .as_array()
        .ok_or_else(|| Failure::new("test_fields"))?;
    assert!(observed.contains(&json!("tls.versions")));
    assert!(
        reply["value"]["supplemented_fields"]
            .as_array()
            .ok_or_else(|| Failure::new("test_fields"))?
            .contains(&json!("tls.requested_trust_anchor_ids"))
    );
    let imported_id = reply["value"]["id"]
        .as_u64()
        .ok_or_else(|| Failure::new("test_owner"))?;
    release(base)?;
    let imported = get(imported_id)?;
    assert!(imported.definition.is_none());
    assert_eq!(imported.settings.http2(), retained.settings.http2());
    let exported = fingerprint::export_profile_json(&imported.settings)
        .map_err(|_| Failure::new("test_export"))?;
    assert!(
        !exported
            .windows(b"server.phantom.test".len())
            .any(|value| value == b"server.phantom.test")
    );
    assert_eq!(
        fingerprint::export_profile_json(&retained.settings)
            .map_err(|_| Failure::new("test_export"))?,
        before
    );
    release(imported_id)?;
    Ok(())
}

#[test]
fn observation_commands_require_base_and_format_without_leaking_values() -> Result<(), Failure> {
    let base = create()?;
    for command in [
        json!({"kind":"import_ja3"}),
        json!({"kind":"import_ja4", "base":base}),
        json!({"kind":"import_akamai", "base":base, "extra":"private-secret"}),
    ] {
        let (reply, _) = value(command, b"private-secret", 0)?;
        assert_eq!(reply["error"]["kind"], "invalid_command");
        assert!(!reply.to_string().contains("private-secret"));
    }
    for (command, input, field) in [
        (json!({"kind":"import_ja3", "base":base}), &[255][..], "ja3"),
        (
            json!({"kind":"import_ja4", "base":base, "format":"guess"}),
            b"private-secret",
            "ja4.format",
        ),
    ] {
        let (reply, _) = value(command, input, 0)?;
        assert_eq!(reply["error"]["kind"], "profile_import_invalid_value");
        assert_eq!(reply["error"]["field"], field);
        assert!(!reply.to_string().contains("private-secret"));
    }
    release(base)?;
    let (reply, _) = value(json!({"kind":"import_akamai", "base":base}), b"", 0)?;
    assert_eq!(reply["error"]["kind"], "profile_closed");
    Ok(())
}

#[test]
fn oversized_import_report_does_not_publish_owner() -> Result<(), Failure> {
    let mut registry = Registry::default();
    let owner = ProfileState::catalog("chrome/154.0.8037.97/windows-11-26200/r1", None)?;
    assert_eq!(
        registry
            .insert(
                owner,
                Some((vec!["x".repeat(operations::MAX_METADATA)], Vec::new()))
            )
            .err()
            .map(|error| error.kind),
        Some("metadata_limit")
    );
    assert!(registry.owners.is_empty());
    assert_eq!(registry.last, 0);
    Ok(())
}
