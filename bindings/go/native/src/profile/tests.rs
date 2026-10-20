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
        exhausted.insert(owner).err().map(|error| error.kind),
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
