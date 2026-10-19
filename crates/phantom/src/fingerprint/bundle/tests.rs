use super::*;
use crate::fingerprint::{describe_profile, export_profile_json};
use phantom_profile::{
    ClientProfile,
    browser::chrome,
    catalog::{self, RequestTemplateKind},
};
use serde_json::{Value, json};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn document() -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let definition = &catalog::profiles()[0];
    let profile = definition.instantiate(&[])?;
    Ok(
        json!({"format":"phantom.profile-bundle", "version":1, "id":"my/profiles", "revision":1,
        "profiles":[{"name":"custom/example", "document":describe_profile(&profile)?,
            "provenance":[{"source":"https://example.test/observations", "revision":"commit-1"}]}]}),
    )
}

fn import(value: &Value) -> Result<ProfileBundle> {
    ProfileBundle::from_json(
        &serde_json::to_vec(value)
            .map_err(|error| FingerprintImportError::native("bundle", error))?,
    )
}

#[test]
fn every_catalog_profile_and_template_retains_order_in_a_bundle() -> TestResult {
    let mut profiles = Vec::new();
    for definition in catalog::profiles() {
        let base = definition.instantiate(&[])?;
        profiles.push(base.clone());
        for kind in [
            RequestTemplateKind::Navigation,
            RequestTemplateKind::Fetch,
            RequestTemplateKind::FetchNoStore,
            RequestTemplateKind::FetchUpload,
        ] {
            if let Ok(template) = definition.request_template(kind) {
                profiles.push(base.clone().with_request_template(template));
            }
        }
    }
    for profiles in profiles.chunks(MAX_PROFILES) {
        let entries = profiles.iter().enumerate().map(|(index, profile)| {
            Ok(json!({"name":format!("entry/{index}"), "document":describe_profile(profile)?, "provenance":[]}))
        }).collect::<std::result::Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let value = json!({"format":"phantom.profile-bundle","version":1,"id":"all","revision":1,"profiles":entries});
        let bundle = import(&value)?;
        assert_eq!(bundle.profiles().len(), profiles.len());
        for (index, profile) in profiles.iter().enumerate() {
            let restored = bundle
                .profiles()
                .get(&format!("entry/{index}"))
                .ok_or("missing entry")?;
            assert_eq!(restored, profile);
            assert_eq!(
                export_profile_json(restored)?,
                export_profile_json(profile)?
            );
        }
    }
    Ok(())
}

#[test]
fn exact_lookup_and_raw_bytes_digest_preserve_publisher_references_without_catalog_claims()
-> TestResult {
    let value = document()?;
    let bytes = serde_json::to_vec(&value)?;
    let bundle = ProfileBundle::from_json(&bytes)?;
    assert_eq!(bundle.id(), "my/profiles");
    assert_eq!(bundle.revision(), 1);
    assert!(bundle.profiles().get("CUSTOM/example").is_none());
    assert!(
        bundle
            .profiles()
            .get(catalog::profiles()[0].id().as_str())
            .is_none()
    );
    let references = bundle
        .provenance("custom/example")
        .ok_or("missing provenance")?;
    assert_eq!(references[0].source(), "https://example.test/observations");
    assert_eq!(references[0].revision(), "commit-1");
    assert!(bundle.provenance("missing").is_none());
    let mut changed = bytes.clone();
    changed.push(b'\n');
    assert_ne!(
        bundle.sha256(),
        ProfileBundle::from_json(&changed)?.sha256()
    );
    let expected: String = btls::sha::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(bundle.sha256(), expected);
    assert!(!format!("{bundle:?}").contains("observations"));
    Ok(())
}

#[test]
fn invalid_later_entries_fail_with_redacted_indexed_errors() -> TestResult {
    let mut value = document()?;
    let mut later = value["profiles"][0].clone();
    later["name"] = json!("second");
    later["document"]["profile"]["tls"]["cipher_suites"] = json!(["SECRET_UNSUPPORTED"]);
    value["profiles"]
        .as_array_mut()
        .ok_or("missing entries")?
        .push(later);
    let error = import(&value)
        .err()
        .ok_or("invalid second profile accepted")?;
    assert_eq!(error.kind(), Kind::UnsupportedSetting);
    assert!(error.field().starts_with("profiles[1].document."));
    assert!(!format!("{error} {error:?}").contains("SECRET"));
    Ok(())
}

#[test]
fn duplicates_unknown_fields_versions_and_labels_are_rejected() -> TestResult {
    let base = document()?;
    for path in ["version", "revision"] {
        let mut value = base.clone();
        value[path] = json!(if path == "version" { 2 } else { 0 });
        assert!(import(&value).is_err());
    }
    for name in ["", "../SECRET", "UPPER", "bad\nname", &"x".repeat(129)] {
        let mut value = base.clone();
        value["id"] = json!(name);
        let error = import(&value).err().ok_or("invalid label accepted")?;
        assert_eq!(error.field(), "id");
        assert!(!format!("{error:?}").contains("SECRET"));
    }
    let mut value = base.clone();
    let entry = value["profiles"][0].clone();
    value["profiles"]
        .as_array_mut()
        .ok_or("entries")?
        .push(entry);
    assert_eq!(
        import(&value).err().ok_or("duplicate accepted")?.field(),
        "profiles[1].name"
    );
    for level in 0..3 {
        let mut value = base.clone();
        let object = match level {
            0 => &mut value,
            1 => &mut value["profiles"][0],
            _ => &mut value["profiles"][0]["provenance"][0],
        };
        object["unexpected"] = json!(true);
        assert_eq!(
            import(&value).err().ok_or("unknown accepted")?.kind(),
            Kind::UnsupportedSetting
        );
    }
    let mut bytes = serde_json::to_vec(&base)?;
    bytes.pop();
    bytes.extend_from_slice(br#", "\u0076ersion":1}"#);
    assert_eq!(
        ProfileBundle::from_json(&bytes)
            .err()
            .ok_or("duplicate version")?
            .kind(),
        Kind::DuplicateField
    );
    let error = ProfileBundle::from_json(b"{")
        .err()
        .ok_or("malformed accepted")?;
    assert!(!format!("{error}").contains("phantom.custom-profile"));
    Ok(())
}

#[test]
fn bundle_and_original_profile_resource_limits_remain_separate() -> TestResult {
    let base = document()?;
    for count in [0, 65] {
        let mut value = base.clone();
        value["profiles"] = json!(vec![base["profiles"][0].clone(); count]);
        assert_eq!(
            import(&value).err().ok_or("entry limit")?.kind(),
            Kind::TooLarge
        );
    }
    let oversized = vec![b' '; json::MAX_BYTES + 1];
    assert_eq!(
        ProfileBundle::from_json(&oversized)
            .err()
            .ok_or("size limit")?
            .kind(),
        Kind::TooLarge
    );
    for (key, text) in [
        ("source", "s".repeat(2049)),
        ("revision", "r".repeat(129)),
        ("source", "SECRET\n".into()),
    ] {
        let mut value = base.clone();
        value["profiles"][0]["provenance"][0][key] = json!(text);
        assert!(import(&value).is_err());
    }
    let mut value = base.clone();
    value["profiles"][0]["provenance"] =
        json!(vec![base["profiles"][0]["provenance"][0].clone(); 17]);
    assert_eq!(
        import(&value).err().ok_or("reference limit")?.kind(),
        Kind::TooLarge
    );
    let nested = |depth| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    assert!(json::parse(nested(16).as_bytes()).is_ok());
    assert!(json::parse(nested(17).as_bytes()).is_err());
    let wrapped = json::parse_bundle(nested(19).as_bytes())?;
    assert_eq!(
        wrapped
            .profile_depth()
            .err()
            .ok_or("profile depth weakened")?
            .kind(),
        Kind::TooLarge
    );
    Ok(())
}

#[tokio::test]
async fn a_client_keeps_owned_settings_when_a_new_revision_is_loaded() -> TestResult {
    use crate::{Client, HttpProtocol};
    use phantom_profile::RequestField;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let profile = |value: &str| {
        let mut template = chrome::v154_windows_navigation_template();
        template
            .http1_fields
            .insert(0, RequestField::literal("X-Identity", value));
        template
            .http2_fields
            .insert(0, RequestField::literal("x-identity", value));
        template.http3_fields = None;
        chrome::v154_windows().with_request_template(template)
    };
    let encode = |revision,
                  profile: &ClientProfile|
     -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(serde_json::to_vec(
            &json!({"format":"phantom.profile-bundle","version":1,"id":"identities","revision":revision,
            "profiles":[{"name":"chosen","document":describe_profile(profile)?,"provenance":[]}]}),
        )?)
    };
    let first = ProfileBundle::from_json(&encode(1, &profile("old"))?)?;
    let old =
        Client::builder(first.profiles().get("chosen").ok_or("old missing")?.clone()).build()?;
    drop(first);
    let second = ProfileBundle::from_json(&encode(2, &profile("new"))?)?;
    let new = Client::builder(
        second
            .profiles()
            .get("chosen")
            .ok_or("new missing")?
            .clone(),
    )
    .build()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/", listener.local_addr()?);
    let peer = tokio::spawn(async move {
        let mut heads = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await?;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await?);
            }
            heads.push(String::from_utf8_lossy(&head).into_owned());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
        }
        Ok::<_, std::io::Error>(heads)
    });
    for client in [&old, &new] {
        drop(client.get(HttpProtocol::Http1, &url)?.send().await?);
    }
    let heads = peer.await??;
    assert!(heads[0].contains("X-Identity: old\r\n"));
    assert!(heads[1].contains("X-Identity: new\r\n"));
    Ok(())
}
