use super::*;
use phantom::fingerprint::{ProfileBundle, describe_profile};
use phantom_profile::{
    RequestField, RequestTemplate, browser::chrome, catalog::RequestTemplateKind,
};
use serde_json::json;

fn bundle(revision: u64, identity: &str) -> TestResult<Vec<u8>> {
    let mut template = chrome::v154_windows_navigation_template();
    template.http1_fields.splice(
        0..0,
        [
            RequestField::literal("X-Identity", identity),
            RequestField::literal("X-Last", "end"),
        ],
    );
    template.http2_fields.splice(
        0..0,
        [
            RequestField::literal("x-identity", identity),
            RequestField::literal("x-last", "end"),
        ],
    );
    template.http3_fields = None;
    let profile = chrome::v154_windows()
        .with_request_template(template)
        .with_request_contexts([
            (
                RequestTemplateKind::Navigation,
                named_template(revision, identity, "navigation"),
            ),
            (
                RequestTemplateKind::Fetch,
                named_template(revision, identity, "fetch"),
            ),
        ]);
    Ok(serde_json::to_vec(
        &json!({"format":"phantom.profile-bundle","version":1,"id":"offline/release","revision":revision,
        "profiles":[{"name":"chosen","document":describe_profile(&profile)?,"provenance":[{"source":"unverified publisher reference","revision":"source-1"}]}]}),
    )?)
}

fn named_template(revision: u64, identity: &str, context: &str) -> RequestTemplate {
    let mut template = chrome::v154_windows_navigation_template();
    let mut fields = [
        RequestField::literal("X-Identity", format!("{identity}-{context}")),
        RequestField::literal("X-Last", context),
    ];
    if revision == 2 {
        fields.reverse();
    }
    template.http1_fields.splice(0..0, fields);
    template.http3_fields = None;
    template
}

fn observed_request(listener: TcpListener, command: &mut Command) -> TestResult<String> {
    let peer = thread::spawn(move || -> TestResult<Vec<u8>> {
        let mut stream = accept(&listener)?;
        let request = head(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
        Ok(request)
    });
    let output = command.output()?;
    let request = peer.join().map_err(|_| "peer panicked")??;
    success(&output);
    assert_eq!(output.stdout, b"ok");
    assert!(output.stderr.is_empty());
    Ok(String::from_utf8(request)?)
}

fn pinned(url: &str, store: &std::path::Path, digest: &str) -> Command {
    pinned_profile(url, store, digest, "chosen")
}

fn pinned_profile(url: &str, store: &std::path::Path, digest: &str, profile: &str) -> Command {
    let mut command = command();
    command
        .args([
            "request",
            url,
            "--protocol",
            "h1",
            "--timeout-ms",
            "5000",
            "--bundle",
            digest,
            "--bundle-profile",
            profile,
            "--bundle-store",
        ])
        .arg(store);
    command
}

#[test]
fn offline_install_pin_and_rollback_preserve_versions_and_wire_headers() -> TestResult {
    let directory = Directory::new()?;
    let store = directory.path("store");
    fs::create_dir(&store)?;
    let mut digests = Vec::new();
    for (revision, identity) in [(1, "old"), (2, "new")] {
        let bytes = bundle(revision, identity)?;
        let source = directory.path(&format!("{revision}.json"));
        fs::write(&source, &bytes)?;
        let inspected = command()
            .args(["profiles", "bundle", "inspect"])
            .arg(&source)
            .output()?;
        success(&inspected);
        let report: serde_json::Value = serde_json::from_slice(&inspected.stdout)?;
        let expected = ProfileBundle::from_json(&bytes)?.sha256().to_owned();
        assert_eq!(report["sha256"], expected);
        assert_eq!(report["revision"], revision);
        assert_eq!(
            report["profiles"],
            json!([{
                "name": "chosen",
                "provenance": [{
                    "source": "unverified publisher reference",
                    "revision": "source-1"
                }]
            }])
        );
        for _ in 0..2 {
            let installed = command()
                .args(["profiles", "bundle", "install"])
                .arg(&source)
                .arg("--store")
                .arg(&store)
                .output()?;
            success(&installed);
            assert_eq!(String::from_utf8(installed.stdout)?.trim(), expected);
            assert_eq!(fs::read(store.join(&expected))?, bytes);
        }
        fs::remove_file(source)?;
        digests.push(expected);
    }
    assert_ne!(digests[0], digests[1]);
    assert_eq!(fs::read_dir(&store)?.count(), 2);
    for (digest, identity, revision) in [
        (&digests[0], "old", 1),
        (&digests[1], "new", 2),
        (&digests[0], "old", 1),
    ] {
        for context in [None, Some("navigation"), Some("fetch")] {
            let listener = listener()?;
            let url = format!("http://{}/", listener.local_addr()?);
            let mut command = pinned(&url, &store, digest);
            if let Some(context) = context {
                command.args(["--context", context]);
            }
            let request = observed_request(listener, &mut command)?;
            let expected = match context {
                None => format!("X-Identity: {identity}\r\nX-Last: end\r\n"),
                Some(context) if revision == 2 => {
                    format!("X-Last: {context}\r\nX-Identity: {identity}-{context}\r\n")
                }
                Some(context) => {
                    format!("X-Identity: {identity}-{context}\r\nX-Last: {context}\r\n")
                }
            };
            assert!(request.contains(&expected), "{request}");
        }
    }
    Ok(())
}

#[test]
fn invalid_bundles_conflicts_and_selection_errors_preserve_installed_content() -> TestResult {
    let directory = Directory::new()?;
    let store = directory.path("store");
    fs::create_dir(&store)?;
    let bytes = bundle(1, "old")?;
    let digest = ProfileBundle::from_json(&bytes)?.sha256().to_owned();
    let source = directory.path("input.json");
    fs::write(&source, &bytes)?;
    let destination = store.join(&digest);
    fs::write(&destination, b"incomplete")?;
    let conflict = command()
        .args(["profiles", "bundle", "install"])
        .arg(&source)
        .arg("--store")
        .arg(&store)
        .output()?;
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(fs::read(&destination)?, b"incomplete");
    let selected = pinned("http://127.0.0.1:1/", &store, &digest).output()?;
    assert_eq!(selected.status.code(), Some(1));
    fs::remove_file(&destination)?;
    let mut invalid: serde_json::Value = serde_json::from_slice(&bytes)?;
    let mut bad = invalid["profiles"][0].clone();
    bad["name"] = json!("another");
    bad["document"]["profile"]["tls"] = serde_json::Value::Null;
    invalid["profiles"]
        .as_array_mut()
        .ok_or("entries")?
        .push(bad);
    fs::write(&source, serde_json::to_vec(&invalid)?)?;
    let output = command()
        .args(["profiles", "bundle", "install"])
        .arg(&source)
        .arg("--store")
        .arg(&store)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read_dir(&store)?.count(), 0);
    fs::write(&destination, &bytes)?;
    for supplied in ["../escape", &digest.to_uppercase(), &"0".repeat(64)] {
        assert!(
            !pinned("http://127.0.0.1:1/", &store, supplied)
                .output()?
                .status
                .success()
        );
    }
    let listener = listener()?;
    listener.set_nonblocking(true)?;
    let url = format!("http://{}/", listener.local_addr()?);
    for context in ["script", "fetch-upload"] {
        let unavailable = pinned(&url, &store, &digest)
            .args(["--context", context])
            .output()?;
        assert_eq!(
            unavailable.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&unavailable.stderr)
        );
        assert!(String::from_utf8_lossy(&unavailable.stderr).contains("request context"));
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
    let missing = pinned_profile("http://127.0.0.1:1/", &store, &digest, "missing").output()?;
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("exact bundle profile name"));
    assert_eq!(fs::read(&destination)?, bytes);
    let different = bundle(2, "different")?;
    fs::write(&destination, &different)?;
    let mismatched = pinned("http://127.0.0.1:1/", &store, &digest).output()?;
    assert_eq!(mismatched.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&mismatched.stderr).contains("pinned digest"));
    assert_eq!(fs::read(&destination)?, different);
    Ok(())
}

#[test]
fn profile_files_select_portable_contexts_and_legacy_bundles_keep_the_default() -> TestResult {
    let directory = Directory::new()?;
    let mut envelope: serde_json::Value = serde_json::from_slice(&bundle(1, "old")?)?;
    let source = directory.path("profile.json");
    fs::write(
        &source,
        serde_json::to_vec(&envelope["profiles"][0]["document"])?,
    )?;
    for (context, expected) in [
        (None, "X-Identity: old\r\nX-Last: end\r\n"),
        (
            Some("navigation"),
            "X-Identity: old-navigation\r\nX-Last: navigation\r\n",
        ),
        (Some("fetch"), "X-Identity: old-fetch\r\nX-Last: fetch\r\n"),
    ] {
        let listener = listener()?;
        let url = format!("http://{}/", listener.local_addr()?);
        let mut command = command();
        command
            .args([
                "request",
                &url,
                "--protocol",
                "h1",
                "--timeout-ms",
                "5000",
                "--profile-file",
            ])
            .arg(&source);
        if let Some(context) = context {
            command.args(["--context", context]);
        }
        assert!(observed_request(listener, &mut command)?.contains(expected));
    }

    let document = &mut envelope["profiles"][0]["document"];
    assert_eq!(document["version"], 2);
    document["version"] = json!(1);
    assert!(
        document["profile"]
            .as_object_mut()
            .ok_or("profile")?
            .remove("request_contexts")
            .is_some()
    );
    let bytes = serde_json::to_vec(&envelope)?;
    let digest = ProfileBundle::from_json(&bytes)?.sha256().to_owned();
    let store = directory.path("store");
    fs::create_dir(&store)?;
    fs::write(store.join(&digest), bytes)?;
    let listener = listener()?;
    let url = format!("http://{}/", listener.local_addr()?);
    assert!(
        observed_request(listener, &mut pinned(&url, &store, &digest))?
            .contains("X-Identity: old\r\nX-Last: end\r\n")
    );

    let listener = listener()?;
    listener.set_nonblocking(true)?;
    let url = format!("http://{}/", listener.local_addr()?);
    let unavailable = pinned(&url, &store, &digest)
        .args(["--context", "navigation"])
        .output()?;
    assert_eq!(unavailable.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("request context"));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    Ok(())
}
