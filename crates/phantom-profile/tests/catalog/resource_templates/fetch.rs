use phantom_profile::{
    Http2Priority, Http2RequestPriority,
    catalog::{RequestTemplateKind, profile},
};

use super::{Fields, TestResult, declared_fields, field};

const FETCH: [&str; 2] = [
    include_str!(
        "../../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/revalidate-h1.txt"
    ),
    include_str!(
        "../../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/revalidate-h2.txt"
    ),
];
const UPLOAD: [&str; 2] = [
    include_str!(
        "../../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/upload-h1.txt"
    ),
    include_str!(
        "../../../../../fixtures/lifecycle/chrome/156.0.8078.48/windows-11-26200/upload-h2.txt"
    ),
];

fn compare(captures: [&str; 2], kind: RequestTemplateKind, paths: &[&str]) -> TestResult {
    let definition = profile("chrome-156-windows")?;
    let selected = definition.instantiate(&[])?;
    let hints = selected
        .client_hints()
        .ok_or("missing client hints")?
        .hints();
    let template = definition.request_template(kind)?;
    template.validate()?;
    assert!(template.http3_fields.is_none());

    for (protocol, capture) in captures.into_iter().enumerate() {
        let fields = if protocol == 0 {
            &template.http1_fields
        } else {
            &template.http2_fields
        };
        let mut observed = Vec::new();
        for index in 0..field(capture, "request_count")?.parse::<usize>()? {
            let request = field(capture, &format!("request_{index}"))?;
            let path = request
                .split(',')
                .find_map(|part| part.strip_prefix("path:"))
                .ok_or("missing request path")?;
            if !paths.contains(&path) {
                continue;
            }
            observed.push(path);
            let captured: Vec<(String, String)> =
                serde_json::from_str(field(capture, &format!("request_{index}_headers_json"))?)?;
            let captured: Fields = captured
                .into_iter()
                .filter(|(name, _)| !name.starts_with(':') && !name.eq_ignore_ascii_case("host"))
                .map(|(name, value)| (name, value.into_bytes()))
                .collect();
            // Only caller-owned fields come from the capture. Automatic values and
            // their order must come from the declaration under test.
            let caller = captured
                .iter()
                .filter(|(name, _)| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "referer"
                            | "origin"
                            | "content-type"
                            | "content-length"
                            | "if-none-match"
                            | "if-modified-since"
                    )
                })
                .cloned()
                .collect();
            assert_eq!(declared_fields(fields, hints, &caller)?, captured, "{path}");
            if protocol == 0 {
                assert!(
                    !captured
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("priority"))
                );
            } else {
                let priority: serde_json::Value =
                    serde_json::from_str(field(capture, &format!("request_{index}_priority"))?)?;
                assert_eq!(
                    template.http2_priority,
                    Some(Http2RequestPriority::Fixed(Http2Priority {
                        dependency_stream_id: priority["depends_on"]
                            .as_u64()
                            .ok_or("missing dependency")?
                            .try_into()?,
                        weight: priority["weight"]
                            .as_u64()
                            .ok_or("missing weight")?
                            .try_into()?,
                        exclusive: priority["exclusive"]
                            .as_bool()
                            .ok_or("missing exclusive flag")?,
                    }))
                );
            }
            if path == "/post-blob" {
                assert!(
                    !captured
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                );
            }
        }
        let expected: Vec<_> = if kind == RequestTemplateKind::Fetch {
            vec![
                "/etag",
                "/etag",
                "/last-modified",
                "/last-modified",
                "/both",
                "/both",
                "/heuristic",
            ]
        } else {
            paths.to_vec()
        };
        assert_eq!(observed, expected);
    }
    Ok(())
}

#[test]
fn windows156_fetch_fields_and_validators_match_both_protocol_captures() -> TestResult {
    compare(
        FETCH,
        RequestTemplateKind::Fetch,
        &["/etag", "/last-modified", "/both", "/heuristic"],
    )
}

#[test]
fn windows156_upload_fields_match_string_blob_and_form_data_captures() -> TestResult {
    compare(
        UPLOAD,
        RequestTemplateKind::FetchUpload,
        &[
            "/post-small",
            "/post-large",
            "/post-blob",
            "/post-multipart",
        ],
    )
}
