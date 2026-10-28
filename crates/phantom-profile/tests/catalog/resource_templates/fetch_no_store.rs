use phantom_profile::{
    Http2Priority, Http2RequestPriority,
    catalog::{RequestTemplateKind, profile},
};

use super::{Fields, TestResult, captured_fields, declared_fields, field, unhex};

fn done_request(capture: &str) -> TestResult<&str> {
    for index in 0..field(capture, "request_count")?.parse::<usize>()? {
        let request = field(capture, &format!("request_{index}"))?;
        if request.split(',').any(|part| part == "path:/done") {
            return Ok(request);
        }
    }
    Err("missing no-store completion request".into())
}

fn expected_fields(capture: &str, request: &str) -> TestResult<Fields> {
    let script = captured_fields(capture, "script")?;
    let names = request
        .split_once(",fields:")
        .ok_or("missing completion fields")?
        .1
        .split(',')
        .next()
        .ok_or("missing completion field order")?;
    names
        .split('|')
        .filter(|name| !name.starts_with(':') && !name.eq_ignore_ascii_case("host"))
        .map(|name| {
            // These literals are decoded from /done's retained HPACK/QPACK bytes.
            // The other fields share the resource request's captured values.
            let value = match name.to_ascii_lowercase().as_str() {
                "pragma" | "cache-control" => b"no-cache".to_vec(),
                "sec-fetch-mode" => b"cors".to_vec(),
                "sec-fetch-dest" => b"empty".to_vec(),
                "priority" => b"u=1, i".to_vec(),
                _ => script
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .ok_or_else(|| format!("missing captured field {name}"))?
                    .1
                    .clone(),
            };
            Ok((name.to_owned(), value))
        })
        .collect()
}

fn captured_priority(capture: &str, request: &str) -> TestResult<Http2Priority> {
    let number = |name: &str| -> TestResult<u32> {
        Ok(request
            .split(',')
            .find_map(|part| part.strip_prefix(name))
            .ok_or("missing request identifier")?
            .parse()?)
    };
    let connection = number("connection:")?;
    let stream = number("stream:")?;
    let prefix = format!("resource_connection_{connection}_client_chunk");
    let mut wire = Vec::new();
    for index in 0..field(capture, &format!("{prefix}_count"))?.parse::<usize>()? {
        let chunk = field(capture, &format!("{prefix}_{index}"))?;
        wire.extend(unhex(
            chunk
                .split_once(",data_hex:")
                .ok_or("missing chunk bytes")?
                .1,
        )?);
    }
    let mut remaining = wire
        .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .ok_or("missing HTTP/2 preface")?;
    while !remaining.is_empty() {
        let header = remaining.get(..9).ok_or("short HTTP/2 frame header")?;
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let payload = remaining.get(9..9 + length).ok_or("short HTTP/2 frame")?;
        let frame_stream = u32::from_be_bytes(header[5..9].try_into()?);
        if header[3] == 1 && frame_stream == stream {
            assert_eq!(header[4] & 0x28, 0x20, "unpadded HEADERS priority");
            let dependency = u32::from_be_bytes(
                payload
                    .get(..4)
                    .ok_or("missing HEADERS dependency")?
                    .try_into()?,
            );
            return Ok(Http2Priority {
                dependency_stream_id: dependency & 0x7fff_ffff,
                weight: u16::from(*payload.get(4).ok_or("missing HEADERS weight")?) + 1,
                exclusive: dependency & 0x8000_0000 != 0,
            });
        }
        remaining = &remaining[9 + length..];
    }
    Err("missing completion HEADERS priority".into())
}

pub(crate) fn compare(selector: &str, captures: [&str; 3]) -> TestResult {
    let definition = profile(selector)?;
    let selected = definition.instantiate(&[])?;
    let hints = selected
        .client_hints()
        .ok_or("missing client hints")?
        .hints();
    let template = definition.request_template(RequestTemplateKind::FetchNoStore)?;
    template.validate()?;
    let protocols = [
        template.http1_fields.as_slice(),
        template.http2_fields.as_slice(),
        template
            .http3_fields
            .as_deref()
            .ok_or("missing HTTP/3 fields")?,
    ];
    for (index, (capture, fields)) in captures.into_iter().zip(protocols).enumerate() {
        assert_eq!(field(capture, "page_result")?, "resources:ok");
        let request = done_request(capture)?;
        assert!(request.contains(",method:GET,"));
        assert!(request.contains(",body_bytes:0,status:200,"));
        let expected = expected_fields(capture, request)?;
        let caller = expected
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("referer"))
            .cloned()
            .collect();
        assert_eq!(
            declared_fields(fields, hints, &caller)?,
            expected,
            "{selector}"
        );
        if index == 1 {
            assert_eq!(
                template.http2_priority,
                Some(Http2RequestPriority::Fixed(captured_priority(
                    capture, request
                )?))
            );
        }
    }
    Ok(())
}

#[test]
fn windows156_no_store_fetch_matches_all_three_protocol_captures() -> TestResult {
    compare("chrome-156-windows", super::CAPTURES)
}
