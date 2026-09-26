//! Replays the retained HTTP/3 cookie captures through the QPACK encoder.
//!
//! Each capture holds four requests on one connection: `/start` without
//! cookies, then `/page`, `/fetch`, and `/done` with five probe cookies
//! (`fixtures/cookies/<browser>/<version>/windows-11-26200/crumbs-h3.txt`).
//! The replay supplies each request's fields with the crumbs joined back into
//! one caller `cookie` field, encodes the four requests in order against the
//! capture server's QPACK limits, and acknowledges each field section as the
//! capture server's decoder did. The encoder stream and every field section
//! must equal the captured bytes.

use std::collections::BTreeMap;

use bytes::{Bytes, BytesMut};
use phantom_profile::{Http3CookieCrumbs, Http3RequestSettings, chromium};

use super::TestResult;
use crate::http3::{OriginForm, RequestHeader};

const CHROME: &str = include_str!(
    "../../../../../fixtures/cookies/chrome/154.0.8037.58/windows-11-26200/crumbs-h3.txt"
);
const EDGE: &str = include_str!(
    "../../../../../fixtures/cookies/edge/154.0.4258.37/windows-11-26200/crumbs-h3.txt"
);
/// The capture server's `SETTINGS_QPACK_BLOCKED_STREAMS` (aioquic 1.3.0).
const CAPTURE_BLOCKED_STREAMS: usize = 16;

#[test]
fn chrome_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    assert_replay_matches(&Capture::parse(CHROME)?)
}

#[test]
fn edge_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    // Edge 154 replays against the Chromium recipes (`phantom_profile::edge`).
    assert_replay_matches(&Capture::parse(EDGE)?)
}

#[test]
fn whole_cookie_setting_encodes_one_cookie_field() -> TestResult<()> {
    let capture = Capture::parse(CHROME)?;
    let mut settings = chromium::v154_http3_request();
    settings.cookie_crumbs = Http3CookieCrumbs::Whole;
    let page = &capture.requests[1];
    let fields = encoder_input(&settings, page)?;
    let cookies = fields
        .iter()
        .filter(|field| field.name.as_ref() == b"cookie")
        .map(|field| field.value.as_ref().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(cookies, [page.joined_cookie().into_bytes()]);
    Ok(())
}

fn assert_replay_matches(capture: &Capture) -> TestResult<()> {
    let settings = chromium::v154_http3_request();
    let mut encoder = h3::qpack::Encoder::default();
    let mut instructions = BytesMut::new();
    encoder.set_max_table_capacity(capture.max_table_capacity, &mut instructions)?;
    encoder.set_max_blocked_streams(CAPTURE_BLOCKED_STREAMS)?;
    for (index, request) in capture.requests.iter().enumerate() {
        let fields = encoder_input(&settings, request)?;
        let crumbs = fields
            .iter()
            .filter(|field| field.name.as_ref() == b"cookie")
            .count();
        assert_eq!(crumbs, request.crumb_count(), "request {index} crumbs");
        let mut section = BytesMut::new();
        encoder.encode(request.stream_id, &mut section, &mut instructions, fields)?;
        assert_eq!(
            section.as_ref(),
            request.field_section.as_slice(),
            "request {index} field section"
        );
        // Section Acknowledgment (RFC 9204 section 4.4.1) for the stream.
        let stream = u8::try_from(request.stream_id)?;
        if stream >= 0x80 {
            return Err("capture stream id needs a multi-byte acknowledgment".into());
        }
        encoder.on_decoder_recv(&mut Bytes::from(vec![0x80 | stream]))?;
    }
    assert_eq!(instructions.as_ref(), capture.encoder_instructions());
    Ok(())
}

/// Returns the encoder's input for one captured request, with its crumbs
/// joined into one caller `cookie` field at the first crumb's position.
fn encoder_input(
    settings: &Http3RequestSettings,
    request: &CapturedRequest,
) -> TestResult<Vec<h3::qpack::HeaderField>> {
    let value = |name: &str| {
        request
            .fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| format!("captured request has no {name}"))
    };
    let mut headers = Vec::new();
    let mut joined = false;
    for (name, field_value) in &request.fields {
        if name.starts_with(':') {
            continue;
        }
        if name == "cookie" {
            if !joined {
                headers.push(RequestHeader::new("cookie", request.joined_cookie()));
                joined = true;
            }
            continue;
        }
        headers.push(RequestHeader::new(name.clone(), field_value.clone()));
    }
    let prepared = crate::http3::request::prepare_get(
        settings,
        &value(":authority")?,
        OriginForm::parse(&value(":path")?)?,
        headers,
    )?;
    let (parts, ()) = prepared.into_parts();
    let header = h3::proto::headers::Header::request(
        parts.method,
        parts.uri,
        parts.headers,
        parts.extensions,
    )?;
    Ok(header.into_iter().collect())
}

struct CapturedRequest {
    stream_id: u64,
    field_section: Vec<u8>,
    /// Decoded fields in wire order, pseudo-fields first.
    fields: Vec<(String, String)>,
}

impl CapturedRequest {
    fn crumb_count(&self) -> usize {
        self.fields
            .iter()
            .filter(|(name, _)| name == "cookie")
            .count()
    }

    fn joined_cookie(&self) -> String {
        self.fields
            .iter()
            .filter(|(name, _)| name == "cookie")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Run 0 of one retained `phantom-cookie-crumbs-v1` HTTP/3 capture.
struct Capture {
    max_table_capacity: usize,
    encoder_stream: Vec<u8>,
    requests: Vec<CapturedRequest>,
}

impl Capture {
    fn parse(text: &'static str) -> TestResult<Self> {
        let values = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let value = |key: &str| {
            values
                .get(key)
                .copied()
                .ok_or_else(|| format!("capture omitted {key}"))
        };
        if value("format")? != "phantom-cookie-crumbs-v1" || value("scenario")? != "h3" {
            return Err("unexpected capture format or scenario".into());
        }
        let mut connection = None;
        let mut requests = Vec::new();
        for request in 0..value("run_0_request_count")?.parse::<usize>()? {
            let key = format!("run_0_request_{request}");
            let record = value(&key)?;
            let attribute = |name: &str| {
                record
                    .split(',')
                    .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                    .ok_or_else(|| format!("capture request omitted {name}"))
            };
            let this_connection = attribute("connection")?;
            if connection
                .replace(this_connection)
                .is_some_and(|c| c != this_connection)
            {
                return Err("capture run 0 spans more than one connection".into());
            }
            let mut fields = Vec::new();
            for field in 0..value(&format!("{key}_field_count"))?.parse::<usize>()? {
                let line = value(&format!("{key}_field_{field}"))?;
                let hex = |name: &str| -> TestResult<String> {
                    let encoded = line
                        .split(',')
                        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                        .ok_or_else(|| format!("capture field omitted {name}"))?;
                    Ok(String::from_utf8(decode_hex(encoded)?)?)
                };
                fields.push((hex("name_hex")?, hex("value_hex")?));
            }
            requests.push(CapturedRequest {
                stream_id: attribute("stream")?.parse()?,
                field_section: decode_hex(value(&format!("{key}_block_hex"))?)?,
                fields,
            });
        }
        let connection = connection.ok_or("capture run 0 holds no request")?;
        Ok(Self {
            max_table_capacity: value("server_qpack_max_table_capacity")?.parse()?,
            encoder_stream: decode_hex(value(&format!(
                "run_0_connection_{connection}_encoder_stream_hex"
            ))?)?,
            requests,
        })
    }

    /// Returns the captured encoder stream without its stream type byte.
    fn encoder_instructions(&self) -> &[u8] {
        self.encoder_stream.get(1..).unwrap_or_default()
    }
}

fn decode_hex(encoded: &str) -> TestResult<Vec<u8>> {
    (0..encoded.len())
        .step_by(2)
        .map(|index| {
            let pair = encoded
                .get(index..index + 2)
                .ok_or("capture hex has odd length")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}
