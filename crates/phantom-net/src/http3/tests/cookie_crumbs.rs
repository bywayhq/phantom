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
use phantom_profile::{
    Http3CookieCrumbs, Http3RequestSettings,
    browser::{chrome, firefox},
};

use super::TestResult;
use crate::request::{OriginForm, RequestHeader};

use crate::http3::request::{
    MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, prepare_profiled_request_body,
};
use crate::request::RequestBody;

const CHROME: &str = include_str!(
    "../../../../../fixtures/cookies/chrome/154.0.8037.58/windows-11-26200/crumbs-h3.txt"
);
const EDGE: &str = include_str!(
    "../../../../../fixtures/cookies/edge/154.0.4258.37/windows-11-26200/crumbs-h3.txt"
);
const BRAVE: &str = include_str!(
    "../../../../../fixtures/cookies/brave/154.1.96.59/windows-11-26200/crumbs-h3.txt"
);
const OPERA: &str = include_str!(
    "../../../../../fixtures/cookies/opera/136.0.6008.52/windows-11-26200/crumbs-h3.txt"
);
const FIREFOX: &str =
    include_str!("../../../../../fixtures/cookies/firefox/157.0/windows-11-26200/crumbs-h3.txt");
/// The capture server's `SETTINGS_QPACK_BLOCKED_STREAMS` (aioquic 1.3.0).
const CAPTURE_BLOCKED_STREAMS: usize = 16;

#[test]
fn chrome_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    assert_replay_matches(&Capture::parse(CHROME)?)
}

#[test]
fn edge_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    // Edge 154 replays against the Chromium recipes (`phantom_profile::browser::edge`).
    assert_replay_matches(&Capture::parse(EDGE)?)
}

#[test]
fn brave_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    // Brave 154 replays against the Chromium recipes (`phantom_profile::browser::brave`).
    assert_replay_matches(&Capture::parse(BRAVE)?)
}

#[test]
fn opera_cookie_crumbs_match_the_captured_qpack_bytes() -> TestResult<()> {
    // Opera 136 replays against the Chromium recipes (`phantom_profile::browser::opera`).
    assert_replay_matches(&Capture::parse(OPERA)?)
}

#[test]
fn firefox_cookie_fields_match_the_captured_qpack_bytes() -> TestResult<()> {
    // Firefox sends one joined `cookie` field and encodes with neqo's policy.
    let capture = Capture::parse(FIREFOX)?;
    let encoder = h3::qpack::Encoder::with_policy(
        h3::client::QpackInsertPolicy::UnmatchedNames,
        h3::client::QpackHuffman::Always,
    );
    assert_replay_matches_with(&capture, &firefox::v157_http3_request(), encoder)
}

#[test]
fn whole_cookie_setting_encodes_one_cookie_field() -> TestResult<()> {
    let capture = Capture::parse(CHROME)?;
    let mut settings = chrome::v154_http3_request();
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

#[test]
fn split_cookie_keeps_more_than_100_crumbs_in_place() -> TestResult<()> {
    let pairs = cookie_pairs(MAX_REQUEST_HEADERS + 1);
    let request = prepare_cookie_fields(
        vec![
            RequestHeader::new("x-before", "first"),
            RequestHeader::new("cookie", pairs.join("; ")),
            RequestHeader::new("x-after", "last"),
        ],
        None,
        Http3CookieCrumbs::Split,
    )?;
    let fields = request
        .extensions()
        .get::<h3::ext::OrderedHeaders>()
        .ok_or("prepared request omitted ordered fields")?
        .as_slice();
    assert_eq!(fields.len(), pairs.len() + 2);
    assert_eq!(fields[0].0, "x-before");
    assert_eq!(fields[0].1, "first");
    for ((name, value), expected) in fields[1..fields.len() - 1].iter().zip(pairs) {
        assert_eq!(name.as_str(), "cookie");
        assert_eq!(value.as_bytes(), expected.as_bytes());
    }
    assert_eq!(fields[fields.len() - 1].0, "x-after");
    assert_eq!(fields[fields.len() - 1].1, "last");
    Ok(())
}

#[test]
fn split_cookie_accepts_100_crumbs() -> TestResult<()> {
    let pairs = cookie_pairs(MAX_REQUEST_HEADERS);
    let request = prepare_cookie_fields(
        vec![RequestHeader::new("cookie", pairs.join("; "))],
        None,
        Http3CookieCrumbs::Split,
    )?;
    assert_eq!(request.headers().get_all("cookie").iter().count(), 100);
    Ok(())
}

#[test]
fn extended_connect_splits_more_than_100_cookie_pairs() -> TestResult<()> {
    let pairs = cookie_pairs(MAX_REQUEST_HEADERS + 1);
    let settings = extended_cookie_settings();
    for protocol in [h3::ext::Protocol::WEBSOCKET, h3::ext::Protocol::CONNECT_UDP] {
        let fields = vec![RequestHeader::new("cookie", pairs.join("; "))];
        let request = if protocol == h3::ext::Protocol::CONNECT_UDP {
            crate::http3::request::prepare_connect_udp(
                &settings,
                "example.test",
                OriginForm::parse("/")?,
                fields,
            )?
        } else {
            crate::http3::request::prepare_extended_connect(
                &settings,
                protocol,
                "example.test",
                OriginForm::parse("/")?,
                fields,
            )?
        };
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.extensions().get::<h3::ext::Protocol>(),
            Some(&protocol)
        );
        let observed = request
            .headers()
            .get_all("cookie")
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>();
        assert_eq!(observed.len(), pairs.len());
        for (observed, expected) in observed.iter().zip(&pairs) {
            assert_eq!(*observed, expected.as_bytes());
        }
        if protocol == h3::ext::Protocol::CONNECT_UDP {
            assert_eq!(request.headers()["capsule-protocol"], "?1");
        }
    }
    Ok(())
}

#[test]
fn generated_capsule_field_counts_toward_the_request_limit() -> TestResult<()> {
    let settings = extended_cookie_settings();
    let fields = (0..MAX_REQUEST_HEADERS - 1)
        .map(|_| RequestHeader::new("x-field", "v"))
        .collect::<Vec<_>>();
    let request = crate::http3::request::prepare_connect_udp(
        &settings,
        "example.test",
        OriginForm::parse("/")?,
        fields.clone(),
    )?;
    assert_eq!(request.headers().len(), MAX_REQUEST_HEADERS);
    assert_eq!(request.headers()["capsule-protocol"], "?1");
    let mut excessive = fields;
    excessive.push(RequestHeader::new("x-field", "v"));
    assert_request_limit(
        crate::http3::request::prepare_connect_udp(
            &settings,
            "example.test",
            OriginForm::parse("/")?,
            excessive,
        )
        .map_err(Into::into),
        "HTTP/3 request has too many headers",
    );
    Ok(())
}

fn extended_cookie_settings() -> Http3RequestSettings {
    use phantom_profile::Http3PseudoHeader;
    let mut settings = chrome::v154_http3_request();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
        Http3PseudoHeader::Protocol,
    ]);
    settings
}

#[test]
fn split_cookie_applies_the_byte_limit_before_repeating_its_name() -> TestResult<()> {
    let mut pairs = cookie_pairs(MAX_REQUEST_HEADERS);
    let padding = MAX_REQUEST_HEADER_BYTES - "cookie".len() - pairs.join("; ").len();
    pairs[MAX_REQUEST_HEADERS - 1].push_str(&"x".repeat(padding));
    let joined = pairs.join("; ");
    assert_eq!("cookie".len() + joined.len(), MAX_REQUEST_HEADER_BYTES);

    for crumbs in [Http3CookieCrumbs::Whole, Http3CookieCrumbs::Split] {
        let request =
            prepare_cookie_fields(vec![RequestHeader::new("cookie", &joined)], None, crumbs)?;
        let values = request.headers().get_all("cookie");
        if crumbs == Http3CookieCrumbs::Whole {
            assert_eq!(values.iter().count(), 1);
            assert_eq!(
                values.iter().next().map(|value| value.as_bytes()),
                Some(joined.as_bytes())
            );
        } else {
            assert_eq!(values.iter().count(), pairs.len());
            for (value, expected) in values.iter().zip(&pairs) {
                assert_eq!(value.as_bytes(), expected.as_bytes());
            }
            let emitted_bytes = request
                .headers()
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len())
                .sum::<usize>();
            assert!(emitted_bytes > MAX_REQUEST_HEADER_BYTES);
        }
        assert_request_limit(
            prepare_cookie_fields(
                vec![RequestHeader::new("cookie", format!("{joined}x"))],
                None,
                crumbs,
            ),
            "HTTP/3 request headers are too large",
        );
    }
    Ok(())
}

#[test]
fn supplied_header_count_keeps_its_exact_limit() -> TestResult<()> {
    for crumbs in [Http3CookieCrumbs::Whole, Http3CookieCrumbs::Split] {
        let fields = (0..MAX_REQUEST_HEADERS)
            .map(|_| RequestHeader::new("x-field", "v"))
            .collect::<Vec<_>>();
        assert_eq!(
            prepare_cookie_fields(fields.clone(), None, crumbs)?
                .headers()
                .len(),
            MAX_REQUEST_HEADERS
        );
        let mut excessive = fields;
        excessive.push(RequestHeader::new("x-field", "v"));
        assert_request_limit(
            prepare_cookie_fields(excessive, None, crumbs),
            "HTTP/3 request has too many headers",
        );
    }
    Ok(())
}

#[test]
fn generated_framing_fields_count_toward_request_limits() -> TestResult<()> {
    for wait in [None, Some(std::time::Duration::from_secs(1))] {
        let body = || {
            let body = RequestBody::from_bytes(Bytes::from_static(b"x"));
            Some(match wait {
                Some(wait) => body.expect_continue(wait),
                None => body,
            })
        };
        let generated = if wait.is_some() { 2 } else { 1 };
        let fields = (0..MAX_REQUEST_HEADERS - generated)
            .map(|_| RequestHeader::new("x-field", "v"))
            .collect::<Vec<_>>();
        let request = prepare_cookie_fields(fields.clone(), body(), Http3CookieCrumbs::Split)?;
        assert_eq!(request.headers().len(), MAX_REQUEST_HEADERS);
        assert_eq!(request.headers()["content-length"], "1");
        assert_eq!(request.headers().contains_key("expect"), wait.is_some());
        let mut excessive = fields;
        excessive.push(RequestHeader::new("x-field", "v"));
        assert_request_limit(
            prepare_cookie_fields(excessive, body(), Http3CookieCrumbs::Split),
            "HTTP/3 request has too many headers",
        );

        let framing_bytes = "content-length".len()
            + 1
            + if wait.is_some() {
                "expect".len() + "100-continue".len()
            } else {
                0
            };
        let value = "x".repeat(MAX_REQUEST_HEADER_BYTES - "x-long".len() - framing_bytes);
        prepare_cookie_fields(
            vec![RequestHeader::new("x-long", &value)],
            body(),
            Http3CookieCrumbs::Split,
        )?;
        assert_request_limit(
            prepare_cookie_fields(
                vec![RequestHeader::new("x-long", format!("{value}x"))],
                body(),
                Http3CookieCrumbs::Split,
            ),
            "HTTP/3 request headers are too large",
        );
    }
    Ok(())
}

fn cookie_pairs(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("k{index}=v{index}"))
        .collect()
}

fn prepare_cookie_fields(
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
    crumbs: Http3CookieCrumbs,
) -> TestResult<http::Request<()>> {
    let mut settings = chrome::v154_http3_request();
    settings.cookie_crumbs = crumbs;
    let prepared = prepare_profiled_request_body(
        &settings,
        http::Method::GET,
        "example.test",
        OriginForm::parse("/")?,
        headers,
        body,
    )?;
    Ok(prepared.into_parts().0)
}

fn assert_request_limit(result: TestResult<http::Request<()>>, expected: &str) {
    let Err(error) = result else {
        panic!("request exceeded its supplied-field limit");
    };
    assert_eq!(
        error
            .downcast_ref::<crate::http3::Http3Error>()
            .map(crate::http3::Http3Error::kind),
        Some(crate::http3::Http3ErrorKind::Request)
    );
    assert_eq!(error.to_string(), expected);
}

fn assert_replay_matches(capture: &Capture) -> TestResult<()> {
    assert_replay_matches_with(
        capture,
        &chrome::v154_http3_request(),
        h3::qpack::Encoder::default(),
    )
}

fn assert_replay_matches_with(
    capture: &Capture,
    settings: &Http3RequestSettings,
    mut encoder: h3::qpack::Encoder,
) -> TestResult<()> {
    let mut instructions = BytesMut::new();
    encoder.set_max_table_capacity(capture.max_table_capacity, &mut instructions)?;
    encoder.set_max_blocked_streams(CAPTURE_BLOCKED_STREAMS)?;
    for (index, request) in capture.requests.iter().enumerate() {
        let fields = encoder_input(settings, request)?;
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
