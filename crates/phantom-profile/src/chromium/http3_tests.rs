use crate::{
    Http3PseudoHeader, Http3QpackDecoderStream, Http3QpackEncoderStream, Http3QpackEncoding,
    Http3QpackStreamOrder, Http3RequestSettings, Http3Setting, Http3SettingOrder, Http3Settings,
};

use super::{v154_http3, v154_http3_request};

const EDGE_153_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
);
const BRAVE_154_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/brave/154.1.96.59/windows-11-26200/client-startup.txt"
);
const BRAVE_154_DEVTOOLS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/brave/154.1.96.59/windows-11-26200/launch-mode/client-startup-devtools.txt"
);
const OPERA_135_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/opera/135.0.5973.92/windows-11-26200/client-startup.txt"
);
const V154_WINDOWS_FIXTURE: &str = include_str!(
    "../../../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt"
);

#[test]
fn chrome_154_http3_recipe_matches_windows_capture() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture_field(V154_WINDOWS_FIXTURE, "client")?,
        "Google Chrome"
    );
    assert_eq!(
        fixture_field(V154_WINDOWS_FIXTURE, "client_version")?,
        "154.0.8037.58"
    );
    assert_settings_match_control_stream(V154_WINDOWS_FIXTURE, v154_http3(), v154_http3_request())
}

/// Edge 153 shares the Chromium H3 control stream and request order; only
/// persona values differ.
#[test]
fn edge_153_h3_capture_matches_the_chromium_recipe() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture_field(EDGE_153_WINDOWS_FIXTURE, "client")?,
        "Microsoft Edge"
    );
    assert_eq!(
        fixture_field(EDGE_153_WINDOWS_FIXTURE, "client_version")?,
        "153.0.4234.48"
    );
    assert_settings_match_control_stream(
        EDGE_153_WINDOWS_FIXTURE,
        v154_http3(),
        v154_http3_request(),
    )?;
    assert_request_fields_match_except_persona(V154_WINDOWS_FIXTURE, EDGE_153_WINDOWS_FIXTURE)
}

/// Brave 154 shares the Chromium H3 control stream and pseudo-header order;
/// its request fields differ and are compared with the Brave navigation
/// template in the request-template tests.
#[test]
fn brave_154_h3_capture_matches_the_chromium_recipe() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(fixture_field(BRAVE_154_WINDOWS_FIXTURE, "client")?, "Brave");
    assert_eq!(
        fixture_field(BRAVE_154_WINDOWS_FIXTURE, "client_version")?,
        "154.1.96.59"
    );
    assert_settings_match_control_stream(
        BRAVE_154_WINDOWS_FIXTURE,
        v154_http3(),
        v154_http3_request(),
    )
}

/// A Brave H3 startup opened by a DevTools navigation, the launch Opera's
/// H3 fixture needed, sends the same control stream and request fields as a
/// command-line launch, apart from `:authority`.
#[test]
fn brave_154_devtools_launch_sends_the_command_line_h3_startup()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fixture_field(BRAVE_154_DEVTOOLS_FIXTURE, "launch_mode")?,
        "devtools-navigate"
    );
    assert_settings_match_control_stream(
        BRAVE_154_DEVTOOLS_FIXTURE,
        v154_http3(),
        v154_http3_request(),
    )?;
    let without_authority = |fixture| -> Result<Vec<_>, Box<dyn std::error::Error>> {
        Ok(request_fields(fixture)?
            .into_iter()
            .filter(|(name, _)| name != ":authority")
            .collect())
    };
    assert_eq!(
        without_authority(BRAVE_154_DEVTOOLS_FIXTURE)?,
        without_authority(BRAVE_154_WINDOWS_FIXTURE)?
    );
    Ok(())
}

/// Opera 135 shares the Chromium H3 control stream and request order; only
/// persona values differ.
#[test]
fn opera_135_h3_capture_matches_the_chromium_recipe() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(fixture_field(OPERA_135_WINDOWS_FIXTURE, "client")?, "Opera");
    assert_eq!(
        fixture_field(OPERA_135_WINDOWS_FIXTURE, "client_version")?,
        "135.0.5973.92"
    );
    assert_settings_match_control_stream(
        OPERA_135_WINDOWS_FIXTURE,
        v154_http3(),
        v154_http3_request(),
    )?;
    assert_request_fields_match_except_persona(V154_WINDOWS_FIXTURE, OPERA_135_WINDOWS_FIXTURE)
}

fn fixture_field<'a>(fixture: &'a str, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    let prefix = format!("{key}=");
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .ok_or_else(|| format!("fixture omitted {key}").into())
}

fn assert_request_fields_match_except_persona(
    reference: &str,
    candidate: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const PERSONA_FIELDS: [&str; 4] = [
        "user-agent",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    ];
    let macos = request_fields(reference)?;
    let windows = request_fields(candidate)?;
    assert_eq!(macos.len(), 17);
    assert_eq!(windows.len(), macos.len());
    for ((macos_name, macos_value), (windows_name, windows_value)) in macos.iter().zip(&windows) {
        assert_eq!(windows_name, macos_name);
        if windows_name == ":authority" || PERSONA_FIELDS.contains(&windows_name.as_str()) {
            continue;
        }
        assert_eq!(windows_value, macos_value, "{windows_name}");
    }
    Ok(())
}

fn request_fields(fixture: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let count: usize = fixture
        .lines()
        .find_map(|line| line.strip_prefix("request_header_count="))
        .ok_or("fixture must contain request_header_count")?
        .parse()?;
    (0..count)
        .map(|index| {
            let prefix = format!("request_header_{index}=");
            let (name, value) = fixture
                .lines()
                .find_map(|line| line.strip_prefix(prefix.as_str()))
                .and_then(|field| field.split_once(':'))
                .ok_or("fixture request header must contain a name and value")?;
            Ok((decode_ascii_hex(name)?, decode_ascii_hex(value)?))
        })
        .collect()
}

fn decode_ascii_hex(encoded: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<Vec<u8>, Box<dyn std::error::Error>>>()?;
    Ok(String::from_utf8(bytes)?)
}

fn assert_settings_match_control_stream(
    fixture: &str,
    profile: Http3Settings,
    request: Http3RequestSettings,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(profile.setting_order, Http3SettingOrder::Ascending);
    assert_eq!(profile.qpack_encoding, Http3QpackEncoding::Dynamic);
    assert_eq!(
        profile.qpack_decoder_stream,
        Http3QpackDecoderStream::OnFeedback
    );
    assert_eq!(
        request.pseudo_header_order,
        [
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Path,
        ]
    );
    assert_eq!(
        (0..4)
            .map(|index| fixture_request_name(fixture, index))
            .collect::<Result<Vec<_>, _>>()?,
        [":method", ":authority", ":scheme", ":path"]
    );
    assert_eq!(
        profile.initial_settings,
        [
            Http3Setting::QpackMaxTableCapacity(fixture_value(fixture, 0)),
            Http3Setting::MaxFieldSectionSize(fixture_value(fixture, 1)),
            Http3Setting::QpackBlockedStreams(fixture_value(fixture, 2)),
            Http3Setting::H3Datagram(fixture_value(fixture, 3) == 1),
            Http3Setting::RandomizedGrease,
        ]
    );
    Ok(())
}

fn fixture_request_name(fixture: &str, index: usize) -> Result<String, std::string::FromUtf8Error> {
    let prefix = format!("request_header_{index}=");
    let line = fixture
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    let encoded = line[prefix.len()..]
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or_else(|| panic!("fixture request header must contain a value"));
    let bytes = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .unwrap_or_else(|| panic!("fixture request header name must be valid hex"))
        })
        .collect();
    String::from_utf8(bytes)
}

fn fixture_value(fixture: &str, index: usize) -> u64 {
    let prefix = format!("setting_{index}=");
    let line = fixture
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    line.split(',')
        .find_map(|field| field.strip_prefix("value:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("fixture setting value must be an integer"))
}

#[test]
fn named_http3_recipes_leave_extended_connect_order_unset() {
    assert_eq!(
        v154_http3_request().extended_connect_pseudo_header_order,
        None
    );
}

const STREAM_FIXTURES: [&str; 4] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-streams-accept.txt"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/chrome/154.0.8037.58/windows-11-26200/resumption-streams-reject.txt"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/resumption-streams-accept.txt"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/resumption-streams-reject.txt"
    )),
];

/// In every captured Chrome 154 and Edge 153 connection, fresh or resumed,
/// the control stream (type 0x00) is client stream 2 and carries the first
/// unidirectional byte. The QPACK encoder stream (type 0x02) is stream 10, is
/// written exactly on the connections that carried a request, and its first
/// STREAM frame holds instructions after the type. The decoder stream (type
/// 0x03) is stream 6 and, when written at all, comes after the encoder
/// stream. The recipe opens the decoder stream first and defers both types.
#[test]
fn chromium_captures_open_qpack_streams_in_the_recipe_order()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = v154_http3();
    assert_eq!(
        profile.qpack_stream_order,
        Http3QpackStreamOrder::DecoderFirst
    );
    assert_eq!(
        profile.qpack_encoder_stream,
        Http3QpackEncoderStream::OnFirstInstruction
    );
    assert_eq!(
        profile.qpack_decoder_stream,
        Http3QpackDecoderStream::OnFeedback
    );

    let mut connections = 0;
    for fixture in STREAM_FIXTURES {
        let fields = fixture
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::HashMap<_, _>>();
        let mut requested = std::collections::HashSet::new();
        for (key, value) in &fields {
            if let Some(rest) = key.strip_prefix("run_")
                && let Some((run, request)) = rest.split_once("_request_")
                && request.parse::<usize>().is_ok()
            {
                let connection = value
                    .split(',')
                    .find_map(|field| field.strip_prefix("connection:"))
                    .ok_or("request line names no connection")?;
                requested.insert(format!("run_{run}_connection_{connection}"));
            }
        }
        for (key, order) in &fields {
            let Some(prefix) = key.strip_suffix("_unidirectional_streams") else {
                continue;
            };
            connections += 1;
            let order = order.split(',').collect::<Vec<_>>();
            let expected: &[&str] = match (requested.contains(prefix), order.len()) {
                (false, _) => &["2"],
                (true, 2) => &["2", "10"],
                (true, _) => &["2", "10", "6"],
            };
            assert_eq!(order, expected, "{prefix}");
            for stream in order {
                let record = fields
                    .get(format!("{prefix}_unidirectional_stream_{stream}").as_str())
                    .ok_or("stream record missing")?;
                let expected_type = match stream {
                    "2" => "type:0x00,",
                    "6" => "type:0x03,",
                    _ => "type:0x02,",
                };
                assert!(record.starts_with(expected_type), "{prefix} {stream}");
                let first_frame_bytes: usize = record
                    .split(',')
                    .find_map(|field| field.strip_prefix("first_frame_bytes:"))
                    .ok_or("first frame length missing")?
                    .parse()?;
                assert!(first_frame_bytes > 1, "{prefix} {stream}");
            }
        }
    }
    assert_eq!(connections, 69);
    Ok(())
}
