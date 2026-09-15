//! Regression for the retained local Chrome HTTP/2 startup fixture.

use std::{collections::BTreeMap, error::Error, io, time::Duration};

use phantom_testkit::http2::{CaptureCompletion, CaptureLimits, capture_client_frames};

const FIXTURE: &str =
    include_str!("../../../fixtures/http2/chrome/152.0.7977.83/macos-15.5/client-startup.txt");

#[tokio::test]
async fn chrome_fixture_parses_and_retains_initial_http2_semantics() -> Result<(), Box<dyn Error>> {
    let fields = parse_fields(FIXTURE)?;
    assert_eq!(required(&fields, "format")?, "phantom-http2-tls-v1");
    assert_eq!(required(&fields, "browser")?, "Google Chrome 152.0.7977.83");
    assert_eq!(required(&fields, "operating_system")?, "macOS 15.5 (24F74)");
    assert_eq!(required(&fields, "hostname")?, "server.phantom.test");
    assert_eq!(required(&fields, "selected_alpn_hex")?, "6832");
    assert_eq!(required(&fields, "peer_alps_state")?, "empty");
    assert_eq!(required(&fields, "peer_alps_length")?, "0");
    assert_eq!(required(&fields, "peer_alps_hex")?, "");

    let frame_count = required(&fields, "frame_count")?.parse::<usize>()?;
    let mut wire = decode_hex(required(&fields, "preface_hex")?)?;
    let mut expected_frames = Vec::with_capacity(frame_count);
    for index in 0..frame_count {
        let frame = decode_hex(required(&fields, &format!("frame_{index}_hex"))?)?;
        wire.extend_from_slice(&frame);
        expected_frames.push(frame);
    }

    let mut input = wire.as_slice();
    let capture = capture_client_frames(
        &mut input,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(
            required(&fields, "max_frame_payload_bytes")?.parse()?,
            required(&fields, "max_total_frame_bytes")?.parse()?,
            required(&fields, "max_frames")?.parse()?,
        ),
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    assert_eq!(capture.frames().len(), frame_count);
    for (captured, expected) in capture.frames().iter().zip(expected_frames) {
        assert_eq!(captured.wire_bytes(), expected);
    }

    let Some(settings) = capture.frames()[0].settings()? else {
        return Err("first retained frame is not SETTINGS".into());
    };
    let settings = settings
        .entries()
        .iter()
        .map(|setting| format!("{:#06x}:{}", setting.identifier(), setting.value()))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(settings, required(&fields, "initial_settings")?);

    let Some(window_update) = capture.frames()[1].window_update()? else {
        return Err("second retained frame is not WINDOW_UPDATE".into());
    };
    assert_eq!(
        window_update.increment().to_string(),
        required(&fields, "connection_window_update")?
    );
    Ok(())
}

fn parse_fields(input: &str) -> Result<BTreeMap<&str, &str>, Box<dyn Error>> {
    let mut fields = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("fixture line {} has no '=' delimiter", index + 1))?;
        if key.is_empty() {
            return Err(format!("fixture line {} has an empty key", index + 1).into());
        }
        if fields.insert(key, value).is_some() {
            return Err(format!("fixture key {key:?} occurs more than once").into());
        }
    }
    Ok(fields)
}

fn required<'a>(fields: &'a BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, Box<dyn Error>> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| format!("fixture omitted required key {key:?}").into())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err(invalid_data("hex value has an odd length").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| {
            let high = hex_digit(digits[0])?;
            let low = hex_digit(digits[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_data(format!("invalid lowercase hex digit {value:#04x}")).into()),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
