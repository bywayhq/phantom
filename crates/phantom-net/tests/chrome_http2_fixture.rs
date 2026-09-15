//! Regressions for the retained local Chrome HTTP/2 startup fixture.

use std::{error::Error, io, net::SocketAddr, time::Duration};

use phantom_net::http2::{OriginForm, send_get};
use phantom_profile::chromium::v152_macos_http2;
use phantom_testkit::http2::{
    CLIENT_CONNECTION_PREFACE, CaptureCompletion, CaptureLimits, capture_client_frames,
};
use tokio::{io::duplex, time::timeout};

const FIXTURE: &str =
    include_str!("../../../fixtures/http2/chrome/152.0.7977.83/macos-15.5/client-startup.txt");
const CHROME_FLAGS: &str = "--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom";
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

type TestResult<T> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn chrome_fixture_parses_and_retains_initial_http2_semantics() -> TestResult<()> {
    let fixture = RetainedFixture::parse(FIXTURE)?;
    let capture = capture_wire(&fixture).await?;

    assert_eq!(capture.frames().len(), fixture.frames.len());
    for (captured, expected) in capture.frames().iter().zip(&fixture.frames) {
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
    assert_eq!(settings, fixture.initial_settings);

    let window_update = capture
        .frames()
        .iter()
        .find_map(|frame| frame.window_update().transpose())
        .transpose()?
        .ok_or("retained frames omit a WINDOW_UPDATE")?;
    assert_eq!(window_update.increment(), fixture.connection_window_update);
    Ok(())
}

#[tokio::test]
async fn phantom_chrome_startup_matches_retained_browser_frames_exactly() -> TestResult<()> {
    let fixture = RetainedFixture::parse(FIXTURE)?;
    let settings = v152_macos_http2();
    let target = OriginForm::parse("/")?;
    let (client, mut server) = duplex(64 * 1024);
    let transaction = tokio::spawn(async move {
        send_get(client, &settings, "server.phantom.test", target, vec![])
            .await
            .map(drop)
    });

    let capture = capture_client_frames(
        &mut server,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        fixture.limits,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    assert_eq!(capture.preface_bytes(), &fixture.preface);
    assert_eq!(capture.frames().len(), fixture.frames.len());
    for (actual, expected) in capture.frames().iter().zip(&fixture.frames) {
        assert_eq!(actual.wire_bytes(), expected);
    }

    drop(server);
    let client_result = timeout(TEST_TIMEOUT, transaction).await??;
    assert!(
        client_result.is_err(),
        "client unexpectedly received an HTTP/2 response"
    );
    Ok(())
}

#[test]
fn fixture_schema_rejects_unknown_duplicate_misordered_missing_and_misnumbered_keys() {
    let mut swapped = FIXTURE.lines().collect::<Vec<_>>();
    swapped.swap(1, 2);
    let swapped = swapped.join("\n");

    let duplicate = FIXTURE.replacen(
        "browser=Google Chrome 152.0.7977.83",
        "browser=Google Chrome 152.0.7977.83\nbrowser=Google Chrome 152.0.7977.83",
        1,
    );
    let unknown = FIXTURE.replacen(
        "format=phantom-http2-tls-v1",
        "format=phantom-http2-tls-v1\nunknown=value",
        1,
    );
    let missing = FIXTURE
        .lines()
        .filter(|line| !line.starts_with("operating_system="))
        .collect::<Vec<_>>()
        .join("\n");
    let misnumbered = FIXTURE.replacen("frame_1_hex=", "frame_2_hex=", 1);

    for malformed in [&swapped, &duplicate, &unknown, &missing, &misnumbered] {
        assert!(RetainedFixture::parse(malformed).is_err());
    }
}

async fn capture_wire(
    fixture: &RetainedFixture,
) -> Result<phantom_testkit::http2::ClientFrameCapture, phantom_testkit::http2::CaptureError> {
    let mut wire = fixture.preface.to_vec();
    for frame in &fixture.frames {
        wire.extend_from_slice(frame);
    }
    let mut input = wire.as_slice();
    capture_client_frames(
        &mut input,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        fixture.limits,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await
}

struct RetainedFixture {
    limits: CaptureLimits,
    preface: [u8; 24],
    frames: Vec<Vec<u8>>,
    initial_settings: String,
    connection_window_update: u32,
}

impl RetainedFixture {
    fn parse(input: &str) -> TestResult<Self> {
        let mut lines = FixtureLines::new(input);
        lines.exact("format", "phantom-http2-tls-v1")?;

        let captured_at_unix = lines.value("captured_at_unix")?.parse::<u64>()?;
        if captured_at_unix == 0 {
            return Err("captured_at_unix must be positive".into());
        }
        lines.exact("browser", "Google Chrome 152.0.7977.83")?;
        lines.exact("operating_system", "macOS 15.5 (24F74)")?;
        lines.exact("hostname", "server.phantom.test")?;

        let listen_address = lines.value("listen_address")?.parse::<SocketAddr>()?;
        if listen_address != "127.0.0.1:9444".parse()? || !listen_address.ip().is_loopback() {
            return Err(format!("unexpected fixture listen address {listen_address}").into());
        }
        lines.exact("listener_loopback", "true")?;
        lines.exact("peer_loopback", "true")?;
        lines.exact("connection_limit", "1")?;
        lines.exact("chrome_flags", CHROME_FLAGS)?;
        lines.exact("accept_timeout_ms", "30000")?;
        lines.exact("handshake_timeout_ms", "10000")?;
        lines.exact("frame_timeout_ms", "10000")?;

        let max_frame_payload_bytes = lines.value("max_frame_payload_bytes")?.parse()?;
        let max_total_frame_bytes = lines.value("max_total_frame_bytes")?.parse()?;
        let max_frames = lines.value("max_frames")?.parse()?;
        if (max_frame_payload_bytes, max_total_frame_bytes, max_frames) != (65_536, 131_072, 16) {
            return Err("unexpected HTTP/2 fixture limits".into());
        }
        let limits = CaptureLimits::new(max_frame_payload_bytes, max_total_frame_bytes, max_frames);

        let selected_alpn = decode_hex(lines.value("selected_alpn_hex")?)?;
        if selected_alpn != b"h2" {
            return Err(format!("unexpected selected ALPN {selected_alpn:?}").into());
        }
        let alps_state = lines.value("peer_alps_state")?;
        let alps_length = lines.value("peer_alps_length")?.parse::<usize>()?;
        let alps = decode_hex(lines.value("peer_alps_hex")?)?;
        if alps.len() != alps_length {
            return Err("peer ALPS length does not match its hex payload".into());
        }
        match alps_state {
            "absent" | "empty" if alps.is_empty() => {}
            "nonempty" if !alps.is_empty() => {}
            _ => return Err("peer ALPS state contradicts its payload".into()),
        }
        if alps_state != "empty" {
            return Err("retained Chrome peer ALPS state is not empty".into());
        }

        let preface = decode_hex(lines.value("preface_hex")?)?;
        let preface = <[u8; 24]>::try_from(preface.as_slice())
            .map_err(|_| "retained HTTP/2 preface is not 24 bytes")?;
        if preface != *CLIENT_CONNECTION_PREFACE {
            return Err("retained HTTP/2 preface is not exact".into());
        }

        let frame_count = lines.value("frame_count")?.parse::<usize>()?;
        if frame_count == 0 || frame_count > max_frames {
            return Err("fixture frame_count is outside its declared bounds".into());
        }
        let mut frames = Vec::with_capacity(frame_count);
        for index in 0..frame_count {
            frames.push(decode_hex(lines.value(&format!("frame_{index}_hex"))?)?);
        }

        let initial_settings = lines.value("initial_settings")?.to_owned();
        let connection_window_update = lines.value("connection_window_update")?.parse()?;
        lines.finish()?;
        Ok(Self {
            limits,
            preface,
            frames,
            initial_settings,
            connection_window_update,
        })
    }
}

struct FixtureLines<'a> {
    lines: std::iter::Enumerate<std::str::Lines<'a>>,
}

impl<'a> FixtureLines<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lines: input.lines().enumerate(),
        }
    }

    fn value(&mut self, expected_key: &str) -> TestResult<&'a str> {
        let (index, line) = self
            .lines
            .next()
            .ok_or_else(|| format!("fixture omitted ordered key {expected_key:?}"))?;
        let (actual_key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("fixture line {} has no '=' delimiter", index + 1))?;
        if actual_key != expected_key {
            return Err(format!(
                "fixture line {} has key {actual_key:?}; expected {expected_key:?}",
                index + 1
            )
            .into());
        }
        Ok(value)
    }

    fn exact(&mut self, key: &str, expected_value: &str) -> TestResult<()> {
        let actual = self.value(key)?;
        if actual != expected_value {
            return Err(format!(
                "fixture key {key:?} has value {actual:?}; expected {expected_value:?}"
            )
            .into());
        }
        Ok(())
    }

    fn finish(mut self) -> TestResult<()> {
        if let Some((index, line)) = self.lines.next() {
            return Err(format!(
                "fixture has unexpected trailing line {}: {line:?}",
                index + 1
            )
            .into());
        }
        Ok(())
    }
}

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
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

fn hex_digit(value: u8) -> TestResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_data(format!("invalid lowercase hex digit {value:#04x}")).into()),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
