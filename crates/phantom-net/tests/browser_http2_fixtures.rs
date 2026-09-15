//! Browser HTTP/2 fixture regressions.

#[path = "browser_http2_fixtures/fixture.rs"]
mod fixture;

use std::{error::Error, time::Duration};

use fixture::Fixture;
use phantom_net::http2::{Http2Error, OriginForm, send_get};
use phantom_profile::chromium::v152_macos_http2;
use phantom_testkit::http2::{CaptureCompletion, ClientFrameCapture, capture_client_frames};
use tokio::{io::duplex, time::timeout};

const CHROME_152: &str =
    include_str!("../../../fixtures/http2/chrome/152.0.7977.83/macos-15.5/client-startup.txt");
const EXPECTED_LAUNCH_ARGUMENTS: &str = "--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom";
const TEST_TIMEOUT: Duration = Duration::from_secs(2);

type TestResult<T> = Result<T, Box<dyn Error>>;

#[tokio::test]
async fn chrome_fixture_parses_and_retains_initial_http2_semantics() -> TestResult<()> {
    let fixture = Fixture::parse(CHROME_152)?;
    assert_chrome_152_metadata(&fixture)?;
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
    let fixture = Fixture::parse(CHROME_152)?;
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

    assert!(
        !transaction.is_finished(),
        "client completed before the captured peer was closed"
    );
    drop(server);
    let client_result = timeout(TEST_TIMEOUT, transaction).await??;
    assert!(matches!(client_result, Err(Http2Error::Protocol(_))));
    Ok(())
}

#[test]
fn fixture_schema_rejects_unknown_duplicate_misordered_missing_and_misnumbered_keys() {
    let mut swapped = CHROME_152.lines().collect::<Vec<_>>();
    swapped.swap(1, 2);
    let swapped = swapped.join("\n");

    let duplicate = CHROME_152.replacen(
        "browser=Google Chrome",
        "browser=Google Chrome\nbrowser=Google Chrome",
        1,
    );
    let unknown = CHROME_152.replacen(
        "format=phantom-http2-tls-v2",
        "format=phantom-http2-tls-v2\nunknown=value",
        1,
    );
    let missing = CHROME_152
        .lines()
        .filter(|line| !line.starts_with("operating_system="))
        .collect::<Vec<_>>()
        .join("\n");
    let misnumbered = CHROME_152.replacen("frame_1_hex=", "frame_2_hex=", 1);

    for malformed in [&swapped, &duplicate, &unknown, &missing, &misnumbered] {
        assert!(Fixture::parse(malformed).is_err());
    }
}

fn assert_chrome_152_metadata(fixture: &Fixture<'_>) -> TestResult<()> {
    assert_eq!(fixture.browser, "Google Chrome");
    assert_eq!(fixture.browser_version, "152.0.7977.83");
    assert_eq!(fixture.operating_system, "macOS 15.5 (24F74)");
    assert_eq!(fixture.listen_address, "127.0.0.1:9444".parse()?);
    assert_eq!(fixture.launch_mode, "command-line");
    assert_eq!(fixture.launch_arguments, EXPECTED_LAUNCH_ARGUMENTS);
    assert_eq!(fixture.peer_alps_state, "empty");
    Ok(())
}

async fn capture_wire(
    fixture: &Fixture<'_>,
) -> Result<ClientFrameCapture, phantom_testkit::http2::CaptureError> {
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
