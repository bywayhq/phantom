//! Browser HTTP/2 fixture regressions.

#[path = "browser_http2_fixtures/chrome.rs"]
mod chrome;
#[path = "browser_http2_fixtures/firefox.rs"]
mod firefox;
#[path = "browser_http2_fixtures/fixture.rs"]
mod fixture;

use std::{error::Error, time::Duration};

use fixture::Fixture;
use phantom_testkit::http2::{CaptureCompletion, ClientFrameCapture, capture_client_frames};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);
type TestResult<T> = Result<T, Box<dyn Error>>;

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

async fn assert_raw_startup(fixture: &Fixture<'_>) -> TestResult<()> {
    let capture = capture_wire(fixture).await?;
    assert_eq!(capture.preface_bytes(), &fixture.preface);
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

#[test]
fn fixture_schema_rejects_unknown_duplicate_misordered_missing_and_misnumbered_keys() {
    let valid = chrome::FIXTURE_TEXT;
    let mut swapped = valid.lines().collect::<Vec<_>>();
    swapped.swap(1, 2);
    let swapped = swapped.join("\n");

    let duplicate = valid.replacen(
        "browser=Google Chrome",
        "browser=Google Chrome\nbrowser=Google Chrome",
        1,
    );
    let unknown = valid.replacen(
        "format=phantom-http2-tls-v2",
        "format=phantom-http2-tls-v2\nunknown=value",
        1,
    );
    let missing = valid
        .lines()
        .filter(|line| !line.starts_with("operating_system="))
        .collect::<Vec<_>>()
        .join("\n");
    let misnumbered = valid.replacen("frame_1_hex=", "frame_2_hex=", 1);

    for malformed in [&swapped, &duplicate, &unknown, &missing, &misnumbered] {
        assert!(Fixture::parse(malformed).is_err());
    }
}

#[test]
fn fixture_schema_allows_no_launch_arguments_but_rejects_multiline_values() {
    let valid = chrome::FIXTURE_TEXT;
    let without_arguments = replace_fixture_value(valid, "launch_arguments", "");
    assert!(Fixture::parse(&without_arguments).is_ok());

    for separator in ['\r', '\n'] {
        let multiline = replace_fixture_value(
            valid,
            "launch_arguments",
            &format!("first{separator}second"),
        );
        assert!(Fixture::parse(&multiline).is_err());
    }
}

fn replace_fixture_value(input: &str, field: &str, replacement: &str) -> String {
    let prefix = format!("{field}=");
    input
        .lines()
        .map(|line| {
            line.strip_prefix(&prefix)
                .map_or_else(|| line.to_owned(), |_| format!("{prefix}{replacement}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}
