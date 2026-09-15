use std::{io, net::SocketAddr};

use phantom_testkit::http2::{ClientFrameCapture, Setting};

use super::{
    ACCEPT_TIMEOUT, CaptureResult, FRAME_MAX_COUNT, FRAME_MAX_PAYLOAD_BYTES, FRAME_MAX_TOTAL_BYTES,
    FRAME_TIMEOUT, HANDSHAKE_TIMEOUT, HOSTNAME,
};

pub(super) struct FrameSummary {
    initial_settings: String,
    connection_window_update: u32,
}

impl FrameSummary {
    pub(super) fn from_capture(capture: &ClientFrameCapture) -> CaptureResult<Self> {
        let first = capture
            .frames()
            .first()
            .ok_or_else(|| invalid_data("HTTP/2 capture contained no frames"))?;
        let settings = first
            .settings()?
            .ok_or_else(|| invalid_data("HTTP/2 capture did not begin with SETTINGS"))?;
        let initial_settings = settings
            .entries()
            .iter()
            .map(format_setting)
            .collect::<Vec<_>>()
            .join(",");

        let mut connection_window_update = None;
        for frame in capture.frames() {
            if frame.header().stream_id() != 0 {
                continue;
            }
            if let Some(update) = frame.window_update()? {
                connection_window_update = Some(update.increment());
                break;
            }
        }
        let connection_window_update = connection_window_update
            .ok_or_else(|| invalid_data("HTTP/2 capture omitted a connection WINDOW_UPDATE"))?;
        Ok(Self {
            initial_settings,
            connection_window_update,
        })
    }
}

fn format_setting(setting: &Setting) -> String {
    format!("{:#06x}:{}", setting.identifier(), setting.value())
}

pub(super) struct Fixture<'a> {
    pub(super) browser: &'a str,
    pub(super) browser_version: &'a str,
    pub(super) operating_system: &'a str,
    pub(super) launch_mode: &'a str,
    pub(super) launch_arguments: &'a str,
    pub(super) captured_at_unix: u64,
    pub(super) listen_address: SocketAddr,
    pub(super) selected_alpn: &'a [u8],
    pub(super) peer_alps: Option<&'a [u8]>,
    pub(super) frames: &'a ClientFrameCapture,
    pub(super) summary: FrameSummary,
}

pub(super) fn write_fixture(output: &mut impl io::Write, fixture: &Fixture<'_>) -> io::Result<()> {
    let (alps_state, alps_bytes) = alps_fields(fixture.peer_alps);

    writeln!(output, "format=phantom-http2-tls-v2")?;
    writeln!(output, "captured_at_unix={}", fixture.captured_at_unix)?;
    writeln!(output, "browser={}", fixture.browser)?;
    writeln!(output, "browser_version={}", fixture.browser_version)?;
    writeln!(output, "operating_system={}", fixture.operating_system)?;
    writeln!(output, "hostname={HOSTNAME}")?;
    writeln!(output, "listen_address={}", fixture.listen_address)?;
    writeln!(output, "listener_loopback=true")?;
    writeln!(output, "peer_loopback=true")?;
    writeln!(output, "connection_limit=1")?;
    writeln!(output, "launch_mode={}", fixture.launch_mode)?;
    writeln!(output, "launch_arguments={}", fixture.launch_arguments)?;
    writeln!(output, "accept_timeout_ms={}", ACCEPT_TIMEOUT.as_millis())?;
    writeln!(
        output,
        "handshake_timeout_ms={}",
        HANDSHAKE_TIMEOUT.as_millis()
    )?;
    writeln!(output, "frame_timeout_ms={}", FRAME_TIMEOUT.as_millis())?;
    writeln!(output, "max_frame_payload_bytes={FRAME_MAX_PAYLOAD_BYTES}")?;
    writeln!(output, "max_total_frame_bytes={FRAME_MAX_TOTAL_BYTES}")?;
    writeln!(output, "max_frames={FRAME_MAX_COUNT}")?;
    writeln!(output, "selected_alpn_hex={}", hex(fixture.selected_alpn))?;
    writeln!(output, "peer_alps_state={alps_state}")?;
    writeln!(output, "peer_alps_length={}", alps_bytes.len())?;
    writeln!(output, "peer_alps_hex={}", hex(alps_bytes))?;
    writeln!(
        output,
        "preface_hex={}",
        hex(fixture.frames.preface_bytes())
    )?;
    writeln!(output, "frame_count={}", fixture.frames.frames().len())?;
    for (index, frame) in fixture.frames.frames().iter().enumerate() {
        writeln!(output, "frame_{index}_hex={}", hex(frame.wire_bytes()))?;
    }
    writeln!(
        output,
        "initial_settings={}",
        fixture.summary.initial_settings
    )?;
    writeln!(
        output,
        "connection_window_update={}",
        fixture.summary.connection_window_update
    )
}

fn alps_fields(settings: Option<&[u8]>) -> (&'static str, &[u8]) {
    match settings {
        None => ("absent", &[][..]),
        Some([]) => ("empty", &[][..]),
        Some(bytes) => ("nonempty", bytes),
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::{alps_fields, hex};

    #[test]
    fn byte_values_use_unambiguous_lowercase_hex() {
        assert_eq!(hex(b"h2"), "6832");
        assert_eq!(hex(&[0, 0xaf, 0xff]), "00afff");
    }

    #[test]
    fn alps_metadata_distinguishes_absent_empty_and_nonempty() {
        assert_eq!(alps_fields(None), ("absent", &[][..]));
        assert_eq!(alps_fields(Some(&[])), ("empty", &[][..]));
        assert_eq!(
            alps_fields(Some(b"settings")),
            ("nonempty", &b"settings"[..])
        );
    }
}
