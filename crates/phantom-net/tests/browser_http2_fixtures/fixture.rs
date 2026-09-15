use std::{error::Error, io, net::SocketAddr};

use phantom_testkit::http2::{CLIENT_CONNECTION_PREFACE, CaptureLimits};

type FixtureResult<T> = Result<T, Box<dyn Error>>;

pub(super) struct Fixture<'a> {
    pub(super) browser: &'a str,
    pub(super) browser_version: &'a str,
    pub(super) operating_system: &'a str,
    pub(super) launch_mode: &'a str,
    pub(super) launch_arguments: &'a str,
    pub(super) listen_address: SocketAddr,
    pub(super) peer_alps_state: &'a str,
    pub(super) limits: CaptureLimits,
    pub(super) preface: [u8; 24],
    pub(super) frames: Vec<Vec<u8>>,
    pub(super) initial_settings: &'a str,
    pub(super) connection_window_update: u32,
}

impl<'a> Fixture<'a> {
    pub(super) fn parse(input: &'a str) -> FixtureResult<Self> {
        let mut lines = FixtureLines::new(input);
        lines.exact("format", "phantom-http2-tls-v2")?;

        let captured_at_unix = lines.value("captured_at_unix")?.parse::<u64>()?;
        if captured_at_unix == 0 {
            return Err("captured_at_unix must be positive".into());
        }
        let browser = lines.nonempty("browser")?;
        let browser_version = lines.nonempty("browser_version")?;
        let operating_system = lines.nonempty("operating_system")?;
        lines.exact("hostname", "server.phantom.test")?;

        let listen_address = lines.value("listen_address")?.parse::<SocketAddr>()?;
        if !listen_address.ip().is_loopback() {
            return Err(format!("fixture listen address is not loopback: {listen_address}").into());
        }
        lines.exact("listener_loopback", "true")?;
        lines.exact("peer_loopback", "true")?;
        lines.exact("connection_limit", "1")?;
        let launch_mode = lines.nonempty("launch_mode")?;
        let launch_arguments = lines.nonempty("launch_arguments")?;
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
        let peer_alps_state = lines.value("peer_alps_state")?;
        let alps_length = lines.value("peer_alps_length")?.parse::<usize>()?;
        let alps = decode_hex(lines.value("peer_alps_hex")?)?;
        if alps.len() != alps_length {
            return Err("peer ALPS length does not match its hex payload".into());
        }
        match peer_alps_state {
            "absent" | "empty" if alps.is_empty() => {}
            "nonempty" if !alps.is_empty() => {}
            _ => return Err("peer ALPS state contradicts its payload".into()),
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

        let initial_settings = lines.nonempty("initial_settings")?;
        let connection_window_update = lines.value("connection_window_update")?.parse()?;
        lines.finish()?;
        Ok(Self {
            browser,
            browser_version,
            operating_system,
            launch_mode,
            launch_arguments,
            listen_address,
            peer_alps_state,
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

    fn value(&mut self, expected_key: &str) -> FixtureResult<&'a str> {
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

    fn nonempty(&mut self, key: &str) -> FixtureResult<&'a str> {
        let value = self.value(key)?;
        if value.is_empty() {
            return Err(format!("fixture key {key:?} must be nonempty").into());
        }
        Ok(value)
    }

    fn exact(&mut self, key: &str, expected_value: &str) -> FixtureResult<()> {
        let actual = self.value(key)?;
        if actual != expected_value {
            return Err(format!(
                "fixture key {key:?} has value {actual:?}; expected {expected_value:?}"
            )
            .into());
        }
        Ok(())
    }

    fn finish(mut self) -> FixtureResult<()> {
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

fn decode_hex(value: &str) -> FixtureResult<Vec<u8>> {
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

fn hex_digit(value: u8) -> FixtureResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_data(format!("invalid lowercase hex digit {value:#04x}")).into()),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
