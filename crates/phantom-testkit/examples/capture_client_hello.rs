//! Captures one bounded TLS ClientHello from a loopback TCP listener.

use std::{
    env,
    error::Error,
    io::{self, Write as _},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello};
use tokio::{net::TcpListener, time::timeout};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);
const CAPTURE_LIMITS: CaptureLimits = CaptureLimits::new(128 * 1024, 128 * 1024, 16);

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let listener = TcpListener::bind(arguments.listen_address).await?;
    let local_address = listener.local_addr()?;
    if !local_address.ip().is_loopback() {
        return Err("capture listener must bind to a loopback address".into());
    }

    eprintln!("listening on {local_address} for one TLS ClientHello");
    let (mut stream, peer_address) = timeout(ACCEPT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| "timed out waiting for a connection")??;
    if !peer_address.ip().is_loopback() {
        return Err("capture connection did not originate on loopback".into());
    }

    let capture = capture_client_hello(
        &mut stream,
        tokio::time::Instant::now() + CAPTURE_TIMEOUT,
        CAPTURE_LIMITS,
    )
    .await?;
    let summary = capture.summary()?;
    let hostname = summary
        .server_name()
        .ok_or("captured ClientHello did not include an SNI hostname")?;
    let hostname = std::str::from_utf8(hostname)?;
    let captured_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut output = io::BufWriter::new(io::stdout().lock());
    writeln!(output, "format=phantom-client-hello-v2")?;
    writeln!(output, "captured_at_unix={captured_at}")?;
    writeln!(output, "browser={}", arguments.browser)?;
    writeln!(output, "browser_version={}", arguments.browser_version)?;
    writeln!(output, "operating_system={}", arguments.operating_system)?;
    writeln!(output, "hostname={hostname}")?;
    writeln!(output, "listen_address={local_address}")?;
    writeln!(output, "launch_mode={}", arguments.launch_mode)?;
    writeln!(output, "launch_arguments={}", arguments.launch_arguments)?;
    writeln!(output, "record_count={}", capture.records().len())?;
    for (index, record) in capture.records().iter().enumerate() {
        writeln!(output, "record_{index}_hex={}", hex(record.wire_bytes()))?;
    }
    write_summary(&mut output, &summary)?;
    output.flush()?;
    Ok(())
}

struct Arguments {
    listen_address: String,
    browser: String,
    browser_version: String,
    operating_system: String,
    launch_mode: String,
    launch_arguments: String,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let usage = concat!(
            "usage: capture_client_hello <loopback-address:port> <browser> ",
            "<browser-version> <operating-system> <launch-mode> <launch-arguments>"
        );
        let listen_address = values.next().ok_or(usage)?;
        let browser = values.next().ok_or(usage)?;
        let browser_version = values.next().ok_or(usage)?;
        let operating_system = values.next().ok_or(usage)?;
        let launch_mode = values.next().ok_or(usage)?;
        let launch_arguments = values.next().ok_or(usage)?;
        if values.next().is_some() {
            return Err(usage.into());
        }
        for (name, value) in [
            ("browser", &browser),
            ("browser-version", &browser_version),
            ("operating-system", &operating_system),
            ("launch-mode", &launch_mode),
        ] {
            validate_required_metadata(name, value)?;
        }
        validate_single_line("launch-arguments", &launch_arguments)?;
        Ok(Self {
            listen_address,
            browser,
            browser_version,
            operating_system,
            launch_mode,
            launch_arguments,
        })
    }
}

fn validate_required_metadata(name: &str, value: &str) -> Result<(), Box<dyn Error>> {
    validate_single_line(name, value)?;
    if value.is_empty() {
        return Err(format!("{name} must be nonempty").into());
    }
    Ok(())
}

fn validate_single_line(name: &str, value: &str) -> Result<(), Box<dyn Error>> {
    if value.contains(['\r', '\n']) {
        return Err(format!("{name} must fit on one fixture line").into());
    }
    Ok(())
}

fn write_summary(output: &mut impl io::Write, summary: &ClientHelloSummary) -> io::Result<()> {
    writeln!(output, "legacy_version={:#06x}", summary.legacy_version())?;
    writeln!(
        output,
        "cipher_suites={}",
        u16_list(summary.cipher_suites())
    )?;
    writeln!(
        output,
        "extension_types={}",
        u16_list(summary.extension_types())
    )?;
    writeln!(
        output,
        "supported_groups={}",
        u16_list(summary.supported_groups())
    )?;
    writeln!(
        output,
        "ec_point_formats={}",
        u8_list(summary.ec_point_formats())
    )?;
    writeln!(
        output,
        "signature_algorithms={}",
        u16_list(summary.signature_algorithms())
    )?;
    let alpn = summary
        .alpn_protocols()
        .iter()
        .map(|protocol| hex(protocol))
        .collect::<Vec<_>>()
        .join(",");
    writeln!(output, "alpn_protocols_hex={alpn}")?;
    writeln!(
        output,
        "supported_versions={}",
        u16_list(summary.supported_versions())
    )?;
    writeln!(
        output,
        "key_share_groups={}",
        u16_list(summary.key_share_groups())
    )?;
    writeln!(
        output,
        "server_name_hex={}",
        summary.server_name().map(hex).unwrap_or_default()
    )
}

fn u16_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("{value:#06x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn u8_list(values: &[u8]) -> String {
    values
        .iter()
        .map(|value| format!("{value:#04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::Arguments;

    fn arguments(launch_arguments: &str) -> impl Iterator<Item = String> {
        [
            "127.0.0.1:9443",
            "Example Browser",
            "1.2.3",
            "Example OS",
            "application",
            launch_arguments,
        ]
        .into_iter()
        .map(str::to_owned)
    }

    #[test]
    fn launch_arguments_may_be_empty() {
        let parsed = Arguments::parse(arguments(""));
        assert!(parsed.is_ok());
    }

    #[test]
    fn launch_arguments_must_fit_on_one_line() {
        for value in ["argument\rbreak", "argument\nbreak"] {
            assert!(Arguments::parse(arguments(value)).is_err());
        }
    }
}
