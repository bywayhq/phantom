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
    let address = env::args()
        .nth(1)
        .ok_or("usage: capture_client_hello <loopback-address:port>")?;
    let listener = TcpListener::bind(&address).await?;
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
    let captured_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut output = io::BufWriter::new(io::stdout().lock());
    writeln!(output, "format=phantom-client-hello-v1")?;
    writeln!(output, "captured_at_unix={captured_at}")?;
    writeln!(output, "listen_address={local_address}")?;
    writeln!(output, "record_count={}", capture.records().len())?;
    for (index, record) in capture.records().iter().enumerate() {
        writeln!(output, "record_{index}_hex={}", hex(record.wire_bytes()))?;
    }
    write_summary(&mut output, &summary)?;
    output.flush()?;
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
