//! Captures one bounded browser HTTP/2 startup sequence over loopback TLS.

use std::{
    env,
    error::Error,
    io::{self, Write as _},
    net::SocketAddr,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, NameType, Ssl, SslAcceptor, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use phantom_testkit::http2::{
    CaptureCompletion, CaptureLimits, ClientFrameCapture, Setting, capture_client_frames,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use tokio::{net::TcpListener, time::timeout_at};
use tokio_btls::SslStream;

const HOSTNAME: &str = "server.phantom.test";
const H2: &[u8] = b"h2";
const H2_ALPN_WIRE: &[u8] = b"\x02h2";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const FRAME_MAX_TOTAL_BYTES: usize = 128 * 1024;
const FRAME_MAX_COUNT: usize = 16;
const FRAME_LIMITS: CaptureLimits = CaptureLimits::new(
    FRAME_MAX_PAYLOAD_BYTES,
    FRAME_MAX_TOTAL_BYTES,
    FRAME_MAX_COUNT,
);
type CaptureResult<T> = Result<T, Box<dyn Error>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> CaptureResult<()> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let listener = TcpListener::bind(arguments.listen_address).await?;
    let listen_address = listener.local_addr()?;
    require_loopback(listen_address, "listener")?;

    eprintln!("listening on {listen_address} for one browser HTTP/2 connection");
    let accept_deadline = tokio::time::Instant::now() + ACCEPT_TIMEOUT;
    let (tcp, peer_address) = timeout_at(accept_deadline, listener.accept())
        .await
        .map_err(|_| timeout_error("accept", ACCEPT_TIMEOUT))??;
    require_loopback(peer_address, "peer")?;
    drop(listener);

    let acceptor = tls_acceptor()?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.add_application_settings_with_payload(H2, &[])?;
    ssl.set_alps_use_new_codepoint(true);
    let mut tls = SslStream::new(ssl, tcp)?;
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    timeout_at(handshake_deadline, Pin::new(&mut tls).accept())
        .await
        .map_err(|_| timeout_error("TLS handshake", HANDSHAKE_TIMEOUT))??;

    let selected_alpn = tls
        .ssl()
        .selected_alpn_protocol()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid_data("browser did not negotiate an ALPN protocol"))?;
    if selected_alpn != H2 {
        return Err(invalid_data(format!(
            "browser negotiated ALPN {}, expected h2",
            hex(&selected_alpn)
        ))
        .into());
    }
    let server_name = tls
        .ssl()
        .servername(NameType::HOST_NAME)
        .ok_or_else(|| invalid_data("browser did not send an SNI hostname"))?;
    if server_name != HOSTNAME {
        return Err(invalid_data(format!(
            "browser sent SNI {server_name:?}, expected {HOSTNAME:?}"
        ))
        .into());
    }
    let peer_alps = tls.ssl().peer_application_settings().map(ToOwned::to_owned);

    let frame_deadline = tokio::time::Instant::now() + FRAME_TIMEOUT;
    let frames = capture_client_frames(
        &mut tls,
        frame_deadline,
        FRAME_LIMITS,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    let summary = FrameSummary::from_capture(&frames)?;
    let captured_at_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let fixture = Fixture {
        browser: &arguments.browser,
        browser_version: &arguments.browser_version,
        operating_system: &arguments.operating_system,
        launch_mode: &arguments.launch_mode,
        launch_arguments: &arguments.launch_arguments,
        captured_at_unix,
        listen_address,
        selected_alpn: &selected_alpn,
        peer_alps: peer_alps.as_deref(),
        frames: &frames,
        summary,
    };
    let mut output = io::BufWriter::new(io::stdout().lock());
    write_fixture(&mut output, &fixture)?;
    output.flush()?;
    Ok(())
}

struct Arguments {
    listen_address: SocketAddr,
    browser: String,
    browser_version: String,
    operating_system: String,
    launch_mode: String,
    launch_arguments: String,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> CaptureResult<Self> {
        let usage = concat!(
            "usage: capture_http2_tls <loopback-address:port> <browser> ",
            "<browser-version> <operating-system> <launch-mode> <launch-arguments>"
        );
        let listen_address = values.next().ok_or(usage)?.parse()?;
        let browser = values.next().ok_or(usage)?;
        let browser_version = values.next().ok_or(usage)?;
        let operating_system = values.next().ok_or(usage)?;
        let launch_mode = values.next().ok_or(usage)?;
        let launch_arguments = values.next().ok_or(usage)?;
        if values.next().is_some() {
            return Err(usage.into());
        }
        validate_metadata("browser", &browser)?;
        validate_metadata("browser-version", &browser_version)?;
        validate_metadata("operating-system", &operating_system)?;
        validate_metadata("launch-mode", &launch_mode)?;
        validate_metadata("launch-arguments", &launch_arguments)?;
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

fn validate_metadata(name: &str, value: &str) -> CaptureResult<()> {
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name} must be nonempty and fit on one fixture line").into());
    }
    Ok(())
}

fn tls_acceptor() -> CaptureResult<SslAcceptor> {
    let mut parameters = CertificateParams::new(vec![HOSTNAME.to_owned()])?;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = parameters.self_signed(&key)?;

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let certificate = X509::from_der(certificate.der())?;
    let private_key = PKey::private_key_from_pkcs8(&key.serialize_der())?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_certificate(&certificate)?;
    acceptor.set_private_key(&private_key)?;
    acceptor.check_private_key()?;
    acceptor.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

fn require_loopback(address: SocketAddr, role: &str) -> CaptureResult<()> {
    if !address.ip().is_loopback() {
        return Err(format!("capture {role} must be loopback, received {address}").into());
    }
    Ok(())
}

fn timeout_error(stage: &str, duration: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{stage} exceeded its {} ms deadline", duration.as_millis()),
    )
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct FrameSummary {
    initial_settings: String,
    connection_window_update: u32,
}

impl FrameSummary {
    fn from_capture(capture: &ClientFrameCapture) -> CaptureResult<Self> {
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

struct Fixture<'a> {
    browser: &'a str,
    browser_version: &'a str,
    operating_system: &'a str,
    launch_mode: &'a str,
    launch_arguments: &'a str,
    captured_at_unix: u64,
    listen_address: SocketAddr,
    selected_alpn: &'a [u8],
    peer_alps: Option<&'a [u8]>,
    frames: &'a ClientFrameCapture,
    summary: FrameSummary,
}

fn write_fixture(output: &mut impl io::Write, fixture: &Fixture<'_>) -> io::Result<()> {
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
    use super::{Arguments, H2, alps_fields, hex};

    #[test]
    fn arguments_require_explicit_single_line_metadata() {
        let valid = Arguments::parse(
            [
                "127.0.0.1:9443",
                "Example Browser",
                "1.2.3",
                "Example OS",
                "command-line",
                "--isolated-profile=<temporary-directory>",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(valid.is_ok());

        for values in [
            vec![
                "127.0.0.1:9443",
                "",
                "1.2.3",
                "Example OS",
                "command-line",
                "--isolated-profile=<temporary-directory>",
            ],
            vec![
                "127.0.0.1:9443",
                "Example Browser",
                "1.2.3",
                "Example\nOS",
                "command-line",
                "--isolated-profile=<temporary-directory>",
            ],
        ] {
            assert!(Arguments::parse(values.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn byte_values_use_unambiguous_lowercase_hex() {
        assert_eq!(hex(H2), "6832");
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
