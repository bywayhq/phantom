//! Captures one bounded browser HTTP/2 startup sequence over loopback TLS.
//!
//! This vendor-neutral command targets the measured startup shape used by the
//! retained fixtures: initial SETTINGS followed by a connection WINDOW_UPDATE.
//! It times out when that connection WINDOW_UPDATE is absent.

#[path = "capture_http2_tls/fixture.rs"]
mod fixture;

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
use fixture::{Fixture, FrameSummary, hex, write_fixture};
use phantom_testkit::http2::{CaptureCompletion, CaptureLimits, capture_client_frames};
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

    eprintln!(
        "listening on {listen_address}; capture requires initial SETTINGS and a connection WINDOW_UPDATE"
    );
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
    // Retained startup fixtures deliberately require this measured frame shape.
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
            "<browser-version> <operating-system> <launch-mode> <launch-arguments>\n",
            "capture requires initial SETTINGS and a connection WINDOW_UPDATE"
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
        validate_required_metadata("browser", &browser)?;
        validate_required_metadata("browser-version", &browser_version)?;
        validate_required_metadata("operating-system", &operating_system)?;
        validate_required_metadata("launch-mode", &launch_mode)?;
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

fn validate_required_metadata(name: &str, value: &str) -> CaptureResult<()> {
    validate_single_line(name, value)?;
    if value.is_empty() {
        return Err(format!("{name} must be nonempty and fit on one fixture line").into());
    }
    Ok(())
}

fn validate_single_line(name: &str, value: &str) -> CaptureResult<()> {
    if value.contains(['\r', '\n']) {
        return Err(format!("{name} must fit on one fixture line").into());
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

#[cfg(test)]
mod tests {
    use super::Arguments;

    #[test]
    fn arguments_require_single_line_metadata_and_allow_no_launch_arguments() {
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

        let no_launch_arguments = Arguments::parse(
            [
                "127.0.0.1:9443",
                "Example Browser",
                "1.2.3",
                "Example OS",
                "application",
                "",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(no_launch_arguments.is_ok());

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
            vec![
                "127.0.0.1:9443",
                "Example Browser",
                "1.2.3",
                "Example OS",
                "application",
                "argument\rbreak",
            ],
        ] {
            assert!(Arguments::parse(values.into_iter().map(str::to_owned)).is_err());
        }
    }
}
