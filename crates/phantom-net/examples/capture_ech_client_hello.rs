//! Records a browser's ClientHellos against a loopback origin that decrypts
//! Encrypted Client Hello, with the origin's HTTPS record served by a
//! loopback DNS-over-HTTPS server.
//!
//! The origin serves `https://server.phantom.test/` on a loopback address.
//! The DNS-over-HTTPS server answers that name's A query with the origin's
//! address, its AAAA query with no records, and its HTTPS query with one
//! ServiceMode record whose `ech` value names `public.phantom.test`. Every
//! other name is answered with NXDOMAIN. In the `accept` scenario the origin
//! holds the published key; in `reject` it holds another key, so the browser
//! sees a rejection with retry configurations and connects again.
//!
//! Standard error gets one `ready doh_template=<url> origin=<address>` line
//! once both listeners are bound. Standard output gets the fixture after the
//! page request has been answered and no connection has arrived for the
//! grace period.

use std::{
    env,
    error::Error,
    io::{self, Write as _},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use btls::{
    hpke::HpkeKey,
    pkey::PKey,
    ssl::{
        AlpnError, NameType, Ssl, SslAcceptor, SslEchKeys, SslMethod, SslVersion, select_next_proto,
    },
    x509::X509,
};
use phantom_testkit::tls::{
    CaptureLimits, EchOuterExtension, TEST_ECH_KEYS, capture_client_hello, ech_config,
    ech_config_list,
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

const HOSTNAME: &str = "server.phantom.test";
const PUBLIC_NAME: &str = "public.phantom.test";
const HTTP1_ALPN_WIRE: &[u8] = b"\x08http/1.1";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);
const GRACE_PERIOD: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 8;
const MAX_REQUEST_HEAD: usize = 64 * 1024;
const CAPTURE_LIMITS: CaptureLimits = CaptureLimits::new(128 * 1024, 128 * 1024, 16);
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_HTTPS: u16 = 65;
const DNS_TTL: u32 = 60;

type CaptureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> CaptureResult<()> {
    let arguments = Arguments::parse(env::args().skip(1))?;
    let identity = Identity::generate()?;
    let published = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let published_list = ech_config_list(std::slice::from_ref(&published));
    let (server_config, server_key) = match arguments.scenario {
        Scenario::Accept => (published.clone(), &TEST_ECH_KEYS[0]),
        Scenario::Reject => (
            ech_config(2, &TEST_ECH_KEYS[1], PUBLIC_NAME),
            &TEST_ECH_KEYS[1],
        ),
    };

    let origin = TcpListener::bind(arguments.origin).await?;
    let origin_address = origin.local_addr()?;
    require_loopback(origin_address.ip(), "origin listener")?;
    let doh = TcpListener::bind((origin_address.ip(), 0)).await?;
    let doh_address = doh.local_addr()?;
    let doh_template = format!("https://{doh_address}/dns-query");

    let queries = Arc::new(Mutex::new(Vec::new()));
    let doh_acceptor = identity.acceptor(None)?;
    let doh_task = tokio::spawn(serve_doh(
        doh,
        doh_acceptor,
        Arc::clone(&queries),
        DnsAnswers {
            address: origin_address.ip(),
            port: origin_address.port(),
            ech_config_list: published_list.clone(),
        },
    ));

    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &server_config,
        HpkeKey::dhkem_p256_sha256(&server_key.private_key)?,
    )?;
    let keys = keys.build();
    let origin_acceptor = identity.acceptor(Some(&keys))?;

    eprintln!("ready doh_template={doh_template} origin={origin_address}");
    let mut connections = Vec::new();
    let mut page_served = false;
    while connections.len() < MAX_CONNECTIONS {
        let wait = if page_served {
            GRACE_PERIOD
        } else {
            ACCEPT_TIMEOUT
        };
        let Ok(accepted) = timeout(wait, origin.accept()).await else {
            break;
        };
        let (tcp, peer) = accepted?;
        require_loopback(peer.ip(), "origin peer")?;
        let connection = record_connection(tcp, &origin_acceptor).await?;
        page_served |= connection.request_served;
        connections.push(connection);
    }
    doh_task.abort();
    let queries = queries
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if !page_served {
        return Err(format!(
            "no page request completed after {} DNS-over-HTTPS queries and {} connections",
            queries.len(),
            connections.len()
        )
        .into());
    }
    let captured_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut output = io::BufWriter::new(io::stdout().lock());
    writeln!(output, "format=phantom-ech-client-hello-v1")?;
    writeln!(output, "captured_at_unix={captured_at}")?;
    writeln!(output, "browser={}", arguments.browser)?;
    writeln!(output, "browser_version={}", arguments.browser_version)?;
    writeln!(output, "operating_system={}", arguments.operating_system)?;
    writeln!(output, "scenario={}", arguments.scenario.name())?;
    writeln!(output, "hostname={HOSTNAME}")?;
    writeln!(output, "public_name={PUBLIC_NAME}")?;
    writeln!(output, "listen_address={origin_address}")?;
    writeln!(output, "doh_template={doh_template}")?;
    writeln!(output, "dns_configuration={}", arguments.dns_configuration)?;
    writeln!(output, "launch_mode={}", arguments.launch_mode)?;
    writeln!(output, "launch_arguments={}", arguments.launch_arguments)?;
    writeln!(output, "dns_ech_config_list_hex={}", hex(&published_list))?;
    writeln!(output, "server_ech_config_hex={}", hex(&server_config))?;
    // Only lookups of the test origin are recorded; the rest are the fresh
    // profile's background requests, which get NXDOMAIN.
    let (origin_queries, other_queries): (Vec<_>, Vec<_>) =
        queries.iter().partition(|query| query.ends_with(HOSTNAME));
    writeln!(output, "dns_other_query_count={}", other_queries.len())?;
    writeln!(output, "dns_query_count={}", origin_queries.len())?;
    for (index, query) in origin_queries.iter().enumerate() {
        writeln!(output, "dns_query_{index}={query}")?;
    }
    writeln!(output, "connection_count={}", connections.len())?;
    for (index, connection) in connections.iter().enumerate() {
        connection.write(&mut output, index)?;
    }
    output.flush()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Scenario {
    Accept,
    Reject,
}

impl Scenario {
    const fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
        }
    }
}

struct Arguments {
    scenario: Scenario,
    origin: SocketAddr,
    browser: String,
    browser_version: String,
    operating_system: String,
    dns_configuration: String,
    launch_mode: String,
    launch_arguments: String,
}

impl Arguments {
    fn parse(mut values: impl Iterator<Item = String>) -> CaptureResult<Self> {
        let usage = concat!(
            "usage: capture_ech_client_hello <accept|reject> <loopback-address:port> ",
            "<browser> <browser-version> <operating-system> <dns-configuration> <launch-mode> ",
            "<launch-arguments>"
        );
        let scenario = match values.next().ok_or(usage)?.as_str() {
            "accept" => Scenario::Accept,
            "reject" => Scenario::Reject,
            _ => return Err(usage.into()),
        };
        let origin = values.next().ok_or(usage)?.parse::<SocketAddr>()?;
        let mut text = || values.next().ok_or(usage);
        let parsed = Self {
            scenario,
            origin,
            browser: text()?,
            browser_version: text()?,
            operating_system: text()?,
            dns_configuration: text()?,
            launch_mode: text()?,
            launch_arguments: text()?,
        };
        if values.next().is_some() {
            return Err(usage.into());
        }
        for value in [
            &parsed.browser,
            &parsed.browser_version,
            &parsed.operating_system,
            &parsed.dns_configuration,
            &parsed.launch_mode,
            &parsed.launch_arguments,
        ] {
            if value.contains(['\r', '\n']) {
                return Err("every argument must fit on one fixture line".into());
            }
        }
        Ok(parsed)
    }
}

struct Identity {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

impl Identity {
    fn generate() -> CaptureResult<Self> {
        let mut params = CertificateParams::new(vec![
            HOSTNAME.to_owned(),
            PUBLIC_NAME.to_owned(),
            "127.0.0.1".to_owned(),
        ])?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate()?;
        let certificate = params.self_signed(&key)?;
        Ok(Self {
            certificate: certificate.der().to_vec(),
            private_key: key.serialize_der(),
        })
    }

    fn acceptor(&self, ech_keys: Option<&SslEchKeys>) -> CaptureResult<SslAcceptor> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(&self.certificate)?;
        builder.set_certificate(&certificate)?;
        let private_key = PKey::private_key_from_pkcs8(&self.private_key)?;
        builder.set_private_key(&private_key)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_alpn_select_callback(|_, offered| {
            select_next_proto(HTTP1_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
        });
        if let Some(keys) = ech_keys {
            builder.set_ech_keys(keys)?;
        }
        Ok(builder.build())
    }
}

struct Connection {
    records: Vec<Vec<u8>>,
    outer_server_name: Option<Vec<u8>>,
    extension_types: Vec<u16>,
    ech: Option<Vec<u8>>,
    handshake: Result<(), String>,
    ech_accepted: bool,
    inner_server_name: Option<String>,
    request_served: bool,
}

impl Connection {
    fn write(&self, output: &mut impl io::Write, index: usize) -> io::Result<()> {
        let prefix = format!("connection_{index}");
        writeln!(output, "{prefix}_record_count={}", self.records.len())?;
        for (record, bytes) in self.records.iter().enumerate() {
            writeln!(output, "{prefix}_record_{record}_hex={}", hex(bytes))?;
        }
        writeln!(
            output,
            "{prefix}_extension_types={}",
            self.extension_types
                .iter()
                .map(|value| format!("{value:#06x}"))
                .collect::<Vec<_>>()
                .join(",")
        )?;
        writeln!(
            output,
            "{prefix}_outer_server_name={}",
            self.outer_server_name
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default()
        )?;
        let ech = self.ech.as_deref().and_then(EchOuterExtension::parse);
        match ech {
            Some(ech) => writeln!(
                output,
                "{prefix}_ech_outer=kdf={:#06x},aead={:#06x},config_id={},enc_length={},payload_length={}",
                ech.kdf_id, ech.aead_id, ech.config_id, ech.enc_length, ech.payload_length
            )?,
            None => writeln!(output, "{prefix}_ech_outer=absent")?,
        }
        match &self.handshake {
            Ok(()) => writeln!(output, "{prefix}_handshake=ok")?,
            Err(error) => writeln!(output, "{prefix}_handshake=failed: {error}")?,
        }
        writeln!(output, "{prefix}_ech_accepted={}", self.ech_accepted)?;
        writeln!(
            output,
            "{prefix}_inner_server_name={}",
            self.inner_server_name.as_deref().unwrap_or_default()
        )?;
        writeln!(output, "{prefix}_request_served={}", self.request_served)
    }
}

async fn record_connection(
    mut tcp: TcpStream,
    acceptor: &SslAcceptor,
) -> CaptureResult<Connection> {
    let capture = capture_client_hello(
        &mut tcp,
        tokio::time::Instant::now() + HANDSHAKE_TIMEOUT,
        CAPTURE_LIMITS,
    )
    .await?;
    let summary = capture.summary()?;
    let records = capture
        .records()
        .iter()
        .map(|record| record.wire_bytes().to_vec())
        .collect::<Vec<_>>();
    let mut connection = Connection {
        records: records.clone(),
        outer_server_name: summary.server_name().map(<[u8]>::to_vec),
        extension_types: summary.extension_types().to_vec(),
        ech: summary.encrypted_client_hello().map(<[u8]>::to_vec),
        handshake: Ok(()),
        ech_accepted: false,
        inner_server_name: None,
        request_served: false,
    };
    let replayed = Replayed {
        prefix: records.concat(),
        offset: 0,
        inner: tcp,
    };
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, replayed)?;
    match timeout(HANDSHAKE_TIMEOUT, Pin::new(&mut tls).accept()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            connection.handshake = Err(error.to_string());
            return Ok(connection);
        }
        Err(_) => {
            connection.handshake = Err("timed out".to_owned());
            return Ok(connection);
        }
    }
    connection.ech_accepted = tls.ssl().ech_accepted();
    connection.inner_server_name = tls.ssl().servername(NameType::HOST_NAME).map(str::to_owned);
    // A browser that rejected the outer handshake closes it with an alert,
    // which surfaces here as a read error or end of stream.
    connection.request_served = serve_page(&mut tls).await.unwrap_or(false);
    Ok(connection)
}

async fn serve_page(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<bool> {
    let Some(_) = read_request_head(stream).await? else {
        return Ok(false);
    };
    let body = b"<!doctype html><meta charset=utf-8><link rel=icon href=\"data:,\">ok\n";
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(true)
}

async fn read_request_head(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_REQUEST_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too long",
            ));
        }
        if stream.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        head.push(byte[0]);
    }
    Ok(Some(head))
}

/// A stream that yields already captured ClientHello records before reading
/// the socket, so BoringSSL sees the connection from its first byte.
struct Replayed {
    prefix: Vec<u8>,
    offset: usize,
    inner: TcpStream,
}

impl AsyncRead for Replayed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let count = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Replayed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[derive(Clone)]
struct DnsAnswers {
    address: IpAddr,
    port: u16,
    ech_config_list: Vec<u8>,
}

async fn serve_doh(
    listener: TcpListener,
    acceptor: SslAcceptor,
    queries: Arc<Mutex<Vec<String>>>,
    answers: DnsAnswers,
) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let acceptor = acceptor.clone();
        let queries = Arc::clone(&queries);
        let answers = answers.clone();
        tokio::spawn(async move {
            let _ = serve_doh_connection(tcp, &acceptor, &queries, &answers).await;
        });
    }
}

async fn serve_doh_connection(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    queries: &Mutex<Vec<String>>,
    answers: &DnsAnswers,
) -> CaptureResult<()> {
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
    Pin::new(&mut tls).accept().await?;
    loop {
        let Some(head) = read_request_head(&mut tls).await? else {
            return Ok(());
        };
        let head = String::from_utf8_lossy(&head).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default();
        let content_length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let message = if request_line.starts_with("POST ") {
            if content_length > 65_535 {
                return Err("DNS message too long".into());
            }
            let mut body = vec![0; content_length];
            tls.read_exact(&mut body).await?;
            body
        } else {
            let target = request_line.split(' ').nth(1).unwrap_or_default();
            let encoded = target
                .split_once("dns=")
                .map(|(_, value)| value.split('&').next().unwrap_or_default())
                .unwrap_or_default();
            base64url_decode(encoded).ok_or("malformed dns parameter")?
        };
        let (response, description) =
            dns_response(&message, answers).ok_or("malformed DNS query")?;
        queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(description);
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\ncache-control: max-age={DNS_TTL}\r\n\r\n",
            response.len()
        );
        tls.write_all(head.as_bytes()).await?;
        tls.write_all(&response).await?;
        tls.flush().await?;
    }
}

/// Answers one DNS query and describes it as `<type> <name>`.
fn dns_response(query: &[u8], answers: &DnsAnswers) -> Option<(Vec<u8>, String)> {
    let header = query.get(..12)?;
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*query.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        labels.push(String::from_utf8_lossy(query.get(offset..offset + length)?).to_lowercase());
        offset += length;
    }
    let record_type = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    let question_end = offset + 4;
    let question = query.get(12..question_end)?;
    let name = labels.join(".");
    let https_name = if answers.port == 443 {
        HOSTNAME.to_owned()
    } else {
        format!("_{}._https.{HOSTNAME}", answers.port)
    };

    let mut records = Vec::new();
    let mut rcode = 0;
    if name == HOSTNAME && record_type == DNS_TYPE_A {
        if let IpAddr::V4(address) = answers.address {
            records.push((DNS_TYPE_A, address.octets().to_vec()));
        }
    } else if name == HOSTNAME && record_type == DNS_TYPE_AAAA {
        if let IpAddr::V6(address) = answers.address {
            records.push((DNS_TYPE_AAAA, address.octets().to_vec()));
        }
    } else if name == https_name && record_type == DNS_TYPE_HTTPS {
        records.push((DNS_TYPE_HTTPS, https_rdata(&answers.ech_config_list)));
    } else if name != HOSTNAME && name != https_name {
        // NXDOMAIN
        rcode = 3;
    }

    let recursion_desired = u16::from_be_bytes([header[2], header[3]]) & 0x0100;
    let flags = 0x8080 | recursion_desired | rcode;
    let mut response = header[..2].to_vec();
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::try_from(records.len()).ok()?.to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(question);
    for (kind, rdata) in records {
        // A pointer to the question name at offset 12.
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&DNS_TTL.to_be_bytes());
        response.extend_from_slice(&u16::try_from(rdata.len()).ok()?.to_be_bytes());
        response.extend_from_slice(&rdata);
    }
    Some((response, format!("{} {name}", type_name(record_type))))
}

/// One ServiceMode record for the origin itself: priority 1, TargetName `.`,
/// `alpn=h2`, and `ech`.
fn https_rdata(ech_config_list: &[u8]) -> Vec<u8> {
    let mut rdata = vec![0x00, 0x01, 0x00];
    rdata.extend_from_slice(&1_u16.to_be_bytes());
    rdata.extend_from_slice(&3_u16.to_be_bytes());
    rdata.extend_from_slice(b"\x02h2");
    rdata.extend_from_slice(&5_u16.to_be_bytes());
    rdata.extend_from_slice(&(ech_config_list.len() as u16).to_be_bytes());
    rdata.extend_from_slice(ech_config_list);
    rdata
}

fn type_name(record_type: u16) -> String {
    match record_type {
        DNS_TYPE_A => "A".to_owned(),
        DNS_TYPE_AAAA => "AAAA".to_owned(),
        DNS_TYPE_HTTPS => "HTTPS".to_owned(),
        other => format!("TYPE{other}"),
    }
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut output = Vec::new();
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            output.push((bits >> count) as u8);
        }
    }
    Some(output)
}

fn require_loopback(address: IpAddr, role: &str) -> CaptureResult<()> {
    if address.is_loopback() {
        Ok(())
    } else {
        Err(format!("{role} must use a loopback address").into())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
