//! Replays the retained two-request cookie captures over HTTP/2.
//!
//! Each test serves the capture's `/start` response, which sets the probe
//! cookies, and then sends the captured `/page`, `/fetch`, and `/done`
//! requests through a client with a cookie jar and the browser's recipe. The
//! caller supplies every captured ordinary field except `cookie`, so the jar
//! adds its field at the recipe's placement, and the HPACK encoder splits it.
//! The server records the client's HEADERS blocks and compares each crumb's
//! position, value, and representation with the capture
//! (`fixtures/cookies/<browser>/<version>/windows-11-26200/crumbs-h2.txt`).

#![cfg(feature = "cookies")]

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    collections::BTreeMap,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::Ssl;
use bytes::Bytes;
use http::{Response, StatusCode, header::SET_COOKIE};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestHeader,
    profile::{ClientProfile, CookiePlacement, Http2Settings, chromium, firefox},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    time::timeout,
};
use tokio_btls::SslStream;

use tls_support::{H2_ALPN, TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

const CHROME: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cookies/chrome/154.0.8037.58/windows-11-26200/crumbs-h2.txt"
));
const EDGE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cookies/edge/153.0.4234.48/windows-11-26200/crumbs-h2.txt"
));
const FIREFOX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/cookies/firefox/156.0/windows-11-26200/crumbs-h2.txt"
));

#[tokio::test]
async fn chrome_sends_one_indexed_field_per_jar_cookie_as_captured() -> TestResult<()> {
    let capture = Capture::parse(CHROME)?;
    let observed = replay(
        &capture,
        chromium::v154_http2(),
        chromium::v154_cookie_placement(),
    )
    .await?;
    assert_crumbs_match(&capture, &observed, NameIndex::Exact)
}

#[tokio::test]
async fn edge_sends_one_indexed_field_per_jar_cookie_as_captured() -> TestResult<()> {
    // Edge 153 replays against the Chromium recipes (`phantom::profile::edge`).
    let capture = Capture::parse(EDGE)?;
    let observed = replay(
        &capture,
        chromium::v154_http2(),
        chromium::v154_cookie_placement(),
    )
    .await?;
    assert_crumbs_match(&capture, &observed, NameIndex::Exact)
}

#[tokio::test]
async fn firefox_never_indexes_short_jar_cookies_as_captured() -> TestResult<()> {
    let capture = Capture::parse(FIREFOX)?;
    let observed = replay(
        &capture,
        firefox::v156_http2(),
        firefox::v156_cookie_placement(),
    )
    .await?;
    // Firefox names a literal with the highest-numbered matching table entry,
    // the oldest dynamic `cookie` entry once one exists; the encoder names
    // static entry 32 or the newest dynamic entry instead
    // (vendor/http2/PHANTOM.md, "Cookie crumbs"). Every other part of each
    // crumb must match.
    assert_crumbs_match(&capture, &observed, NameIndex::StaticOnly)
}

#[tokio::test]
async fn whole_cookie_setting_keeps_one_field() -> TestResult<()> {
    let capture = Capture::parse(CHROME)?;
    let mut settings = chromium::v154_http2();
    settings.hpack.cookie_crumbs = phantom::profile::Http2CookieCrumbs::Whole;
    let observed = replay(&capture, settings, chromium::v154_cookie_placement()).await?;
    let page = observed.get(1).ok_or("the page request was not recorded")?;
    let cookies = page
        .iter()
        .filter(|field| field.name == "cookie")
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].value, capture.joined_cookie());
    assert_eq!(cookies[0].representation, "never-indexed");
    Ok(())
}

/// Whether a captured crumb's name index must match exactly.
#[derive(Clone, Copy)]
enum NameIndex {
    Exact,
    /// Only a static name index (61 or less) must match.
    StaticOnly,
}

fn assert_crumbs_match(
    capture: &Capture,
    observed: &[Vec<Field>],
    names: NameIndex,
) -> TestResult<()> {
    assert_eq!(observed.len(), capture.requests.len());
    for (request, (captured, emitted)) in capture.requests.iter().zip(observed).enumerate() {
        let captured_order = ordinary(captured)
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        let emitted_order = ordinary(emitted)
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(emitted_order, captured_order, "request {request} order");

        let captured_crumbs = crumbs(captured);
        let emitted_crumbs = crumbs(emitted);
        assert_eq!(
            emitted_crumbs.len(),
            captured_crumbs.len(),
            "request {request} crumb count"
        );
        for (crumb, (want, got)) in captured_crumbs.iter().zip(&emitted_crumbs).enumerate() {
            let context = format!("request {request} crumb {crumb} ({})", want.value);
            assert_eq!(got.value, want.value, "{context}");
            assert_eq!(got.representation, want.representation, "{context}");
            assert_eq!(got.value_huffman, want.value_huffman, "{context}");
            match names {
                NameIndex::Exact => assert_eq!(got.index, want.index, "{context}"),
                NameIndex::StaticOnly if want.index <= 61 || want.representation == "indexed" => {
                    assert_eq!(got.index, want.index, "{context}");
                }
                NameIndex::StaticOnly => {}
            }
        }
    }
    Ok(())
}

fn ordinary(fields: &[Field]) -> impl Iterator<Item = &Field> {
    fields.iter().filter(|field| !field.name.starts_with(':'))
}

fn crumbs(fields: &[Field]) -> Vec<&Field> {
    fields
        .iter()
        .filter(|field| field.name == "cookie")
        .collect()
}

/// Sends the captured requests and returns each emitted HEADERS block.
async fn replay(
    capture: &Capture,
    http2: Http2Settings,
    placement: CookiePlacement,
) -> TestResult<Vec<Vec<Field>>> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let set_cookies = capture.set_cookies();
    let expected = capture.requests.len();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut tls = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
        Pin::new(&mut tls).accept().await?;
        let wire = Arc::new(Mutex::new(Vec::new()));
        let io = RecordingIo {
            inner: tls,
            read: Arc::clone(&wire),
        };
        let mut connection = ::http2::server::handshake(io).await?;
        let mut names = Vec::new();
        for index in 0..expected {
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("client closed before every request")??;
            let fields = request
                .extensions()
                .get::<::http2::ext::OrderedHeaders>()
                .ok_or("server request omitted its field order")?
                .as_slice()
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.as_str().to_owned(),
                        String::from_utf8(value.as_bytes().to_vec())?,
                    ))
                })
                .collect::<TestResult<Vec<_>>>()?;
            names.push(fields);
            let mut response = Response::builder().status(StatusCode::OK);
            if index == 0 {
                for cookie in &set_cookies {
                    response = response.header(SET_COOKIE, cookie.as_str());
                }
            }
            let mut send = respond.send_response(response.body(())?, false)?;
            send.send_data(Bytes::from_static(b"ok"), true)?;
        }
        // Keep driving the connection so the last response is flushed; the
        // client closes it after reading that response.
        let _closed = std::future::poll_fn(|context| connection.poll_closed(context)).await;
        let wire = wire.lock().map_err(|_| "wire lock was poisoned")?.clone();
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((wire, names))
    });

    let profile = ClientProfile::new(tls_settings())
        .with_http2(http2)
        .with_cookie_placement(placement);
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .cookies()
        .build()?;
    for request in &capture.requests {
        let path = request
            .iter()
            .find(|field| field.name == ":path")
            .ok_or("captured request has no :path")?;
        let headers = ordinary(request)
            .filter(|field| field.name != "cookie")
            .map(|field| RequestHeader::new(field.name.clone(), field.value.clone()))
            .collect::<Vec<_>>();
        let url = format!("https://{address}{}", path.value);
        let sent = timeout(
            TEST_TIMEOUT,
            client
                .get(HttpProtocol::Http2, &url)?
                .headers(headers)
                .send(),
        )
        .await?;
        let response = match sent {
            Ok(response) => response,
            // A server failure explains the client's; report both.
            Err(error) => {
                let server = timeout(TEST_TIMEOUT, server).await;
                return Err(format!("client: {error}; server: {server:?}").into());
            }
        };
        response.into_body().collect().await?;
    }
    drop(client);
    let (wire, decoded) = timeout(TEST_TIMEOUT, server).await???;
    let blocks = header_blocks(&wire)?;
    if blocks.len() != decoded.len() {
        return Err("server decoded a different number of HEADERS blocks".into());
    }
    blocks
        .iter()
        .zip(decoded)
        .map(|(block, fields)| label(block, &fields))
        .collect()
}

/// One field of a HEADERS block with its HPACK representation.
#[derive(Clone, Debug)]
struct Field {
    name: String,
    value: String,
    /// `indexed`, `incremental`, `without-indexing`, or `never-indexed`.
    representation: String,
    index: usize,
    value_huffman: Option<bool>,
}

/// Pairs each representation with the server's decoded ordinary fields.
///
/// A client request block holds four pseudo-fields first; their names and
/// values are not compared, so they are labeled only by position.
fn label(block: &[u8], ordinary: &[(String, String)]) -> TestResult<Vec<Field>> {
    let representations = representations(block)?;
    let pseudo = representations.len().checked_sub(ordinary.len());
    if pseudo != Some(4) {
        return Err("HEADERS block did not hold four pseudo-fields".into());
    }
    Ok(representations
        .into_iter()
        .enumerate()
        .map(|(position, (representation, index, value_huffman))| {
            let (name, value) = match position.checked_sub(4) {
                None => (format!(":pseudo-{position}"), String::new()),
                Some(field) => ordinary[field].clone(),
            };
            Field {
                name,
                value,
                representation,
                index,
                value_huffman,
            }
        })
        .collect())
}

/// Returns each representation's kind, index, and value Huffman flag, in
/// order, leaving out dynamic-table size updates.
fn representations(block: &[u8]) -> TestResult<Vec<(String, usize, Option<bool>)>> {
    let mut cursor = 0;
    let mut output = Vec::new();
    while let Some(&first) = block.get(cursor) {
        let (kind, prefix) = if first & 0x80 != 0 {
            ("indexed", 7)
        } else if first & 0xc0 == 0x40 {
            ("incremental", 6)
        } else if first & 0xe0 == 0x20 {
            read_integer(block, &mut cursor, 5)?;
            continue;
        } else if first & 0x10 != 0 {
            ("never-indexed", 4)
        } else {
            ("without-indexing", 4)
        };
        let index = read_integer(block, &mut cursor, prefix)?;
        let mut value_huffman = None;
        if kind != "indexed" {
            if index == 0 {
                skip_string(block, &mut cursor)?;
            }
            value_huffman = Some(skip_string(block, &mut cursor)?);
        }
        output.push((kind.to_owned(), index, value_huffman));
    }
    Ok(output)
}

fn read_integer(block: &[u8], cursor: &mut usize, prefix_bits: u8) -> TestResult<usize> {
    let mask = (1_u8 << prefix_bits) - 1;
    let first = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
    *cursor += 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
        *cursor += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn skip_string(block: &[u8], cursor: &mut usize) -> TestResult<bool> {
    let huffman = block.get(*cursor).ok_or("HPACK string is truncated")? & 0x80 != 0;
    let length = read_integer(block, cursor, 7)?;
    if block.len() < *cursor + length {
        return Err("HPACK string is truncated".into());
    }
    *cursor += length;
    Ok(huffman)
}

/// Returns every client HEADERS block in order; each must fit one frame.
fn header_blocks(wire: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut offset = PREFACE.len();
    if !wire.starts_with(PREFACE) {
        return Err("client omitted the HTTP/2 preface".into());
    }
    let mut blocks = Vec::new();
    while let Some(head) = wire.get(offset..offset + 9) {
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let payload = wire
            .get(offset + 9..offset + 9 + length)
            .ok_or("client frame is truncated")?;
        let (kind, flags) = (head[3], head[4]);
        offset += 9 + length;
        if kind != 1 {
            continue;
        }
        if flags & 0x08 != 0 || flags & 0x04 == 0 {
            return Err("test decoder supports only unpadded single-frame HEADERS".into());
        }
        let block = if flags & 0x20 != 0 {
            &payload[5..]
        } else {
            payload
        };
        blocks.push(block.to_vec());
    }
    Ok(blocks)
}

/// Run 0 of one retained `phantom-cookie-crumbs-v1` capture.
struct Capture {
    probes: Vec<String>,
    /// Every request of run 0, in arrival order, starting with `/start`.
    requests: Vec<Vec<Field>>,
}

impl Capture {
    fn parse(text: &str) -> TestResult<Self> {
        let values = text
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let value = |key: &str| {
            values
                .get(key)
                .copied()
                .ok_or_else(|| format!("capture omitted {key}"))
        };
        if value("format")? != "phantom-cookie-crumbs-v1" {
            return Err("unexpected capture format".into());
        }
        let probes = (0..value("probe_cookie_count")?.parse::<usize>()?)
            .map(|index| value(&format!("probe_cookie_{index}")).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let mut requests = Vec::new();
        for request in 0..value("run_0_request_count")?.parse::<usize>()? {
            let key = format!("run_0_request_{request}");
            let mut fields = Vec::new();
            for field in 0..value(&format!("{key}_field_count"))?.parse::<usize>()? {
                let record = value(&format!("{key}_field_{field}"))?;
                let attribute = |name: &str| {
                    record
                        .split(',')
                        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                        .ok_or_else(|| format!("capture field omitted {name}"))
                };
                let representation = attribute("repr")?;
                if representation == "size-update" {
                    continue;
                }
                let value_huffman = match attribute("value_huffman")? {
                    "none" => None,
                    flag => Some(flag == "true"),
                };
                fields.push(Field {
                    name: String::from_utf8(decode_hex(attribute("name_hex")?)?)?,
                    value: String::from_utf8(decode_hex(attribute("value_hex")?)?)?,
                    representation: representation.to_owned(),
                    index: attribute("index")?.parse()?,
                    value_huffman,
                });
            }
            requests.push(fields);
        }
        Ok(Self { probes, requests })
    }

    fn set_cookies(&self) -> Vec<String> {
        self.probes
            .iter()
            .map(|cookie| format!("{cookie}; Path=/"))
            .collect()
    }

    fn joined_cookie(&self) -> String {
        self.probes.join("; ")
    }
}

fn decode_hex(encoded: &str) -> TestResult<Vec<u8>> {
    (0..encoded.len())
        .step_by(2)
        .map(|index| {
            encoded
                .get(index..index + 2)
                .ok_or_else(|| "capture hex has odd length".into())
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(Into::into))
        })
        .collect()
}

struct RecordingIo<T> {
    inner: T,
    read: Arc<Mutex<Vec<u8>>>,
}

impl<T> AsyncRead for RecordingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = result {
            this.read
                .lock()
                .map_err(|_| io::Error::other("recorded wire lock was poisoned"))?
                .extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl<T> AsyncWrite for RecordingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}
