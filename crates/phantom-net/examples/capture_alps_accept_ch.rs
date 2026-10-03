//! Serves HTTP/2 over loopback TLS whose ALPS names `ACCEPT_CH` hints for the
//! origin, and prints each request's field names in the order the server
//! decoded them.
//!
//! `scripts/capture/alps_accept_ch.py` runs it beside a Chromium browser to see
//! whether a navigation starts again for the hints and where they go. The page
//! at `/` fetches `/fetch`, then `/done`, which ends the run.

use std::{env, error::Error, net::SocketAddr, pin::Pin, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use bytes::Bytes;
use http::{Response, StatusCode};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_btls::SslStream;

const HOSTNAME: &str = "server.phantom.test";
const H2_ALPN_WIRE: &[u8] = b"\x02h2";
const ACCEPT_CH_FRAME_TYPE: u8 = 0x89;
/// The hints Chromium sends without being asked.
const DEFAULT_HINTS: [&str; 3] = ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];
const RUN_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE: &[u8] = b"<!doctype html><meta charset=utf-8><link rel=icon href=\"data:,\">\
<script>fetch('/fetch', {cache: 'no-store'}).then(() => fetch('/done', {cache: 'no-store'}));\
</script>\n";

type CaptureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> CaptureResult<()> {
    let usage = "usage: capture_alps_accept_ch <listen-address> <accept-ch-value>";
    let mut arguments = env::args().skip(1);
    let listen: SocketAddr = arguments.next().ok_or(usage)?.parse()?;
    let accept_ch = arguments.next().ok_or(usage)?;
    if !listen.ip().is_loopback() {
        return Err("the listener must use a loopback address".into());
    }
    let listener = TcpListener::bind(listen).await?;
    let address = listener.local_addr()?;
    let settings = accept_ch_frame(
        &format!("https://{HOSTNAME}:{}", address.port()),
        &accept_ch,
    )?;
    let acceptor = acceptor()?;
    eprintln!("listening on {address}");

    let (done, mut finished) = mpsc::channel::<()>(1);
    let accept_loop = async {
        let mut next = 0_usize;
        loop {
            let (tcp, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let connection = next;
            next += 1;
            let mut ssl = Ssl::new(acceptor.context())?;
            ssl.add_application_settings_with_payload(b"h2", &settings)?;
            ssl.set_alps_use_new_codepoint(true);
            let done = done.clone();
            tokio::spawn(async move {
                if let Err(error) = serve(connection, ssl, tcp, done).await {
                    eprintln!("connection {connection} failed: {error}");
                }
            });
        }
    };
    tokio::select! {
        result = accept_loop => result,
        _ = finished.recv() => Ok(()),
        () = tokio::time::sleep(RUN_TIMEOUT) => Err("the browser never requested /done".into()),
    }
}

async fn serve(
    connection: usize,
    ssl: Ssl,
    tcp: TcpStream,
    done: mpsc::Sender<()>,
) -> CaptureResult<()> {
    let mut tls = SslStream::new(ssl, tcp)?;
    Pin::new(&mut tls).accept().await?;
    let alpn = String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or_default())
        .into_owned();
    let alps = tls.ssl().peer_application_settings().is_some();
    println!("connection={connection} alpn={alpn} client_alps={alps}");
    let mut h2 = http2::server::handshake(tls).await?;
    let mut order = 0_usize;
    while let Some(request) = h2.accept().await {
        let (request, mut respond) = request?;
        let path = request.uri().path().to_owned();
        let names: Vec<&str> = request.headers().keys().map(|name| name.as_str()).collect();
        let hints: Vec<String> = request
            .headers()
            .iter()
            .filter(|(name, _)| !DEFAULT_HINTS.contains(&name.as_str()))
            .filter(|(name, _)| name.as_str().starts_with("sec-ch-"))
            .map(|(name, value)| format!("{name}:{}", value.to_str().unwrap_or("<binary>")))
            .collect();
        println!(
            "request connection={connection} order={order} method={} path={path} fields={} added_hints={}",
            request.method(),
            names.join("|"),
            if hints.is_empty() {
                "none".to_owned()
            } else {
                hints.join(";")
            },
        );
        order += 1;
        let (body, content_type) = if path == "/" {
            (PAGE, "text/html; charset=utf-8")
        } else {
            (&b"ok"[..], "text/plain")
        };
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .header("cache-control", "no-store")
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        send.send_data(Bytes::from_static(body), true)?;
        if path == "/done" {
            // A second /done finds the channel full; one is enough.
            let _ = done.try_send(());
        }
    }
    Ok(())
}

fn acceptor() -> CaptureResult<SslAcceptor> {
    let mut params = CertificateParams::new(vec![HOSTNAME.to_owned()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let certificate = X509::from_der(certificate.der())?;
    builder.set_certificate(&certificate)?;
    let private_key = PKey::private_key_from_pkcs8(&key.serialize_der())?;
    builder.set_private_key(&private_key)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_alpn_select_callback(|_, offered| {
        select_next_proto(H2_ALPN_WIRE, offered).ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

/// An HTTP/2 ALPS payload holding one `ACCEPT_CH` frame with one entry
/// (draft-davidben-http-client-hint-reliability, section 4.1): an empty
/// SETTINGS frame, then the frame on stream 0.
fn accept_ch_frame(origin: &str, value: &str) -> CaptureResult<Vec<u8>> {
    let origin_length = u16::try_from(origin.len())?;
    let value_length = u16::try_from(value.len())?;
    let payload_length = u32::try_from(4 + origin.len() + value.len())?;
    let mut frame = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&payload_length.to_be_bytes()[1..]);
    frame.extend_from_slice(&[ACCEPT_CH_FRAME_TYPE, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&origin_length.to_be_bytes());
    frame.extend_from_slice(origin.as_bytes());
    frame.extend_from_slice(&value_length.to_be_bytes());
    frame.extend_from_slice(value.as_bytes());
    Ok(frame)
}
