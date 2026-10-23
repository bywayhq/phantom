//! One logical origin advertising a separately named QUIC destination.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpListener,
    sync::Notify,
    time::{Instant, timeout},
};
use tokio_btls::SslStream;

use super::{
    CaptureResult, Captured, DnsAnswers, HANDSHAKE_TIMEOUT, HOSTNAME, MAX_DOH_QUERIES,
    MAX_DOH_QUERY_BYTES, PUBLIC_NAME, QuicConnection, Replayed, ServerHandshakeData, TEST_ECH_KEYS,
    ech_config, ech_config_list, hex, read_request_head,
};

pub(super) const HOST_B: &str = "alternative.phantom.test";
const MAX_REQUESTS: usize = 32;
const PROBE_BODY: &[u8] = b"alternative-probe";

pub(super) async fn bind(
    config: quinn::ServerConfig,
    address: IpAddr,
) -> CaptureResult<(quinn::Endpoint, TcpListener)> {
    let mut last = None;
    for _ in 0..32 {
        let udp = phantom_testkit::udp::bind(SocketAddr::new(address, 0))?;
        let local = udp.local_addr()?;
        match TcpListener::bind(local).await {
            Ok(reservation) => {
                udp.set_nonblocking(true)?;
                let endpoint = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(config),
                    udp,
                    std::sync::Arc::new(quinn::TokioRuntime),
                )?;
                return Ok((endpoint, reservation));
            }
            Err(error)
                if error.kind() == io::ErrorKind::AddrInUse
                    || (cfg!(windows) && error.raw_os_error() == Some(10013)) =>
            {
                last = Some(error)
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(last.map_or_else(|| "no paired alternative port".into(), Into::into))
}

struct DnsObservation {
    name: String,
    query: Vec<u8>,
    response: Vec<u8>,
    elapsed_ms: u128,
}

struct Request {
    transport: &'static str,
    connection: usize,
    authority: String,
    path: String,
    completed: bool,
    elapsed_ms: u128,
    body: Bytes,
}

struct Handshake {
    connection: usize,
    alpn: Vec<u8>,
    ech_accepted: bool,
    elapsed_ms: u128,
}

pub(super) struct AlternativeHost {
    origin: SocketAddr,
    destination: SocketAddr,
    started: Instant,
    handshake: AtomicBool,
    ready: Notify,
    probe: AtomicBool,
    dns: Mutex<Vec<DnsObservation>>,
    requests: Mutex<Vec<Request>>,
    handshakes: Mutex<Vec<Handshake>>,
}

pub(super) struct Response {
    pub(super) body: Bytes,
    index: usize,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl AlternativeHost {
    pub(super) fn new(origin: SocketAddr, destination: SocketAddr) -> io::Result<Self> {
        if !origin.ip().is_loopback() || !destination.ip().is_loopback() || origin == destination {
            return Err(invalid(
                "alternative origin and destination must be distinct loopback endpoints",
            ));
        }
        Ok(Self {
            origin,
            destination,
            started: Instant::now(),
            handshake: AtomicBool::new(false),
            ready: Notify::new(),
            probe: AtomicBool::new(false),
            dns: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            handshakes: Mutex::new(Vec::new()),
        })
    }

    fn authority(&self) -> String {
        if self.origin.port() == 443 {
            HOSTNAME.to_owned()
        } else {
            format!("{HOSTNAME}:{}", self.origin.port())
        }
    }

    pub(super) fn owns_destination(&self, name: &str) -> bool {
        name == HOST_B || name == format!("_{}._https.{HOST_B}", self.destination.port())
    }

    pub(super) fn answers(&self) -> DnsAnswers {
        DnsAnswers {
            address: self.destination.ip(),
            port: self.destination.port(),
            ech_config_list: Some(ech_config_list(&[ech_config(
                2,
                &TEST_ECH_KEYS[1],
                PUBLIC_NAME,
            )])),
            quic: true,
            alternative: None,
        }
    }

    pub(super) fn record_dns(&self, name: &str, query: &[u8], response: &[u8]) -> Option<()> {
        if name != HOSTNAME
            && name != format!("_{}._https.{HOSTNAME}", self.origin.port())
            && !self.owns_destination(name)
        {
            return Some(());
        }
        let mut dns = self.dns.lock().unwrap_or_else(PoisonError::into_inner);
        let retained = dns
            .iter()
            .map(|item| item.query.len() + item.response.len())
            .sum::<usize>();
        if dns.len() == MAX_DOH_QUERIES
            || query
                .len()
                .saturating_add(response.len())
                .saturating_add(retained)
                > MAX_DOH_QUERY_BYTES
        {
            return None;
        }
        dns.push(DnsObservation {
            name: name.to_owned(),
            query: query.to_vec(),
            response: response.to_vec(),
            elapsed_ms: self.started.elapsed().as_millis(),
        });
        Some(())
    }

    pub(super) fn authenticated(
        &self,
        slot: usize,
        connection: &QuicConnection,
        data: Option<&ServerHandshakeData>,
    ) -> CaptureResult<()> {
        let data = data.ok_or("alternative QUIC handshake metadata missing")?;
        if data.protocol() != b"h3" || connection.inner_server_name.as_deref() != Some(HOSTNAME) {
            return Err("alternative QUIC must authenticate logical origin A with h3".into());
        }
        let mut handshakes = self
            .handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if handshakes.len() == super::MAX_CONNECTIONS {
            return Err("alternative handshake limit exceeded".into());
        }
        handshakes.push(Handshake {
            connection: slot,
            alpn: data.protocol().to_vec(),
            ech_accepted: data.ech_accepted(),
            elapsed_ms: self.started.elapsed().as_millis(),
        });
        drop(handshakes);
        self.handshake.store(true, Ordering::Release);
        self.ready.notify_waiters();
        Ok(())
    }

    fn page(&self) -> Bytes {
        Bytes::from_static(
            br#"<!doctype html><meta charset=utf-8><link rel=icon href="data:"><script>
(async()=>{
  const get=async path=>{const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw Error('status');return r.text();};
  await get('/learn');await get('/ready');
  if(await get('/probe')!=='alternative-probe')throw Error('probe body');
  await get('/done?ok=1');
})();</script>"#
        )
    }

    pub(super) async fn response(
        &self,
        transport: &'static str,
        connection: usize,
        request: &http::Request<()>,
    ) -> io::Result<Response> {
        if request.method() != http::Method::GET
            || request.uri().authority().map(http::uri::Authority::as_str)
                != Some(self.authority().as_str())
            || request.headers().keys().any(|name| {
                matches!(
                    name.as_str(),
                    "cookie" | "authorization" | "proxy-authorization"
                )
            })
        {
            return Err(invalid(
                "alternative request must be a credential-free GET for logical origin A",
            ));
        }
        let path = request
            .uri()
            .path_and_query()
            .ok_or_else(|| invalid("alternative path missing"))?
            .as_str();
        let body = match path {
            "/" => self.page(),
            "/learn" => Bytes::from_static(b"learn"),
            "/ready" => {
                timeout(HANDSHAKE_TIMEOUT, async {
                    loop {
                        let ready = self.ready.notified();
                        if self.handshake.load(Ordering::Acquire) {
                            break;
                        }
                        ready.await;
                    }
                })
                .await
                .map_err(|_| invalid("alternative handshake did not complete"))?;
                Bytes::from_static(b"ready")
            }
            "/probe" if transport == "h3" => Bytes::from_static(PROBE_BODY),
            "/done?ok=1" if self.probe.load(Ordering::Acquire) => Bytes::from_static(b"done"),
            _ => return Err(invalid("unexpected alternative request path or protocol")),
        };
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        if requests.len() == MAX_REQUESTS {
            return Err(invalid("alternative request limit exceeded"));
        }
        let index = requests.len();
        requests.push(Request {
            transport,
            connection,
            authority: self.authority(),
            path: path.to_owned(),
            completed: false,
            elapsed_ms: self.started.elapsed().as_millis(),
            body: body.clone(),
        });
        Ok(Response { body, index })
    }

    pub(super) fn completed(&self, response: &Response, captured: &Captured) -> io::Result<()> {
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        let request = requests
            .get_mut(response.index)
            .ok_or_else(|| invalid("alternative response index missing"))?;
        request.completed = true;
        if request.transport == "h3" && request.path == "/probe" {
            self.probe.store(true, Ordering::Release);
        }
        if request.path == "/done?ok=1" {
            captured.mark_served();
        }
        Ok(())
    }

    pub(super) async fn serve_tcp(
        &self,
        tls: &mut SslStream<Replayed>,
        captured: &Captured,
        slot: usize,
    ) -> io::Result<bool> {
        if tls.ssl().selected_alpn_protocol() != Some(b"http/1.1")
            || tls.ssl().servername(btls::ssl::NameType::HOST_NAME) != Some(HOSTNAME)
        {
            return Err(invalid(
                "alternative bootstrap must use logical origin A and HTTP/1.1",
            ));
        }
        let head = timeout(HANDSHAKE_TIMEOUT, read_request_head(tls))
            .await
            .map_err(|_| invalid("alternative request head timed out"))??;
        let Some(head) = head else { return Ok(false) };
        let mut fields = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut fields);
        if !parsed
            .parse(&head)
            .map_err(|_| invalid("malformed alternative HTTP/1 request"))?
            .is_complete()
            || parsed.version != Some(1)
        {
            return Err(invalid("incomplete alternative HTTP/1 request"));
        }
        let mut builder = http::Request::builder()
            .method(parsed.method.ok_or_else(|| invalid("method missing"))?)
            .uri(format!(
                "https://{}{}",
                self.authority(),
                parsed.path.ok_or_else(|| invalid("path missing"))?
            ));
        let mut hosts = Vec::new();
        for header in parsed.headers.iter() {
            if header.name.eq_ignore_ascii_case("host") {
                hosts.push(header.value);
            }
            if header.name.eq_ignore_ascii_case("transfer-encoding")
                || (header.name.eq_ignore_ascii_case("content-length") && header.value != b"0")
            {
                return Err(invalid("alternative request bodies are unsupported"));
            }
            builder = builder.header(header.name, header.value);
        }
        if hosts != [self.authority().as_bytes()] {
            return Err(invalid("alternative Host differs from logical origin A"));
        }
        let request = builder
            .body(())
            .map_err(|_| invalid("invalid alternative HTTP fields"))?;
        let response = self.response("http/1.1", slot, &request).await?;
        let advertisement = if request.uri().path() == "/learn" {
            format!(
                "Alt-Svc: h3=\"{HOST_B}:{}\"; ma=300\r\n",
                self.destination.port()
            )
        } else {
            String::new()
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
            response.body.len(),
            advertisement
        );
        timeout(HANDSHAKE_TIMEOUT, async {
            tls.write_all(head.as_bytes()).await?;
            tls.write_all(&response.body).await?;
            tls.flush().await
        })
        .await
        .map_err(|_| invalid("alternative response timed out"))??;
        self.completed(&response, captured)?;
        timeout(HANDSHAKE_TIMEOUT, tls.shutdown())
            .await
            .map_err(|_| invalid("alternative TLS shutdown timed out"))??;
        Ok(true)
    }

    pub(super) fn write(&self, output: &mut impl io::Write) -> io::Result<()> {
        writeln!(output, "alternative_origin={}", self.origin)?;
        writeln!(output, "alternative_destination_name={HOST_B}")?;
        writeln!(output, "alternative_destination={}", self.destination)?;
        writeln!(output, "alternative_origin_https=nodata")?;
        writeln!(output, "alternative_destination_config_id=2")?;
        writeln!(output, "alternative_probe_body_hex={}", hex(PROBE_BODY))?;
        let handshakes = self
            .handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        writeln!(
            output,
            "alternative_authenticated_count={}",
            handshakes.len()
        )?;
        for (index, handshake) in handshakes.iter().enumerate() {
            writeln!(
                output,
                "alternative_authenticated_{index}=connection={} logical_name={HOSTNAME} alpn_hex={} ech_accepted={} at_ms={}",
                handshake.connection,
                hex(&handshake.alpn),
                handshake.ech_accepted,
                handshake.elapsed_ms
            )?;
        }
        drop(handshakes);
        let dns = self.dns.lock().unwrap_or_else(PoisonError::into_inner);
        writeln!(output, "alternative_dns_count={}", dns.len())?;
        for (index, query) in dns.iter().enumerate() {
            writeln!(output, "alternative_dns_{index}_name={}", query.name)?;
            writeln!(output, "alternative_dns_{index}_at_ms={}", query.elapsed_ms)?;
            writeln!(
                output,
                "alternative_dns_{index}_query_hex={}",
                hex(&query.query)
            )?;
            writeln!(
                output,
                "alternative_dns_{index}_response_hex={}",
                hex(&query.response)
            )?;
        }
        let requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        writeln!(output, "alternative_request_count={}", requests.len())?;
        for (index, request) in requests.iter().enumerate() {
            writeln!(
                output,
                "alternative_request_{index}={} connection={} authority={} path={} completed={} at_ms={}",
                request.transport,
                request.connection,
                request.authority,
                request.path,
                request.completed,
                request.elapsed_ms
            )?;
            if request.completed && request.path != "/" {
                writeln!(
                    output,
                    "alternative_request_{index}_response_body_hex={}",
                    hex(&request.body)
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
