//! Upload field order from retained captures; body bytes from encoder contracts.

use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    task::Poll,
};

use http::{Response, StatusCode};
use phantom::{
    Client, HttpProtocol, Method, MultipartPart, PreparedRequestBody, PreparedRequestTemplate,
    RedirectPolicy, RequestHeader,
    profile::{
        ClientProfile,
        browser::{chrome, firefox},
    },
};
use phantom_testkit::http1::{CaptureLimits, capture_request_head};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::oneshot,
    time::{Instant, timeout},
};

use super::{BUDGET, finish_prepared_peer};
use crate::support::{
    tls::{H1_ALPN, H2_ALPN, TestIdentity, accept_tls, tls_settings},
    tunnel_proxy::ConnectionPeer,
};

mod lifecycle_contract;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Server = ConnectionPeer<TestResult<Observed>>;

fn collect_upload(
    operation: impl Future<Output = TestResult<()>>,
    stop: oneshot::Sender<()>,
    server: impl Into<Server>,
) -> impl Future<Output = TestResult<Observed>> {
    let server = server.into();

    async move {
        let result = operation.await;
        // A finished or cancelled recorder may have dropped its receiver.
        let _ = stop.send(());
        finish_prepared_peer(result, server).await
    }
}

pub(super) struct Observed {
    pub(super) method: Vec<u8>,
    pub(super) fields: Vec<(String, Vec<u8>)>,
    pub(super) body: Vec<u8>,
}

impl Observed {
    pub(super) fn value(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(seen, _)| seen.eq_ignore_ascii_case(name))
            .map(|(_, value)| &**value)
    }
}

pub(super) async fn read_upload<T: AsyncRead + Unpin>(
    stream: &mut BufReader<T>,
) -> TestResult<Observed> {
    let head = capture_request_head(
        stream,
        Instant::now() + BUDGET,
        CaptureLimits::new(16384, 4096, 64),
    )
    .await?;
    let fields = head
        .headers()
        .iter()
        .map(|field| {
            Ok((
                std::str::from_utf8(field.name())?.to_owned(),
                std::str::from_utf8(field.value_bytes())?
                    .trim()
                    .as_bytes()
                    .to_vec(),
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let length = fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| -> TestResult<usize> { Ok(std::str::from_utf8(value)?.parse()?) })
        .transpose()?
        .unwrap_or(0);
    assert!(length <= 4096, "test body limit");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(Observed {
        method: head.method().to_vec(),
        fields,
        body,
    })
}

async fn next_data<T: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut ::http2::server::Connection<T, bytes::Bytes>,
    body: &mut ::http2::RecvStream,
) -> TestResult<Option<bytes::Bytes>> {
    poll_fn(|cx| {
        if let Poll::Ready(item) = body.poll_data(cx) {
            return Poll::Ready(item.transpose());
        }
        match connection.poll_closed(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
    .map_err(Into::into)
}

async fn serve_upload(
    identity: &TestIdentity,
    protocol: HttpProtocol,
) -> TestResult<(String, oneshot::Sender<()>, Server)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/post-multipart", listener.local_addr()?);
    let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 {
        H1_ALPN
    } else {
        H2_ALPN
    })?;
    let (stop, stopped) = oneshot::channel();
    let server = ConnectionPeer::spawn(async move {
        let stream = accept_tls(listener, acceptor).await?;
        if protocol == HttpProtocol::Http1 {
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;

            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(observed);
        }

        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection.accept().await.ok_or("missing H2 request")??;
        let method = request.method().as_str().as_bytes().to_vec();
        let fields = request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .ok_or("missing ordered H2 headers")?
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let mut incoming = request.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = next_data(&mut connection, &mut incoming).await? {
            assert!(body.len() + chunk.len() <= 4096, "test body limit");
            body.extend_from_slice(&chunk);
            incoming.flow_control().release_capacity(chunk.len())?;
        }

        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
            true,
        )?;
        tokio::select! {
            result = poll_fn(|cx| connection.poll_closed(cx)) => result?,
            _ = stopped => {},
        }
        Ok(Observed {
            method,
            fields,
            body,
        })
    });
    Ok((url, stop, server))
}

fn capture_names(capture: &str) -> TestResult<Vec<&str>> {
    Ok(capture
        .lines()
        .find(|line| line.starts_with("request_4="))
        .ok_or("captured multipart request")?
        .split_once(",fields:")
        .ok_or("captured fields")?
        .1
        .split(',')
        .next()
        .ok_or("field order")?
        .split('|')
        .filter(|name| *name != "Host" && !name.starts_with(':'))
        .collect())
}

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/",
            $path
        ))
    };
}

fn multipart() -> TestResult<PreparedRequestBody> {
    let body = PreparedRequestBody::multipart(
        "upload-boundary",
        [
            MultipartPart::text("na\"me\n", "line1\nline2")?,
            MultipartPart::bytes("file", b"\x00\xff")?
                .with_filename("a\"b\n.bin")?
                .with_content_type("application/octet-stream")?,
        ],
        4096,
    )?;
    // Encoder contract only: the lifecycle capture does not retain multipart bytes.
    assert_eq!(body.bytes().as_ref(), b"--upload-boundary\r\nContent-Disposition: form-data; name=\"na%22me%0D%0A\"\r\n\r\nline1\r\nline2\r\n--upload-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a%22b%0A.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xff\r\n--upload-boundary--\r\n");
    Ok(body)
}

#[tokio::test]
async fn named_uploads_send_captured_field_order_and_exact_prepared_bodies() -> TestResult<()> {
    for (browser, template, h1, h2) in [
        (
            ClientProfile::new(tls_settings())
                .with_http1(chrome::v154_http1())
                .with_http2(chrome::v154_http2())
                .with_client_hints(chrome::v154_windows_client_hints()),
            chrome::v154_windows_fetch_upload_template(),
            fixture!("lifecycle/chrome/154.0.8037.97/windows-11-26200/upload-h1.txt"),
            fixture!("lifecycle/chrome/154.0.8037.97/windows-11-26200/upload-h2.txt"),
        ),
        (
            ClientProfile::new(tls_settings())
                .with_http1(firefox::v157_http1())
                .with_http2(firefox::v157_http2()),
            firefox::v157_windows_fetch_upload_template(),
            fixture!("lifecycle/firefox/157.0/windows-11-26200/upload-h1.txt"),
            fixture!("lifecycle/firefox/157.0/windows-11-26200/upload-h2.txt"),
        ),
    ] {
        let bodies = vec![
            multipart()?,
            PreparedRequestBody::form([("a +", "b&é"), ("a +", "")], 4096)?,
        ];
        assert_eq!(bodies[1].bytes().as_ref(), b"a+%2B=b%26%C3%A9&a+%2B=");
        #[cfg(feature = "json")]
        let bodies = {
            let mut bodies = bodies;
            let body = PreparedRequestBody::json(&serde_json::json!({"line":"a\nb"}), 4096)?;
            assert_eq!(body.bytes().as_ref(), br#"{"line":"a\nb"}"#);
            bodies.push(body);
            bodies
        };
        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            for body in &bodies {
                timeout(BUDGET, async {
                    let identity = TestIdentity::generate()?;
                    // These tests assert request fields and body bytes, not TLS parity.
                    let client = Client::builder(browser.clone())
                        .add_root_certificate_der(identity.root_der.clone())
                        .build()?;
                    let prepared = PreparedRequestTemplate::new(template.clone())?;
                    let (url, stop, server) = serve_upload(&identity, protocol).await?;

                    let observed = collect_upload(
                        async {
                            let origin = url.trim_end_matches("/post-multipart");
                            let request = client
                                .request(protocol, Method::POST, &url)?
                                .template(&prepared)
                                .fill_slots(|slots| {
                                    slots.fill(RequestHeader::new("Origin", origin))?;
                                    slots.fill(RequestHeader::new(
                                        "Referer",
                                        format!("{origin}/start"),
                                    ))?;
                                    if slots.declares("Priority") {
                                        slots.fill(RequestHeader::new("Priority", "u=4"))?;
                                    }
                                    Ok(())
                                })?
                                .prepared_body(body.clone());
                            assert_eq!(request.send().await?.status(), StatusCode::NO_CONTENT);
                            Ok(())
                        },
                        stop,
                        server,
                    )
                    .await?;

                    let actual: Vec<_> = observed
                        .fields
                        .iter()
                        .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                        .map(|(name, _)| name.as_str())
                        .collect();
                    assert_eq!(
                        actual,
                        capture_names(if protocol == HttpProtocol::Http1 {
                            h1
                        } else {
                            h2
                        })?
                    );
                    assert_eq!(observed.method, b"POST");
                    assert_eq!(
                        observed.value("content-type"),
                        Some(body.content_type().as_bytes())
                    );
                    assert_eq!(
                        observed.value("content-length"),
                        Some(body.bytes().len().to_string().as_bytes())
                    );
                    assert_eq!(observed.body, body.bytes().as_ref());
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                })
                .await??;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn prepared_upload_replays_identical_type_length_and_bytes_on_307() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/first", listener.local_addr()?);
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN)).build()?;
        let prepared = super::template(true, true)?;
        let body = multipart()?;

        let server = ConnectionPeer::spawn(async move {
            let mut observed = Vec::new();
            for hop in 0..2 {
                let (stream, _) = listener.accept().await?;
                let mut stream = BufReader::new(stream);
                observed.push(read_upload(&mut stream).await?);

                let response = if hop == 0 {
                    &b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..]
                } else { &b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"[..] };
                stream.get_mut().write_all(response).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let operation = async {
            assert_eq!(client.request(HttpProtocol::Http1, Method::POST, &url)?.template(&prepared)
                .prepared_body(body.clone()).send().await?.status(), StatusCode::NO_CONTENT);
            Ok(())
        }.await;

        let observations = finish_prepared_peer(operation, server).await?;

        assert_eq!(observations.len(), 2);
        for observed in &observations {
            assert_eq!(observed.method, b"POST");
            assert_eq!(observed.body, body.bytes().as_ref());
            assert_eq!(observed.value("content-type"), Some(body.content_type().as_bytes()));
            assert_eq!(observed.value("content-length"), Some(body.bytes().len().to_string().as_bytes()));
        }
        assert_eq!(observations[0].fields, observations[1].fields);
        Ok(())
    }).await?
}

#[tokio::test]
async fn explicit_matching_content_type_keeps_caller_order_without_template() -> TestResult<()> {
    timeout(BUDGET, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}/upload", listener.local_addr()?);
        let body = PreparedRequestBody::form([("a", "b")], 128)?;
        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;

        let server = ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let observed = read_upload(&mut stream).await?;

            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let operation = async {
            client
                .request(HttpProtocol::Http1, Method::POST, &url)?
                .header(RequestHeader::new("X-Before", "first"))
                .header(RequestHeader::new("Content-Type", body.content_type()).sensitive())
                .header(RequestHeader::new("X-After", "last"))
                .prepared_body(body.clone())
                .send()
                .await?;
            Ok(())
        }
        .await;

        let observed = finish_prepared_peer(operation, server).await?;

        let names: Vec<_> = observed
            .fields
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(
            names,
            ["X-Before", "Content-Type", "X-After", "Content-Length"]
        );
        assert_eq!(observed.body, body.bytes().as_ref());
        Ok(())
    })
    .await?
}
