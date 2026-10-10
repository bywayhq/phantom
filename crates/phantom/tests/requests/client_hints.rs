//! Public client-hint session integration tests.

use crate::support::h2 as h2_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{
    error::Error,
    fmt,
    future::poll_fn,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor, SslVersion};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, PreparedRequestTemplate, RequestErrorKind, RequestHeader,
    profile::{
        AlpsSettings, CipherSuite, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, Http3ClientSettings, NamedGroup, TlsVersion, browser::chrome,
    },
};
use phantom_quic_btls::QuicServerConfig;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use h3_support::{accept_request, client_settings, quic_server, server_endpoint};
use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, read_head, tls_settings};

mod deadline_contract;
mod hint_values;
mod quiet_contract;
mod received_order;
mod task_ownership;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_CH_VALUE: &str = "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version";

#[derive(Debug)]
struct HintDeadline {
    source: tokio::time::error::Elapsed,
}

impl fmt::Display for HintDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("client-hint test timed out")
    }
}

impl Error for HintDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[tokio::test]
async fn http1_client_hints_share_the_canonical_origin_key() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(answer_http1_hint_requests(listener, acceptor, None));

        let session = client(&identity)?;
        let url = format!("https://{address}/");
        let unicode_url = format!("https://１２７．０．０．１:{}/", address.port());
        let requests = finish_hint_operation(server, async {
            send_and_drain(&session, HttpProtocol::Http1, &unicode_url).await?;
            send_and_drain(&session, HttpProtocol::Http1, &url).await?;
            send_and_drain(&session, HttpProtocol::Http1, &url).await?;
            Ok(())
        })
        .await?;
        assert_http1_hints(&requests[0], false)?;
        assert_http1_hints(&requests[1], true)?;
        assert_http1_hints(&requests[2], false)?;
        Ok(())
    })
    .await
}

async fn answer_http1_hint_requests(
    listener: TcpListener,
    acceptor: SslAcceptor,
    observed: Option<oneshot::Sender<Vec<u8>>>,
) -> TestResult<[Vec<u8>; 3]> {
    let mut stream = accept_tls(&listener, &acceptor).await?;
    let first = read_head(&mut stream).await?;
    write_http1_response(&mut stream, Some(ACCEPT_CH_VALUE)).await?;
    if let Some(observed) = observed {
        observed
            .send(first.clone())
            .map_err(|_| "HTTP/1 hint observer disappeared")?;
    }
    let second = read_head(&mut stream).await?;
    write_http1_response(&mut stream, Some("")).await?;
    let third = read_head(&mut stream).await?;
    write_http1_response(&mut stream, None).await?;
    Ok::<_, Box<dyn std::error::Error + Send + Sync>>([first, second, third])
}

#[tokio::test]
async fn http2_client_hints_share_one_session_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (first, mut first_response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", ACCEPT_CH_VALUE)
                    .body(())?,
                true,
            )?;

            let (second, mut second_response) = accept_http2(&mut connection).await?;
            assert_hints(second.headers(), true)?;
            second_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "")
                    .body(())?,
                true,
            )?;

            let (third, mut third_response) = accept_http2(&mut connection).await?;
            assert_hints(third.headers(), false)?;
            third_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((
                first,
                first_response,
                second,
                second_response,
                third,
                third_response,
            ));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let session = client(&identity)?;
        let url = format!("https://{address}/");
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_alps_accept_ch_applies_to_the_first_request_without_a_probe() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let application_settings = accept_ch_alps(&origin, ACCEPT_CH_VALUE);
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"caller\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((request, response));

            let outcome: TestResult<()> = tokio::select! {
                request = connection.accept() => {
                    match request {
                        Some(Ok(_)) => Err("client sent an unexpected HTTP/2 probe request".into()),
                        Some(Err(error)) => Err(error.into()),
                        None => Err("HTTP/2 connection closed before client completion".into()),
                    }
                }
                result = wait_for_client => {
                    result.map_err(|_| "client stopped before HTTP/2 response completion".into())
                }
            };
            outcome
        });

        let response = alps_client(&identity)?
            .get(HttpProtocol::Http2, &format!("{origin}/"))?
            .header(RequestHeader::new("sec-ch-ua-arch", "\"caller\""))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http2_applies_alps_and_retains_response_accept_ch() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let application_settings = accept_ch_alps(&origin, ACCEPT_CH_VALUE);
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let server = tokio::spawn(async move {
            let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"caller\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((request, response));
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"arm\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((request, response));
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = alps_client(&identity)?;
        let response = client
            .get_negotiated(&format!("{origin}/"))?
            .header(RequestHeader::new("sec-ch-ua-arch", "\"caller\""))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        let response = client
            .get_negotiated(&format!("{origin}/retained"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);
        server.await??;
        Ok(())
    })
    .await
}

/// The first connection's ACCEPT_CH restarts the request with
/// `Sec-CH-UA-Arch`; the graceful-GOAWAY replacement's names
/// `Sec-CH-UA-Platform-Version`, so the request restarts again and keeps the
/// first hint, as Chromium merges each restart's hints into the request.
#[tokio::test]
async fn http2_replacement_restart_keeps_the_hint_the_first_connection_asked_for() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let first_settings = accept_ch_alps(&origin, "Sec-CH-UA-Arch");
        let replacement_settings = accept_ch_alps(&origin, "Sec-CH-UA-Platform-Version");
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut first = accept_tls_with_alps(&listener, &acceptor, &first_settings).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let replacement =
                accept_tls_with_alps(&listener, &acceptor, &replacement_settings).await?;
            let mut connection = ::http2::server::handshake(replacement).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_hints(request.headers(), true)?;
            // The request already carries the critical hint, so no
            // Critical-CH retry follows.
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("critical-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((request, response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let response = alps_client(&identity)?
            .get(HttpProtocol::Http2, &format!("{origin}/replacement"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

/// A hint learned while a request waits for admission reaches only the next
/// request: the waiting request's fields were fixed when it was built, as
/// Chromium fixes a request's hints before it asks for a connection.
#[tokio::test]
async fn http2_hint_learned_while_a_request_waits_reaches_only_the_next_request() -> TestResult<()>
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (first_arrived, wait_for_first) = oneshot::channel();
        let (answer_first, wait_to_answer) = oneshot::channel::<()>();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut first_response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            let _ = first_arrived.send(());
            // The connection must keep running while the answer is held.
            tokio::select! {
                result = poll_fn(|context| connection.poll_closed(context)) => {
                    result?;
                    return Err("HTTP/2 client closed before the first answer".into());
                }
                result = wait_to_answer => {
                    result.map_err(|_| "client stopped before the first answer")?;
                }
            }
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", ACCEPT_CH_VALUE)
                    .body(())?,
                true,
            )?;

            let (waiting, mut waiting_response) = accept_http2(&mut connection).await?;
            assert_hints(waiting.headers(), false)?;
            waiting_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            let (next, mut next_response) = accept_http2(&mut connection).await?;
            assert_hints(next.headers(), true)?;
            next_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((first, waiting, waiting_response, next, next_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        // One active request per origin, so the second waits for the first.
        let session = Client::builder(
            ClientProfile::new(tls_settings())
                .with_http2(chrome::v154_http2())
                .with_client_hints(client_hint_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .max_concurrent_http2_requests_per_origin(std::num::NonZeroUsize::MIN)
        .max_pending_http2_requests_per_origin(std::num::NonZeroUsize::MIN)
        .build()?;
        let url = format!("https://{address}/");
        let first = tokio::spawn({
            let session = session.clone();
            let url = url.clone();
            async move { send_and_drain(&session, HttpProtocol::Http2, &url).await }
        });
        wait_for_first
            .await
            .map_err(|_| "server stopped before the first request")?;
        let mut waiting = Box::pin(send_and_drain(&session, HttpProtocol::Http2, &url));
        require_waiting_http2_admission(waiting.as_mut(), &session, &url).await?;
        answer_first
            .send(())
            .map_err(|_| "server stopped before the first answer")?;
        first.await??;
        waiting.await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

async fn require_waiting_http2_admission<F>(
    mut waiting: Pin<&mut F>,
    session: &Client,
    url: &str,
) -> TestResult<()>
where
    F: std::future::Future<Output = TestResult<()>>,
{
    loop {
        let selected =
            poll_fn(|context| std::task::Poll::Ready(waiting.as_mut().poll(context))).await;
        match selected {
            std::task::Poll::Pending => {}
            std::task::Poll::Ready(Ok(())) => {
                return Err("selected HTTP/2 request completed before the first response".into());
            }
            std::task::Poll::Ready(Err(error)) => return Err(error),
        }

        let observed = {
            let mut probe = std::pin::pin!(session.get(HttpProtocol::Http2, url)?.send());
            poll_fn(|context| std::task::Poll::Ready(probe.as_mut().poll(context))).await
        };
        match observed {
            std::task::Poll::Ready(Err(error)) => {
                if error.kind() != RequestErrorKind::Capacity
                    || error.protocol() != Some(HttpProtocol::Http2)
                {
                    return Err(error.into());
                }
                // Capacity proves that the selected request owns the only waiting slot.
                return Ok(());
            }
            std::task::Poll::Ready(Ok(_)) => {
                return Err("HTTP/2 queue probe was admitted before the first response".into());
            }
            std::task::Poll::Pending => {}
        }

        // A pending probe must release its reservation before the selected request advances.
        tokio::task::yield_now().await;
    }
}

/// Chromium restarts only navigations for a connection's ACCEPT_CH, so a
/// fetch template's request goes out once, as built, and succeeds.
#[tokio::test]
async fn http2_fetch_template_on_an_alps_accept_ch_connection_is_sent_as_built() -> TestResult<()> {
    bounded(async {
        let (identity, origin, server) = alps_origin_answering("Sec-CH-UA-Arch").await?;
        let names = finish_hint_operation(server, async {
            let template =
                PreparedRequestTemplate::new(chrome::v154_windows_fetch_no_store_template())?;
            let response = alps_client_with_hints(&identity, chrome::v154_windows_client_hints())?
                .get(HttpProtocol::Http2, &format!("{origin}/"))?
                .template(&template)
                .header(RequestHeader::new("referer", format!("{origin}/").as_str()))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
            Ok(())
        })
        .await?;
        assert!(
            !names.iter().any(|name| name == "sec-ch-ua-arch"),
            "{names:?}"
        );
        assert!(names.iter().any(|name| name == "sec-ch-ua"), "{names:?}");
        Ok(())
    })
    .await
}

/// A navigation template restarts, and the hint the restart added goes
/// after `accept` and before `sec-fetch-site`, where Chromium's header merge
/// appends it to the navigation's own fields.
#[tokio::test]
async fn http2_navigation_template_restart_places_the_hint_after_accept() -> TestResult<()> {
    bounded(async {
        let (identity, origin, server) = alps_origin_answering("Sec-CH-UA-Arch").await?;
        let names = finish_hint_operation(server, async {
            let template =
                PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;
            let response = alps_client_with_hints(&identity, chrome::v154_windows_client_hints())?
                .get(HttpProtocol::Http2, &format!("{origin}/"))?
                .template(&template)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            response.into_body().collect().await?;
            Ok(())
        })
        .await?;
        let accept = names
            .iter()
            .position(|name| name == "accept")
            .ok_or("no accept field")?;
        assert_eq!(
            names[accept + 1..accept + 3],
            ["sec-ch-ua-arch", "sec-fetch-site"],
            "{names:?}"
        );
        assert_eq!(
            names.first().map(String::as_str),
            Some("sec-ch-ua"),
            "{names:?}"
        );
        Ok(())
    })
    .await
}

/// Starts a TLS 1.3 H2 origin whose ALPS names `accept_ch` for itself, and
/// returns the field names, in order, of the one request it answers. It fails
/// if a second request follows.
async fn alps_origin_answering(
    accept_ch: &str,
) -> TestResult<(
    TestIdentity,
    String,
    tokio::task::JoinHandle<TestResult<Vec<String>>>,
)> {
    alps_origin_answering_with_io(accept_ch, |stream| stream, None).await
}

struct AlpsRequestObservation {
    method: http::Method,
    uri: http::Uri,
    version: Version,
    headers: HeaderMap,
    ordered_names: Vec<String>,
    body_ended: bool,
}

async fn alps_origin_answering_with_io<I>(
    accept_ch: &str,
    wrap_io: impl FnOnce(SslStream<TcpStream>) -> I + Send + 'static,
    observed: Option<oneshot::Sender<AlpsRequestObservation>>,
) -> TestResult<(
    TestIdentity,
    String,
    tokio::task::JoinHandle<TestResult<Vec<String>>>,
)>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin = format!("https://{}", listener.local_addr()?);
    let application_settings = accept_ch_alps(&origin, accept_ch);
    let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    let acceptor = acceptor.build();
    let server = tokio::spawn(async move {
        let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
        answer_alps_request(wrap_io(stream), observed).await
    });
    Ok((identity, origin, server))
}

async fn answer_alps_request<I>(
    stream: I,
    observed: Option<oneshot::Sender<AlpsRequestObservation>>,
) -> TestResult<Vec<String>>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut response) = accept_http2(&mut connection).await?;
    let names = observed_names(&request)?;

    if let Some(observed) = observed {
        observed
            .send(AlpsRequestObservation {
                method: request.method().clone(),
                uri: request.uri().clone(),
                version: request.version(),
                headers: request.headers().clone(),
                ordered_names: names.clone(),
                body_ended: request.body().is_end_stream(),
            })
            .map_err(|_| "ALPS request observation receiver disappeared")?;
    }

    response.send_response(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())?,
        true,
    )?;
    drop((request, response));
    match timeout(Duration::from_millis(200), connection.accept()).await {
        Ok(Some(Ok(_))) => Err("the server saw a second request".into()),
        Ok(Some(Err(error))) => Err(error.into()),
        Ok(None) | Err(_) => Ok(names),
    }
}

/// A restart writes nothing of the request, so a one-shot streaming body
/// goes out unpolled with the restarted request.
#[tokio::test]
async fn http2_alps_accept_ch_restart_sends_a_streaming_body_once() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let application_settings = accept_ch_alps(&origin, "Sec-CH-UA-Platform-Version");
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            let mut body = request.into_body();
            let mut received = Vec::new();
            while let Some(chunk) = poll_fn(|context| {
                if let std::task::Poll::Ready(item) = body.poll_data(context) {
                    return std::task::Poll::Ready(item.transpose());
                }
                // The connection must run for the body to arrive.
                match connection.poll_closed(context) {
                    std::task::Poll::Ready(result) => std::task::Poll::Ready(result.map(|()| None)),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await?
            {
                received.extend_from_slice(&chunk);
            }
            assert_eq!(received, b"one-shot");
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop(response);
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let response = alps_client(&identity)?
            .request(
                HttpProtocol::Http2,
                http::Method::POST,
                &format!("{origin}/"),
            )?
            .streaming_body(Full::new(Bytes::from_static(b"one-shot")))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

/// A BoringSSL QUIC server whose ALPS names `Sec-CH-UA-Platform-Version` in
/// ACCEPT_CH sees one request on the connection, carrying that hint: the
/// request restarted before anything of it was written.
#[tokio::test]
async fn http3_alps_accept_ch_restarts_the_request_with_the_missing_hint() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // The ALPS entry names the origin, whose port is known only once the
        // endpoint is bound.
        let alps_origin = Arc::new(OnceLock::new());
        let endpoint = quic_server(
            ::quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::new(
                http3_alps_context(&identity, Arc::clone(&alps_origin))?,
            ))),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let origin = format!("https://{address}");
        alps_origin
            .set(origin.clone())
            .map_err(|_| "ALPS origin set twice")?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (request, mut stream, mut connection) = accept_request(&endpoint).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert!(!request.headers().contains_key("sec-ch-ua-arch"));
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            drop(stream);
            tokio::select! {
                request = connection.accept() => match request {
                    Ok(Some(_)) => return Err("client sent a second HTTP/3 request".into()),
                    Ok(None) => return Err("HTTP/3 client closed before completion".into()),
                    Err(error) => return Err(error.into()),
                },
                result = wait_for_client => {
                    result.map_err(|_| "client stopped before HTTP/3 response completion")?;
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut tls = h3_support::client_tls_settings();
        tls.alps = Some(AlpsSettings {
            protocol: Box::from(&b"h3"[..]),
            settings: Box::default(),
            use_new_codepoint: true,
        });
        let profile = ClientProfile::new(tls_settings())
            .with_http3(Http3ClientSettings::new(
                tls,
                chrome::v154_quic(),
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            ))
            .with_client_hints(client_hint_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let response = client
            .get(HttpProtocol::Http3, &format!("{origin}/"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        let _ = client_done.send(());
        server.await??;
        Ok(())
    })
    .await
}

/// A navigation template's HTTP/3 request restarts, and the hint it lacked
/// goes after `accept` and before `sec-fetch-site`, as on HTTP/2.
#[tokio::test]
async fn http3_navigation_template_restart_places_the_hint_after_accept() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let alps_origin = Arc::new(OnceLock::new());
        let endpoint = quic_server(
            ::quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::new(
                http3_alps_context(&identity, Arc::clone(&alps_origin))?,
            ))),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let origin = format!("https://{}", endpoint.local_addr()?);
        alps_origin
            .set(origin.clone())
            .map_err(|_| "ALPS origin set twice")?;
        let (client_done, wait_for_client) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            let names = observed_names(&request)?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            let _ = wait_for_client.await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(names)
        });

        let mut tls = h3_support::client_tls_settings();
        tls.alps = Some(AlpsSettings {
            protocol: Box::from(&b"h3"[..]),
            settings: Box::default(),
            use_new_codepoint: true,
        });
        let profile = ClientProfile::new(tls_settings())
            .with_http3(Http3ClientSettings::new(
                tls,
                chrome::v154_quic(),
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            ))
            .with_client_hints(chrome::v154_windows_client_hints());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let template = PreparedRequestTemplate::new(chrome::v154_windows_navigation_template())?;
        let response = client
            .get(HttpProtocol::Http3, &format!("{origin}/"))?
            .template(&template)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        let _ = client_done.send(());
        let names = server.await??;
        let accept = names
            .iter()
            .position(|name| name == "accept")
            .ok_or("no accept field")?;
        assert_eq!(
            names[accept + 1..accept + 3],
            ["sec-ch-ua-platform-version", "sec-fetch-site"],
            "{names:?}"
        );
        Ok(())
    })
    .await
}

/// A TLS 1.3 context for `h3` whose every connection sends an HTTP/3
/// ACCEPT_CH frame through ALPS for `origin`, once it is set.
fn http3_alps_context(
    identity: &TestIdentity,
    origin: Arc<OnceLock<String>>,
) -> TestResult<btls::ssl::SslContext> {
    let mut acceptor = identity.acceptor_builder(b"\x02h3")?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    acceptor.set_select_certificate_callback(move |mut hello| {
        let Some(origin) = origin.get() else {
            return Err(btls::ssl::SelectCertError::ERROR);
        };
        let settings = http3_accept_ch_alps(origin, "Sec-CH-UA-Platform-Version");
        let ssl = hello.ssl_mut();
        ssl.add_application_settings_with_payload(b"h3", &settings)
            .map_err(|_| btls::ssl::SelectCertError::ERROR)?;
        ssl.set_alps_use_new_codepoint(true);
        Ok(())
    });
    Ok(acceptor.build().into_context())
}

/// Encodes an HTTP/3 ACCEPT_CH frame (type 0x89) with one entry.
fn http3_accept_ch_alps(origin: &str, value: &str) -> Vec<u8> {
    let mut entry = Vec::new();
    push_varint(&mut entry, origin.len());
    entry.extend_from_slice(origin.as_bytes());
    push_varint(&mut entry, value.len());
    entry.extend_from_slice(value.as_bytes());
    let mut frame = Vec::new();
    push_varint(&mut frame, 0x89);
    push_varint(&mut frame, entry.len());
    frame.extend(entry);
    frame
}

/// Appends a QUIC variable-length integer of at most two bytes.
fn push_varint(buffer: &mut Vec<u8>, value: usize) {
    match (u8::try_from(value), u16::try_from(value)) {
        (Ok(byte), _) if byte < 0x40 => buffer.push(byte),
        (_, Ok(two)) if two < 0x4000 => buffer.extend((0x4000 | two).to_be_bytes()),
        _ => panic!("test ALPS value exceeds a two-byte varint"),
    }
}

#[tokio::test]
async fn http3_client_hints_share_one_session_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(answer_http3_hint_requests(endpoint, wait_for_client, None));

        let session = client(&identity)?;
        let url = format!("https://{address}/");
        finish_hint_operation(server, async {
            send_and_drain(&session, HttpProtocol::Http3, &url).await?;
            send_and_drain(&session, HttpProtocol::Http3, &url).await?;
            send_and_drain(&session, HttpProtocol::Http3, &url).await?;
            let _ = client_done.send(());
            drop(session);
            Ok(())
        })
        .await?;
        Ok(())
    })
    .await
}

async fn answer_http3_hint_requests(
    endpoint: ::quinn::Endpoint,
    wait_for_client: oneshot::Receiver<()>,
    observed: Option<oneshot::Sender<Request<()>>>,
) -> TestResult<()> {
    let (first, mut first_stream, mut connection) = accept_request(&endpoint).await?;
    assert_hints(first.headers(), false)?;
    first_stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("accept-ch", ACCEPT_CH_VALUE)
                .body(())?,
        )
        .await?;
    first_stream.finish().await?;
    drop(first_stream);
    if let Some(observed) = observed {
        observed
            .send(first.clone())
            .map_err(|_| "HTTP/3 hint observer disappeared")?;
    }

    let resolver = connection
        .accept()
        .await?
        .ok_or("HTTP/3 connection closed before learned request")?;
    let (second, mut second_stream) = resolver.resolve_request().await?;
    assert_hints(second.headers(), true)?;
    second_stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("accept-ch", "")
                .body(())?,
        )
        .await?;
    second_stream.finish().await?;
    drop(second_stream);

    let resolver = connection
        .accept()
        .await?
        .ok_or("HTTP/3 connection closed before cleared request")?;
    let (third, mut third_stream) = resolver.resolve_request().await?;
    assert_hints(third.headers(), false)?;
    third_stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
        )
        .await?;
    third_stream.finish().await?;
    wait_for_client
        .await
        .map_err(|_| "client stopped before HTTP/3 response completion")?;
    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
}

#[tokio::test]
async fn critical_ch_retries_once_with_only_supported_requested_hints() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut first_response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .header("critical-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .body(())?,
                true,
            )?;

            let (retry, mut retry_response) = accept_http2(&mut connection).await?;
            assert_eq!(
                retry.headers().get("sec-ch-ua-arch"),
                Some(&"\"arm\"".parse()?)
            );
            assert!(!retry.headers().contains_key("sec-ch-unknown"));
            retry_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .header("critical-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .body(())?,
                true,
            )?;
            drop((first, first_response, retry, retry_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let response = client(&identity)?
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .retry_policy(phantom::RetryPolicy::none().with_max_retries(Some(0)))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn critical_ch_retry_rejects_a_consumed_streaming_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut first_response) = accept_http2(&mut connection).await?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", "Sec-CH-UA-Arch")
                    .header("critical-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((first, first_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let result = client(&identity)?
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .streaming_body(Full::new(Bytes::from_static(b"one-shot")))
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("Critical-CH retry replayed a one-shot streaming body".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_retains_accept_ch_across_requests() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(&listener, &acceptor).await?;
            let first = read_head(&mut stream).await?;
            write_http1_response(&mut stream, Some(ACCEPT_CH_VALUE)).await?;
            let second = read_head(&mut stream).await?;
            write_http1_response(&mut stream, None).await?;
            let observed = vec![first, second];
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let client = client(&identity)?;
        let url = format!("https://{address}/");
        send_client_and_drain(&client, HttpProtocol::Http1, &url).await?;
        send_client_and_drain(&client, HttpProtocol::Http1, &url).await?;
        let requests = server.await??;
        assert_http1_hints(&requests[0], false)?;
        assert_http1_hints(&requests[1], true)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cloned_clients_share_client_hints_while_new_clients_are_isolated() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut shared = accept_tls(&listener, &acceptor).await?;
            let first = read_head(&mut shared).await?;
            write_http1_response(&mut shared, Some("Sec-CH-UA-Arch")).await?;
            let cloned = read_head(&mut shared).await?;
            write_http1_response(&mut shared, None).await?;
            let cleared = read_head(&mut shared).await?;
            write_http1_response(&mut shared, None).await?;

            let mut isolated = accept_tls(&listener, &acceptor).await?;
            let separate = read_head(&mut isolated).await?;
            write_http1_response(&mut isolated, None).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>([first, cloned, cleared, separate])
        });

        let shared = client(&identity)?;
        let clone = shared.clone();
        let url = format!("https://{address}/");
        send_and_drain(&shared, HttpProtocol::Http1, &url).await?;
        send_and_drain(&clone, HttpProtocol::Http1, &url).await?;
        shared.clear_client_hints();
        send_and_drain(&shared, HttpProtocol::Http1, &url).await?;
        send_and_drain(&client(&identity)?, HttpProtocol::Http1, &url).await?;

        let requests = server.await??;
        assert_http1_hints(&requests[0], false)?;
        assert!(std::str::from_utf8(&requests[1])?.contains("\r\nsec-ch-ua-arch: \"arm\"\r\n"));
        assert_http1_hints(&requests[2], false)?;
        assert_http1_hints(&requests[3], false)?;
        Ok(())
    })
    .await
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(client_settings())
        .with_client_hints(client_hint_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn alps_client(identity: &TestIdentity) -> TestResult<Client> {
    alps_client_with_hints(identity, client_hint_settings())
}

fn alps_client_with_hints(
    identity: &TestIdentity,
    hints: ClientHintSettings,
) -> TestResult<Client> {
    let mut tls = tls_settings();
    tls.versions = phantom_profile::TlsVersionRange::only(TlsVersion::Tls13);
    tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    tls.key_shares = vec![NamedGroup::X25519];
    tls.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h2"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });
    let profile = ClientProfile::new(tls)
        .with_http2(chrome::v154_http2())
        .with_client_hints(hints);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn client_hint_settings() -> ClientHintSettings {
    ClientHintSettings::new(vec![
        ClientHint::new("sec-ch-ua", "baseline", ClientHintDelivery::Default),
        ClientHint::new("sec-ch-ua-arch", "\"arm\"", ClientHintDelivery::AcceptCh),
        ClientHint::new(
            "sec-ch-ua-platform-version",
            "\"15.5.0\"",
            ClientHintDelivery::AcceptCh,
        ),
    ])
}

async fn finish_hint_operation<T, F>(
    peer: tokio::task::JoinHandle<TestResult<T>>,
    operation: F,
) -> TestResult<T>
where
    F: std::future::Future<Output = TestResult<()>>,
{
    operation.await?;
    peer.await?
}

async fn send_and_drain(client: &Client, protocol: HttpProtocol, url: &str) -> TestResult<()> {
    let response = client.get(protocol, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

async fn send_client_and_drain(
    client: &Client,
    protocol: HttpProtocol,
    url: &str,
) -> TestResult<()> {
    let response = client.get(protocol, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn accept_tls_with_alps(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    application_settings: &[u8],
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.add_application_settings_with_payload(b"h2", application_settings)?;
    ssl.set_alps_use_new_codepoint(true);
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

fn accept_ch_alps(origin: &str, value: &str) -> Vec<u8> {
    let Ok(origin_len) = u16::try_from(origin.len()) else {
        panic!("test origin exceeds the HTTP/2 ALPS field width");
    };
    let Ok(value_len) = u16::try_from(value.len()) else {
        panic!("test value exceeds the HTTP/2 ALPS field width");
    };
    let payload_len = 4 + origin.len() + value.len();
    let mut encoded = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
    encoded.extend([
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
        0x89,
        0,
        0,
        0,
        0,
        0,
    ]);
    encoded.extend(origin_len.to_be_bytes());
    encoded.extend(origin.as_bytes());
    encoded.extend(value_len.to_be_bytes());
    encoded.extend(value.as_bytes());
    encoded
}

async fn write_http1_response(
    stream: &mut SslStream<TcpStream>,
    accept_ch: Option<&str>,
) -> TestResult<()> {
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n")
        .await?;
    if let Some(value) = accept_ch {
        stream.write_all(b"Accept-CH: ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

async fn accept_http2<I>(
    connection: &mut ::http2::server::Connection<I, bytes::Bytes>,
) -> TestResult<(
    Request<::http2::RecvStream>,
    ::http2::server::SendResponse<bytes::Bytes>,
)>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    connection
        .accept()
        .await
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "HTTP/2 connection closed before request".into()
        })?
        .map_err(Into::into)
}

async fn drive_http2_until_client_done(
    connection: &mut ::http2::server::Connection<SslStream<TcpStream>, bytes::Bytes>,
    wait_for_client: oneshot::Receiver<()>,
) -> TestResult<()> {
    tokio::select! {
        result = poll_fn(|context| connection.poll_closed(context)) => {
            result?;
            Err("HTTP/2 client closed before response completion".into())
        }
        result = wait_for_client => {
            result.map_err(|_| "client stopped before HTTP/2 response completion".into())
        }
    }
}

fn observed_names<T>(request: &Request<T>) -> TestResult<Vec<String>> {
    let ordered = match request.version() {
        Version::HTTP_2 => request
            .extensions()
            .get::<::http2::ext::OrderedHeaders>()
            .ok_or("HTTP/2 hint request omitted decoded header order")?
            .as_slice(),
        Version::HTTP_3 => request
            .extensions()
            .get::<h3::ext::OrderedHeaders>()
            .ok_or("HTTP/3 hint request omitted decoded header order")?
            .as_slice(),
        _ => return Err("hint order observer requires HTTP/2 or HTTP/3".into()),
    };

    Ok(ordered
        .iter()
        .map(|(name, _)| name.as_str().to_owned())
        .collect())
}

fn assert_hints(headers: &http::HeaderMap, high_entropy: bool) -> TestResult<()> {
    assert_hint_value(headers, "sec-ch-ua", Some("baseline"))?;
    assert_hint_value(headers, "sec-ch-ua-arch", high_entropy.then_some("\"arm\""))?;
    assert_hint_value(
        headers,
        "sec-ch-ua-platform-version",
        high_entropy.then_some("\"15.5.0\""),
    )?;
    Ok(())
}

fn assert_hint_value(headers: &HeaderMap, name: &str, expected: Option<&str>) -> TestResult<()> {
    match expected {
        Some(value) => {
            assert_eq!(headers.get_all(name).iter().count(), 1, "{name}");
            assert_eq!(headers.get(name), Some(&value.parse()?), "{name}");
        }
        None => assert!(!headers.contains_key(name), "unsolicited {name}"),
    }

    Ok(())
}

fn assert_http1_hints(head: &[u8], high_entropy: bool) -> TestResult<()> {
    let text = std::str::from_utf8(head)?;
    let block = text
        .strip_suffix("\r\n\r\n")
        .ok_or("incomplete HTTP/1 hint head")?;

    let (_, fields) = block
        .split_once("\r\n")
        .ok_or("HTTP/1 hint head has no headers")?;

    let mut headers = HeaderMap::new();
    for field in fields.split("\r\n") {
        let (name, value) = field
            .split_once(':')
            .ok_or("HTTP/1 hint header has no separator")?;
        let name: HeaderName = name.parse()?;
        let value: HeaderValue = value.trim_matches([' ', '\t']).parse()?;
        headers.append(name, value);
    }

    assert_hints(&headers, high_entropy)
}

async fn bounded<F, T>(future: F) -> TestResult<T>
where
    F: std::future::Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|source| HintDeadline { source })?
}

#[test]
fn caller_header_type_remains_public_for_overrides() {
    let header = RequestHeader::new("sec-ch-ua", "caller");
    assert_eq!(header.name(), "sec-ch-ua");
}
