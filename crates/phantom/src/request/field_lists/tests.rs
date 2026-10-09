//! A negotiated request builds and checks each field list once per hop, and
//! again only after a response.

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use bytes::Bytes;
use http::StatusCode;
use phantom_profile::{ClientProfile, Http3ClientSettings, browser::chrome};
use phantom_testkit::tcp::ReservedPort;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use super::counts::{self, Counts};
use crate::{
    AddressResolver, AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot,
    AltSvcSnapshotEntry, Client, ClientBuilder, HttpProtocol, ResponseInfo, RetryPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ORIGIN_NAME: &str = "origin.phantom.test";
const H1_ALPN: &[u8] = b"\x08http/1.1";
const H2_ALPN: &[u8] = b"\x02h2";
const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// One build and one check of the HTTP/1.1 and HTTP/2 lists.
const NEGOTIATED_ONCE: Counts = Counts {
    built: [1, 1, 0],
    checked: [1, 1, 0],
};

/// One build and one check of each list.
const RACED_ONCE: Counts = Counts {
    built: [1, 1, 1],
    checked: [1, 1, 1],
};

#[tokio::test]
async fn a_race_won_by_the_origin_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept(&listener, &acceptor).await?;
            read_head(&mut stream).await?;
            stream.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(stream)
        });
        // The alternative's datagrams reach a socket that never answers, so
        // the origin wins.
        let blackhole = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let client = racing_client(&identity, Duration::ZERO)?;
        import_alternative(&client, origin, blackhole.local_addr()?.port())?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(counts::take(), RACED_ONCE);
        assert_eq!(protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(server.await??);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_race_won_by_the_alternative_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        // The origin waits longer than the test runs, so the alternative
        // wins; nothing connects to this listener.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let endpoint = identity.http3_endpoint()?;
        let alternative = endpoint.local_addr()?;
        let server = tokio::spawn(serve_http3(endpoint));
        let client = racing_client(&identity, TEST_TIMEOUT)?;
        import_alternative(&client, origin, alternative.port())?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(counts::take(), RACED_ONCE);
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(client);
        server.await??;
        drop(listener);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_negotiated_setup_retry_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        // The first connect is refused; the retry's lookup starts the
        // listener before it connects.
        let reserved = ReservedPort::bind()?;
        let port = reserved.address().port();
        let (listening, listener) = oneshot::channel();
        let resolver = listening_on_second_lookup(reserved, listening);
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let listener = listener.await??;
            let mut stream = accept(&listener, &acceptor).await?;
            read_head(&mut stream).await?;
            stream.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(stream)
        });
        let client = client_builder(&identity, profile(false))
            .dns_resolver(resolver)
            .build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}/"))?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::from_millis(10),
            ))
            .send()
            .await?;

        assert_eq!(counts::take(), NEGOTIATED_ONCE);
        assert_eq!(info(&response)?.retries_performed(), 1);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(server.await??);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_negotiated_graceful_goaway_retry_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        // The first connection selects h2 and the replacement http/1.1, so
        // the retry sends the other list.
        let acceptor = identity.acceptor_selecting(&[H2_ALPN, H1_ALPN])?;
        let server = tokio::spawn(async move {
            let mut first = accept(&listener, &acceptor).await?;
            accept_http2_preface(&mut first).await?;
            read_http2_headers(&mut first, 1).await?;
            // GOAWAY(NO_ERROR) with last-stream-id 0: stream 1 was not
            // processed.
            write_http2_frame(&mut first, 0x7, 0, 0, &[0; 8]).await?;
            first.flush().await?;
            first.shutdown().await?;
            let mut replacement = accept(&listener, &acceptor).await?;
            read_head(&mut replacement).await?;
            replacement.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(replacement)
        });
        let client = client_builder(&identity, profile(false)).build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(counts::take(), NEGOTIATED_ONCE);
        assert_eq!(protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(server.await??);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_reused_connection_replay_sends_the_lists_of_the_closed_attempt() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut reused = accept(&listener, &acceptor).await?;
            read_head(&mut reused).await?;
            reused.write_all(OK_RESPONSE).await?;
            // The second request reaches the reused connection, which
            // closes before any response byte.
            let closed = read_head(&mut reused).await?;
            reused.shutdown().await?;
            drop(reused);
            let mut fresh = accept(&listener, &acceptor).await?;
            let replayed = read_head(&mut fresh).await?;
            fresh.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((closed, replayed, fresh))
        });
        let client = client_builder(&identity, profile(false))
            .retry_policy(RetryPolicy::none().with_reused_connection_replay(true))
            .build()?;
        let url = format!("https://{origin}/");
        let first = client.get_negotiated(&url)?.send().await?;
        assert_eq!(first.into_body().collect_with_limit(16).await?, "ok");
        counts::take();

        let response = client.get_negotiated(&url)?.send().await?;

        assert_eq!(counts::take(), NEGOTIATED_ONCE);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        let (closed, replayed, _fresh) = server.await??;
        assert_eq!(closed, replayed);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_refused_http2_stream_replay_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        // The refusing connection selects h2 and the replacement http/1.1,
        // so the replay sends the other list.
        let acceptor = identity.acceptor_selecting(&[H2_ALPN, H1_ALPN])?;
        let server = tokio::spawn(async move {
            let mut refusing = accept(&listener, &acceptor).await?;
            accept_http2_preface(&mut refusing).await?;
            read_http2_headers(&mut refusing, 1).await?;
            // RST_STREAM(REFUSED_STREAM): stream 1 was not processed.
            write_http2_frame(&mut refusing, 0x3, 0, 1, &[0, 0, 0, 0x7]).await?;
            refusing.flush().await?;
            let mut replacement = accept(&listener, &acceptor).await?;
            read_head(&mut replacement).await?;
            replacement.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((refusing, replacement))
        });
        let client = client_builder(&identity, profile(false))
            .retry_policy(unprocessed_replay())
            .build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(counts::take(), NEGOTIATED_ONCE);
        assert_eq!(protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(server.await??);
        Ok(())
    })
    .await?
}

/// A resend after the H2 connection's PING failed sends the lists of the
/// failed attempt, built once for the hop.
#[tokio::test]
async fn a_ping_failure_resend_builds_each_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        // The connection whose PING fails selects h2 and the replacement
        // http/1.1, so the resend sends the other list.
        let acceptor = identity.acceptor_selecting(&[H2_ALPN, H1_ALPN])?;
        let server = tokio::spawn(async move {
            let mut silent = accept(&listener, &acceptor).await?;
            accept_http2_preface(&mut silent).await?;
            read_http2_headers(&mut silent, 1).await?;
            // `:status: 200` is static table entry 8.
            write_http2_frame(&mut silent, 0x1, 0x5, 1, &[0x88]).await?;
            silent.flush().await?;
            read_http2_headers(&mut silent, 3).await?;
            // The PING goes unanswered until the client's GOAWAY.
            while read_http2_frame(&mut silent).await?.0 != 0x7 {}
            let mut replacement = accept(&listener, &acceptor).await?;
            read_head(&mut replacement).await?;
            replacement.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((silent, replacement))
        });
        let mut http2 = chrome::v154_http2();
        http2.preface_ping_after = Some(Duration::from_secs(1));
        http2.ping_timeout = Some(Duration::from_secs(2));
        let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(http2);
        let client = client_builder(&identity, profile).build()?;
        let first = client
            .get_negotiated(&format!("https://{origin}/first"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        drop(first);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(counts::take(), NEGOTIATED_ONCE);
        assert_eq!(protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(server.await??);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn an_alternative_replay_after_a_rejected_request_builds_its_list_once() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        // A client without a race sends the request to the alternative
        // only; nothing connects to this listener.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let endpoint = identity.http3_endpoint()?;
        let alternative = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut rejected, first) = accept_http3_request(&endpoint).await?;
            rejected.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            // The replay arrives on a new connection to this endpoint.
            let (mut replayed, mut second) = accept_http3_request(&endpoint).await?;
            answer_http3(&mut replayed).await?;
            let _ = second.accept().await;
            drop(first);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = alternative_client_builder(&identity)
            .retry_policy(unprocessed_replay())
            .build()?;
        import_alternative(&client, origin, alternative.port())?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(
            counts::take(),
            Counts {
                built: [0, 0, 1],
                checked: [0, 0, 1],
            }
        );
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        drop(client);
        server.await??;
        drop(listener);
        Ok(())
    })
    .await?
}

/// A `Critical-CH` retry follows a response that requested a hint, so the
/// retry builds its lists again and carries the hint.
#[tokio::test]
async fn a_critical_ch_retry_builds_the_lists_again_with_the_requested_hint() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept(&listener, &acceptor).await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nAccept-CH: sec-ch-ua-arch\r\n\
                      Critical-CH: sec-ch-ua-arch\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            let retried = read_head(&mut stream).await?;
            stream.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first, retried, stream))
        });
        let client = client_builder(
            &identity,
            profile(false).with_client_hints(chrome::v154_windows_client_hints()),
        )
        .build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(
            counts::take(),
            Counts {
                built: [2, 2, 0],
                checked: [2, 2, 0],
            }
        );
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        let (first, retried, _stream) = server.await??;
        let (first, retried) = (String::from_utf8(first)?, String::from_utf8(retried)?);
        assert!(!first.contains("sec-ch-ua-arch"), "{first}");
        assert!(
            retried.contains("\r\nsec-ch-ua-arch: \"x86\"\r\n"),
            "{retried}"
        );
        Ok(())
    })
    .await?
}

/// A connection whose ALPS `ACCEPT_CH` names a hint the request lacks
/// restarts the request before anything of it is sent; the restart builds
/// and checks the lists again with the hint, and the server sees one request.
#[tokio::test]
async fn an_accept_ch_restart_builds_the_lists_again_with_the_hint() -> TestResult {
    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let settings = http2_accept_ch_alps(&format!("https://{origin}"), "sec-ch-ua-arch");
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut ssl = Ssl::new(acceptor.context())?;
            ssl.add_application_settings_with_payload(b"h2", &settings)?;
            ssl.set_alps_use_new_codepoint(true);
            let mut stream = SslStream::new(ssl, tcp)?;
            Pin::new(&mut stream).accept().await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = connection
                .accept()
                .await
                .ok_or("client sent no request")??;
            let arch = request.headers().get("sec-ch-ua-arch").cloned();
            response.send_response(
                http::Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            // A second request on the connection would be the unrestarted one.
            let extra = timeout(Duration::from_millis(200), connection.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((arch, matches!(extra, Ok(Some(_)))))
        });
        let client = client_builder(
            &identity,
            profile(false).with_client_hints(chrome::v154_windows_client_hints()),
        )
        .build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(
            counts::take(),
            Counts {
                built: [2, 2, 0],
                checked: [2, 2, 0],
            }
        );
        assert_eq!(protocol(&response)?, HttpProtocol::Http2);
        let (arch, extra) = server.await??;
        drop(response);
        assert_eq!(
            arch.as_ref().map(http::HeaderValue::as_bytes),
            Some(&b"\"x86\""[..])
        );
        assert!(!extra, "the server saw a second request");
        Ok(())
    })
    .await?
}

/// Encodes HTTP/2 ALPS with an empty SETTINGS frame and one ACCEPT_CH entry.
fn http2_accept_ch_alps(origin: &str, value: &str) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend(
        u16::try_from(origin.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    entry.extend_from_slice(origin.as_bytes());
    entry.extend(u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    entry.extend_from_slice(value.as_bytes());
    let length = u32::try_from(entry.len()).unwrap_or(0).to_be_bytes();
    let mut encoded = vec![0, 0, 0, 0x4, 0, 0, 0, 0, 0];
    encoded.extend([length[1], length[2], length[3], 0x89, 0, 0, 0, 0, 0]);
    encoded.extend(entry);
    encoded
}

/// A status retry follows a response, which may store cookies, so the retry
/// builds its lists again and carries the cookie.
#[cfg(feature = "cookies")]
#[tokio::test]
async fn a_status_retry_builds_the_lists_again_with_the_response_s_cookie() -> TestResult {
    use crate::StatusRetry;

    timeout(TEST_TIMEOUT, async {
        let identity = Identity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept(&listener, &acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nSet-Cookie: retry=1\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await?;
            let retried = read_head(&mut stream).await?;
            stream.write_all(OK_RESPONSE).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((retried, stream))
        });
        let status_retry = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::from_millis(10),
        )?;
        let client = client_builder(&identity, profile(false))
            .cookies()
            .retry_policy(RetryPolicy::none().with_status_retry(status_retry))
            .build()?;
        counts::take();

        let response = client
            .get_negotiated(&format!("https://{origin}/"))?
            .send()
            .await?;

        assert_eq!(
            counts::take(),
            Counts {
                built: [2, 2, 0],
                checked: [2, 2, 0],
            }
        );
        assert_eq!(response.into_body().collect_with_limit(16).await?, "ok");
        let (retried, _stream) = server.await??;
        let retried = String::from_utf8(retried)?;
        assert!(retried.contains("\r\nCookie: retry=1\r\n"), "{retried}");
        Ok(())
    })
    .await?
}

/// The Chrome 154 recipes, which negotiate h2 or http/1.1, with HTTP/3 when
/// `http3` is set.
fn profile(http3: bool) -> ClientProfile {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
    if !http3 {
        return profile;
    }
    profile.with_http3(Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    ))
}

fn client_builder(identity: &Identity, profile: ClientProfile) -> ClientBuilder {
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

/// A client that sends a learned alternative's requests to it without a
/// race.
fn alternative_client_builder(identity: &Identity) -> ClientBuilder {
    client_builder(identity, profile(true)).alt_svc(NonZeroUsize::MIN.saturating_add(7))
}

fn racing_client(identity: &Identity, origin_delay: Duration) -> TestResult<Client> {
    let backoff = AltSvcBrokenBackoff::new(Duration::from_secs(60), Duration::from_secs(600))?;
    Ok(alternative_client_builder(identity)
        .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(origin_delay, backoff)))
        .build()?)
}

fn unprocessed_replay() -> RetryPolicy {
    RetryPolicy::none().with_unprocessed_replay(Some(NonZeroUsize::MIN))
}

/// Seeds an HTTP/3 alternative for `origin` without a request to it.
fn import_alternative(client: &Client, origin: SocketAddr, port: u16) -> TestResult {
    client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        format!("https://{origin}"),
        "127.0.0.1",
        port,
        SystemTime::now() + Duration::from_secs(3600),
    )]))?;
    Ok(())
}

/// Resolves every name to the loopback address, and on the second lookup
/// first starts `reserved` listening and sends its listener.
fn listening_on_second_lookup(
    reserved: ReservedPort,
    listening: oneshot::Sender<std::io::Result<TcpListener>>,
) -> AddressResolver {
    let pending = Mutex::new(Some((reserved, listening)));
    let lookups = AtomicUsize::new(0);
    AddressResolver::from_fn(move |_| {
        if lookups.fetch_add(1, Ordering::SeqCst) == 1
            && let Some((reserved, listening)) = pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        {
            let _ = listening.send(reserved.listen());
        }
        async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) }
    })
}

fn info<B>(response: &http::Response<B>) -> TestResult<&ResponseInfo> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or_else(|| "response omitted its metadata".into())
}

fn protocol<B>(response: &http::Response<B>) -> TestResult<HttpProtocol> {
    Ok(info(response)?.protocol())
}

/// A certificate for `127.0.0.1` and [`ORIGIN_NAME`], issued by a root the
/// client is told to trust.
struct Identity {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl Identity {
    fn generate() -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;
        let mut leaf_params = CertificateParams::new(Vec::<String>::new())?;
        leaf_params.subject_alt_names = vec![
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SanType::DnsName(ORIGIN_NAME.try_into()?),
        ];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf_key = KeyPair::generate()?;
        let leaf = leaf_params.signed_by(&leaf_key, &root)?;
        Ok(Self {
            root_der: root.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            private_key_der: leaf_key.serialize_der(),
        })
    }

    fn acceptor(&self, alpn: &'static [u8]) -> TestResult<SslAcceptor> {
        self.acceptor_selecting(&[alpn])
    }

    /// An acceptor whose `n`th handshake selects the `n`th protocol of
    /// `selections`, and the last one after that.
    fn acceptor_selecting(&self, selections: &[&'static [u8]]) -> TestResult<SslAcceptor> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(&self.leaf_der)?;
        acceptor.set_certificate(&certificate)?;
        let private_key = PKey::private_key_from_pkcs8(&self.private_key_der)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.add_extra_chain_cert(X509::from_der(&self.root_der)?)?;
        let selections = selections.to_vec();
        let handshakes = AtomicUsize::new(0);
        acceptor.set_alpn_select_callback(move |_, offered| {
            let handshake = handshakes.fetch_add(1, Ordering::SeqCst);
            let alpn = selections
                .get(handshake)
                .or_else(|| selections.last())
                .ok_or(AlpnError::NOACK)?;
            select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
        });
        Ok(acceptor.build())
    }

    fn http3_endpoint(&self) -> TestResult<quinn::Endpoint> {
        let certificate = CertificateDer::from(self.leaf_der.clone());
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.clone()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        Ok(quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
            phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
            Arc::new(quinn::TokioRuntime),
        )?)
    }
}

async fn accept(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

/// Reads one HTTP/1.1 request head.
async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(head)
}

type Http3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type Http3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Serves one HTTP/3 request with `200` and `ok`, then waits for the client
/// to close.
async fn serve_http3(endpoint: quinn::Endpoint) -> TestResult {
    let (mut stream, mut connection) = accept_http3_request(&endpoint).await?;
    answer_http3(&mut stream).await?;
    let _ = connection.accept().await;
    Ok(())
}

/// Accepts a connection and its first request.
async fn accept_http3_request(
    endpoint: &quinn::Endpoint,
) -> TestResult<(Http3Stream, Http3Connection)> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
    let mut connection = Http3Connection::new(h3_quinn::Connection::new(connection)).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before a request")?;
    let (_request, stream) = resolver.resolve_request().await?;
    Ok((stream, connection))
}

async fn answer_http3(stream: &mut Http3Stream) -> TestResult {
    stream
        .send_response(http::Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    Ok(())
}

/// Reads the client preface and its SETTINGS, then sends the server's
/// SETTINGS and acknowledges the client's.
async fn accept_http2_preface<T>(stream: &mut T) -> TestResult
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return Err("client omitted the HTTP/2 preface".into());
    }
    loop {
        let (kind, flags, stream_id) = read_http2_frame(stream).await?;
        if kind == 0x4 && stream_id == 0 && flags & 0x1 == 0 {
            break;
        }
    }
    write_http2_frame(stream, 0x4, 0, 0, &[]).await?;
    write_http2_frame(stream, 0x4, 0x1, 0, &[]).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads frames until the HEADERS frame of `stream_id`.
async fn read_http2_headers<T>(stream: &mut T, stream_id: u32) -> TestResult
where
    T: AsyncRead + Unpin,
{
    loop {
        let (kind, _, id) = read_http2_frame(stream).await?;
        if kind == 0x1 && id == stream_id {
            return Ok(());
        }
    }
}

/// Reads one frame and returns its type, flags, and stream identifier.
async fn read_http2_frame<T>(stream: &mut T) -> TestResult<(u8, u8, u32)>
where
    T: AsyncRead + Unpin,
{
    let mut head = [0; 9];
    stream.read_exact(&mut head).await?;
    let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    let stream_id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Ok((head[3], head[4], stream_id))
}

/// Writes one frame.
async fn write_http2_frame<T>(
    stream: &mut T,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> TestResult
where
    T: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len())?.to_be_bytes();
    let id = stream_id.to_be_bytes();
    stream
        .write_all(&[
            length[1], length[2], length[3], kind, flags, id[0], id[1], id[2], id[3],
        ])
        .await?;
    stream.write_all(payload).await?;
    Ok(())
}
