//! Public cookie-session integration tests.

#![cfg(feature = "cookies")]

#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    time::Duration,
};

use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, select_next_proto},
    x509::X509,
};
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode, header::COOKIE, header::SET_COOKIE};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RedirectPolicy, RequestHeader, Route, profile::ClientProfile,
    profile::chromium,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const LEARNED_COOKIES: [&str; 2] = ["root=one; Path=/", "deep=two; Path=/next"];
const ORDERED_COOKIE_VALUE: &str = "deep=two; root=one";
const ORDERED_HTTP1_COOKIE_FIELD: &str = "Cookie: deep=two; root=one";

#[tokio::test]
async fn redirect_learns_cookie_and_strips_caller_credentials_across_ports() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let first_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let first_address = first_listener.local_addr()?;
        let second_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let second_address = second_listener.local_addr()?;
        let first_acceptor = identity.acceptor(H2_ALPN)?;
        let second_acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let first = accept_tls(&first_listener, &first_acceptor).await?;
            let mut first_connection = ::http2::server::handshake(first).await?;
            let (initial, mut initial_response) = accept_http2(&mut first_connection).await?;
            assert_eq!(initial.uri().path(), "/start");
            assert_eq!(cookie_fields(initial.headers())?, ["manual=first"]);
            assert_eq!(
                initial.headers().get("authorization"),
                Some(&"secret".parse()?)
            );
            assert_eq!(
                initial.headers().get("proxy-authorization"),
                Some(&"proxy".parse()?)
            );
            assert_eq!(initial.headers().get("cookie2"), Some(&"legacy".parse()?));
            initial_response.send_response(
                Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("location", format!("https://{second_address}/final"))
                    .header(SET_COOKIE, "learned=redirect; Secure; Path=/")
                    .header("content-length", "0")
                    .body(())?,
                true,
            )?;
            drop(initial);
            drop(initial_response);
            let first_driver = tokio::spawn(async move {
                std::future::poll_fn(|context| first_connection.poll_closed(context)).await
            });

            let second = accept_tls(&second_listener, &second_acceptor).await?;
            let mut second_connection = ::http2::server::handshake(second).await?;
            let (followed, mut final_response) = accept_http2(&mut second_connection).await?;
            assert_eq!(followed.uri().path(), "/final");
            assert_eq!(cookie_fields(followed.headers())?, ["learned=redirect"]);
            assert!(!followed.headers().contains_key("authorization"));
            assert!(!followed.headers().contains_key("proxy-authorization"));
            assert!(!followed.headers().contains_key("cookie2"));
            final_response.send_response(Response::builder().status(204).body(())?, true)?;
            drop(followed);
            drop(final_response);
            let second_driver = tokio::spawn(async move {
                std::future::poll_fn(|context| second_connection.poll_closed(context)).await
            });
            wait_for_client
                .await
                .map_err(|_| "client stopped before redirected response completion")?;
            first_driver.abort();
            second_driver.abort();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let session = cookie_client(&identity)?
            .session_builder()
            .cookies()
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build();
        let response = session
            .get(
                HttpProtocol::Http2,
                &format!("https://{first_address}/start"),
            )?
            .headers(vec![
                RequestHeader::new("cookie", "manual=first").sensitive(),
                RequestHeader::new("authorization", "secret").sensitive(),
                RequestHeader::new("proxy-authorization", "proxy").sensitive(),
                RequestHeader::new("cookie2", "legacy").sensitive(),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "redirect server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http1_cookies_share_the_canonical_host_key() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for cookies in [&LEARNED_COOKIES[..], &[][..]] {
                let mut stream = accept_tls(&listener, &acceptor).await?;
                requests.push(read_head(&mut stream).await?);
                write_http1_response(&mut stream, cookies).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        let client = cookie_client(&identity)?;
        let session = client.session_builder().cookies().build();
        send_and_drain(
            &session,
            HttpProtocol::Http1,
            &format!("https://１２７．０．０．１:{}/seed", address.port()),
        )
        .await?;
        send_and_drain(
            &session,
            HttpProtocol::Http1,
            &format!("https://{address}/next/page"),
        )
        .await?;

        let requests = server.await??;
        assert_http1_cookie_fields(&requests[0], &[])?;
        assert_http1_cookie_fields(&requests[1], &[ORDERED_HTTP1_COOKIE_FIELD])?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_learns_repeated_set_cookie_and_emits_one_ordered_cookie_field() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let mut first = accept_http2(&mut connection).await?;
            assert_cookie_fields(first.0.headers(), &[])?;
            first
                .1
                .send_response(response_with_cookies(&LEARNED_COOKIES)?, true)?;

            let mut second = accept_http2(&mut connection).await?;
            let observed = cookie_fields(second.0.headers())?;
            second
                .1
                .send_response(Response::builder().status(204).body(())?, true)?;
            drop(first);
            drop(second);
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let client = cookie_client(&identity)?;
        let session = client.session_builder().cookies().build();
        send_and_drain(
            &session,
            HttpProtocol::Http2,
            &format!("https://{address}/seed"),
        )
        .await?;
        send_and_drain(
            &session,
            HttpProtocol::Http2,
            &format!("https://{address}/next/page"),
        )
        .await?;
        drop(session);

        assert_eq!(server.await??, [ORDERED_COOKIE_VALUE]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_learns_repeated_set_cookie_and_emits_one_ordered_cookie_field() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (first_done, wait_for_first) = oneshot::channel();
        let (second_done, wait_for_second) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (first, mut stream, mut connection) = accept_request(&endpoint).await?;
            assert_cookie_fields(first.headers(), &[])?;
            stream
                .send_response(response_with_cookies(&LEARNED_COOKIES)?)
                .await?;
            stream.finish().await?;
            wait_for_first.await.map_err(io::Error::other)?;
            drop(stream);

            let resolver = connection
                .accept()
                .await?
                .ok_or("HTTP/3 connection closed before cookie follow-up")?;
            let (second, mut stream) = resolver.resolve_request().await?;
            let observed = cookie_fields(second.headers())?;
            stream
                .send_response(Response::builder().status(204).body(())?)
                .await?;
            stream.finish().await?;
            wait_for_second.await.map_err(io::Error::other)?;
            drop((stream, connection));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let client = cookie_client(&identity)?;
        let session = client.session_builder().cookies().build();
        send_and_drain(
            &session,
            HttpProtocol::Http3,
            &format!("https://{address}/seed"),
        )
        .await?;
        first_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped after its first response")?;
        send_and_drain(
            &session,
            HttpProtocol::Http3,
            &format!("https://{address}/next/page"),
        )
        .await?;
        second_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped after its second response")?;

        assert_eq!(server.await??, [ORDERED_COOKIE_VALUE]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn caller_cookie_suppresses_injection_but_response_learning_continues() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let mut first = accept_http2(&mut connection).await?;
            assert_cookie_fields(first.0.headers(), &[])?;
            first
                .1
                .send_response(response_with_cookies(&["stored=one; Path=/"])?, true)?;

            let mut second = accept_http2(&mut connection).await?;
            let explicit = cookie_fields(second.0.headers())?;
            second
                .1
                .send_response(response_with_cookies(&["learned=two; Path=/"])?, true)?;

            let mut third = accept_http2(&mut connection).await?;
            let learned = cookie_fields(third.0.headers())?;
            third
                .1
                .send_response(Response::builder().status(204).body(())?, true)?;
            drop((first, second, third));
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((explicit, learned))
        });

        let client = cookie_client(&identity)?;
        let session = client.session_builder().cookies().build();
        let url = format!("https://{address}/");
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        session
            .get(HttpProtocol::Http2, &url)?
            .header(RequestHeader::new("cookie", "manual=caller"))
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        drop(session);

        let (explicit, learned) = server.await??;
        assert_eq!(explicit, ["manual=caller"]);
        assert_eq!(learned, ["stored=one; learned=two"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_body_after_headers_preserves_learned_cookie() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first_request, mut first_response) = accept_http2(&mut connection).await?;
            assert_cookie_fields(first_request.headers(), &[])?;
            let mut first_body = first_response.send_response(
                response_with_cookies(&["cancelled=kept; Path=/"])?,
                false,
            )?;
            first_body.send_data(Bytes::from_static(b"partial"), false)?;

            let mut reset = None;
            let mut later = None;
            while reset.is_none() || later.is_none() {
                tokio::select! {
                    observed = std::future::poll_fn(|context| first_body.poll_reset(context)), if reset.is_none() => {
                        reset = Some(observed?);
                    }
                    incoming = connection.accept(), if later.is_none() => {
                        later = Some(incoming.ok_or("connection closed before later request")??);
                    }
                }
            }

            let (later_request, mut later_response) = later.ok_or("later request was not retained")?;
            let observed = cookie_fields(later_request.headers())?;
            later_response
                .send_response(Response::builder().status(204).body(())?, true)?;
            drop((first_request, first_body, first_response, later_request, later_response));
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                reset.ok_or("stream reset was not retained")?,
                observed,
            ))
        });

        let client = cookie_client(&identity)?;
        let session = client.session_builder().cookies().build();
        let response = session
            .get(HttpProtocol::Http2, &format!("https://{address}/abandoned"))?
            .send()
            .await?;
        drop(response);
        send_and_drain(
            &session,
            HttpProtocol::Http2,
            &format!("https://{address}/later"),
        )
        .await?;
        drop(session);

        let (reset, observed) = server.await??;
        assert_eq!(reset, ::http2::Reason::CANCEL);
        assert_eq!(observed, ["cancelled=kept"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_response_cookies_do_not_block_independent_siblings() -> TestResult<()> {
    bounded(async {
        let identity = NamedTestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            let first_request = read_head(&mut first).await?;
            write_http1_response(
                &mut first,
                &[
                    "before=one; Path=/",
                    "=missing-name",
                    "partitioned=ignored; Secure; Partitioned",
                    "suffix=ignored; Domain=com",
                    "after=two; Path=/",
                ],
            )
            .await?;

            let mut second = accept_tls(&listener, &acceptor).await?;
            let second_request = read_head(&mut second).await?;
            write_http1_response(&mut second, &[]).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((first_request, second_request))
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(forward_connects(proxy_listener, address, 2));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let mut tls = tls_settings();
        tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let client = Client::builder(ClientProfile::new(tls))
            .add_root_certificate_der(identity.root_der)
            .route(route)
            .build()?;
        let session = client.session_builder().cookies().build();
        let url = format!("https://example.com:{}/", address.port());
        send_and_drain(&session, HttpProtocol::Http1, &url).await?;
        send_and_drain(&session, HttpProtocol::Http1, &url).await?;

        let (first, second) = server.await??;
        assert_eq!(proxy.await??.len(), 2);
        assert_http1_cookie_fields(&first, &[])?;
        assert_http1_cookie_fields(&second, &["Cookie: before=one; after=two"])?;
        assert_eq!(
            session.cookie_jar().ok_or("cookie jar was disabled")?.len(),
            2
        );
        Ok(())
    })
    .await
}

fn cookie_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_macos_http2())
        .with_http3(client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn send_and_drain(
    session: &phantom::Session,
    protocol: HttpProtocol,
    url: &str,
) -> TestResult<()> {
    let response = session.get(protocol, url)?.send().await?;
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

async fn write_http1_response(
    stream: &mut SslStream<TcpStream>,
    cookies: &[&str],
) -> TestResult<()> {
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n")
        .await?;
    for cookie in cookies {
        stream.write_all(b"Set-Cookie: ").await?;
        stream.write_all(cookie.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"\r\n").await?;
    stream.shutdown().await?;
    Ok(())
}

fn response_with_cookies(cookies: &[&str]) -> Result<Response<()>, http::Error> {
    let mut response = Response::builder().status(StatusCode::NO_CONTENT);
    for cookie in cookies {
        response = response.header(SET_COOKIE, *cookie);
    }
    response.body(())
}

async fn accept_http2<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
) -> TestResult<(
    Request<::http2::RecvStream>,
    ::http2::server::SendResponse<Bytes>,
)>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Ok(connection
        .accept()
        .await
        .ok_or("connection closed before expected request")??)
}

fn cookie_fields(headers: &HeaderMap) -> TestResult<Vec<String>> {
    let values = headers
        .get_all(COOKIE)
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if !values.is_empty() {
        let name = headers
            .keys()
            .find(|name| name.as_str().eq_ignore_ascii_case("cookie"))
            .ok_or("Cookie value had no field name")?;
        assert_eq!(name.as_str(), "cookie");
    }
    Ok(values)
}

struct NamedTestIdentity {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl NamedTestIdentity {
    fn generate() -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;

        let mut leaf_params = CertificateParams::new(vec!["example.com".to_owned()])?;
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
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let certificate = X509::from_der(&self.leaf_der)?;
        let private_key = PKey::private_key_from_pkcs8(&self.private_key_der)?;
        acceptor.set_certificate(&certificate)?;
        acceptor.set_private_key(&private_key)?;
        acceptor.add_extra_chain_cert(X509::from_der(&self.root_der)?)?;
        acceptor.check_private_key()?;
        acceptor.set_alpn_select_callback(move |_, offered| {
            select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
        });
        Ok(acceptor.build())
    }
}

async fn forward_connects(
    listener: TcpListener,
    origin: SocketAddr,
    count: usize,
) -> TestResult<Vec<Vec<u8>>> {
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let (mut client, _) = listener.accept().await?;
        requests.push(read_head(&mut client).await?);
        let mut upstream = TcpStream::connect(origin).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        client.flush().await?;
        copy_bidirectional(&mut client, &mut upstream).await?;
    }
    Ok(requests)
}

fn assert_cookie_fields(headers: &HeaderMap, expected: &[&str]) -> TestResult<()> {
    assert_eq!(cookie_fields(headers)?, expected);
    Ok(())
}

fn assert_http1_cookie_fields(head: &[u8], expected: &[&str]) -> TestResult<()> {
    let head = std::str::from_utf8(head)?;
    let actual = head
        .split("\r\n")
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "cookie integration test exceeded its deadline")?
}
