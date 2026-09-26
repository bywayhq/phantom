//! Encrypted Client Hello from an HTTPS DNS record on exact-protocol
//! requests and WebSocket openings, through the client facade.
//!
//! Each test opens its connections twice: the first may start before the
//! record's lookup finishes, and the second finds it cached.

use crate::support::ech as ech_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy;
// `tunnel_proxy` reaches the TLS helpers as `super::tls`.

use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use btls::ssl::SslAcceptor;
#[cfg(feature = "websocket")]
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, Client, HttpProtocol, HttpProxy, Route,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, chromium},
};
use phantom_testkit::{
    dns::DnsServer,
    tls::{TEST_ECH_KEYS, ech_config, ech_config_list},
};
#[cfg(feature = "websocket")]
use tokio::io::AsyncReadExt;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout};
use tokio_btls::SslStream;

use ech_support::{
    ORIGIN_NAME, Observed, PUBLIC_NAME, Replayed, STAND_IN_NAME, TEST_TIMEOUT, discovering_client,
    ech_acceptor, ech_tls_settings, https_rdata, origin_identity, record_server, try_handshake,
};
use h3_support::client_settings;
use tls_support::{H1_ALPN, H2_ALPN, TestResult, read_head};

/// How a test reaches the origin.
#[derive(Clone, Copy, Debug)]
enum Opening {
    /// `Client::get(HttpProtocol::Http1, ..)`.
    Http1,
    /// `Client::get(HttpProtocol::Http2, ..)`.
    Http2,
    /// A `wss://` opening under Chrome's WebSocket policy: an HTTP/1.1
    /// Upgrade on a connection that offers only `http/1.1`.
    #[cfg(feature = "websocket")]
    WebSocket,
    /// A `wss://` opening over exact HTTP/2 extended CONNECT.
    #[cfg(feature = "websocket")]
    WebSocketHttp2,
}

impl Opening {
    const fn server_alpn(self) -> &'static [u8] {
        match self {
            Self::Http1 => H1_ALPN,
            Self::Http2 => H2_ALPN,
            #[cfg(feature = "websocket")]
            Self::WebSocket => H1_ALPN,
            #[cfg(feature = "websocket")]
            Self::WebSocketHttp2 => H2_ALPN,
        }
    }

    /// Chrome 154's HTTP/2 and WebSocket settings over test TLS settings
    /// that set `ech_from_https_records` as given.
    fn profile(ech_from_https_records: bool) -> ClientProfile {
        let mut tls = ech_tls_settings();
        tls.ech_from_https_records = ech_from_https_records;
        let profile = ClientProfile::new(tls)
            .with_http2(chromium::v154_http2())
            .with_http3(client_settings());
        #[cfg(feature = "websocket")]
        let profile = profile.with_websocket(chromium::v154_websocket());
        profile
    }

    /// Sends one request, or completes one opening, to `path` on the origin.
    async fn send(self, client: &Client, port: u16, path: &str) -> TestResult<()> {
        let url = |scheme: &str| format!("{scheme}://{ORIGIN_NAME}:{port}{path}");
        match self {
            Self::Http1 | Self::Http2 => {
                let protocol = match self {
                    Self::Http1 => HttpProtocol::Http1,
                    _ => HttpProtocol::Http2,
                };
                let response = client.get(protocol, &url("https"))?.send().await?;
                response.into_body().collect().await?;
            }
            #[cfg(feature = "websocket")]
            Self::WebSocket => {
                drop(
                    client
                        .websocket_with_profile_policy(&url("wss"))?
                        .connect()
                        .await?,
                );
            }
            #[cfg(feature = "websocket")]
            Self::WebSocketHttp2 => {
                drop(
                    client
                        .websocket_with_protocol(HttpProtocol::Http2, &url("wss"))?
                        .connect()
                        .await?,
                );
            }
        }
        Ok(())
    }

    /// Answers the request or opening on an established connection.
    async fn serve(self, mut tls: SslStream<Replayed>) -> TestResult<()> {
        match self {
            Self::Http1 => {
                read_head(&mut tls).await?;
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                )
                .await?;
                tls.shutdown().await?;
            }
            Self::Http2 => {
                let mut connection = ::http2::server::handshake(tls).await?;
                let (_, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("the client sent no request")??;
                respond.send_response(Response::new(()), true)?;
                // Closing lets the second request find no pooled connection.
                connection.graceful_shutdown();
                while let Some(Ok(_)) = connection.accept().await {}
            }
            #[cfg(feature = "websocket")]
            Self::WebSocket => {
                let head = read_head(&mut tls).await?;
                let accept = websocket_accept(&head).ok_or("missing Sec-WebSocket-Key")?;
                tls.write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
                tls.flush().await?;
                let _ = tls.read_to_end(&mut Vec::new()).await;
            }
            #[cfg(feature = "websocket")]
            Self::WebSocketHttp2 => {
                let mut builder = ::http2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(tls).await?;
                let (_, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("the client sent no extended CONNECT")??;
                let _stream = respond.send_response(Response::new(()), false)?;
                while let Some(Ok(_)) = connection.accept().await {}
            }
        }
        Ok(())
    }
}

#[cfg(feature = "websocket")]
fn websocket_accept(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let key = text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("sec-websocket-key")
            .then(|| value.trim())
    })?;
    let input = [key.as_bytes(), b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].concat();
    Some(btls::base64::encode_block(&btls::sha::sha1(&input)))
}

/// A loopback origin that records each connection's handshake and serves
/// each completed one with the next entry of its plan.
struct Origin {
    port: u16,
    stop: oneshot::Sender<()>,
    task: JoinHandle<TestResult<Vec<Observed>>>,
}

impl Origin {
    async fn spawn(acceptor: SslAcceptor, plan: Vec<Opening>) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut observed = Vec::new();
            let mut plan = plan.into_iter();
            let mut serving = Vec::new();
            loop {
                let tcp = tokio::select! {
                    accepted = listener.accept() => accepted?.0,
                    _ = &mut stopped => break,
                };
                let (seen, tls) = try_handshake(tcp, &acceptor).await?;
                // A rejection completes under the public name, and the client
                // then aborts it to retry, so it is not served.
                let rejected =
                    !seen.ech_accepted && seen.outer_server_name.as_deref() == Some(PUBLIC_NAME);
                observed.push(seen);
                if let Some(tls) = tls.filter(|_| !rejected) {
                    let opening = plan.next().ok_or("more connections than planned")?;
                    serving.push(tokio::spawn(opening.serve(tls)));
                }
            }
            for task in serving {
                task.abort();
            }
            Ok(observed)
        });
        Ok(Self { port, stop, task })
    }

    fn address(&self) -> std::net::SocketAddr {
        (Ipv4Addr::LOCALHOST, self.port).into()
    }

    async fn finish(self) -> TestResult<Vec<Observed>> {
        let _ = self.stop.send(());
        self.task.await?
    }
}

/// A DNS server whose record publishes configuration 1 under the first key.
async fn published_record() -> TestResult<DnsServer> {
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    record_server(vec![https_rdata(&ech_config_list(&[config]))]).await
}

fn assert_accepted(connection: &Observed) {
    assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(connection.ech_accepted, "{connection:?}");
    assert_eq!(connection.inner_server_name.as_deref(), Some(ORIGIN_NAME));
}

async fn bounded(test: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, test)
        .await
        .map_err(|_| "ECH test exceeded its deadline")?
}

/// Two sequential openings; the second finds the record cached and must have
/// its ECH accepted, with the origin's name inside.
async fn record_is_used(opening: Opening) -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let acceptor = ech_acceptor(&identity, opening.server_alpn(), 1, &TEST_ECH_KEYS[0])?;
        let origin = Origin::spawn(acceptor, vec![opening; 2]).await?;
        let client = discovering_client(&identity, &dns, Opening::profile(true), None)?;

        for path in ["/first", "/second"] {
            opening.send(&client, origin.port, path).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = origin.finish().await?;
        assert_accepted(observed.last().ok_or("no connection")?);
        Ok(())
    })
    .await
}

/// The origin holds configuration 2 under another key and rejects the
/// published one: the second opening is rejected once and then retried on a
/// new connection with the retry configuration, which the origin accepts.
async fn rejection_is_retried_once(opening: Opening) -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let acceptor = ech_acceptor(&identity, opening.server_alpn(), 2, &TEST_ECH_KEYS[1])?;
        let origin = Origin::spawn(acceptor, vec![opening; 2]).await?;
        let client = discovering_client(&identity, &dns, Opening::profile(true), None)?;

        for path in ["/first", "/second"] {
            opening.send(&client, origin.port, path).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = origin.finish().await?;
        let [.., rejected, retried] = &observed[..] else {
            return Err(format!("expected a rejection and a retry, saw {observed:?}").into());
        };
        assert_eq!(rejected.outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert!(!rejected.ech_accepted);
        assert_accepted(retried);
        Ok(())
    })
    .await
}

/// Through an HTTP proxy, the client sends no HTTPS query and no ECH.
async fn proxy_route_sends_no_ech(opening: Opening) -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let acceptor = ech_acceptor(&identity, opening.server_alpn(), 1, &TEST_ECH_KEYS[0])?;
        let origin = Origin::spawn(acceptor, vec![opening]).await?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(
            proxy_listener,
            origin.address(),
        ));
        let route = Route::http_connect(HttpProxy::new(&format!("http://{proxy_address}"))?);
        let client = discovering_client(&identity, &dns, Opening::profile(true), Some(route))?;

        opening.send(&client, origin.port, "/").await?;

        proxy.await??;
        let observed = origin.finish().await?;
        let [only] = &observed[..] else {
            return Err(format!("expected one connection, saw {observed:?}").into());
        };
        assert_eq!(only.outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!only.ech_accepted);
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}

/// With `ech_from_https_records` unset, the client makes no HTTPS query for
/// these connections, and every one of them sends GREASE and the origin's
/// name.
async fn unset_field_keeps_grease(opening: Opening) -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let acceptor = ech_acceptor(&identity, opening.server_alpn(), 1, &TEST_ECH_KEYS[0])?;
        let origin = Origin::spawn(acceptor, vec![opening; 2]).await?;
        let client = discovering_client(&identity, &dns, Opening::profile(false), None)?;

        for path in ["/first", "/second"] {
            opening.send(&client, origin.port, path).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = origin.finish().await?;
        assert_eq!(observed.len(), 2, "{observed:?}");
        for connection in &observed {
            assert_eq!(connection.outer_server_name.as_deref(), Some(ORIGIN_NAME));
            assert!(!connection.ech_accepted);
        }
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http1_offers_the_records_ech() -> TestResult<()> {
    record_is_used(Opening::Http1).await
}

#[tokio::test]
async fn exact_http2_offers_the_records_ech() -> TestResult<()> {
    record_is_used(Opening::Http2).await
}

#[tokio::test]
async fn exact_http1_retries_a_rejection_once() -> TestResult<()> {
    rejection_is_retried_once(Opening::Http1).await
}

#[tokio::test]
async fn exact_http2_retries_a_rejection_once() -> TestResult<()> {
    rejection_is_retried_once(Opening::Http2).await
}

#[tokio::test]
async fn exact_http1_without_the_field_keeps_grease() -> TestResult<()> {
    unset_field_keeps_grease(Opening::Http1).await
}

#[tokio::test]
async fn exact_http2_without_the_field_keeps_grease() -> TestResult<()> {
    unset_field_keeps_grease(Opening::Http2).await
}

#[tokio::test]
async fn exact_http1_through_a_proxy_sends_no_ech() -> TestResult<()> {
    proxy_route_sends_no_ech(Opening::Http1).await
}

#[tokio::test]
async fn exact_http2_through_a_proxy_sends_no_ech() -> TestResult<()> {
    proxy_route_sends_no_ech(Opening::Http2).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_opening_offers_the_records_ech() -> TestResult<()> {
    record_is_used(Opening::WebSocket).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_over_exact_http2_offers_the_records_ech() -> TestResult<()> {
    record_is_used(Opening::WebSocketHttp2).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_opening_retries_a_rejection_once() -> TestResult<()> {
    rejection_is_retried_once(Opening::WebSocket).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_over_exact_http2_retries_a_rejection_once() -> TestResult<()> {
    rejection_is_retried_once(Opening::WebSocketHttp2).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_opening_through_a_proxy_sends_no_ech() -> TestResult<()> {
    proxy_route_sends_no_ech(Opening::WebSocket).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_over_exact_http2_through_a_proxy_sends_no_ech() -> TestResult<()> {
    proxy_route_sends_no_ech(Opening::WebSocketHttp2).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_opening_without_the_field_keeps_grease() -> TestResult<()> {
    unset_field_keeps_grease(Opening::WebSocket).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_over_exact_http2_without_the_field_keeps_grease() -> TestResult<()> {
    unset_field_keeps_grease(Opening::WebSocketHttp2).await
}

/// A ServiceMode record at the owner name with the given parameters.
#[cfg(feature = "websocket")]
fn service_rdata(priority: u16, h2_only: bool, ech: Option<&[u8]>) -> Vec<u8> {
    let mut rdata = priority.to_be_bytes().to_vec();
    rdata.push(0x00);
    if h2_only {
        // `alpn=h2` and `no-default-alpn`.
        rdata.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, 0x02, b'h', b'2']);
        rdata.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
    }
    if let Some(list) = ech {
        rdata.extend_from_slice(&5_u16.to_be_bytes());
        rdata.extend_from_slice(&(list.len() as u16).to_be_bytes());
        rdata.extend_from_slice(list);
    }
    rdata
}

/// The record is chosen for the connection's own ALPN offer. The first record
/// supports only `h2` and carries `ech`; the second supports `http/1.1` and
/// carries none. An exact HTTP/1.1 request, which offers `h2` too, takes the
/// first and encrypts its ClientHello, which also shows the lookup is cached.
/// A WebSocket opening after it offers only `http/1.1`, so it takes the
/// second record and sends GREASE.
#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_opening_takes_the_record_for_its_alpn_offer() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let list = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
        let dns = record_server(vec![
            service_rdata(1, true, Some(&list)),
            service_rdata(2, false, None),
        ])
        .await?;
        let acceptor = ech_acceptor(&identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])?;
        let plan = vec![Opening::Http1, Opening::Http1, Opening::WebSocket];
        let origin = Origin::spawn(acceptor, plan).await?;
        let client = discovering_client(&identity, &dns, Opening::profile(true), None)?;

        for (opening, path) in [
            (Opening::Http1, "/first"),
            (Opening::Http1, "/second"),
            (Opening::WebSocket, "/third"),
        ] {
            opening.send(&client, origin.port, path).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = origin.finish().await?;
        let [.., request, websocket] = &observed[..] else {
            return Err(format!("expected three connections, saw {observed:?}").into());
        };
        assert_accepted(request);
        assert_eq!(websocket.outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!websocket.ech_accepted);
        Ok(())
    })
    .await
}

/// An exact request that offers the record's ECH resolves its origin through
/// the client's host resolver: the override answers the name, so the caller's
/// resolver, which fails every lookup, is never asked, and the handshake
/// still offers and completes ECH.
#[tokio::test]
async fn exact_http2_with_ech_connects_to_an_overridden_name() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let acceptor = ech_acceptor(&identity, H2_ALPN, 1, &TEST_ECH_KEYS[0])?;
        let origin = Origin::spawn(acceptor, vec![Opening::Http2; 2]).await?;
        let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
        let records = HttpsRecordResolver::from_fn(move |_, port| {
            let upstream = upstream.clone();
            async move { upstream.lookup(STAND_IN_NAME, port).await }
        });
        let failing = AddressResolver::from_fn(|host| async move {
            Err(std::io::Error::other(format!(
                "no lookup expected for {host}"
            )))
        });
        let client = Client::builder(Opening::profile(true))
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .https_record_discovery(records)
            .dns_resolver(failing)
            .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
            .build()?;

        for path in ["/first", "/second"] {
            Opening::Http2.send(&client, origin.port, path).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let observed = origin.finish().await?;
        assert_accepted(observed.last().ok_or("no connection")?);
        Ok(())
    })
    .await
}
