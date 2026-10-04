//! HTTP/3 WebSocket extended CONNECT (RFC 9220) integration tests.
//!
//! The origin speaks raw HTTP/3 over `quinn` so the tests see the request's
//! field section as the client encoded it and how each stream ended. It
//! announces no QPACK dynamic table, so every field section decodes alone.

use crate::support::h3 as h3_support;
use crate::support::masque as masque_support;
use crate::support::socks5_udp as socks5_udp_support;
use crate::support::tls as tls_support;
use crate::support::websocket as websocket_support;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, HttpProxy, RequestHeader, Route,
    Socks5Proxy, WebSocket, WebSocketErrorKind, WebSocketMessage,
    profile::{
        ClientProfile, Http2PseudoHeader, Http3ClientSettings, Http3RequestSettings, chromium,
    },
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

use h3_support::{client_settings, server_endpoint};
use masque_support::{
    MasqueProxy, MasqueStreamProxy, ProxyMode, StreamLeg, StreamMode, extended_request_settings,
};
use socks5_udp_support::{
    forward_one_remote_dns_socks5_udp_associate, forward_one_socks5_udp_associate,
};
use tls_support::{TestIdentity, TestResult, tls_settings};
use websocket_support::{ClientFrame, append_server_frame, append_server_frame_with_rsv1};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
/// A name only the SOCKS5 proxy resolves, for `socks5h://`.
const REMOTE_ORIGIN: &str = "origin.phantom.invalid";
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// RFC 9114, section 8.1.
const H3_REQUEST_CANCELLED: u64 = 0x10c;
const DATA_FRAME: u64 = 0x00;
const HEADERS_FRAME: u64 = 0x01;
const SETTINGS_FRAME: u64 = 0x04;
/// RFC 9220, section 3.
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// "hello" compressed with a raw DEFLATE block, as RFC 7692 section 7.2.3.1
/// shows it.
const COMPRESSED_HELLO: &[u8] = &[0xca, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];

#[tokio::test]
async fn http3_websocket_sends_ordered_extended_connect_and_echoes_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client(&identity)?;

        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/chat?room=1"))?
            .header(RequestHeader::new(
                "sec-websocket-protocol",
                "chat, superchat",
            ))
            .header(RequestHeader::new("origin", "https://app.example"))
            .connect()
            .await?;

        assert_eq!(socket.handshake_response().version(), Version::HTTP_3);
        assert_eq!(socket.handshake_response().status(), StatusCode::OK);
        assert_eq!(socket.selected_protocol(), Some("chat"));
        assert_echoes(&mut socket).await?;
        let authority = format!("127.0.0.1:{}", origin.address.port());
        assert_eq!(
            origin.requests(),
            [vec![
                field(":method", "CONNECT"),
                field(":protocol", "websocket"),
                field(":scheme", "https"),
                field(":authority", &authority),
                field(":path", "/chat?room=1"),
                field("sec-websocket-version", "13"),
                field("sec-websocket-protocol", "chat, superchat"),
                field("origin", "https://app.example"),
            ]]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn closing_an_http3_websocket_ends_its_stream_with_fin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client(&identity)?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/close"))?
            .connect()
            .await?;

        socket.close(None).await?;
        assert_eq!(socket.receive().await?, WebSocketMessage::Close(None));

        assert_eq!(origin.next_ending().await?, Ending::Finished);
        drop(socket);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_an_http3_websocket_cancels_only_its_stream() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client(&identity)?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/drop"))?
            .connect()
            .await?;
        socket.send(WebSocketMessage::Text("hello".into())).await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("hello".into())
        );

        drop(socket);

        assert_eq!(
            origin.next_ending().await?,
            Ending::Reset(H3_REQUEST_CANCELLED)
        );
        // The connection outlives the cancelled stream and stays pooled.
        ordinary_get(&client, &origin).await?;
        assert_eq!(origin.connections(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_needs_a_peer_that_enables_extended_connect() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(
            &identity,
            Behavior {
                extended_connect: false,
                answer: Answer::Echo,
            },
        )?;
        let client = client(&identity)?;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/"))?
            .connect()
            .await
        {
            Ok(_) => return Err("WebSocket opened on a peer without extended CONNECT".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WebSocketErrorKind::Http3);
        assert!(origin.requests().is_empty(), "a request stream was sent");
        assert_eq!(origin.connections(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_http3_websocket_returns_the_response_with_its_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(
            &identity,
            Behavior {
                extended_connect: true,
                answer: Answer::Reject,
            },
        )?;
        let client = client(&identity)?;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/private"))?
            .connect()
            .await
        {
            Ok(_) => return Err("a 403 answer opened a WebSocket".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let response = error.into_response().ok_or("rejection kept no response")?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.version(), Version::HTTP_3);
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "forbidden"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_without_extended_connect_order_fails_before_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let silent = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let address = silent.local_addr()?;
        let client = Client::builder(profile(chromium::v154_http3_request()))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &format!("wss://{address}/"))?
            .connect()
            .await
        {
            Ok(_) => return Err("a profile without an extended CONNECT order opened".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WebSocketErrorKind::ProtocolUnavailable);
        assert_no_datagram(&silent).await
    })
    .await
}

#[tokio::test]
async fn plaintext_scheme_and_http_proxy_route_fail_before_io_over_http3() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let silent = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let address = silent.local_addr()?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let client = client(&identity)?;

        let plaintext = client
            .websocket_with_protocol(HttpProtocol::Http3, &format!("ws://{address}/"))?
            .connect()
            .await
            .err()
            .ok_or("ws:// opened over HTTP/3")?;
        let proxied = client
            .websocket_with_protocol(HttpProtocol::Http3, &format!("wss://{address}/"))?
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{}",
                proxy.local_addr()?
            ))?))
            .connect()
            .await
            .err()
            .ok_or("an HTTP proxy route carried HTTP/3")?;

        assert_eq!(plaintext.kind(), WebSocketErrorKind::UnsupportedRoute);
        assert_eq!(proxied.kind(), WebSocketErrorKind::UnsupportedRoute);
        assert!(
            timeout(Duration::from_millis(100), proxy.accept())
                .await
                .is_err(),
            "the HTTP proxy received a connection"
        );
        assert_no_datagram(&silent).await
    })
    .await
}

#[tokio::test]
async fn http3_websocket_reuses_the_pooled_connection_of_an_ordinary_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client(&identity)?;

        ordinary_get(&client, &origin).await?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/after-get"))?
            .connect()
            .await?;
        assert_echoes(&mut socket).await?;
        // The pooled connection still serves requests beside the WebSocket.
        ordinary_get(&client, &origin).await?;

        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.methods(), ["GET", "CONNECT", "GET"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_travels_through_a_socks5_udp_association() -> TestResult<()> {
    bounded(async {
        for remote_dns in [false, true] {
            let identity =
                TestIdentity::generate_for_ip_and_dns(Ipv4Addr::LOCALHOST.into(), REMOTE_ORIGIN)?;
            let origin = Origin::spawn(&identity, Behavior::ECHO)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy_address = listener.local_addr()?;
            let port = origin.address.port();
            let (proxy, scheme, uri) = if remote_dns {
                let proxy = tokio::spawn(forward_one_remote_dns_socks5_udp_associate(
                    listener,
                    origin.address,
                    REMOTE_ORIGIN.to_owned(),
                    port,
                ));
                (
                    proxy,
                    "socks5h",
                    format!("wss://{REMOTE_ORIGIN}:{port}/socks"),
                )
            } else {
                let proxy =
                    tokio::spawn(forward_one_socks5_udp_associate(listener, origin.address));
                (proxy, "socks5", origin.uri("/socks"))
            };
            let client = client_builder(&identity, extended_request_settings())
                .route(Route::socks5(Socks5Proxy::new(&format!(
                    "{scheme}://{proxy_address}"
                ))?))
                .build()?;

            let mut socket = client
                .websocket_with_protocol(HttpProtocol::Http3, &uri)?
                .connect()
                .await?;
            assert_echoes(&mut socket).await?;
            drop(socket);
            drop(client);

            let observed = proxy.await??;
            assert!(observed.client_datagrams > 0);
            assert!(observed.origin_datagrams > 0);
            assert_eq!(origin.methods(), ["CONNECT"]);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_travels_through_a_connect_udp_proxy() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Relay)?;
        let client = client_builder(&identity, extended_request_settings())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
            .build()?;

        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/masque"))?
            .connect()
            .await?;
        assert_echoes(&mut socket).await?;

        let requests = proxy.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].protocol.as_deref(), Some("connect-udp"));
        assert_eq!(origin.methods(), ["CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_travels_through_connect_udp_over_http1_and_http2_legs() -> TestResult<()> {
    bounded(async {
        for (leg, expected_method) in [(StreamLeg::Http1, "GET"), (StreamLeg::Http2, "CONNECT")] {
            let identity = TestIdentity::generate()?;
            let proxy_identity = TestIdentity::generate()?;
            let origin = Origin::spawn(&identity, Behavior::ECHO)?;
            let proxy = MasqueStreamProxy::spawn(&proxy_identity, leg, StreamMode::Relay).await?;
            let route = match leg {
                StreamLeg::Http1 => ConnectUdpProxy::new(&proxy.template())?.with_http1_transport(),
                StreamLeg::Http2 => ConnectUdpProxy::new(&proxy.template())?.with_http2_transport(),
            };
            let mut http2 = chromium::v154_http2();
            http2.extended_connect_pseudo_header_order = Some(vec![
                Http2PseudoHeader::Method,
                Http2PseudoHeader::Protocol,
                Http2PseudoHeader::Authority,
                Http2PseudoHeader::Scheme,
                Http2PseudoHeader::Path,
            ]);
            let client = Client::builder(profile(extended_request_settings()).with_http2(http2))
                .add_root_certificate_der(identity.root_der.clone())
                .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                .route(Route::connect_udp(route))
                .build()?;

            let mut socket = client
                .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/capsules"))?
                .connect()
                .await?;
            assert_echoes(&mut socket).await?;

            let requests = proxy.requests();
            let [request] = requests.as_slice() else {
                return Err("proxy did not observe exactly one CONNECT-UDP request".into());
            };
            assert_eq!(request.method, expected_method);
            assert_eq!(origin.methods(), ["CONNECT"]);
        }
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket-deflate")]
#[tokio::test]
async fn http3_websocket_negotiates_and_transfers_compressed_messages() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(
            &identity,
            Behavior {
                extended_connect: true,
                answer: Answer::Deflate,
            },
        )?;
        let client = client(&identity)?;

        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/compressed"))?
            .permessage_deflate(phantom::PerMessageDeflate::new())
            .connect()
            .await?;

        let negotiated = socket
            .negotiated_permessage_deflate()
            .ok_or("server compression selection was not retained")?;
        assert!(negotiated.server_no_context_takeover());
        assert_eq!(negotiated.client_max_window_bits(), 8);
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("hello".into())
        );
        socket
            .send(WebSocketMessage::Text("client hello".into()))
            .await?;

        let frame = origin.next_frame().await?;
        assert!(frame.rsv1);
        assert_eq!(frame.opcode, 0x1);
        assert_ne!(frame.payload, b"client hello");
        let request = origin.requests().pop().ok_or("no request was seen")?;
        assert!(request.contains(&field(
            "sec-websocket-extensions",
            "permessage-deflate; client_max_window_bits"
        )));
        Ok(())
    })
    .await
}

/// Sends a text and a binary message and expects each echoed back.
async fn assert_echoes(socket: &mut WebSocket) -> TestResult<()> {
    socket
        .send(WebSocketMessage::Text("over h3".into()))
        .await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("over h3".into())
    );
    let binary = Bytes::from_static(&[0, 1, 2, 0xff]);
    socket
        .send(WebSocketMessage::Binary(binary.clone()))
        .await?;
    assert_eq!(socket.receive().await?, WebSocketMessage::Binary(binary));
    Ok(())
}

async fn ordinary_get(client: &Client, origin: &Origin) -> TestResult<()> {
    let response = client
        .get(
            HttpProtocol::Http3,
            &format!("https://{}/ordinary", origin.address),
        )?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ordinary");
    Ok(())
}

async fn assert_no_datagram(socket: &tokio::net::UdpSocket) -> TestResult<()> {
    let mut buffer = [0; 1_500];
    match timeout(Duration::from_millis(100), socket.recv_from(&mut buffer)).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the origin received a datagram".into()),
    }
}

fn profile(request: Http3RequestSettings) -> ClientProfile {
    let base = client_settings();
    ClientProfile::new(tls_settings()).with_http3(Http3ClientSettings::new(
        base.tls().clone(),
        base.quic_transport().clone(),
        base.http3().clone(),
        request,
    ))
}

fn client_builder(identity: &TestIdentity, request: Http3RequestSettings) -> ClientBuilder {
    Client::builder(profile(request)).add_root_certificate_der(identity.root_der.clone())
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(client_builder(identity, extended_request_settings()).build()?)
}

fn field(name: &str, value: &str) -> (String, Vec<u8>) {
    (name.to_owned(), value.as_bytes().to_vec())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 WebSocket test exceeded its deadline")?
}

/// How the origin's request stream ended.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Ending {
    Finished,
    Reset(u64),
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Answer {
    /// Accept with 200 and echo text and binary messages and the Close frame.
    Echo,
    /// Answer 403 with a body.
    Reject,
    /// Accept with a `permessage-deflate` selection, send one compressed
    /// message, and record the client's frames.
    Deflate,
}

#[derive(Clone, Copy, Debug)]
struct Behavior {
    /// Whether SETTINGS carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
    extended_connect: bool,
    answer: Answer,
}

impl Behavior {
    const ECHO: Self = Self {
        extended_connect: true,
        answer: Answer::Echo,
    };
}

#[derive(Default)]
struct Log {
    connections: usize,
    requests: Vec<Vec<(String, Vec<u8>)>>,
    endings: Vec<Ending>,
    frames: Vec<ClientFrame>,
}

/// A raw HTTP/3 origin on a loopback QUIC endpoint; aborted on drop.
struct Origin {
    address: SocketAddr,
    log: Arc<Mutex<Log>>,
    task: JoinHandle<()>,
}

impl Origin {
    fn spawn(identity: &TestIdentity, behavior: Behavior) -> TestResult<Self> {
        let (address, endpoint) = server_endpoint(identity)?;
        let log = Arc::new(Mutex::new(Log::default()));
        let task_log = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let log = Arc::clone(&task_log);
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    lock(&log).connections += 1;
                    let _ = serve_connection(connection, behavior, log).await;
                });
            }
        });
        Ok(Self { address, log, task })
    }

    fn uri(&self, path_and_query: &str) -> String {
        format!("wss://{}{path_and_query}", self.address)
    }

    fn connections(&self) -> usize {
        lock(&self.log).connections
    }

    fn requests(&self) -> Vec<Vec<(String, Vec<u8>)>> {
        lock(&self.log).requests.clone()
    }

    fn methods(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|fields| {
                fields
                    .iter()
                    .find(|(name, _)| name == ":method")
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
            })
            .collect()
    }

    async fn next_ending(&self) -> TestResult<Ending> {
        loop {
            if let Some(ending) = lock(&self.log).endings.first().cloned() {
                return Ok(ending);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    #[cfg(feature = "websocket-deflate")]
    async fn next_frame(&self) -> TestResult<ClientFrame> {
        loop {
            {
                let mut log = lock(&self.log);
                if !log.frames.is_empty() {
                    return Ok(log.frames.remove(0));
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lock(log: &Mutex<Log>) -> MutexGuard<'_, Log> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn serve_connection(
    connection: quinn::Connection,
    behavior: Behavior,
    log: Arc<Mutex<Log>>,
) -> TestResult<()> {
    let mut settings = Vec::new();
    if behavior.extended_connect {
        put_varint(&mut settings, SETTINGS_ENABLE_CONNECT_PROTOCOL);
        put_varint(&mut settings, 1);
    }
    // Stream type 0x00 is the control stream (RFC 9114, section 6.2.1); it
    // must stay open for the connection's lifetime.
    let mut control = connection.open_uni().await?;
    let mut opening = vec![0x00];
    put_frame(&mut opening, SETTINGS_FRAME, &settings);
    control.write_all(&opening).await?;
    loop {
        let (send, recv) = connection.accept_bi().await?;
        let log = Arc::clone(&log);
        tokio::spawn(async move {
            let _ = serve_stream(send, recv, behavior.answer, log).await;
        });
    }
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    answer: Answer,
    log: Arc<Mutex<Log>>,
) -> TestResult<()> {
    let mut section = loop {
        match next_frame(&mut recv).await {
            Ok(Some((HEADERS_FRAME, payload))) => break Bytes::from(payload),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return Err("request stream ended before HEADERS".into()),
        }
    };
    let fields = h3::qpack::decode_stateless(&mut section, u64::MAX)?
        .fields
        .into_iter()
        .map(|field| {
            (
                String::from_utf8_lossy(&field.name).into_owned(),
                field.value.into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let value = |name: &str| {
        fields
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
    };
    let method = value(":method");
    let protocol = value("sec-websocket-protocol");
    lock(&log).requests.push(fields.clone());

    if method.as_deref() != Some("CONNECT") {
        write_headers(&mut send, &[(":status", "200")]).await?;
        write_frame(&mut send, DATA_FRAME, b"ordinary").await?;
        send.finish()?;
        return Ok(());
    }
    match answer {
        Answer::Reject => {
            write_headers(&mut send, &[(":status", "403")]).await?;
            write_frame(&mut send, DATA_FRAME, b"forbidden").await?;
            send.finish()?;
            return Ok(());
        }
        Answer::Echo => {
            let selected = protocol
                .as_deref()
                .and_then(|offer| offer.split(',').next())
                .map(str::trim)
                .map(str::to_owned);
            let mut head = vec![(":status", "200")];
            if let Some(selected) = selected.as_deref() {
                head.push(("sec-websocket-protocol", selected));
            }
            write_headers(&mut send, &head).await?;
        }
        Answer::Deflate => {
            write_headers(
                &mut send,
                &[
                    (":status", "200"),
                    (
                        "sec-websocket-extensions",
                        "permessage-deflate; server_no_context_takeover; client_max_window_bits=8",
                    ),
                ],
            )
            .await?;
            let mut frame = Vec::new();
            append_server_frame_with_rsv1(&mut frame, true, true, 0x1, COMPRESSED_HELLO);
            write_frame(&mut send, DATA_FRAME, &frame).await?;
        }
    }

    let (mut reader, writer) = tokio::io::duplex(64 * 1024);
    let (ended, ending) = oneshot::channel();
    tokio::spawn(async move {
        let _ = ended.send(pump_data(recv, writer).await);
    });
    while let Ok(frame) = websocket_support::read_client_frame(&mut reader).await {
        let opcode = frame.opcode;
        if answer == Answer::Deflate {
            lock(&log).frames.push(frame);
            continue;
        }
        let mut reply = Vec::new();
        append_server_frame(&mut reply, true, opcode, &frame.payload);
        write_frame(&mut send, DATA_FRAME, &reply).await?;
        if opcode == 0x8 {
            break;
        }
    }
    let ending = ending
        .await
        .unwrap_or_else(|_| Ending::Failed("DATA pump stopped".into()));
    lock(&log).endings.push(ending.clone());
    if ending == Ending::Finished {
        send.finish()?;
    }
    Ok(())
}

/// Copies the payload of each DATA frame into `writer` until the stream
/// ends, and reports how it ended.
async fn pump_data(mut recv: quinn::RecvStream, mut writer: DuplexStream) -> Ending {
    loop {
        match next_frame(&mut recv).await {
            Ok(Some((DATA_FRAME, payload))) => {
                if writer.write_all(&payload).await.is_err() {
                    // The reader stopped; keep draining to see the ending.
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return Ending::Finished,
            Err(ending) => return ending,
        }
    }
}

/// Reads one HTTP/3 frame, or `None` at a FIN between frames.
async fn next_frame(recv: &mut quinn::RecvStream) -> Result<Option<(u64, Vec<u8>)>, Ending> {
    let mut first = [0];
    match recv.read(&mut first).await {
        Ok(Some(1)) => {}
        Ok(Some(_)) => return Err(Ending::Failed("empty read".into())),
        Ok(None) => return Ok(None),
        Err(error) => return Err(read_ending(error)),
    }
    let frame_type = read_varint_after(recv, first[0]).await?;
    let mut length = [0];
    read_exact(recv, &mut length).await?;
    let length = read_varint_after(recv, length[0]).await?;
    let mut payload =
        vec![0; usize::try_from(length).map_err(|_| Ending::Failed("frame too long".into()))?];
    read_exact(recv, &mut payload).await?;
    Ok(Some((frame_type, payload)))
}

async fn read_varint_after(recv: &mut quinn::RecvStream, first: u8) -> Result<u64, Ending> {
    let width = 1_usize << (first >> 6);
    let mut encoded = [0; 8];
    encoded[0] = first & 0x3f;
    read_exact(recv, &mut encoded[1..width]).await?;
    Ok(encoded[..width]
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
}

async fn read_exact(recv: &mut quinn::RecvStream, buffer: &mut [u8]) -> Result<(), Ending> {
    recv.read_exact(buffer).await.map_err(|error| match error {
        quinn::ReadExactError::FinishedEarly(_) => Ending::Failed("frame cut short".into()),
        quinn::ReadExactError::ReadError(error) => read_ending(error),
    })
}

fn read_ending(error: quinn::ReadError) -> Ending {
    match error {
        quinn::ReadError::Reset(code) => Ending::Reset(code.into_inner()),
        error => Ending::Failed(error.to_string()),
    }
}

async fn write_headers(send: &mut quinn::SendStream, fields: &[(&str, &str)]) -> TestResult<()> {
    let fields = fields
        .iter()
        .map(|(name, value)| h3::qpack::HeaderField::new(*name, *value))
        .collect::<Vec<_>>();
    let mut block = BytesMut::new();
    h3::qpack::encode_stateless(&mut block, &fields)?;
    write_frame(send, HEADERS_FRAME, &block).await
}

async fn write_frame(
    send: &mut quinn::SendStream,
    frame_type: u64,
    payload: &[u8],
) -> TestResult<()> {
    let mut frame = Vec::with_capacity(payload.len() + 16);
    put_frame(&mut frame, frame_type, payload);
    send.write_all(&frame).await?;
    Ok(())
}

fn put_frame(output: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    put_varint(output, frame_type);
    put_varint(output, payload.len() as u64);
    output.extend_from_slice(payload);
}

/// Appends `value` as a QUIC variable-length integer (RFC 9000, section 16).
fn put_varint(output: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        output.push(value as u8);
    } else if value < 1 << 14 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1 << 30 {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}
