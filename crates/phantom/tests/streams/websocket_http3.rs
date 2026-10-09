//! HTTP/3 WebSocket extended CONNECT (RFC 9220) integration tests.
//!
//! The origin speaks raw HTTP/3 over `quinn` so the tests see the request's
//! field section as the client encoded it and how each stream ended.

mod origin;

use crate::support::client_certificate::{ClientIdentity, quic_endpoint_requiring};
use crate::support::h3 as h3_support;
use crate::support::masque as masque_support;
use crate::support::socks5_udp as socks5_udp_support;
use crate::support::tls as tls_support;

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use bytes::Bytes;
use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, HttpProxy, RequestHeader, Route,
    Socks5Proxy, TimeoutPhase, WebSocket, WebSocketErrorKind, WebSocketMessage,
    WebSocketRetryPolicy,
    profile::{
        ClientProfile, Http2PseudoHeader, Http3ClientSettings, Http3RequestSettings, chromium,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::TcpListener, net::UdpSocket, task::JoinHandle, time::timeout};

use h3_support::{client_settings, server_endpoint};
use masque_support::{
    MasqueProxy, MasqueStreamProxy, ProxyMode, StreamLeg, StreamMode, extended_request_settings,
};
use origin::{Answer, Behavior, Ending, Origin, SendEnding};
use socks5_udp_support::{
    forward_one_remote_dns_socks5_udp_associate, forward_one_socks5_udp_associate,
};
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
/// A name only the SOCKS5 proxy resolves, for `socks5h://`.
const REMOTE_ORIGIN: &str = "origin.phantom.invalid";
/// RFC 9114, section 8.1.
const H3_REQUEST_CANCELLED: u64 = 0x10c;
/// Long enough for a request that could run to have reached the origin.
const ADMISSION_WAIT: Duration = Duration::from_millis(200);

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
async fn closing_an_http3_websocket_ends_both_directions_with_fin() -> TestResult<()> {
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

        // The origin ends its side with FIN right after echoing Close; the
        // client ends its own once the reply arrived.
        assert_eq!(origin.next_ending().await?, Ending::Finished);
        drop(socket);
        assert_eq!(origin.next_send_ending().await?, SendEnding::Acknowledged);
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
        assert_eq!(
            origin.next_send_ending().await?,
            SendEnding::Stopped(H3_REQUEST_CANCELLED)
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
        let origin = Origin::spawn(&identity, Behavior::answering(Answer::Reject))?;
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
async fn an_open_http3_websocket_holds_its_origin_admission_until_dropped() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client_builder(&identity, extended_request_settings())
            .max_concurrent_http3_requests_per_origin(NonZeroUsize::MIN)
            .build()?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/held"))?
            .connect()
            .await?;
        assert_echoes(&mut socket).await?;

        let waiting = tokio::spawn({
            let client = client.clone();
            let uri = format!("https://{}/ordinary", origin.address);
            async move { get_body(&client, &uri).await }
        });
        tokio::time::sleep(ADMISSION_WAIT).await;
        assert!(
            !waiting.is_finished(),
            "a GET ran beside the open WebSocket"
        );
        assert_eq!(origin.methods(), ["CONNECT"]);

        drop(socket);
        assert_eq!(waiting.await??, "ordinary");
        assert_eq!(origin.methods(), ["CONNECT", "GET"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http3_websocket_fails_with_capacity_when_the_origin_queue_is_full() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let client = client_builder(&identity, extended_request_settings())
            .max_concurrent_http3_requests_per_origin(NonZeroUsize::MIN)
            .max_pending_http3_requests_per_origin(NonZeroUsize::MIN)
            .build()?;
        let socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/held"))?
            .connect()
            .await?;
        let waiting = tokio::spawn({
            let client = client.clone();
            let uri = format!("https://{}/ordinary", origin.address);
            async move { get_body(&client, &uri).await }
        });
        tokio::time::sleep(ADMISSION_WAIT).await;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/second"))?
            .connect()
            .await
        {
            Ok(_) => return Err("a WebSocket passed a full origin queue".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WebSocketErrorKind::Capacity);
        drop(socket);
        assert_eq!(waiting.await??, "ordinary");
        assert_eq!(origin.methods(), ["CONNECT", "GET"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_retry_policy_retries_a_refused_quic_handshake() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        // The first two attempts are refused with CONNECTION_REFUSED.
        let origin = Origin::serve(server_endpoint(&identity)?, Behavior::ECHO, 2);
        let client = client(&identity)?;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/once"))?
            .connect()
            .await
        {
            Ok(_) => return Err("a refused handshake opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_ne!(error.kind(), WebSocketErrorKind::Timeout);
        assert_eq!(origin.attempts(), 1);

        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/retried"))?
            .retry_policy(WebSocketRetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::from_millis(50),
            ))
            .connect()
            .await?;
        assert_echoes(&mut socket).await?;
        assert_eq!(origin.attempts(), 3);
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.methods(), ["CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_websocket_handshake_timeout_cancels_only_its_stream() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::answering(Answer::Withhold))?;
        let client = client(&identity)?;

        let error = match client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/silent"))?
            .handshake_timeout(Some(Duration::from_millis(300)))
            .connect()
            .await
        {
            Ok(_) => return Err("a withheld response opened a WebSocket".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), WebSocketErrorKind::Timeout);
        assert_eq!(
            error.timeout_phase(),
            Some(TimeoutPhase::WebSocketHandshake)
        );
        assert_eq!(
            origin.next_ending().await?,
            Ending::Reset(H3_REQUEST_CANCELLED)
        );
        // The pooled connection stays usable.
        ordinary_get(&client, &origin).await?;
        assert_eq!(origin.connections(), 1);
        Ok(())
    })
    .await
}

/// A resumed connection that an HTTP/3 WebSocket opens offers early data as
/// one that an ordinary exact HTTP/3 request opens does, so a pooled
/// connection's handshake does not depend on which caller opened it.
#[tokio::test]
async fn a_resumed_connection_opened_by_an_http3_websocket_sends_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = h3_support::quic_server(
            early_data_server(&identity)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let origin = Origin::serve((endpoint.local_addr()?, endpoint), Behavior::ECHO, 0);
        let (relay, zero_rtt, relay_task) = zero_rtt_relay(origin.address).await?;
        let client = early_data_client(&identity)?;

        // A full handshake that earns a ticket, then a GET and a WebSocket
        // that each open a resumed connection.
        get_body(&client, &format!("https://{relay}/ticket")).await?;
        origin.close_connections().await;
        get_body(&client, &format!("https://{relay}/resumed")).await?;
        origin.close_connections().await;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &format!("wss://{relay}/resumed"))?
            .connect()
            .await?;
        assert_echoes(&mut socket).await?;

        assert_eq!(origin.connections(), 3);
        assert_eq!(
            zero_rtt
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            [false, true, true],
            "connections that sent 0-RTT packets, in order"
        );
        drop(socket);
        relay_task.abort();
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
async fn direct_http3_websocket_uses_the_origin_scoped_client_certificate() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mapped = ClientIdentity::p256()?;
        let default = ClientIdentity::p256()?;
        // Only the mapped certificate's authority can authenticate here.
        let origin = Origin::serve(
            quic_endpoint_requiring(&identity, &mapped.authority_der)?,
            Behavior::ECHO,
            0,
        );
        let client = client_builder(&identity, extended_request_settings())
            .client_certificate(default.certificate()?)
            .client_certificate_for(
                &format!("https://{}", origin.address),
                mapped.certificate()?,
            )
            .build()?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/mtls"))?
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_3);
        assert_echoes(&mut socket).await?;
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.methods(), ["CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_http3_websocket_sends_the_origin_certificate_only_to_the_origin()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let mapped = ClientIdentity::p256()?;
        let default = ClientIdentity::p256()?;
        let origin = Origin::serve(
            quic_endpoint_requiring(&identity, &mapped.authority_der)?,
            Behavior::ECHO,
            0,
        );
        let proxy = MasqueProxy::spawn_requesting_client_certificates(
            &proxy_identity,
            ProxyMode::Relay,
            &mapped.authority_der,
        )?;
        let client = client_builder(&identity, extended_request_settings())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
            .client_certificate(default.certificate()?)
            .client_certificate_for(
                &format!("https://{}", origin.address),
                mapped.certificate()?,
            )
            // Even an explicit mapping for the proxy is an origin setting.
            .client_certificate_for(&format!("https://{}", proxy.address), mapped.certificate()?)
            .build()?;
        let mut socket = client
            .websocket_with_protocol(HttpProtocol::Http3, &origin.uri("/mtls"))?
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_3);
        assert_echoes(&mut socket).await?;
        assert_eq!(origin.connections(), 1);
        assert_eq!(origin.methods(), ["CONNECT"]);
        assert_eq!(proxy.connections(), 1);
        assert_eq!(proxy.client_certificates(), 0);
        let requests = proxy.requests();
        let [request] = requests.as_slice() else {
            return Err("expected one CONNECT-UDP tunnel".into());
        };
        assert_eq!(request.protocol.as_deref(), Some("connect-udp"));
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
        let origin = Origin::spawn(&identity, Behavior::answering(Answer::Deflate))?;
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

async fn get_body(client: &Client, uri: &str) -> TestResult<Bytes> {
    let response = client.get(HttpProtocol::Http3, uri)?.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(response.into_body().collect().await?.to_bytes())
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

/// A QUIC server configuration whose session tickets permit early data.
fn early_data_server(identity: &TestIdentity) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC permits only 0 or 0xffffffff here (RFC 9001, section 4.6.1).
    tls.max_early_data_size = u32::MAX;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// A client with QUIC session tickets and HTTP/3 early data enabled.
fn early_data_client(identity: &TestIdentity) -> TestResult<Client> {
    let base = client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = true;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        base.http3().clone(),
        extended_request_settings(),
    );
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    Ok(
        Client::builder(ClientProfile::new(tcp_tls).with_http3(http3))
            .add_root_certificate_der(identity.root_der.clone())
            .http3_early_data(true)
            .build()?,
    )
}

/// Whether each client connection has sent a 0-RTT packet, in the order
/// the connections first reached the relay.
type ZeroRttLog = Arc<Mutex<Vec<bool>>>;

/// Relays UDP between clients and `server`, one upstream socket per client
/// address, and records which client connections sent 0-RTT packets.
async fn zero_rtt_relay(
    server: SocketAddr,
) -> TestResult<(SocketAddr, ZeroRttLog, JoinHandle<()>)> {
    let front = Arc::new(phantom_testkit::udp::bind_tokio(
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?);
    let address = front.local_addr()?;
    let log: ZeroRttLog = Arc::default();
    let task_log = Arc::clone(&log);
    let task = tokio::spawn(async move {
        let mut upstreams: HashMap<SocketAddr, (usize, Arc<UdpSocket>)> = HashMap::new();
        let mut datagram = vec![0; 65_535];
        while let Ok((len, client)) = front.recv_from(&mut datagram).await {
            let (index, upstream) = match upstreams.get(&client) {
                Some((index, upstream)) => (*index, Arc::clone(upstream)),
                None => {
                    let Ok(upstream) =
                        phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())
                    else {
                        return;
                    };
                    if upstream.connect(server).await.is_err() {
                        return;
                    }
                    let upstream = Arc::new(upstream);
                    let index = {
                        let mut log = task_log.lock().unwrap_or_else(PoisonError::into_inner);
                        log.push(false);
                        log.len() - 1
                    };
                    upstreams.insert(client, (index, Arc::clone(&upstream)));
                    tokio::spawn(forward_replies(
                        Arc::clone(&upstream),
                        Arc::clone(&front),
                        client,
                    ));
                    (index, upstream)
                }
            };
            if carries_zero_rtt(&datagram[..len]) {
                task_log.lock().unwrap_or_else(PoisonError::into_inner)[index] = true;
            }
            let _ = upstream.send(&datagram[..len]).await;
        }
    });
    Ok((address, log, task))
}

async fn forward_replies(upstream: Arc<UdpSocket>, front: Arc<UdpSocket>, client: SocketAddr) {
    let mut datagram = vec![0; 65_535];
    while let Ok(len) = upstream.recv(&mut datagram).await {
        let _ = front.send_to(&datagram[..len], client).await;
    }
}

/// Returns whether a client datagram holds a 0-RTT packet among its
/// coalesced long-header packets (RFC 9000, section 17.2; RFC 9369,
/// section 3.2 for QUIC version 2's packet types).
fn carries_zero_rtt(mut datagram: &[u8]) -> bool {
    while let Some(&first) = datagram.first() {
        if first & 0x80 == 0 {
            return false;
        }
        let Some(rest) = long_header_packet(datagram) else {
            return false;
        };
        match rest {
            LongPacket::ZeroRtt => return true,
            LongPacket::Other(next) => datagram = next,
        }
    }
    false
}

enum LongPacket<'a> {
    ZeroRtt,
    /// Another packet type, followed by these coalesced bytes.
    Other(&'a [u8]),
}

fn long_header_packet(packet: &[u8]) -> Option<LongPacket<'_>> {
    let first = *packet.first()?;
    let version = u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?);
    let (initial, zero_rtt) = match version {
        0x0000_0001 => (0, 1),
        0x6b33_43cf => (1, 2),
        _ => return None,
    };
    let kind = (first >> 4) & 0x03;
    if kind == zero_rtt {
        return Some(LongPacket::ZeroRtt);
    }
    let mut at = 5;
    let destination = usize::from(*packet.get(at)?);
    at += 1 + destination;
    let source = usize::from(*packet.get(at)?);
    at += 1 + source;
    if kind == initial {
        let (token, width) = varint(packet.get(at..)?)?;
        at += width + token;
    }
    let (length, width) = varint(packet.get(at..)?)?;
    Some(LongPacket::Other(packet.get(at + width + length..)?))
}

/// Reads a QUIC variable-length integer and returns it with its width.
fn varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let width = 1_usize << (first >> 6);
    let encoded = bytes.get(..width)?;
    let value = encoded[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    Some((usize::try_from(value).ok()?, width))
}
