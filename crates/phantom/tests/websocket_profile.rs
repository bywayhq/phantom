//! Fixture-backed tests of profile WebSocket connection choice and openings.
//!
//! Each test drives `Client::websocket_with_profile_policy` against a loopback
//! origin and compares what the origin observed with a retained Chrome 154,
//! Edge 153, or Firefox 156 capture from `fixtures/websocket/`.
#![cfg(feature = "websocket")]

#[path = "websocket_profile/fixture.rs"]
mod fixture;
#[path = "websocket_profile/server.rs"]
mod server;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[allow(dead_code)]
#[path = "support/tracing.rs"]
mod tracing_support;
#[allow(dead_code)]
#[path = "support/websocket.rs"]
mod websocket_support;

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use http::Version;
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, RequestHeader, WebSocket, WebSocketErrorKind, WebSocketHeader,
    WebSocketMessage, WebSocketRequestBuilder,
    profile::{ClientProfile, Http2Settings, WebSocketField, WebSocketSettings, chromium, firefox},
};

use fixture::{Capture, Representation};
#[cfg(feature = "websocket-deflate")]
use server::ClientDataFrame;
use server::{Behavior, ConnectionLog, H2Headers, Reply, TestServer, client_resets};
use tls_support::{TestIdentity, tls_settings};
use tracing::instrument::WithSubscriber;
use tracing_support::OutcomeSubscriber;
use websocket_support::bounded;

pub(crate) type TestResult<T> = tls_support::TestResult<T>;

macro_rules! fixture {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/websocket/",
            $path
        ))
    };
}

const CHROME_ACCEPT: &str = fixture!("chrome/154.0.8037.58/windows-11-26200/accept.txt");
const CHROME_FRESH: &str = fixture!("chrome/154.0.8037.58/windows-11-26200/fresh-origin.txt");
const CHROME_NO_CONNECT: &str =
    fixture!("chrome/154.0.8037.58/windows-11-26200/no-connect-protocol.txt");
const CHROME_H1: &str = fixture!("chrome/154.0.8037.58/windows-11-26200/h1-accept.txt");
const FIREFOX_H1: &str = fixture!("firefox/156.0/windows-11-26200/h1-accept.txt");
const EDGE_ACCEPT: &str = fixture!("edge/153.0.4234.48/windows-11-26200/accept.txt");
const EDGE_FRESH: &str = fixture!("edge/153.0.4234.48/windows-11-26200/fresh-origin.txt");
const FIREFOX_ACCEPT: &str = fixture!("firefox/156.0/windows-11-26200/accept.txt");
const FIREFOX_FRESH: &str = fixture!("firefox/156.0/windows-11-26200/fresh-origin.txt");
const FIREFOX_NO_CONNECT: &str = fixture!("firefox/156.0/windows-11-26200/no-connect-protocol.txt");

#[tokio::test]
async fn chromium_reuses_a_capable_pooled_session_with_the_captured_connect_shape() -> TestResult<()>
{
    for (fixture, client_name) in [
        (CHROME_ACCEPT, "Google Chrome"),
        (EDGE_ACCEPT, "Microsoft Edge"),
    ] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("client")?, client_name);
        assert_reuses_session(&capture, chromium::v154_http2(), chromium::v154_websocket()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn firefox_reuses_a_capable_pooled_session_with_the_captured_connect_shape() -> TestResult<()>
{
    assert_reuses_session(
        &Capture::parse(FIREFOX_ACCEPT)?,
        firefox::v156_http2(),
        firefox::v156_websocket(),
    )
    .await
}

/// The captured HPACK shapes of extended CONNECT tell the families apart.
///
/// `chromium_reuses_a_capable_pooled_session_with_the_captured_connect_shape`
/// and its Firefox counterpart compare every emitted pseudo-field with the
/// capture, so a recipe that claimed the other family's choices would already
/// fail them. This test states the separation directly: it pins what each
/// capture records, and asserts that each recipe emits its own shape and not
/// the other's. Swapping the two recipes' HPACK settings fails both the
/// equalities and the inequalities below.
#[tokio::test]
async fn hpack_shapes_of_extended_connect_separate_the_client_families() -> TestResult<()> {
    // Chrome 154 and Edge 153: literal without indexing, naming static entry 2
    // (`:method: GET`), with `CONNECT` sent raw because Huffman ties with it.
    let chromium_method = Representation {
        kind: "without-indexing".to_owned(),
        index: 2,
        name_huffman: None,
        value_huffman: Some(false),
    };
    // Firefox 156: incremental indexing against static entry 3
    // (`:method: POST`), Huffman-coded.
    let firefox_method = Representation {
        kind: "incremental".to_owned(),
        index: 3,
        name_huffman: None,
        value_huffman: Some(true),
    };
    assert_ne!(chromium_method, firefox_method);

    for (fixture, expected) in [
        (CHROME_ACCEPT, &chromium_method),
        (EDGE_ACCEPT, &chromium_method),
        (FIREFOX_ACCEPT, &firefox_method),
    ] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(&captured_pseudo(&capture, ":method")?, expected);
    }

    let chromium_emitted =
        emitted_connect_pseudo(chromium::v154_http2(), chromium::v154_websocket()).await?;
    let firefox_emitted =
        emitted_connect_pseudo(firefox::v156_http2(), firefox::v156_websocket()).await?;

    assert_eq!(pseudo(&chromium_emitted, ":method")?, &chromium_method);
    assert_eq!(pseudo(&firefox_emitted, ":method")?, &firefox_method);
    assert_ne!(pseudo(&chromium_emitted, ":method")?, &firefox_method);
    assert_ne!(pseudo(&firefox_emitted, ":method")?, &chromium_method);

    // `:protocol` separates them by representation kind alone, and `:path` by
    // which static entry names it, on every request rather than only CONNECT.
    assert_eq!(
        pseudo(&chromium_emitted, ":protocol")?.kind,
        "without-indexing"
    );
    assert_eq!(pseudo(&firefox_emitted, ":protocol")?.kind, "incremental");
    assert_eq!(pseudo(&chromium_emitted, ":path")?.index, 4);
    assert_eq!(pseudo(&firefox_emitted, ":path")?.index, 5);
    Ok(())
}

#[tokio::test]
async fn chromium_without_a_session_upgrades_on_a_new_http1_only_connection() -> TestResult<()> {
    for fixture in [CHROME_FRESH, EDGE_FRESH] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("scenario")?, "fresh-origin");
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
            let settings = chromium::v154_websocket();
            let client = profile_client(&identity, chromium::v154_http2(), settings.clone())?;

            let socket = upgrade_like(&client, &server, &capture, &settings).await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1, "Chromium opened an extra connection");
            assert_http1_upgrade(&connections[0], &capture)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn chromium_with_an_incapable_session_upgrades_on_a_new_http1_only_connection()
-> TestResult<()> {
    let capture = Capture::parse(CHROME_NO_CONNECT)?;
    assert_incapable_session_upgrades(&capture, chromium::v154_http2(), chromium::v154_websocket())
        .await
}

#[tokio::test]
async fn firefox_with_an_incapable_session_upgrades_on_a_new_http1_only_connection()
-> TestResult<()> {
    let capture = Capture::parse(FIREFOX_NO_CONNECT)?;
    assert_incapable_session_upgrades(&capture, firefox::v156_http2(), firefox::v156_websocket())
        .await
}

#[tokio::test]
async fn firefox_without_a_session_opens_a_new_http2_connection() -> TestResult<()> {
    let capture = Capture::parse(FIREFOX_FRESH)?;
    assert_eq!(capture.value("scenario")?, "fresh-origin");
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let settings = firefox::v156_websocket();
        let client = profile_client(&identity, firefox::v156_http2(), settings.clone())?;
        let connect = capture.connect()?;

        let socket = connect_like(&client, &server, &connect, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        let connection = &connections[0];
        assert_eq!(
            connection.alpn_offer.join(";"),
            capture.websocket_alpn_offer()?
        );
        assert_eq!(connection.protocol.as_deref(), Some("h2"));
        assert!(connection.h1.is_empty());
        assert_eq!(methods(connection), ["CONNECT"]);
        assert_connect_matches(&connection.h2[0], &connect)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_websocket_upgrades_with_the_captured_http1_fields() -> TestResult<()> {
    for (fixture, http2, settings) in [
        (
            CHROME_H1,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        ),
        (FIREFOX_H1, firefox::v156_http2(), firefox::v156_websocket()),
    ] {
        let capture = Capture::parse(fixture)?;
        assert_eq!(capture.value("socket_scheme")?, "ws");
        bounded(async {
            let identity = TestIdentity::generate()?;
            let server = TestServer::start_plaintext(Behavior::ACCEPT).await?;
            let client = profile_client(&identity, http2, settings.clone())?;
            let upgrade = capture.upgrade()?;
            let path = upgrade
                .request_line
                .split(' ')
                .nth(1)
                .ok_or("request line has no target")?;
            let builder =
                client.websocket_with_profile_policy(&format!("ws://{}{path}", server.address))?;
            let builder = fill_callers(builder, &settings.http1_fields, &upgrade.fields);
            let socket = with_profile_compression(builder, &settings)?
                .connect()
                .await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
            exchange(socket).await?;

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1);
            assert_http1_upgrade(&connections[0], &capture)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn rejected_connect_on_a_pooled_session_is_returned_without_fallback() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::Reject,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        )?;
        ordinary_get(&client, &server).await?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("rejected CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        assert_eq!(
            error.response().map(|response| response.status()),
            Some(http::StatusCode::FORBIDDEN)
        );

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "rejection opened another connection");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
        Ok(())
    })
    .await
}

/// Chrome 154 and Edge 153 answer `RST_STREAM(REFUSED_STREAM)` with one more
/// extended CONNECT on the same session and the next client stream id, which
/// the peer then accepted; see the retained `refused-stream` captures.
#[tokio::test]
async fn refused_connect_stream_reopens_once_on_the_same_session() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::RefuseFirstStream,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        )?;
        ordinary_get(&client, &server).await?;

        let socket = websocket(&client, &server)?.connect().await?;
        assert_eq!(socket.handshake_response().status(), 200);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "the reopening left the session");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT", "CONNECT"]);
        // The reopening repeats the recipe, so the pseudo-header order, the
        // ordinary fields and the HEADERS priority are unchanged and only the
        // stream id moves on.
        let [_, refused, reopened] = &connections[0].h2[..] else {
            return Err("session did not carry three streams".into());
        };
        assert_eq!(pseudo_order(reopened), pseudo_order(refused));
        assert_eq!(reopened.fields, refused.fields);
        assert_eq!(reopened.priority, refused.priority);
        assert_eq!(reopened.stream_id, refused.stream_id + 2);
        // The captures show Chrome cancelling a rejected stream but never a
        // refused one, so a stray reset here would be an unobserved
        // fingerprint change.
        assert_eq!(connections[0].resets, [], "reopening wrote a RST_STREAM");
        // The HPACK representations are not compared. The encoder's dynamic
        // table is connection-wide, so the first attempt's entries shrink the
        // second block; Chrome's capture shrinks the same way, from a 177-byte
        // block to a 58-byte one. Which representation each field takes is the
        // open indexing gap recorded in docs/reference/coverage.md.
        Ok(())
    })
    .await
}

/// Proves the span signal the exclusion tests rely on is actually recorded, so
/// their "no reopening" assertions cannot pass because the field never works.
#[tokio::test]
async fn reopening_is_recorded_in_the_connect_span() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    async {
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let behavior = Behavior {
                connect: Reply::RefuseFirstStream,
                ..Behavior::ACCEPT
            };
            let server = TestServer::start(Arc::clone(&identity), behavior).await?;
            let client = profile_client(
                &identity,
                chromium::v154_http2(),
                chromium::v154_websocket(),
            )?;
            ordinary_get(&client, &server).await?;
            websocket(&client, &server)?.connect().await?;
            Ok(())
        })
        .await
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert_eq!(
        subscriber.refused_stream_retries_for("websocket.connect"),
        [true]
    );
    Ok(())
}

/// A peer reset that is not `REFUSED_STREAM` proves nothing about processing,
/// so it is returned. The session stays usable here, so a classifier that
/// ignored the reason code would open a second CONNECT on the wire.
#[tokio::test]
async fn reset_other_than_refused_stream_is_not_reopened() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    async {
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let behavior = Behavior {
                connect: Reply::ResetStream,
                ..Behavior::ACCEPT
            };
            let server = TestServer::start(Arc::clone(&identity), behavior).await?;
            let client = profile_client(
                &identity,
                chromium::v154_http2(),
                chromium::v154_websocket(),
            )?;
            ordinary_get(&client, &server).await?;

            let error = match websocket(&client, &server)?.connect().await {
                Ok(_) => return Err("INTERNAL_ERROR reset opened a WebSocket".into()),
                Err(error) => error,
            };
            assert_eq!(error.kind(), WebSocketErrorKind::Http2);

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1, "the reset left the session");
            assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
            Ok(())
        })
        .await
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert!(
        subscriber
            .refused_stream_retries_for("websocket.connect")
            .is_empty(),
        "a non-REFUSED_STREAM reset was reopened"
    );
    Ok(())
}

/// A second refusal is reported: the profile allows one reopening, not a loop.
#[tokio::test]
async fn twice_refused_connect_stream_fails_without_a_third_attempt() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::RefuseStream,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        )?;
        ordinary_get(&client, &server).await?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("refused CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "refusal opened another connection");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT", "CONNECT"]);
        Ok(())
    })
    .await
}

/// A peer that shuts the session down under the extended CONNECT fails the
/// stream without `REFUSED_STREAM`, so it is returned rather than reopened.
///
/// The server sends `GOAWAY` and closes at once, as a peer abandoning a
/// session does; the client's stream then ends as a transport failure before
/// it processes the frame. A reopening on a session that is gone cannot reach
/// the wire either way, so the span field is the discriminating signal here.
#[tokio::test]
async fn session_shutdown_under_the_connect_stream_is_not_reopened() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    async {
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let behavior = Behavior {
                connect: Reply::GoAway,
                ..Behavior::ACCEPT
            };
            let server = TestServer::start(Arc::clone(&identity), behavior).await?;
            let client = profile_client(
                &identity,
                chromium::v154_http2(),
                chromium::v154_websocket(),
            )?;
            ordinary_get(&client, &server).await?;

            let error = match websocket(&client, &server)?.connect().await {
                Ok(_) => return Err("session shutdown opened a WebSocket".into()),
                Err(error) => error,
            };
            assert_eq!(error.kind(), WebSocketErrorKind::Http2);

            let connections = server.connections()?;
            assert_eq!(connections.len(), 1, "shutdown opened another connection");
            assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
            Ok(())
        })
        .await
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert!(
        subscriber
            .refused_stream_retries_for("websocket.connect")
            .is_empty(),
        "a session shutdown was reopened"
    );
    Ok(())
}

/// Firefox 156 fails the WebSocket with close code 1006 on every refused run
/// in the retained captures, so its recipe reopens nothing.
#[tokio::test]
async fn refused_connect_stream_is_not_retried_without_the_profile_rule() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect: Reply::RefuseFirstStream,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(&identity, firefox::v156_http2(), firefox::v156_websocket())?;
        ordinary_get(&client, &server).await?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("refused CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "refusal opened another connection");
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn new_http2_connection_without_the_peer_setting_fails_without_http1_fallback()
-> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect_protocol: false,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(&identity, firefox::v156_http2(), firefox::v156_websocket())?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("peer without extended CONNECT opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "failure opened another connection");
        assert_eq!(connections[0].protocol.as_deref(), Some("h2"));
        assert!(connections[0].h2.is_empty(), "CONNECT HEADERS were sent");
        assert!(connections[0].h1.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_http1_upgrade_is_returned_without_another_connection() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            upgrade: Reply::Reject,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(
            &identity,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        )?;

        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("rejected Upgrade opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].alpn_offer, ["http/1.1"]);
        assert_eq!(connections[0].h1.len(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http2_uses_the_profile_template_and_connect_priority() -> TestResult<()> {
    let capture = Capture::parse(FIREFOX_FRESH)?;
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let settings = firefox::v156_websocket();
        let client = profile_client(&identity, firefox::v156_http2(), settings.clone())?;
        let connect = capture.connect()?;
        let path = pseudo_value(&connect.pseudo, ":path")?;
        let builder = client.websocket_with_protocol(
            phantom::HttpProtocol::Http2,
            &format!("wss://{}{path}", server.address),
        )?;
        let builder = fill_callers(builder, &settings.http2_fields, &connect.fields);
        let socket = with_profile_compression(builder, &settings)?
            .connect()
            .await?;
        exchange(socket).await?;

        let connections = server.connections()?;
        let expected = expected_fields(&connect.fields);
        assert_eq!(connections[0].h2[0].fields, expected);
        assert_eq!(connections[0].h2[0].priority, Some(connect.priority));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn profile_policy_requires_websocket_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let profile = ClientProfile::new(tls_settings()).with_http2(chromium::v154_http2());
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
    let error = match client.websocket_with_profile_policy("wss://127.0.0.1/") {
        Ok(_) => return Err("profile without WebSocket settings chose a policy".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), WebSocketErrorKind::ProtocolUnavailable);
    Ok(())
}

#[tokio::test]
async fn profile_policy_rejects_a_replaced_field_sequence_before_io() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = profile_client(
            &identity,
            chromium::v154_http2(),
            chromium::v154_websocket(),
        )?;
        let error = match websocket(&client, &server)?
            .headers(vec![WebSocketHeader::field(RequestHeader::new(
                "sec-websocket-version",
                "13",
            ))])
            .connect()
            .await
        {
            Ok(_) => return Err("replaced policy sequence opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidRequest);
        assert!(server.connections()?.is_empty());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn websocket_on_pooled_session_counts_against_origin_admission() -> TestResult<()> {
    for negotiated in [true, false] {
        bounded(async {
            let identity = Arc::new(TestIdentity::generate()?);
            let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
            let client = bounded_client(&identity, NonZeroUsize::MIN, NonZeroUsize::MIN)?;
            pooled_get(&client, &server, negotiated).await?;
            let mut socket = websocket(&client, &server)?.connect().await?;
            assert_eq!(socket.handshake_response().version(), Version::HTTP_2);

            // With one active slot per origin, the open WebSocket holds it.
            let waiting = tokio::spawn({
                let client = client.clone();
                let address = server.address;
                async move {
                    pooled_get_at(&client, address, negotiated)
                        .await
                        .map_err(|error| error.to_string())
                }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                !waiting.is_finished(),
                "request bypassed the WebSocket's admission"
            );
            assert_eq!(methods(&server.connections()?[0]), ["GET", "CONNECT"]);

            close_gracefully(&mut socket).await?;
            waiting.await??;
            assert_eq!(
                methods(&server.connections()?[0]),
                ["GET", "CONNECT", "GET"]
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn admission_released_when_pooled_websocket_closes() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = bounded_client(&identity, NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        ordinary_get(&client, &server).await?;

        // A graceful close releases the slot, so the next WebSocket and the
        // next ordinary request are admitted without waiting.
        let mut socket = websocket(&client, &server)?.connect().await?;
        close_gracefully(&mut socket).await?;
        drop(socket);
        let socket = websocket(&client, &server)?.connect().await?;
        exchange(socket).await?;
        ordinary_get(&client, &server).await?;

        // Dropping an open WebSocket also releases it.
        let socket = websocket(&client, &server)?.connect().await?;
        drop(socket);
        ordinary_get(&client, &server).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(
            methods(&connections[0]),
            ["GET", "CONNECT", "CONNECT", "GET", "CONNECT", "GET"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn pooled_websocket_fails_with_capacity_when_origin_waiters_are_full() -> TestResult<()> {
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = bounded_client(&identity, NonZeroUsize::MIN, NonZeroUsize::MIN)?;
        ordinary_get(&client, &server).await?;
        let socket = websocket(&client, &server)?.connect().await?;

        // The active slot is taken and one request fills the waiting bound.
        let waiting = tokio::spawn({
            let client = client.clone();
            let address = server.address;
            async move {
                pooled_get_at(&client, address, true)
                    .await
                    .map_err(|error| error.to_string())
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("WebSocket exceeded the origin's waiting bound".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Capacity);

        drop(socket);
        waiting.await??;
        assert_eq!(server.connections()?.len(), 1);
        Ok(())
    })
    .await
}

#[test]
fn websocket_policy_needs_an_extended_connect_order() -> TestResult<()> {
    let mut http2 = chromium::v154_http2();
    http2.extended_connect_pseudo_header_order = None;
    http2.extended_connect_priority = None;
    let profile = ClientProfile::new(tls_settings())
        .with_http2(http2)
        .with_websocket(chromium::v154_websocket());
    let error = match Client::builder(profile).build() {
        Ok(_) => return Err("policy without an extended CONNECT order was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

async fn assert_reuses_session(
    capture: &Capture,
    http2: Http2Settings,
    settings: WebSocketSettings,
) -> TestResult<()> {
    assert_eq!(capture.value("scenario")?, "accept");
    let ordinary_priority = http2.headers_priority.map(|priority| {
        (
            priority.exclusive,
            priority.dependency_stream_id,
            priority.weight,
        )
    });
    let ordinary_pseudo = http2.pseudo_header_order.len();
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = profile_client(&identity, http2, settings.clone())?;
        let connect = capture.connect()?;

        ordinary_get(&client, &server).await?;
        let socket = connect_like(&client, &server, &connect, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        // The session still serves ordinary requests with their own shape
        // while the WebSocket stream is open.
        ordinary_get(&client, &server).await?;
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 1, "WebSocket did not reuse the session");
        let connection = &connections[0];
        assert_eq!(methods(connection), ["GET", "CONNECT", "GET"]);
        assert_eq!(
            connection
                .h2
                .iter()
                .map(|headers| headers.stream_id)
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
        assert_connect_matches(&connection.h2[1], &connect)?;
        for ordinary in [&connection.h2[0], &connection.h2[2]] {
            assert_eq!(ordinary.priority, ordinary_priority);
            assert_eq!(ordinary.pseudo.len(), ordinary_pseudo);
        }
        Ok(())
    })
    .await
}

async fn assert_incapable_session_upgrades(
    capture: &Capture,
    http2: Http2Settings,
    settings: WebSocketSettings,
) -> TestResult<()> {
    assert_eq!(capture.value("scenario")?, "no-connect-protocol");
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let behavior = Behavior {
            connect_protocol: false,
            ..Behavior::ACCEPT
        };
        let server = TestServer::start(Arc::clone(&identity), behavior).await?;
        let client = profile_client(&identity, http2, settings.clone())?;

        ordinary_get(&client, &server).await?;
        let socket = upgrade_like(&client, &server, capture, &settings).await?;
        assert_eq!(socket.handshake_response().version(), Version::HTTP_11);
        exchange(socket).await?;

        let connections = server.connections()?;
        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0].protocol.as_deref(), Some("h2"));
        assert_eq!(
            methods(&connections[0]),
            ["GET"],
            "CONNECT reached an incapable session"
        );
        assert_http1_upgrade(&connections[1], capture)?;
        Ok(())
    })
    .await
}

fn assert_http1_upgrade(connection: &ConnectionLog, capture: &Capture) -> TestResult<()> {
    let upgrade = capture.upgrade()?;
    let offer = if connection.alpn_offer.is_empty() {
        "none".to_owned()
    } else {
        connection.alpn_offer.join(";")
    };
    assert_eq!(offer, capture.websocket_alpn_offer()?);
    if capture.value("socket_scheme")? == "wss" {
        assert_eq!(connection.protocol.as_deref(), Some("http/1.1"));
    }
    assert!(connection.h2.is_empty());
    let [request] = connection.h1.as_slice() else {
        return Err("expected exactly one H1 opening".into());
    };
    assert_eq!(request.request_line, upgrade.request_line);
    let expected = expected_fields(&upgrade.fields);
    assert_eq!(
        request
            .fields
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    // Host carries this server's authority and the key is fresh per opening.
    for ((name, value), (_, captured)) in request.fields.iter().zip(&expected) {
        if name != "Host" && name != "Sec-WebSocket-Key" {
            assert_eq!(value, captured, "{name}");
        }
    }
    Ok(())
}

/// Compares one emitted extended CONNECT with the capture it models.
///
/// Every pseudo-field's HPACK representation must match: the representation
/// kind, the static name index, and both Huffman flags. A dynamic index is
/// compared only by kind, because its value depends on what the connection
/// encoded earlier rather than on the recipe.
fn assert_connect_matches(
    observed: &H2Headers,
    connect: &fixture::CapturedConnect,
) -> TestResult<()> {
    assert_eq!(observed.method, "CONNECT");
    assert_eq!(observed.priority, Some(connect.priority));
    assert_eq!(
        observed
            .pseudo
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        connect
            .pseudo
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(observed.fields, expected_fields(&connect.fields));

    for ((name, ours), (_, _, captured)) in observed.pseudo.iter().zip(&connect.pseudo) {
        let captured = if captured.index > 61 {
            // A dynamic index depends on the connection's earlier blocks.
            Representation {
                index: ours.index,
                ..captured.clone()
            }
        } else {
            captured.clone()
        };
        assert_eq!(*ours, captured, "HPACK representation of {name}");
    }
    Ok(())
}

/// Returns the pseudo-field representations of one profile's extended CONNECT.
///
/// The WebSocket opens on a pooled session that already carried an ordinary
/// request, as the captures do, so the dynamic table holds the same entries.
async fn emitted_connect_pseudo(
    http2: Http2Settings,
    settings: WebSocketSettings,
) -> TestResult<Vec<(String, Representation)>> {
    let mut pseudo = Vec::new();
    bounded(async {
        let identity = Arc::new(TestIdentity::generate()?);
        let server = TestServer::start(Arc::clone(&identity), Behavior::ACCEPT).await?;
        let client = profile_client(&identity, http2, settings)?;
        ordinary_get(&client, &server).await?;
        let socket = websocket(&client, &server)?.connect().await?;
        exchange(socket).await?;
        let connections = server.connections()?;
        pseudo = connections[0]
            .h2
            .iter()
            .find(|headers| headers.method == "CONNECT")
            .ok_or("session carried no extended CONNECT")?
            .pseudo
            .clone();
        Ok(())
    })
    .await?;
    Ok(pseudo)
}

/// Returns one pseudo-field's representation from an emitted block.
fn pseudo<'a>(block: &'a [(String, Representation)], name: &str) -> TestResult<&'a Representation> {
    block
        .iter()
        .find_map(|(field, representation)| (field == name).then_some(representation))
        .ok_or_else(|| format!("emitted block omitted {name}").into())
}

/// Returns one pseudo-field's representation from a capture's first CONNECT.
fn captured_pseudo(capture: &Capture, name: &str) -> TestResult<Representation> {
    capture
        .connect()?
        .pseudo
        .into_iter()
        .find_map(|(field, _, representation)| (field == name).then_some(representation))
        .ok_or_else(|| format!("captured CONNECT omitted {name}").into())
}

/// Captured fields, less the compression offer when it cannot be generated.
fn expected_fields(fields: &[(String, String)]) -> Vec<(String, String)> {
    fields
        .iter()
        .filter(|(name, _)| {
            cfg!(feature = "websocket-deflate")
                || !name.eq_ignore_ascii_case("sec-websocket-extensions")
        })
        .cloned()
        .collect()
}

fn profile_client(
    identity: &TestIdentity,
    http2: Http2Settings,
    websocket: WebSocketSettings,
) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(http2)
        .with_websocket(websocket);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn ordinary_get(client: &Client, server: &TestServer) -> TestResult<()> {
    pooled_get(client, server, true).await
}

async fn pooled_get(client: &Client, server: &TestServer, negotiated: bool) -> TestResult<()> {
    pooled_get_at(client, server.address, negotiated).await
}

/// Sends one GET through the negotiated or the exact HTTP/2 pool and reads
/// its body, which releases the request's admission.
async fn pooled_get_at(
    client: &Client,
    address: std::net::SocketAddr,
    negotiated: bool,
) -> TestResult<()> {
    let uri = format!("https://{address}/page");
    let builder = if negotiated {
        client.get_negotiated(&uri)?
    } else {
        client.get(phantom::HttpProtocol::Http2, &uri)?
    };
    let response = builder.send().await?;
    assert_eq!(response.status(), 200);
    response.into_body().collect().await?;
    Ok(())
}

fn bounded_client(
    identity: &TestIdentity,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_websocket(chromium::v154_websocket());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .max_concurrent_http2_requests_per_origin(max_active)
        .max_pending_http2_requests_per_origin(max_pending)
        .build()?)
}

async fn close_gracefully(socket: &mut WebSocket) -> TestResult<()> {
    socket.close(None).await?;
    assert_eq!(socket.receive().await?, WebSocketMessage::Close(None));
    match socket.receive().await {
        Ok(message) => Err(format!("WebSocket stayed open after Close: {message:?}").into()),
        Err(error) if error.kind() == WebSocketErrorKind::Closed => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn websocket(client: &Client, server: &TestServer) -> TestResult<WebSocketRequestBuilder> {
    Ok(client.websocket_with_profile_policy(&format!("wss://{}/echo", server.address))?)
}

/// The profile-policy builder with the recipe's own compression policy.
#[cfg(feature = "websocket-deflate")]
fn compressed_websocket(
    client: &Client,
    server: &TestServer,
    settings: &WebSocketSettings,
) -> TestResult<WebSocketRequestBuilder> {
    with_profile_compression(websocket(client, server)?, settings)
}

async fn connect_like(
    client: &Client,
    server: &TestServer,
    connect: &fixture::CapturedConnect,
    settings: &WebSocketSettings,
) -> TestResult<WebSocket> {
    let path = pseudo_value(&connect.pseudo, ":path")?;
    let builder =
        client.websocket_with_profile_policy(&format!("wss://{}{path}", server.address))?;
    let builder = fill_callers(builder, &settings.http2_fields, &connect.fields);
    Ok(with_profile_compression(builder, settings)?
        .connect()
        .await?)
}

async fn upgrade_like(
    client: &Client,
    server: &TestServer,
    capture: &Capture,
    settings: &WebSocketSettings,
) -> TestResult<WebSocket> {
    let upgrade = capture.upgrade()?;
    let path = upgrade
        .request_line
        .split(' ')
        .nth(1)
        .ok_or("request line has no target")?;
    let builder =
        client.websocket_with_profile_policy(&format!("wss://{}{path}", server.address))?;
    let builder = fill_callers(builder, &settings.http1_fields, &upgrade.fields);
    Ok(with_profile_compression(builder, settings)?
        .connect()
        .await?)
}

/// Supplies the captured value for every caller slot the template names.
fn fill_callers(
    mut builder: WebSocketRequestBuilder,
    template: &[WebSocketField],
    captured: &[(String, String)],
) -> WebSocketRequestBuilder {
    for field in template {
        let WebSocketField::Caller { name } = field else {
            continue;
        };
        if let Some((_, value)) = captured
            .iter()
            .find(|(captured, _)| captured.eq_ignore_ascii_case(name))
        {
            builder = builder.header(RequestHeader::new(name.clone(), value.as_str()));
        }
    }
    builder
}

#[cfg(feature = "websocket-deflate")]
fn with_profile_compression(
    builder: WebSocketRequestBuilder,
    settings: &WebSocketSettings,
) -> TestResult<WebSocketRequestBuilder> {
    Ok(builder.permessage_deflate(phantom::PerMessageDeflate::from_profile(settings)?))
}

#[cfg(not(feature = "websocket-deflate"))]
fn with_profile_compression(
    builder: WebSocketRequestBuilder,
    _settings: &WebSocketSettings,
) -> TestResult<WebSocketRequestBuilder> {
    Ok(builder)
}

async fn exchange(mut socket: WebSocket) -> TestResult<()> {
    socket
        .send(WebSocketMessage::Text("profile".into()))
        .await?;
    assert_eq!(
        socket.receive().await?,
        WebSocketMessage::Text("profile".into())
    );
    Ok(())
}

/// Keeps the "no client reset" assertions honest: the scan must actually find
/// a `RST_STREAM` when one is present, since every real run records none.
#[test]
fn reset_scan_finds_a_client_reset() {
    let mut wire = Vec::from(*b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // SETTINGS(0), then RST_STREAM(stream 3, CANCEL).
    wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(&[0, 0, 4, 3, 0, 0, 0, 0, 3]);
    wire.extend_from_slice(&8_u32.to_be_bytes());
    assert_eq!(client_resets(&wire), [(3, 8)]);
    assert_eq!(client_resets(b"not a preface"), []);
}

/// The pseudo-header names of one HEADERS block, in wire order.
fn pseudo_order(headers: &H2Headers) -> Vec<&str> {
    headers
        .pseudo
        .iter()
        .map(|(name, _)| name.as_str())
        .collect()
}

/// The recipe's empty-message rule must reach the wire, not just the policy
/// object: Chrome 154 compresses a zero-length message and sets RSV1, while
/// Firefox 156 sends it with RSV1 clear and an empty payload.
#[cfg(feature = "websocket-deflate")]
#[tokio::test]
async fn profile_empty_message_rule_reaches_the_wire() -> TestResult<()> {
    for (http2, settings, expected_empty) in [
        (
            chromium::v154_http2(),
            chromium::v154_websocket(),
            ClientDataFrame {
                rsv1: true,
                opcode: 0x1,
                payload_len: 1,
            },
        ),
        (
            firefox::v156_http2(),
            firefox::v156_websocket(),
            ClientDataFrame {
                rsv1: false,
                opcode: 0x1,
                payload_len: 0,
            },
        ),
    ] {
        bounded(async move {
            let identity = Arc::new(TestIdentity::generate()?);
            let behavior = Behavior {
                deflate: true,
                ..Behavior::ACCEPT
            };
            let server = TestServer::start(Arc::clone(&identity), behavior).await?;
            let client = profile_client(&identity, http2, settings.clone())?;
            ordinary_get(&client, &server).await?;

            let mut socket = compressed_websocket(&client, &server, &settings)?
                .connect()
                .await?;
            socket.send(WebSocketMessage::Text(String::new())).await?;
            socket
                .send(WebSocketMessage::Text("compressible".into()))
                .await?;
            // Reading both echoes proves the server logged both frames.
            socket.receive().await?;
            socket.receive().await?;

            let connections = server.connections()?;
            let [empty, non_empty] = &connections[0].client_frames[..] else {
                return Err("session did not carry two client data frames".into());
            };
            assert_eq!(*empty, expected_empty);
            // The rule is scoped to empty messages either way.
            assert!(non_empty.rsv1);
            assert!(non_empty.payload_len > 0);
            Ok(())
        })
        .await?;
    }
    Ok(())
}

fn methods(connection: &ConnectionLog) -> Vec<&str> {
    connection
        .h2
        .iter()
        .map(|headers| headers.method.as_str())
        .collect()
}

fn pseudo_value<'a>(
    pseudo: &'a [(String, String, Representation)],
    name: &str,
) -> TestResult<&'a str> {
    pseudo
        .iter()
        .find(|(candidate, _, _)| candidate == name)
        .map(|(_, value, _)| value.as_str())
        .ok_or_else(|| format!("capture omitted {name}").into())
}
