//! Source-derived refusal restarts through actual profile connection selection.

use super::*;
use phantom::profile::{WebSocketNewConnection, WebSocketRefusedStreamRetry};

pub(super) async fn checked<F>(future: F) -> TestResult<()>
where
    F: std::future::Future<Output = TestResult<()>>,
{
    use futures_util::FutureExt;
    match std::panic::AssertUnwindSafe(future).catch_unwind().await {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("WebSocket profile opening assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    }
}

fn settings() -> WebSocketSettings {
    let settings = chrome::v154_websocket();
    assert_eq!(
        settings.connection.refused_stream_retry,
        WebSocketRefusedStreamRetry::ReacquireTwice
    );
    settings
}

fn client(identity: &TestIdentity, settings: WebSocketSettings) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_websocket(settings);
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .max_concurrent_http2_requests_per_origin(NonZeroUsize::MIN)
        .max_pending_http2_requests_per_origin(NonZeroUsize::MIN)
        .build()?)
}

#[tokio::test]
async fn two_refusals_reacquire_and_accept_the_third_opening() -> TestResult<()> {
    let identity = Arc::new(TestIdentity::generate()?);
    let mut server = TestServer::start(
        Arc::clone(&identity),
        Behavior {
            connect: Reply::RefuseFirstTwoStreams,
            ..Behavior::ACCEPT
        },
    )
    .await?;
    let caller = checked(bounded(async {
        let client = client(&identity, settings())?;
        ordinary_get(&client, &server).await?;
        let socket = websocket(&client, &server)?.connect().await?;
        assert_eq!(socket.handshake_response().status(), 200);
        assert_eq!(socket.handshake_response().version(), Version::HTTP_2);
        exchange(socket).await?;
        ordinary_get(&client, &server).await?;
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(
            methods(&connections[0]),
            ["GET", "CONNECT", "CONNECT", "CONNECT", "GET"]
        );
        let attempts = &connections[0].h2[1..4];
        for pair in attempts.windows(2) {
            assert_eq!(pair[1].stream_id, pair[0].stream_id + 2);
            assert_eq!(pair[1].fields, pair[0].fields);
            assert_eq!(pair[1].priority, pair[0].priority);
            assert_eq!(pseudo_order(&pair[1]), pseudo_order(&pair[0]));
        }
        Ok(())
    }))
    .await;
    server.finish(caller).await
}

#[tokio::test]
async fn third_refusal_is_terminal_and_releases_origin_admission() -> TestResult<()> {
    let identity = Arc::new(TestIdentity::generate()?);
    let mut server = TestServer::start(
        Arc::clone(&identity),
        Behavior {
            connect: Reply::RefuseStream,
            ..Behavior::ACCEPT
        },
    )
    .await?;
    let caller = checked(bounded(async {
        let client = client(&identity, settings())?;
        ordinary_get(&client, &server).await?;
        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("third refusal opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);
        ordinary_get(&client, &server).await?;
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(
            methods(&connections[0]),
            ["GET", "CONNECT", "CONNECT", "CONNECT", "GET"]
        );
        Ok(())
    }))
    .await;
    server.finish(caller).await
}

#[tokio::test]
async fn another_reset_does_not_reacquire_or_consume_a_retry() -> TestResult<()> {
    let identity = Arc::new(TestIdentity::generate()?);
    let mut server = TestServer::start(
        Arc::clone(&identity),
        Behavior {
            connect: Reply::ResetStream,
            ..Behavior::ACCEPT
        },
    )
    .await?;
    let caller = checked(bounded(async {
        let client = client(&identity, settings())?;
        ordinary_get(&client, &server).await?;
        let error = match websocket(&client, &server)?.connect().await {
            Ok(_) => return Err("INTERNAL_ERROR opened a WebSocket".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), WebSocketErrorKind::Http2);
        ordinary_get(&client, &server).await?;
        let connections = server.connections()?;
        assert_eq!(connections.len(), 1);
        assert_eq!(methods(&connections[0]), ["GET", "CONNECT", "GET"]);
        Ok(())
    }))
    .await;
    server.finish(caller).await
}

#[tokio::test]
async fn cancellation_of_reacquired_opening_releases_its_admission() -> TestResult<()> {
    let identity = Arc::new(TestIdentity::generate()?);
    let mut server = TestServer::start(
        Arc::clone(&identity),
        Behavior {
            connect: Reply::RefuseTwoThenHold,
            ..Behavior::ACCEPT
        },
    )
    .await?;
    let caller = checked(bounded(async {
        let client = client(&identity, settings())?;
        ordinary_get(&client, &server).await?;
        let mut opening = Box::pin(websocket(&client, &server)?.connect());
        loop {
            tokio::select! {
                result = &mut opening => {
                    result?;
                    return Err("held third opening unexpectedly completed".into());
                }
                () = tokio::task::yield_now() => {}
            }
            let connections = server.connections()?;
            if connections
                .first()
                .is_some_and(|connection| connection.h2.len() == 4)
            {
                assert_eq!(connections.len(), 1);
                assert_eq!(
                    methods(&connections[0]),
                    ["GET", "CONNECT", "CONNECT", "CONNECT"]
                );
                break;
            }
        }
        drop(opening);
        ordinary_get(&client, &server).await?;
        assert_eq!(
            methods(&server.connections()?[0]),
            ["GET", "CONNECT", "CONNECT", "CONNECT", "GET"]
        );
        Ok(())
    }))
    .await;
    server.finish(caller).await
}

#[tokio::test]
async fn retired_session_reselection_obeys_the_profiles_new_connection_policy() -> TestResult<()> {
    for new_connection in [
        WebSocketNewConnection::Http1Upgrade,
        WebSocketNewConnection::Http2ExtendedConnect,
    ] {
        let identity = Arc::new(TestIdentity::generate()?);
        let mut server = TestServer::start(
            Arc::clone(&identity),
            Behavior {
                connect: Reply::RefuseThenGoAway,
                ..Behavior::ACCEPT
            },
        )
        .await?;
        let caller = checked(bounded(async {
            let mut settings = settings();
            settings.connection.without_http2_session = new_connection;
            let client = client(&identity, settings)?;
            ordinary_get(&client, &server).await?;
            let socket = websocket(&client, &server)?.connect().await?;
            let expected = match new_connection {
                WebSocketNewConnection::Http1Upgrade => Version::HTTP_11,
                WebSocketNewConnection::Http2ExtendedConnect => Version::HTTP_2,
                _ => return Err("unsupported test policy".into()),
            };
            assert_eq!(socket.handshake_response().version(), expected);
            exchange(socket).await?;
            let connections = server.connections()?;
            assert_eq!(
                connections.len(),
                2,
                "restart did not select one fresh connection"
            );
            assert_eq!(methods(&connections[0]), ["GET", "CONNECT"]);
            match new_connection {
                WebSocketNewConnection::Http1Upgrade => {
                    assert_eq!(connections[1].alpn_offer, ["http/1.1"]);
                    assert_eq!(connections[1].h1.len(), 1);
                    assert!(connections[1].h2.is_empty());
                }
                WebSocketNewConnection::Http2ExtendedConnect => {
                    assert_eq!(methods(&connections[1]), ["CONNECT"]);
                    assert!(connections[1].h1.is_empty());
                }
                _ => return Err("unsupported test policy".into()),
            }
            Ok(())
        }))
        .await;
        server.finish(caller).await?;
    }
    Ok(())
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn refusal_restarts_keep_the_first_cookie_snapshot_after_the_jar_changes() -> TestResult<()> {
    for (initial, explicit) in [
        (Some("session=initial"), None),
        (None, None),
        (Some("session=initial"), Some("session=caller")),
    ] {
        let identity = Arc::new(TestIdentity::generate()?);
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_websocket(settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .cookies()
            .build()?;
        let changing_client = client.clone();
        let mut server = TestServer::start_with_first_refusal(
            Arc::clone(&identity),
            Arc::new(move || {
                changing_client
                    .cookie_jar()
                    .ok_or("client has no jar")?
                    .set_cookie("https://127.0.0.1/", "session=changed; Secure; Path=/")?;
                Ok(())
            }),
        )
        .await?;
        let caller = checked(bounded(async {
            let jar = client.cookie_jar().ok_or("client has no jar")?;
            if let Some(initial) = initial {
                jar.set_cookie("https://127.0.0.1/", &format!("{initial}; Secure; Path=/"))?;
            }
            ordinary_get(&client, &server).await?;
            let mut opening = websocket(&client, &server)?;
            if let Some(explicit) = explicit {
                opening = opening.header(RequestHeader::new("Cookie", explicit));
            }
            exchange(opening.connect().await?).await?;
            let connections = server.connections()?;
            assert_eq!(connections.len(), 1);
            assert_eq!(
                methods(&connections[0]),
                ["GET", "CONNECT", "CONNECT", "CONNECT"]
            );
            for opening in &connections[0].h2[1..] {
                let cookies = opening
                    .fields
                    .iter()
                    .filter(|(name, _)| name == "cookie")
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(
                    cookies,
                    explicit.or(initial).into_iter().collect::<Vec<_>>()
                );
            }
            assert_eq!(
                jar.request_value("https://127.0.0.1/")?.as_deref(),
                Some("session=changed")
            );
            Ok(())
        }))
        .await;
        server.finish(caller).await?;
    }
    Ok(())
}
