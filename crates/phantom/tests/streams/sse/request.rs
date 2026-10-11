use std::{net::Ipv4Addr, time::Duration};

use btls::ssl::SslAcceptor;
use http::StatusCode;
use phantom::{
    Client, HttpProtocol, RequestHeader, SseErrorKind, SseHeader,
    profile::{
        ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile, RequestField,
        RequestTemplate,
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    task::{AbortHandle, JoinError},
    time::{Instant, error::Elapsed, timeout, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{
    TestResult,
    tls_support::{H1_ALPN, accept_tls, read_head, test_client},
};

mod managed_id_cycle;
mod owner_contract;

type CrossOriginPeer = ConnectionPeer<TestResult<Vec<String>>>;
type CrossOriginJoin = Result<Result<TestResult<Vec<String>>, JoinError>, Elapsed>;
// Keep caller resources alive through worker joins and header assertions.
type CrossOriginCaller = Option<(phantom::SseEventSource, Client)>;

#[tokio::test]
async fn replacing_headers_removes_event_source_defaults() -> TestResult<()> {
    let identity = super::tls_support::TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
    });

    let response = test_client(&identity, false)?
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .headers(vec![SseHeader::field(RequestHeader::new(
            "X-Custom", "only",
        ))])
        .connect()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let head = String::from_utf8(server.await??)?;
    assert!(head.lines().any(|line| line == "X-Custom: only"));
    assert!(!head.lines().any(|line| line.starts_with("Accept:")));
    assert!(!head.lines().any(|line| line.starts_with("Cache-Control:")));
    Ok(())
}

#[tokio::test]
async fn inherited_last_event_id_defaults_fail_before_connecting() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut template = id_slot_template();
    template.http1_fields[1] = RequestField::literal("Last-Event-ID", "unmanaged");
    let client = Client::builder(
        ClientProfile::new(super::tls_support::tls_settings()).with_request_template(template),
    )
    .build()?;

    let connecting = client
        .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .connect();
    let error = timeout(super::TEST_TIMEOUT, connecting)
        .await
        .map_err(|_| "inherited ID rejection stalled during network setup")?
        .err()
        .ok_or("inherited Last-Event-ID default reached the network")?;
    assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    assert!(
        timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn automatic_last_event_id_hints_fail_before_connecting() -> TestResult<()> {
    use phantom::profile::{ClientHint, ClientHintDelivery, ClientHintSettings};

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    for delivery in [ClientHintDelivery::Default, ClientHintDelivery::AcceptCh] {
        let client = Client::builder(
            ClientProfile::new(super::tls_support::tls_settings()).with_client_hints(
                ClientHintSettings::new(vec![ClientHint::new(
                    "last-event-id",
                    "unmanaged-canary",
                    delivery,
                )]),
            ),
        )
        .build()?;

        let connecting = client
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .connect();
        let error = timeout(super::TEST_TIMEOUT, connecting)
            .await
            .map_err(|_| "automatic ID rejection stalled during network setup")?
            .err()
            .ok_or("automatic Last-Event-ID reached the network")?;
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    }
    assert!(
        timeout(Duration::from_millis(25), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn inherited_optional_id_slot_preserves_order_and_omits_initial_and_reset_ids()
-> TestResult<()> {
    check_managed_id_cycle(id_slot_template(), None, false).await
}

#[tokio::test]
async fn non_emitting_id_hint_preserves_initial_committed_and_reset_ids() -> TestResult<()> {
    check_managed_id_cycle(id_slot_template(), Some(id_hints(false)), false).await
}

#[tokio::test]
async fn non_emitting_id_hint_keeps_caller_slot_order_and_normal_hints() -> TestResult<()> {
    let mut template = id_slot_template();
    template.http1_fields.extend([
        RequestField::ClientHints,
        RequestField::literal("X-Hint-After", "last"),
    ]);
    template.http2_fields = vec![
        RequestField::literal("x-before", "first"),
        RequestField::caller("last-event-id"),
        RequestField::literal("x-after", "last"),
        RequestField::ClientHints,
        RequestField::literal("x-hint-after", "last"),
    ];
    check_managed_id_cycle(template, Some(id_hints(true)), true).await
}

#[tokio::test]
async fn inactive_id_defaults_preserve_initial_committed_and_reset_ids() -> TestResult<()> {
    for field in [
        RequestField::ByTrust {
            name: "Last-Event-ID".into(),
            trustworthy: None,
            untrustworthy: Some("unmanaged-canary".into()),
        },
        RequestField::when_forwarded("Last-Event-ID", "unmanaged-canary"),
    ] {
        let mut template = id_slot_template();
        template.http1_fields[1] = field;
        check_managed_id_cycle(template, None, false).await?;
    }
    Ok(())
}

fn id_hints(normal_hint: bool) -> ClientHintSettings {
    let mut hints = vec![ClientHint::new(
        "last-event-id",
        "unmanaged-canary",
        ClientHintDelivery::AcceptCh,
    )];
    if normal_hint {
        hints.push(ClientHint::new(
            "sec-ch-ua",
            "normal-canary",
            ClientHintDelivery::Default,
        ));
    }
    ClientHintSettings::new(hints)
}

async fn check_managed_id_cycle(
    template: RequestTemplate,
    hints: Option<ClientHintSettings>,
    normal_hint: bool,
) -> TestResult<()> {
    let deadline = Instant::now() + super::TEST_TIMEOUT;
    let (identity, address, server) = timeout_at(deadline, async {
        let identity = super::tls_support::TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = managed_id_cycle::spawn(listener, acceptor, None);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((identity, address, server))
    })
    .await
    .map_err(|elapsed| FixtureDeadline::new("SSE test exceeded its deadline", elapsed))??;

    let caller: TestResult<managed_id_cycle::Caller> = match timeout_at(deadline, async {
        let mut profile =
            ClientProfile::new(super::tls_support::tls_settings()).with_request_template(template);
        if let Some(hints) = hints {
            profile = profile.with_client_hints(hints);
        }
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let mut events = client
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .initial_retry(Duration::ZERO)
            .max_reconnects(2)
            .connect()
            .await?
            .into_body();

        let first = events.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.id(), "first");
        let second = events.next_event().await?.ok_or("reset event missing")?;
        assert_eq!(second.id(), "");
        assert_eq!(events.last_event_id(), "");
        assert_eq!(events.next_event().await?, None);

        Ok(Some((events, client)))
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("SSE test exceeded its deadline", elapsed).into()),
    };

    let (_caller, heads) = managed_id_cycle::collect(caller, server).await?;
    for (index, head) in heads.iter().enumerate() {
        let fields = head
            .lines()
            .skip(1)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        let mut expected = if index == 1 {
            vec![
                "X-Before: first",
                "Last-Event-ID: first",
                "X-After: last",
                "Accept: text/event-stream",
                "Cache-Control: no-cache",
            ]
        } else {
            vec![
                "X-Before: first",
                "X-After: last",
                "Accept: text/event-stream",
                "Cache-Control: no-cache",
            ]
        };
        if normal_hint {
            let position = expected
                .iter()
                .position(|field| *field == "X-After: last")
                .ok_or("template field missing")?
                + 1;
            expected.splice(
                position..position,
                ["sec-ch-ua: normal-canary", "X-Hint-After: last"],
            );
        }
        assert_eq!(&fields[1..], expected, "request {index}");
        assert!(!head.contains("unmanaged-canary"));
    }
    Ok(())
}

#[tokio::test]
async fn redirect_activating_an_inherited_id_default_fails_before_the_next_hop() -> TestResult<()> {
    use phantom::{RedirectPolicy, RequestError, RequestErrorKind};
    use std::num::NonZeroUsize;

    super::bounded(async {
        let identity = super::tls_support::TestIdentity::generate()?;
        let initial_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let initial_address = initial_listener.local_addr()?;
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let target_address = target_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let mut template = id_slot_template();
        template.http1_fields[1] = RequestField::ByTrust {
            name: "Last-Event-ID".into(),
            trustworthy: None,
            untrustworthy: Some("unmanaged-canary".into()),
        };
        // This DNS override gives the redirected URL an untrustworthy logical
        // origin while keeping every socket on loopback.
        let client = Client::builder(ClientProfile::new(super::tls_support::tls_settings())
            .with_request_template(template))
            .add_root_certificate_der(identity.root_der.clone())
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .resolve("redirect.phantom.test", [target_address.ip()])
            .build()?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(initial_listener, acceptor).await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            assert!(!head.to_ascii_lowercase().contains("last-event-id:"));
            let response = format!("HTTP/1.1 302 Found\r\nLocation: http://redirect.phantom.test:{}/events\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target_address.port());
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let error = client.event_source(HttpProtocol::Http1, &format!("https://{initial_address}/events"))?
            .initial_retry(Duration::ZERO).max_reconnects(2).connect().await
            .err().ok_or("activated default reached the redirected origin")?;
        assert_eq!(error.kind(), SseErrorKind::Request);
        let request_error = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<RequestError>())
            .ok_or("validation error source missing")?;
        assert_eq!(request_error.kind(), RequestErrorKind::RequestTemplate);
        server.await??;
        assert!(timeout(Duration::from_millis(25), target_listener.accept()).await.is_err());
        Ok(())
    }).await
}

#[tokio::test]
async fn cross_origin_reconnect_keeps_managed_ids_and_strips_ordinary_caller_hints()
-> TestResult<()> {
    use std::num::NonZeroUsize;

    use phantom::RedirectPolicy;

    let identity = super::tls_support::TestIdentity::generate()?;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin.local_addr()?;
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let destination_address = destination.local_addr()?;
    let origin_acceptor = identity.acceptor(H1_ALPN)?;
    let destination_acceptor = identity.acceptor(H1_ALPN)?;
    let (origin_server, destination_server) = cross_origin_peers(
        origin,
        destination,
        origin_acceptor,
        destination_acceptor,
        destination_address,
        None,
    );

    // Collect both original peers after the caller deadline has ended.
    let caller: TestResult<CrossOriginCaller> = match timeout(super::TEST_TIMEOUT, async {
        let mut template = id_slot_template();
        template.http1_fields.extend([
            RequestField::ClientHints,
            RequestField::literal("X-Hint-After", "last"),
        ]);
        template.http2_fields = vec![
            RequestField::literal("x-before", "first"),
            RequestField::caller("last-event-id"),
            RequestField::literal("x-after", "last"),
            RequestField::ClientHints,
            RequestField::literal("x-hint-after", "last"),
        ];
        let hints = ClientHintSettings::new(vec![
            ClientHint::new(
                "last-event-id",
                "unmanaged-id-canary",
                ClientHintDelivery::AcceptCh,
            ),
            ClientHint::new(
                "sec-ch-ua",
                "profile-hint-canary",
                ClientHintDelivery::Default,
            ),
        ]);
        let client = Client::builder(
            ClientProfile::new(super::tls_support::tls_settings())
                .with_request_template(template)
                .with_client_hints(hints),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .build()?;
        let mut events = client
            .event_source(
                HttpProtocol::Http1,
                &format!("https://{origin_address}/events"),
            )?
            .header(RequestHeader::new("sec-ch-ua", "caller-hint-canary"))
            .initial_retry(Duration::ZERO)
            .max_reconnects(2)
            .connect()
            .await?
            .into_body();
        let first = events.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.id(), "first");
        let second = events.next_event().await?.ok_or("reset event missing")?;
        assert_eq!(second.id(), "");
        assert_eq!(events.last_event_id(), "");
        assert_eq!(events.next_event().await?, None);
        assert_eq!(events.reconnects(), 2);
        Ok(Some((events, client)))
    })
    .await
    {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("SSE test exceeded its deadline", elapsed).into()),
    };

    let (_caller, origin_heads, destination_heads) =
        finish_cross_origin(caller, origin_server, destination_server).await?;
    for (heads, expected_ids, hint_value) in [
        (
            &origin_heads,
            &[None, Some("first"), None][..],
            "caller-hint-canary",
        ),
        (
            &destination_heads,
            &[Some("first"), None][..],
            "profile-hint-canary",
        ),
    ] {
        assert_eq!(heads.len(), expected_ids.len());
        for (attempt, (head, expected_id)) in heads.iter().zip(expected_ids).enumerate() {
            let fields = head
                .lines()
                .skip(1)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            let mut expected = vec!["X-Before: first".to_owned()];
            if let Some(id) = expected_id {
                expected.push(format!("Last-Event-ID: {id}"));
            }
            expected.extend([
                "X-After: last".to_owned(),
                format!("sec-ch-ua: {hint_value}"),
                "X-Hint-After: last".to_owned(),
                "Accept: text/event-stream".to_owned(),
                "Cache-Control: no-cache".to_owned(),
            ]);
            assert_eq!(
                &fields[1..],
                expected,
                "request {attempt}, hint={hint_value}"
            );
            assert!(!head.contains("unmanaged-id-canary"));
        }
    }
    Ok(())
}

fn cross_origin_peers(
    origin: TcpListener,
    destination: TcpListener,
    origin_acceptor: SslAcceptor,
    destination_acceptor: SslAcceptor,
    destination_address: std::net::SocketAddr,
    observation: Option<owner_contract::Observation>,
) -> (CrossOriginPeer, CrossOriginPeer) {
    let (mut origin_control, mut destination_control) = match observation {
        Some(value) => (Some(value.origin), Some(value.destination)),
        None => (None, None),
    };
    let origin_lifetime = origin_control
        .as_ref()
        .map(owner_contract::Control::lifetime);
    let destination_lifetime = destination_control
        .as_ref()
        .map(owner_contract::Control::lifetime);
    let origin_server = ConnectionPeer::spawn(async move {
        let _lifetime = origin_lifetime;
        let mut heads = Vec::new();
        for attempt in 0..3 {
            let (tcp, _) = origin.accept().await?;
            let mut stream =
                super::tls_support::accept_tls_stream(tcp, origin_acceptor.clone()).await?;
            heads.push(String::from_utf8(
                owner_contract::observe_head(&mut stream, origin_control.as_ref()).await?,
            )?);
            let response = if attempt == 0 {
                let body = "id: first\ndata: one\n\n";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: https://{destination_address}/events\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            };
            stream.write_all(response.as_bytes()).await?;
            owner_contract::written(origin_control.as_ref(), response.len());
            stream.shutdown().await?;
            owner_contract::after_shutdown(origin_control.as_mut())?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
    });
    let destination_server = ConnectionPeer::spawn(async move {
        let _lifetime = destination_lifetime;
        let mut heads = Vec::new();
        for attempt in 0..2 {
            let (tcp, _) = destination.accept().await?;
            let mut stream =
                super::tls_support::accept_tls_stream(tcp, destination_acceptor.clone()).await?;
            heads.push(String::from_utf8(
                owner_contract::observe_head(&mut stream, destination_control.as_ref()).await?,
            )?);
            let response = if attempt == 0 {
                let body = "id:\ndata: two\n\n";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccept-CH: last-event-id\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".into()
            };
            stream.write_all(response.as_bytes()).await?;
            owner_contract::written(destination_control.as_ref(), response.len());
            stream.shutdown().await?;
            owner_contract::after_shutdown(destination_control.as_mut())?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
    });
    (origin_server, destination_server)
}

async fn finish_cross_origin(
    caller: TestResult<CrossOriginCaller>,
    mut origin_server: CrossOriginPeer,
    mut destination_server: CrossOriginPeer,
) -> TestResult<(CrossOriginCaller, Vec<String>, Vec<String>)> {
    let origin_abort = origin_server.abort_handle();
    let destination_abort = destination_server.abort_handle();
    let mut origin_requested = false;
    let mut destination_requested = false;
    if caller.is_err() {
        abort_cross_origin_peer(&origin_abort, &mut origin_requested);
        abort_cross_origin_peer(&destination_abort, &mut destination_requested);
    }

    let (origin_joined, destination_joined) = {
        let origin_join = timeout(super::TEST_TIMEOUT, &mut origin_server);
        let destination_join = timeout(super::TEST_TIMEOUT, &mut destination_server);
        tokio::pin!(origin_join, destination_join);
        tokio::select! {
            joined = &mut origin_join => {
                if !matches!(&joined, Ok(Ok(Ok(_)))) {
                    abort_cross_origin_peer(&origin_abort, &mut origin_requested);
                    abort_cross_origin_peer(&destination_abort, &mut destination_requested);
                }
                (joined, destination_join.await)
            }
            joined = &mut destination_join => {
                if !matches!(&joined, Ok(Ok(Ok(_)))) {
                    abort_cross_origin_peer(&origin_abort, &mut origin_requested);
                    abort_cross_origin_peer(&destination_abort, &mut destination_requested);
                }
                (origin_join.await, joined)
            }
        }
    };

    if !matches!(&origin_joined, Ok(Ok(Ok(_)))) || !matches!(&destination_joined, Ok(Ok(Ok(_)))) {
        abort_cross_origin_peer(&origin_abort, &mut origin_requested);
        abort_cross_origin_peer(&destination_abort, &mut destination_requested);
    }

    let origin_result = complete_cross_origin_join(
        &mut origin_server,
        origin_requested,
        origin_joined,
        "cross-origin origin peer did not finish",
    )
    .await;
    let destination_result = complete_cross_origin_join(
        &mut destination_server,
        destination_requested,
        destination_joined,
        "cross-origin destination peer did not finish",
    )
    .await;

    let mut heads = None;
    let cleanup: TestResult<()> = match (origin_result, destination_result) {
        (Ok(origin), Ok(destination)) => {
            heads = Some((origin, destination));
            Ok(())
        }
        (Err(primary), Err(cleanup)) => Err(Box::new(FixtureFailures { primary, cleanup })),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
    };
    let caller = finish_with_cleanup(caller, cleanup)?;
    let (origin_heads, destination_heads) = heads.ok_or("cross-origin results missing")?;
    let origin_heads = origin_heads.ok_or("cross-origin origin cancelled without a failure")?;
    let destination_heads =
        destination_heads.ok_or("cross-origin destination cancelled without a failure")?;
    Ok((caller, origin_heads, destination_heads))
}

fn abort_cross_origin_peer(abort: &AbortHandle, requested: &mut bool) {
    if !abort.is_finished() {
        *requested = true;
        abort.abort();
    }
}

async fn complete_cross_origin_join(
    peer: &mut CrossOriginPeer,
    requested: bool,
    joined: CrossOriginJoin,
    message: &'static str,
) -> TestResult<Option<Vec<String>>> {
    match joined {
        Ok(result) => cross_origin_join_outcome(result, requested),
        Err(elapsed) => {
            let mut requested = requested;
            abort_cross_origin_peer(&peer.abort_handle(), &mut requested);
            let cleanup = match timeout(super::TEST_TIMEOUT, peer).await {
                Ok(result) => cross_origin_join_outcome(result, requested).map(|_| ()),
                Err(elapsed) => Err(FixtureDeadline::new(message, elapsed).into()),
            };
            finish_with_cleanup(Err(FixtureDeadline::new(message, elapsed).into()), cleanup)
        }
    }
}

fn cross_origin_join_outcome(
    joined: Result<TestResult<Vec<String>>, JoinError>,
    requested: bool,
) -> TestResult<Option<Vec<String>>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn id_slot_template() -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("X-Before", "first"),
            RequestField::caller("Last-Event-ID"),
            RequestField::literal("X-After", "last"),
        ],
        http2_fields: Vec::new(),
        http3_fields: None,
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    }
}
