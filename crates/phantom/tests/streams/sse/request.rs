use std::{io, net::Ipv4Addr, time::Duration};

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
    sync::watch,
    task::JoinError,
    time::{Instant, error::Elapsed, timeout, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{
    SsePeer, TEST_TIMEOUT, TestResult, peer_completion,
    tls_support::{H1_ALPN, accept_tls, read_head, test_client},
};

mod managed_id_cycle;
mod owner_contract;

type CrossOriginPeer = SsePeer<Vec<String>>;
type CrossOriginJoin = Result<Result<TestResult<Option<Vec<String>>>, JoinError>, Elapsed>;
// Keep caller resources alive through worker joins and header assertions.
type CrossOriginCaller = Option<(phantom::SseEventSource, Client)>;

#[tokio::test]
async fn replacing_headers_removes_event_source_defaults() -> TestResult<()> {
    replace_headers(HeaderReplacementExit::Success).await
}

#[derive(Debug)]
enum HeaderReplacementExit {
    Success,
    CallerAndPeer { caller: io::Error, peer: io::Error },
}

async fn replace_headers(exit: HeaderReplacementExit) -> TestResult<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let identity = super::tls_support::TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (caller_failure, peer_failure) = match exit {
        HeaderReplacementExit::Success => (None, None),
        HeaderReplacementExit::CallerAndPeer { caller, peer } => (Some(caller), Some(peer)),
    };
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        if let Some(error) = peer_failure {
            return Err(error.into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
    });
    let completed = server.abort_handle();

    let (_response, head) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let response = test_client(&identity, false)?
            .event_source(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .headers(vec![SseHeader::field(RequestHeader::new(
                "X-Custom", "only",
            ))])
            .connect()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        if let Some(error) = caller_failure {
            while !completed.is_finished() {
                tokio::task::yield_now().await;
            }
            return Err(error.into());
        }
        Ok(response)
    })
    .await?;

    let head = String::from_utf8(head)?;
    assert!(head.lines().any(|line| line == "X-Custom: only"));
    assert!(!head.lines().any(|line| line.starts_with("Accept:")));
    assert!(!head.lines().any(|line| line.starts_with("Cache-Control:")));
    Ok(())
}

#[tokio::test]
async fn replacing_headers_keeps_a_caller_failure_and_completed_tls_peer_failure() -> TestResult<()>
{
    let caller = io::Error::new(
        io::ErrorKind::InvalidInput,
        "header caller failed after response",
    );
    let peer = io::Error::new(
        io::ErrorKind::PermissionDenied,
        "header peer failed after shutdown",
    );
    let error = replace_headers(HeaderReplacementExit::CallerAndPeer { caller, peer })
        .await
        .err()
        .ok_or("header caller and peer failures were discarded")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("completed TLS peer failure was not collected with the caller")?;
    let caller = failures
        .primary
        .downcast_ref::<io::Error>()
        .ok_or("original caller I/O error type changed")?;
    let peer = failures
        .cleanup
        .downcast_ref::<io::Error>()
        .ok_or("original TLS peer I/O error type changed")?;
    assert_eq!(caller.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(caller.to_string(), "header caller failed after response");
    assert_eq!(peer.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(peer.to_string(), "header peer failed after shutdown");
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
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "inherited ID rejection stalled during network setup",
                elapsed,
            )
        })?
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
            .map_err(|elapsed| {
                FixtureDeadline::new(
                    "automatic ID rejection stalled during network setup",
                    elapsed,
                )
            })?
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

    let deadline = Instant::now() + TEST_TIMEOUT;
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
    let client = Client::builder(
        ClientProfile::new(super::tls_support::tls_settings()).with_request_template(template),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
    .resolve("redirect.phantom.test", [target_address.ip()])
    .build()?;
    let mut server = SsePeer::spawn(async move {
        let mut stream = accept_tls(initial_listener, acceptor).await?;
        let head = String::from_utf8(read_head(&mut stream).await?)?;
        assert!(!head.to_ascii_lowercase().contains("last-event-id:"));
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://redirect.phantom.test:{}/events\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            target_address.port()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let ((), ()) = peer_completion::run(&mut server, deadline, TEST_TIMEOUT, async {
        let error = client
            .event_source(
                HttpProtocol::Http1,
                &format!("https://{initial_address}/events"),
            )?
            .initial_retry(Duration::ZERO)
            .max_reconnects(2)
            .connect()
            .await
            .err()
            .ok_or("activated default reached the redirected origin")?;
        assert_eq!(error.kind(), SseErrorKind::Request);
        let request_error = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<RequestError>())
            .ok_or("validation error source missing")?;
        assert_eq!(request_error.kind(), RequestErrorKind::RequestTemplate);
        Ok(())
    })
    .await?;
    let quiet = timeout_at(
        deadline,
        timeout(Duration::from_millis(25), target_listener.accept()),
    )
    .await
    .map_err(|elapsed| FixtureDeadline::new("SSE test exceeded its deadline", elapsed))?;
    assert!(quiet.is_err());
    Ok(())
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
    let origin_server = SsePeer::spawn(async move {
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
    let destination_server = SsePeer::spawn(async move {
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
    let origin_stop = origin_server.stop_signal();
    let destination_stop = destination_server.stop_signal();
    if caller.is_err() {
        stop_cross_origin_peer(&origin_stop);
        stop_cross_origin_peer(&destination_stop);
    }

    let (origin_joined, destination_joined) = {
        let origin_join = timeout(super::TEST_TIMEOUT, &mut origin_server);
        let destination_join = timeout(super::TEST_TIMEOUT, &mut destination_server);
        tokio::pin!(origin_join, destination_join);
        tokio::select! {
            joined = &mut origin_join => {
                if !matches!(&joined, Ok(Ok(Ok(Some(_))))) {
                    stop_cross_origin_peer(&origin_stop);
                    stop_cross_origin_peer(&destination_stop);
                }
                (joined, destination_join.await)
            }
            joined = &mut destination_join => {
                if !matches!(&joined, Ok(Ok(Ok(Some(_))))) {
                    stop_cross_origin_peer(&origin_stop);
                    stop_cross_origin_peer(&destination_stop);
                }
                (origin_join.await, joined)
            }
        }
    };

    if !matches!(&origin_joined, Ok(Ok(Ok(Some(_)))))
        || !matches!(&destination_joined, Ok(Ok(Ok(Some(_)))))
    {
        stop_cross_origin_peer(&origin_stop);
        stop_cross_origin_peer(&destination_stop);
    }

    let origin_result = complete_cross_origin_join(
        &mut origin_server,
        origin_joined,
        "cross-origin origin peer did not finish",
    )
    .await;
    let destination_result = complete_cross_origin_join(
        &mut destination_server,
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

fn stop_cross_origin_peer(stop: &watch::Sender<bool>) {
    stop.send_replace(true);
}

async fn complete_cross_origin_join(
    peer: &mut CrossOriginPeer,
    joined: CrossOriginJoin,
    message: &'static str,
) -> TestResult<Option<Vec<String>>> {
    match joined {
        Ok(result) => cross_origin_join_outcome(result),
        Err(elapsed) => {
            peer.request_stop();
            let cleanup = match timeout(super::TEST_TIMEOUT, peer).await {
                Ok(result) => cross_origin_join_outcome(result).map(|_| ()),
                Err(elapsed) => Err(FixtureDeadline::new(message, elapsed).into()),
            };
            finish_with_cleanup(Err(FixtureDeadline::new(message, elapsed).into()), cleanup)
        }
    }
}

fn cross_origin_join_outcome(
    joined: Result<TestResult<Option<Vec<String>>>, JoinError>,
) -> TestResult<Option<Vec<String>>> {
    match joined {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cross_origin_cleanup_keeps_a_pending_external_abort_and_stops_its_sibling()
-> TestResult<()> {
    use std::pin::Pin;

    use btls::{
        ssl::{SslConnector, SslMethod, SslVerifyMode},
        x509::X509,
    };
    use tokio::{io::AsyncReadExt, net::TcpStream};
    use tokio_btls::SslStream;

    let identity = super::tls_support::TestIdentity::generate()?;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin.local_addr()?;
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
    let original_task = origin_server.abort_handle().id();
    let mut clients = Vec::new();
    let caller: TestResult<CrossOriginCaller> = async {
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H1_ALPN)?;
        let connector = connector.build();
        for address in [origin_address, destination_address] {
            let ssl = connector.configure()?.into_ssl("127.0.0.1")?;
            let socket = timeout(TEST_TIMEOUT, TcpStream::connect(address)).await??;
            clients.push(SslStream::new(ssl, socket)?);
            let client = clients
                .last_mut()
                .ok_or("cross-origin control client missing")?;
            timeout(TEST_TIMEOUT, Pin::new(client).connect()).await??;
        }
        origin_server.abort_handle().abort();
        assert!(!origin_server.is_finished());
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "original cross-origin caller failure",
        )
        .into())
    }
    .await;

    let error = finish_cross_origin(caller, origin_server, destination_server)
        .await
        .err()
        .ok_or("pending cross-origin external cancellation was discarded")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("external cross-origin cancellation was mistaken for local cleanup")?;
    let caller = failures
        .primary
        .downcast_ref::<io::Error>()
        .ok_or("original cross-origin caller error lost")?;
    assert_eq!(caller.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(caller.to_string(), "original cross-origin caller failure");
    let cancelled = failures
        .cleanup
        .downcast_ref::<JoinError>()
        .ok_or("original cross-origin cancellation type lost")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(cancelled.id(), original_task);
    for client in &mut clients {
        match timeout(TEST_TIMEOUT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => {}
            Err(error) if super::tls_support::is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("cross-origin cleanup left unexpected bytes".into()),
        }
    }
    for address in [origin_address, destination_address] {
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
    }
    Ok(())
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
