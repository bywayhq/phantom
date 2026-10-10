use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::Method;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, HttpProxy, RequestErrorKind, Route};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};

use crate::support::tunnel_proxy::{ConnectionPeer, FixtureFailures};

use super::{
    H1_ALPN, H2Proxy, Reply, TaskProbe, TaskRole, TestIdentity, TestResult, accept_tls,
    client_builder, connect_error, finish_forward_exchange, read_head, serve_connects_observed,
    serve_forwarded_observed,
};

enum Cancellation {
    Finish,
    Drop,
    Unpolled,
}

async fn acquired_peer_cancellation(kind: Cancellation) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observation = probe.clone();
    let peer = probe.spawn(TaskRole::ProxyConnection, async move {
        let (tcp, _) = listener.accept().await?;
        serve_forwarded_observed(tcp, &acceptor, &[200, 200], None, Some(observation)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "http://acquired.test:8080/first")?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "forwarded"
    );
    assert!(
        !peer.is_finished(),
        "actual peer did not await its second request"
    );
    assert!(probe.live().contains(&TaskRole::ProxyConnection));

    match kind {
        Cancellation::Finish => {
            let error = finish_forward_exchange(
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "caller after first forwarded response",
                )
                .into()),
                peer,
            )
            .await
            .err()
            .ok_or("caller error disappeared")?;
            assert_eq!(
                error
                    .downcast_ref::<io::Error>()
                    .ok_or("caller type disappeared")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        Cancellation::Drop => drop(peer),
        Cancellation::Unpolled => drop(finish_forward_exchange(Ok(()), peer)),
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = probe.live();
    probe.backup().await?;
    drop(client);

    assert!(
        remaining.is_empty(),
        "acquired actual forward peer survived caller cancellation before backup: {remaining:?}"
    );
    Ok(())
}

#[tokio::test]
async fn caller_failure_stops_its_acquired_actual_peer() -> TestResult<()> {
    acquired_peer_cancellation(Cancellation::Finish).await
}
#[tokio::test]
async fn eager_caller_drop_stops_its_acquired_actual_peer() -> TestResult<()> {
    acquired_peer_cancellation(Cancellation::Drop).await
}
#[tokio::test]
async fn an_unpolled_caller_finish_owns_its_acquired_actual_peer() -> TestResult<()> {
    acquired_peer_cancellation(Cancellation::Unpolled).await
}

async fn forward_driver_cancellation(kind: Cancellation) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observation = probe.clone();
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        serve_forwarded_observed(tcp, &acceptor, &[200], None, Some(observation)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "http://forward.test:8080/ready")?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "forwarded"
    );
    let record = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(record.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(record.requests.len(), 1);
    assert_eq!(record.requests[0].method, "GET");
    assert_eq!(record.requests[0].path, "/ready");
    assert!(probe.live().contains(&TaskRole::ForwardDriver));

    match kind {
        Cancellation::Finish => record.finish().await?,
        Cancellation::Drop => drop(record),
        Cancellation::Unpolled => drop(record.finish()),
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = probe.live();
    probe.backup().await?;
    drop(client);

    assert!(
        remaining.is_empty(),
        "returned forwarding fixture left its actual driver live before backup: {remaining:?}"
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_forward_finish_stops_its_actual_driver() -> TestResult<()> {
    forward_driver_cancellation(Cancellation::Finish).await
}
#[tokio::test]
async fn eager_forward_drop_stops_its_actual_driver() -> TestResult<()> {
    forward_driver_cancellation(Cancellation::Drop).await
}
#[tokio::test]
async fn an_unpolled_forward_finish_owns_its_actual_driver() -> TestResult<()> {
    forward_driver_cancellation(Cancellation::Unpolled).await
}

async fn connect_cancellation(kind: Cancellation) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let origin = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let head = read_head(&mut stream).await?;
        assert_eq!(
            head,
            format!("GET /held HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        std::future::pending::<()>().await;
        drop(stream);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observation = probe.clone();
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        serve_connects_observed(
            tcp,
            &acceptor,
            vec![Reply::Tunnel(address)],
            Some(observation),
        )
        .await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http1, &format!("https://{address}/held"))?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "ok"
    );
    let fixture = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(fixture.records.len(), 1);
    assert_eq!(
        fixture.records[0].authority.as_deref(),
        Some(address.to_string().as_str())
    );
    assert!(
        !origin.is_finished(),
        "actual pooled origin was not held open"
    );
    for role in [
        TaskRole::ConnectDriver,
        TaskRole::RelayDownstream,
        TaskRole::RelayUpstream,
    ] {
        assert!(
            probe.live().contains(&role),
            "actual held CONNECT lacked {role:?}"
        );
    }

    match kind {
        Cancellation::Finish => fixture.finish().await?,
        Cancellation::Drop => drop(fixture),
        Cancellation::Unpolled => drop(fixture.finish()),
    }
    sleep(Duration::from_millis(150)).await;
    let remaining = probe.live();
    let backup = probe.backup().await;
    let origin_stop = origin.stop().await;
    crate::support::tunnel_proxy::finish_with_cleanup(backup, origin_stop)?;
    drop(client);

    assert!(
        remaining.is_empty(),
        "actual CONNECT descendants survived fixture cancellation before backup: {remaining:?}"
    );
    Ok(())
}

#[tokio::test]
async fn ordinary_connect_finish_stops_driver_and_relays() -> TestResult<()> {
    connect_cancellation(Cancellation::Finish).await
}
#[tokio::test]
async fn eager_connect_drop_stops_driver_and_relays() -> TestResult<()> {
    connect_cancellation(Cancellation::Drop).await
}
#[tokio::test]
async fn an_unpolled_connect_finish_owns_driver_and_relays() -> TestResult<()> {
    connect_cancellation(Cancellation::Unpolled).await
}

#[derive(Debug)]
struct CompletedPeerFailure;
impl fmt::Display for CompletedPeerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("completed H2 forward peer failure")
    }
}
impl Error for CompletedPeerFailure {}

async fn completed_outcome(fail_peer: bool, fail_caller: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let probe = TaskProbe::default();
    let observation = probe.clone();
    let (released, release) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let record =
            serve_forwarded_observed(tcp, &acceptor, &[200], None, Some(observation)).await?;
        release.await?;
        if fail_peer {
            record.finish().await?;
            return Err(CompletedPeerFailure.into());
        }
        Ok(record)
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "http://completed.test:8080/")?
            .send(),
    )
    .await??;
    assert_eq!(response.status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "forwarded"
    );
    released
        .send(())
        .map_err(|_| "completed peer release disappeared")?;
    timeout(Duration::from_secs(5), async {
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let primary = if fail_caller {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller after real H2 response",
        )
        .into())
    } else {
        Ok(())
    };
    let result = finish_forward_exchange(primary, peer).await;
    probe.backup().await?;
    drop(client);

    match (fail_peer, fail_caller) {
        (true, true) => {
            let error = result
                .err()
                .ok_or("both failed H2 outcomes became success")?;
            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("actual H2 caller discarded its completed secondary failure")?;
            assert_eq!(
                failures
                    .primary
                    .downcast_ref::<io::Error>()
                    .ok_or("primary caller type was lost")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(
                failures
                    .cleanup
                    .downcast_ref::<CompletedPeerFailure>()
                    .is_some()
            );
        }
        (true, false) => {
            assert!(
                result
                    .err()
                    .ok_or("completed peer failure disappeared")?
                    .downcast_ref::<CompletedPeerFailure>()
                    .is_some()
            );
        }
        (false, false) => {
            result?.finish().await?;
        }
        (false, true) => {
            assert_eq!(
                result
                    .err()
                    .ok_or("caller failure disappeared")?
                    .downcast_ref::<io::Error>()
                    .ok_or("caller type disappeared")?
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_completed_peer_failure_survives_a_primary_caller_failure() -> TestResult<()> {
    completed_outcome(true, true).await
}
#[tokio::test]
async fn a_completed_peer_failure_is_observed_after_a_healthy_caller() -> TestResult<()> {
    completed_outcome(true, false).await
}
#[tokio::test]
async fn ordinary_forward_completion_keeps_nonzero_observations() -> TestResult<()> {
    completed_outcome(false, false).await
}
#[tokio::test]
async fn a_caller_failure_keeps_its_concrete_type() -> TestResult<()> {
    completed_outcome(false, true).await
}

async fn recording(poison: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let wire = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&wire);
    let probe = TaskProbe::default();
    let observation = probe.clone();
    let statuses = if poison { vec![200, 200] } else { vec![200] };
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        serve_forwarded_observed(tcp, &acceptor, &statuses, Some(captured), Some(observation)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "http://recording.test:8080/first")?
            .send(),
    )
    .await??;
    assert_eq!(
        timeout(Duration::from_secs(5), response.into_body().collect())
            .await??
            .to_bytes(),
        "forwarded"
    );
    let healthy = wire
        .lock()
        .map_err(|_| "healthy recorder was poisoned")?
        .clone();
    assert!(healthy.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    assert_eq!(super::header_blocks(&healthy)?.len(), 1);
    if poison {
        let shared = Arc::clone(&wire);
        assert!(
            std::thread::spawn(move || {
                let Ok(_guard) = shared.lock() else {
                    return;
                };
                panic!("intentional recording poison");
            })
            .join()
            .is_err()
        );
        let response = timeout(
            Duration::from_secs(5),
            client
                .get(HttpProtocol::Http2, "http://recording.test:8080/second")?
                .send(),
        )
        .await?;
        if let Ok(response) = response {
            let _body = timeout(Duration::from_secs(5), response.into_body().collect()).await?;
        }
    }
    let result = timeout(Duration::from_secs(5), &mut peer).await??;
    probe.backup().await?;
    drop(client);

    if poison {
        let error = result.err().ok_or("poisoned recording was successful")?;
        let mut cause: &(dyn Error + 'static) = error.as_ref();
        while !cause.is::<io::Error>() {
            cause = cause
                .source()
                .ok_or("actual recording lost its typed poison cause")?;
        }
    } else {
        let record = result?;
        assert_eq!(record.requests.len(), 1);
        assert_eq!(record.requests[0].method, Method::GET.as_str());
        assert!(!record.client_wire.is_empty());
        record.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn poisoned_recording_keeps_its_actual_observer_cause() -> TestResult<()> {
    recording(true).await
}
#[tokio::test]
async fn healthy_recording_keeps_real_h2_bytes() -> TestResult<()> {
    recording(false).await
}

#[tokio::test]
async fn deliberate_http_connect_502_is_typed_after_real_traffic() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        super::serve_connect(tcp, &acceptor, Reply::Status(502)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let error = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "https://origin.test/page")?
            .send(),
    )
    .await?
    .err()
    .ok_or("deliberate 502 succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    assert!(matches!(
        connect_error(&error),
        Some(phantom_net::proxy::HttpConnectError::Rejected { status: 502 })
    ));
    drop(client);
    let record = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(record.authority.as_deref(), Some("origin.test:443"));
    assert_eq!(record.stream_id, 1);
    Ok(())
}

#[derive(Clone, Copy)]
enum RejectionCase {
    Actual,
    Success,
    Unrelated,
}

async fn rejection_observation(case: RejectionCase) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        super::serve_connect(tcp, &acceptor, Reply::Status(502)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let error = timeout(
        Duration::from_secs(5),
        client
            .get(HttpProtocol::Http2, "https://origin.test/page")?
            .send(),
    )
    .await?
    .err()
    .ok_or("deliberate rejection succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    assert!(matches!(
        connect_error(&error),
        Some(phantom_net::proxy::HttpConnectError::Rejected { status: 502 })
    ));
    let observed = match case {
        RejectionCase::Success => super::observe_rejection(Ok::<(), io::Error>(())),
        RejectionCase::Unrelated => super::observe_rejection(Err::<(), _>(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unrelated failure after actual rejection",
        ))),
        RejectionCase::Actual => super::observe_rejection(Err::<(), _>(error)),
    };
    drop(client);
    let record = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(record.authority.as_deref(), Some("origin.test:443"));
    assert_eq!(record.stream_id, 1);

    if !matches!(case, RejectionCase::Actual) {
        assert!(
            observed.is_err(),
            "actual CONNECT rejection observer accepted a substituted outcome"
        );
    } else {
        observed?;
    }
    Ok(())
}

#[tokio::test]
async fn the_rejection_observer_accepts_the_actual_typed_502() -> TestResult<()> {
    rejection_observation(RejectionCase::Actual).await
}
#[tokio::test]
async fn the_rejection_observer_rejects_an_unrelated_typed_failure() -> TestResult<()> {
    rejection_observation(RejectionCase::Unrelated).await
}
#[tokio::test]
async fn the_rejection_observer_rejects_an_unexpected_success() -> TestResult<()> {
    rejection_observation(RejectionCase::Success).await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn deliberate_wss_connect_502_is_typed_after_real_traffic() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (uri, root, acceptor, listener) = H2Proxy::bind().await?.into_parts()?;
    let mut peer = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        super::serve_connect(tcp, &acceptor, Reply::Status(502)).await
    });
    let client = client_builder(&identity, true)
        .add_proxy_root_certificate_der(root)
        .route(Route::http_proxy(
            HttpProxy::new(&uri)?.with_http2_transport()?,
        ))
        .build()?;
    let error = timeout(
        Duration::from_secs(5),
        client.websocket("wss://origin.test:8443/socket")?.connect(),
    )
    .await?
    .err()
    .ok_or("deliberate WSS 502 succeeded")?;
    assert_eq!(error.kind(), phantom::WebSocketErrorKind::Proxy);
    assert!(matches!(
        connect_error(&error),
        Some(phantom_net::proxy::HttpConnectError::Rejected { status: 502 })
    ));
    drop(client);
    let record = timeout(Duration::from_secs(5), &mut peer).await???;
    assert_eq!(record.authority.as_deref(), Some("origin.test:8443"));
    Ok(())
}
