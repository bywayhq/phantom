use std::{future::Future, io, net::Ipv4Addr, pin::Pin, sync::Arc, task::Poll};

use http_body_util::BodyExt;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout};

use crate::support::{
    tls::{H2_ALPN, TestIdentity, accept_tls},
    tunnel_proxy::connection_peer::FixtureFailures,
};

use super::super::{
    Client, ClientProfile, HttpProtocol, RecordedHeaders, RecordingIo, RequestHeader, StatusCode,
    collect_h2_recording, finish_h2_request_failure, record_h2_connection, tls_settings,
};
use super::{
    AbortBackup, DEADLINE, FailingRead, Mutex, TestResult, destruction_before_backup,
    peer_with_destruction,
};

struct Recorder {
    client: Option<Client>,
    url: String,
    peer: Option<JoinHandle<TestResult<RecordedHeaders>>>,
    backup: AbortBackup,
    stopped: oneshot::Receiver<()>,
    fail: Option<oneshot::Sender<()>>,
    failure: oneshot::Receiver<Option<(io::ErrorKind, String)>>,
}

async fn recorder(expected: usize) -> TestResult<Recorder> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}/cookies", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let client = Client::builder(ClientProfile::new(tls_settings()))
        .add_root_certificate_der(identity.root_der)
        .build()?;
    let (fail, failed) = oneshot::channel();
    let (failure, observed_failure) = oneshot::channel();

    let (peer, backup, stopped) = peer_with_destruction(async move {
        let tls = accept_tls(listener, acceptor).await?;
        let wire = Arc::new(Mutex::new(Vec::new()));
        let io = RecordingIo {
            inner: FailingRead {
                inner: tls,
                fail: failed,
            },
            read: Arc::clone(&wire),
        };
        let connection = ::http2::server::handshake(io).await?;
        let result = record_h2_connection(connection, wire, Vec::new(), expected).await;
        let observed = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<::http2::Error>())
            .and_then(::http2::Error::get_io)
            .map(|error| (error.kind(), error.to_string()));
        failure
            .send(observed)
            .map_err(|_| "read-failure observer stopped")?;
        result
    });
    Ok(Recorder {
        client: Some(client),
        url,
        peer: Some(peer),
        backup,
        stopped,
        fail: Some(fail),
        failure: observed_failure,
    })
}

async fn exchange(recorder: &Recorder) -> TestResult<()> {
    let client = recorder.client.as_ref().ok_or("recorder client missing")?;
    let response = timeout(
        DEADLINE,
        client
            .get(HttpProtocol::Http2, &recorder.url)?
            .header(RequestHeader::new("accept", "*/*"))
            .send(),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        timeout(DEADLINE, response.into_body().collect())
            .await??
            .to_bytes(),
        &b"ok"[..]
    );
    Ok(())
}

#[tokio::test]
async fn dropping_the_unpolled_capture_collection_destroys_its_live_recorder() -> TestResult<()> {
    let mut recorder = recorder(1).await?;
    exchange(&recorder).await?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;

    let collected = collect_h2_recording(peer);
    drop(collected);
    let stopped = destruction_before_backup(&mut recorder.stopped, &recorder.backup).await?;

    assert!(
        stopped,
        "live HTTP2 recorder outlived its unpolled collection owner"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_capture_collection_destroys_its_live_recorder() -> TestResult<()> {
    let mut recorder = recorder(1).await?;
    exchange(&recorder).await?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let mut collection = Box::pin(collect_h2_recording(peer));
    let selection =
        std::future::poll_fn(|context| Poll::Ready(collection.as_mut().poll(context))).await;

    drop(collection);
    let stopped = destruction_before_backup(&mut recorder.stopped, &recorder.backup).await?;
    if let Poll::Ready(result) = selection {
        result?;
        return Err("live recorder collection completed before cancellation".into());
    }

    assert!(stopped, "live HTTP2 recorder outlived cancelled collection");
    Ok(())
}

#[tokio::test]
async fn an_unrelated_final_driver_read_error_is_retained() -> TestResult<()> {
    let mut recorder = recorder(1).await?;
    exchange(&recorder).await?;
    recorder
        .fail
        .take()
        .ok_or("read-failure sender missing")?
        .send(())
        .map_err(|_| "recorder stopped before read failure")?;
    let mut peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let result = timeout(DEADLINE, &mut peer).await??;

    let error = result
        .err()
        .ok_or("recorder accepted an unrelated final read failure")?;
    let h2 = error
        .downcast_ref::<::http2::Error>()
        .ok_or("driver lost its HTTP2 cause")?;
    let io = h2.get_io().ok_or("driver lost its IO cause")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), "cookie recorder injected read failure913");
    Ok(())
}

#[tokio::test]
async fn a_real_request_failure_keeps_the_completed_recorder_failure() -> TestResult<()> {
    let mut recorder = recorder(2).await?;
    exchange(&recorder).await?;
    recorder
        .fail
        .take()
        .ok_or("read-failure sender missing")?
        .send(())
        .map_err(|_| "recorder stopped before read failure")?;
    let observed = timeout(DEADLINE, &mut recorder.failure)
        .await??
        .ok_or("recorder did not retain its actual read failure")?;
    assert_eq!(observed.0, io::ErrorKind::PermissionDenied);
    assert_eq!(observed.1, "cookie recorder injected read failure913");
    timeout(DEADLINE, &mut recorder.stopped).await??;

    let client = recorder.client.as_ref().ok_or("recorder client missing")?;
    let request = timeout(
        DEADLINE,
        client.get(HttpProtocol::Http2, &recorder.url)?.send(),
    )
    .await?;
    let primary = request
        .err()
        .ok_or("request unexpectedly survived recorder failure")?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let error = finish_h2_request_failure(primary, peer)
        .await
        .err()
        .ok_or("request and recorder failures were accepted")?;

    let combined = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("completed recorder failure was rendered as text instead of retained")?;
    assert!(
        combined
            .primary
            .downcast_ref::<phantom::RequestError>()
            .is_some()
    );
    let h2 = combined
        .cleanup
        .downcast_ref::<::http2::Error>()
        .ok_or("cleanup lost the actual recorder HTTP2 error")?;
    let io = h2
        .get_io()
        .ok_or("cleanup lost the actual recorder IO error")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), "cookie recorder injected read failure913");
    Ok(())
}

#[tokio::test]
async fn a_collected_response_and_clean_client_close_keep_literal_observations() -> TestResult<()> {
    let mut recorder = recorder(1).await?;
    exchange(&recorder).await?;
    drop(recorder.client.take());
    let mut peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let (wire, names) = timeout(DEADLINE, &mut peer).await???;

    assert!(wire.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    assert_eq!(names.len(), 1);
    assert!(
        names[0]
            .iter()
            .any(|(name, value)| name == "accept" && value == "*/*")
    );
    assert_eq!(timeout(DEADLINE, &mut recorder.failure).await??, None);
    Ok(())
}
