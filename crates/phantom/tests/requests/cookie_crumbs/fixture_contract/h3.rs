use std::{
    error::Error,
    future::{Future, pending},
    task::Poll,
};

use http_body_util::BodyExt;
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

use crate::support::{
    h3 as h3_support, tls::TestIdentity, tunnel_proxy::connection_peer::FixtureFailures,
};

use super::super::{
    Client, ClientProfile, HttpProtocol, RequestHeader, StatusCode, cookie_h3_request,
    finish_h3_recording, record_h3_cookies, tls_settings,
};
use super::{AbortBackup, DEADLINE, TestResult, destruction_before_backup, peer_with_destruction};

struct Recorder {
    client: Client,
    url: String,
    peer: Option<JoinHandle<TestResult<Vec<Vec<u8>>>>>,
    backup: AbortBackup,
    stopped: oneshot::Receiver<()>,
    done: Option<oneshot::Sender<()>>,
}

async fn recorder() -> TestResult<Recorder> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = h3_support::server_endpoint(&identity)?;
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tls).with_http3(h3_support::client_settings());
    let client = Client::builder(profile)
        .add_root_certificate_der(identity.root_der)
        .build()?;
    let (done, collected) = oneshot::channel();
    let (peer, backup, stopped) = peer_with_destruction(record_h3_cookies(endpoint, collected));

    Ok(Recorder {
        client,
        url: format!("https://{address}/cookies"),
        peer: Some(peer),
        backup,
        stopped,
        done: Some(done),
    })
}

async fn exchange(recorder: &Recorder) -> TestResult<()> {
    let response = timeout(
        DEADLINE,
        recorder
            .client
            .get(HttpProtocol::Http3, &recorder.url)?
            .header(RequestHeader::new("cookie", "k=v"))
            .send(),
    )
    .await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        timeout(DEADLINE, response.into_body().collect())
            .await??
            .to_bytes()
            .is_empty()
    );
    Ok(())
}

fn has_elapsed(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
        {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

fn has_receiver_error(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.downcast_ref::<oneshot::error::RecvError>().is_some() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

#[tokio::test]
async fn dropping_unpolled_h3_completion_destroys_the_ready_recorder() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;

    let completion = finish_h3_recording(Ok(()), peer);
    drop(completion);
    let stopped = destruction_before_backup(&mut recorder.stopped, &recorder.backup).await?;

    assert!(
        stopped,
        "ready HTTP3 recorder outlived its unpolled completion owner"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_h3_completion_destroys_the_ready_recorder() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let mut completion = Box::pin(finish_h3_recording(Ok(()), peer));
    let selection =
        std::future::poll_fn(|context| Poll::Ready(completion.as_mut().poll(context))).await;

    drop(completion);
    let stopped = destruction_before_backup(&mut recorder.stopped, &recorder.backup).await?;
    if let Poll::Ready(result) = selection {
        result?;
        return Err("ready recorder completion finished before cancellation".into());
    }

    assert!(
        stopped,
        "ready HTTP3 recorder outlived cancelled completion"
    );
    Ok(())
}

#[tokio::test]
async fn a_closed_collection_sender_keeps_its_actual_receiver_error() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    drop(recorder.done.take());
    let mut peer = recorder.peer.take().ok_or("recorder peer missing")?;

    let error = timeout(DEADLINE, &mut peer)
        .await??
        .err()
        .ok_or("closed collection sender was accepted")?;

    assert!(
        has_receiver_error(error.as_ref()),
        "collection receiver error became text"
    );
    Ok(())
}

#[tokio::test]
async fn a_preparation_error_keeps_the_completed_h3_recorder_failure() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    drop(recorder.done.take());
    timeout(DEADLINE, &mut recorder.stopped).await??;
    let primary = recorder
        .client
        .get(HttpProtocol::Http3, "not a URL")
        .err()
        .ok_or("invalid request URL was accepted")?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;

    let error = finish_h3_recording(Err(primary.into()), peer)
        .await
        .err()
        .ok_or("preparation and recorder failures were accepted")?;

    let combined = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("completed HTTP3 recorder failure was discarded")?;
    assert!(
        combined
            .primary
            .downcast_ref::<phantom::RequestError>()
            .is_some()
    );
    assert!(has_receiver_error(combined.cleanup.as_ref()));
    Ok(())
}

#[tokio::test]
async fn h3_request_expiry_keeps_elapsed_after_an_actual_response() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    recorder
        .done
        .take()
        .ok_or("collection sender missing")?
        .send(())
        .map_err(|_| "recorder stopped before collection")?;
    let mut peer = recorder.peer.take().ok_or("recorder peer missing")?;
    let observed = timeout(DEADLINE, &mut peer).await???;
    assert_eq!(observed, [b"k=v".to_vec()]);

    tokio::time::pause();
    let error = cookie_h3_request(pending::<TestResult<()>>())
        .await
        .err()
        .ok_or("pending request did not expire")?;

    assert!(
        error
            .to_string()
            .contains("HTTP/3 cookie request exceeded its deadline")
    );
    assert!(
        has_elapsed(error.as_ref()),
        "request deadline discarded Elapsed"
    );
    Ok(())
}

#[tokio::test]
async fn h3_server_expiry_keeps_elapsed_after_an_actual_response() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;

    tokio::time::pause();
    let error = finish_h3_recording(Ok(()), peer)
        .await
        .err()
        .ok_or("pending recorder did not expire")?;
    timeout(DEADLINE, &mut recorder.stopped).await??;

    assert!(
        error
            .to_string()
            .contains("HTTP/3 cookie server exceeded its deadline")
    );
    assert!(
        has_elapsed(error.as_ref()),
        "server deadline discarded Elapsed"
    );
    Ok(())
}

#[tokio::test]
async fn a_completed_h3_recorder_keeps_literal_cookie_observations() -> TestResult<()> {
    let mut recorder = recorder().await?;
    exchange(&recorder).await?;
    recorder
        .done
        .take()
        .ok_or("collection sender missing")?
        .send(())
        .map_err(|_| "recorder stopped before collection")?;
    let peer = recorder.peer.take().ok_or("recorder peer missing")?;

    let observed = finish_h3_recording(Ok(()), peer).await?;

    assert_eq!(observed, [b"k=v".to_vec()]);
    timeout(DEADLINE, &mut recorder.stopped).await??;
    Ok(())
}

#[tokio::test]
async fn h3_request_wrapper_keeps_ready_values_and_inner_errors() -> TestResult<()> {
    let value = cookie_h3_request(async { Ok(17_u8) }).await?;
    assert_eq!(value, 17);

    let error = cookie_h3_request(async {
        Err::<(), _>(
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cookie wrapper injected operation failure914",
            )
            .into(),
        )
    })
    .await
    .err()
    .ok_or("inner request failure was accepted")?;
    let io = error
        .downcast_ref::<std::io::Error>()
        .ok_or("inner operation cause changed")?;
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        io.to_string(),
        "cookie wrapper injected operation failure914"
    );
    Ok(())
}
