mod peers;

use std::{
    error::Error,
    future::Future,
    io,
    task::{Context, Poll, Waker},
};

use phantom::{BuildError, BuildErrorKind, RequestError, RequestErrorKind};
use tokio::time::{error::Elapsed, timeout};

use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};

use super::{
    ConnectUpload, TestResult, bounded, finish_connect_upload, prepare_connect_upload,
    send_connect_upload,
};
use peers::{DEADLINE, Reply, ready_upload};

#[tokio::test]
async fn dropping_an_unpolled_upload_finish_destroys_both_ready_peers() -> TestResult<()> {
    let (prepared, mut observations, _, origin_address, _) = ready_upload(Reply::Held).await?;
    let retained_client = prepared.client.clone();
    let stopped = async {
        timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await??;
        observations.ready(origin_address).await?;

        let completion = finish_connect_upload(Ok(()), prepared, origin_address);
        drop(completion);
        observations.destroyed_before_backup().await
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    let stopped = finish_with_cleanup(stopped, cleanup)?;
    assert_eq!(
        stopped,
        (true, true),
        "unpolled finish left driven CONNECT peers alive"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_a_polled_upload_finish_destroys_both_ready_peers() -> TestResult<()> {
    let (prepared, mut observations, _, origin_address, _) = ready_upload(Reply::Held).await?;
    let retained_client = prepared.client.clone();
    let observed: TestResult<_> = async {
        timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await??;
        observations.ready(origin_address).await?;

        let mut completion = Box::pin(finish_connect_upload(Ok(()), prepared, origin_address));
        let pending = matches!(
            completion
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        drop(completion);
        let stopped = observations.destroyed_before_backup().await?;
        Ok((pending, stopped))
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    let (pending, stopped) = finish_with_cleanup(observed, cleanup)?;
    assert!(pending, "held origin must leave finish pending");
    assert_eq!(
        stopped,
        (true, true),
        "cancelled finish left driven CONNECT peers alive"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_trust_preparation_destroys_already_acquired_connect_peers() -> TestResult<()> {
    let (prepared, mut observations, mut identity, origin_address, proxy_address) =
        ready_upload(Reply::Held).await?;
    let retained_client = prepared.client.clone();
    let observed: TestResult<_> = async {
        timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await??;
        observations.ready(origin_address).await?;

        let ConnectUpload {
            client,
            origin,
            proxy,
        } = prepared;
        drop(client);
        identity.root_der = b"not-a-certificate".to_vec();
        let preparation = prepare_connect_upload(origin, proxy, &identity, proxy_address);
        let stopped = observations.destroyed_before_backup().await?;
        Ok((preparation, stopped))
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    let (preparation, stopped) = match observed {
        Ok(observed) => observed,
        Err(primary) => return finish_with_cleanup(Err(primary), cleanup),
    };
    if cleanup.is_err() {
        return finish_with_cleanup(preparation.map(|_| ()), cleanup);
    }

    let error = match preparation {
        Ok(_) => return Err("invalid trust root unexpectedly built a client".into()),
        Err(error) => error,
    };
    let build = error
        .downcast_ref::<BuildError>()
        .ok_or("trust preparation lost BuildError")?;
    assert_eq!(build.kind(), BuildErrorKind::TrustStore);
    assert!(build.source().is_some());
    assert_eq!(
        stopped,
        (true, true),
        "preparation failure detached acquired CONNECT peers"
    );
    Ok(())
}

#[tokio::test]
async fn truncated_body_keeps_the_completed_proxy_failure_at_caller_cleanup() -> TestResult<()> {
    let (prepared, mut observations, _, origin_address, _) = ready_upload(Reply::Truncated).await?;
    let retained_client = prepared.client.clone();
    let observed: TestResult<_> = async {
        let operation = timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await?;
        observations.ready(origin_address).await?;
        let primary = operation
            .as_ref()
            .err()
            .ok_or("truncated response was accepted")?;
        assert_http1_body_failure(primary.as_ref())?;

        let cause = timeout(DEADLINE, &mut observations.proxy_failure).await??;
        let stopped = observations.destroyed_before_backup().await?;
        let result = timeout(
            DEADLINE,
            finish_connect_upload(operation, prepared, origin_address),
        )
        .await?;
        Ok((cause, stopped, result))
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    let ((kind, message), stopped, result) = match observed {
        Ok(observed) => observed,
        Err(primary) => return finish_with_cleanup(Err(primary), cleanup),
    };
    if cleanup.is_err() {
        return finish_with_cleanup(result, cleanup);
    }

    assert_eq!(kind, io::ErrorKind::PermissionDenied);
    assert_eq!(message, "completed CONNECT proxy 911");
    assert_eq!(stopped, (true, true));
    let error = result
        .err()
        .ok_or("truncated response and proxy error disappeared")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("caller discarded completed proxy failure")?;
    assert_http1_body_failure(failures.primary.as_ref())?;
    assert_io(
        failures.cleanup.as_ref(),
        io::ErrorKind::PermissionDenied,
        "completed CONNECT proxy 911",
    )?;
    Ok(())
}

#[tokio::test]
async fn completed_proxy_failure_keeps_the_completed_origin_failure() -> TestResult<()> {
    let (prepared, mut observations, _, origin_address, _) = ready_upload(Reply::BothFail).await?;
    let retained_client = prepared.client.clone();
    let observed: TestResult<_> = async {
        timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await??;
        observations.ready(origin_address).await?;

        let proxy = timeout(DEADLINE, &mut observations.proxy_failure).await??;
        let origin = timeout(DEADLINE, &mut observations.origin_failure).await??;
        let stopped = observations.destroyed_before_backup().await?;
        let result = timeout(
            DEADLINE,
            finish_connect_upload(Ok(()), prepared, origin_address),
        )
        .await?;
        Ok((proxy, origin, stopped, result))
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    let (proxy, origin, stopped, result) = match observed {
        Ok(observed) => observed,
        Err(primary) => return finish_with_cleanup(Err(primary), cleanup),
    };
    if cleanup.is_err() {
        return finish_with_cleanup(result, cleanup);
    }

    assert_eq!(
        proxy,
        (
            io::ErrorKind::PermissionDenied,
            "completed CONNECT proxy 911".to_owned()
        )
    );
    assert_eq!(
        origin,
        (
            io::ErrorKind::Unsupported,
            "completed CONNECT origin 912".to_owned()
        )
    );
    assert_eq!(stopped, (true, true));
    let error = result.err().ok_or("completed peer errors disappeared")?;
    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("sequential join discarded completed origin failure")?;
    assert_io(
        failures.primary.as_ref(),
        io::ErrorKind::PermissionDenied,
        "completed CONNECT proxy 911",
    )?;
    assert_io(
        failures.cleanup.as_ref(),
        io::ErrorKind::Unsupported,
        "completed CONNECT origin 912",
    )?;
    Ok(())
}

#[tokio::test]
async fn healthy_upload_finish_keeps_literal_connect_and_origin_bytes() -> TestResult<()> {
    let (prepared, mut observations, _, origin_address, _) = ready_upload(Reply::Complete).await?;
    let retained_client = prepared.client.clone();
    let result = async {
        timeout(
            DEADLINE,
            send_connect_upload(&prepared.client, origin_address),
        )
        .await??;
        observations.ready(origin_address).await?;
        timeout(
            DEADLINE,
            finish_connect_upload(Ok(()), prepared, origin_address),
        )
        .await?
    }
    .await;

    let cleanup = observations.cleanup().await;
    drop(retained_client);
    finish_with_cleanup(result, cleanup)
}

#[tokio::test(start_paused = true)]
async fn bounded_connect_deadline_keeps_context_and_elapsed_cause() -> TestResult<()> {
    let error = bounded(std::future::pending::<TestResult<()>>())
        .await
        .err()
        .ok_or("pending CONNECT operation did not time out")?;
    assert!(
        error
            .to_string()
            .contains("proxy integration test exceeded its deadline")
    );
    assert!(
        has_elapsed(error.as_ref()),
        "CONNECT deadline discarded Elapsed"
    );
    Ok(())
}

#[tokio::test]
async fn bounded_connect_operation_keeps_the_original_inner_error() -> TestResult<()> {
    let error = bounded(async {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "CONNECT inner failure 915").into())
    })
    .await
    .err()
    .ok_or("inner CONNECT error disappeared")?;
    assert_io(
        error.as_ref(),
        io::ErrorKind::PermissionDenied,
        "CONNECT inner failure 915",
    )
}

#[tokio::test]
async fn bounded_connect_ready_operation_succeeds() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}

fn has_elapsed(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<Elapsed>() {
            return true;
        }
        match error.source() {
            Some(source) => error = source,
            None => return false,
        }
    }
}

fn assert_http1_body_failure(error: &(dyn Error + 'static)) -> TestResult<()> {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("truncated body lost RequestError")?;
    assert_eq!(request.kind(), RequestErrorKind::Http1);
    assert!(matches!(
        request
            .source()
            .and_then(|error| error.downcast_ref::<phantom_net::http1::Http1Error>()),
        Some(phantom_net::http1::Http1Error::Protocol(_))
    ));
    Ok(())
}

fn assert_io(error: &(dyn Error + 'static), kind: io::ErrorKind, message: &str) -> TestResult<()> {
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("completed cause lost its io::Error")?;
    assert_eq!(error.kind(), kind);
    assert_eq!(error.to_string(), message);
    Ok(())
}
