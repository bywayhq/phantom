use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, HeaderHookError, HttpProtocol, RequestBuilder, RequestError, RequestErrorKind,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::watch,
    time::{error::Elapsed, timeout},
};

use super::{
    ClientProfile, TEST_TIMEOUT, TestResult, chrome, read_head, send_before_deadline, tls_settings,
};
use crate::support::deadline::FixtureDeadline;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const CLEANUP_LIMIT: Duration = Duration::from_secs(2);
const PURPOSES: [&str; 3] = [
    "the request on this runtime did not finish",
    "the negotiated request on this runtime did not finish",
    "the first negotiated request did not finish",
];
const SEND_CASES: [(RequestMode, &str); 3] = [
    (RequestMode::Exact, PURPOSES[0]),
    (RequestMode::Negotiated, PURPOSES[1]),
    (RequestMode::Negotiated, PURPOSES[2]),
];

#[tokio::test]
async fn actual_runtime_sends_complete_before_each_original_deadline() -> TestResult {
    let client =
        Client::builder(ClientProfile::new(tls_settings()).with_http2(chrome::v154_http2()))
            .build()?;

    for (mode, purpose) in SEND_CASES {
        let (address, peer, received) = start_peer(ResponsePlan::Reply).await?;
        let result: TestResult = async {
            let response = send_before_deadline(
                request(&client, &format!("http://{address}/deadline"), mode)?.send(),
                purpose,
            )
            .await?;

            if response.status() != StatusCode::OK {
                return Err("actual runtime response status changed".into());
            }

            let body = timeout(TEST_TIMEOUT, response.into_body().collect())
                .await??
                .to_bytes();
            if body != "done" {
                return Err("actual runtime response body changed".into());
            }

            require_request(&received)?;
            Ok(())
        }
        .await;

        finish_with_cleanup(result, finish_peer(peer).await)?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_runtime_send_failures_keep_their_original_hook_source() -> TestResult {
    let marker = Arc::new(());
    let hook_marker = Arc::clone(&marker);
    let client =
        Client::builder(ClientProfile::new(tls_settings()).with_http2(chrome::v154_http2()))
            .header_hook(move |_| {
                Err(HeaderHookError::new(OperationFailure(Arc::clone(
                    &hook_marker,
                ))))
            })
            .build()?;

    for (mode, purpose) in SEND_CASES {
        let error = send_before_deadline(
            request(&client, "http://127.0.0.1/deadline", mode)?.send(),
            purpose,
        )
        .await
        .err()
        .ok_or("runtime request hook failure was discarded")?;

        let request = error
            .downcast_ref::<RequestError>()
            .ok_or("original runtime request error type changed")?;
        assert_eq!(request.kind(), RequestErrorKind::HeaderHook);

        let hook = request
            .source()
            .and_then(|source| source.downcast_ref::<HeaderHookError>())
            .ok_or("original runtime request hook error was lost")?;

        let failure = hook
            .source()
            .and_then(|source| source.downcast_ref::<OperationFailure>())
            .ok_or("original runtime request hook payload was lost")?;
        assert!(Arc::ptr_eq(&failure.0, &marker));
    }
    Ok(())
}

#[tokio::test]
async fn exact_request_deadline_keeps_the_elapsed_of_an_actual_pending_send() -> TestResult {
    pending_send(RequestMode::Exact, PURPOSES[0]).await
}

#[tokio::test]
async fn negotiated_request_deadline_keeps_the_elapsed_of_an_actual_pending_send() -> TestResult {
    pending_send(RequestMode::Negotiated, PURPOSES[1]).await
}

#[tokio::test]
async fn first_negotiated_deadline_keeps_the_elapsed_of_an_actual_pending_send() -> TestResult {
    pending_send(RequestMode::Negotiated, PURPOSES[2]).await
}

async fn pending_send(mode: RequestMode, purpose: &'static str) -> TestResult {
    let client =
        Client::builder(ClientProfile::new(tls_settings()).with_http2(chrome::v154_http2()))
            .build()?;
    let (release, released) = watch::channel(false);
    let (address, peer, received) = start_peer(ResponsePlan::Held(released)).await?;
    let entered_pending = Cell::new(false);

    let result: TestResult = async {
        let sending = request(&client, &format!("http://{address}/deadline"), mode)?.send();
        tokio::pin!(sending);
        let observed = poll_fn(|context| {
            let result = sending.as_mut().poll(context);
            if result.is_pending() {
                entered_pending.set(true);
            }

            result
        });
        let error = send_before_deadline(observed, purpose)
            .await
            .err()
            .ok_or("held runtime request completed before its deadline")?;

        if !entered_pending.get() {
            return Err("actual runtime send was never polled Pending".into());
        }

        require_request(&received)?;

        if error.to_string() != purpose {
            return Err("runtime request deadline context changed".into());
        }

        error
            .source()
            .filter(|source| source.is::<Elapsed>())
            .ok_or("original runtime request Elapsed source was lost")?;
        Ok(())
    }
    .await;

    let released: TestResult = release.send(true).map_err(Into::into);
    let cleanup = finish_with_cleanup(released, finish_peer(peer).await);
    finish_with_cleanup(result, cleanup)
}

#[derive(Clone, Copy)]
enum RequestMode {
    Exact,
    Negotiated,
}

fn request(client: &Client, uri: &str, mode: RequestMode) -> Result<RequestBuilder, RequestError> {
    match mode {
        RequestMode::Exact => client.get_with_protocol(HttpProtocol::Http1, uri),
        RequestMode::Negotiated => client.get(uri),
    }
}

enum ResponsePlan {
    Reply,
    Held(watch::Receiver<bool>),
}

async fn start_peer(
    plan: ResponsePlan,
) -> TestResult<(
    SocketAddr,
    ConnectionPeer<TestResult>,
    watch::Receiver<Option<Vec<u8>>>,
)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (received, receipt) = watch::channel(None);
    let peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_head(&mut stream).await?;
        received.send_modify(|received| *received = Some(head));

        match plan {
            ResponsePlan::Reply => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                    .await?;
                stream.flush().await?;
            }
            ResponsePlan::Held(mut released) => {
                released.wait_for(|released| *released).await?;
            }
        }

        drop(stream);
        Ok(())
    });
    Ok((address, peer, receipt))
}

fn require_request(received: &watch::Receiver<Option<Vec<u8>>>) -> TestResult {
    let received = received.borrow();
    let head = received
        .as_ref()
        .ok_or("actual runtime peer did not receive a complete request")?;

    if !head.starts_with(b"GET /deadline HTTP/1.1\r\n") || !head.ends_with(b"\r\n\r\n") {
        return Err("actual runtime peer received a different request".into());
    }

    Ok(())
}

async fn finish_peer(mut peer: ConnectionPeer<TestResult>) -> TestResult {
    match timeout(CLEANUP_LIMIT, &mut peer).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(elapsed) => {
            let primary =
                Err(
                    FixtureDeadline::new("runtime deadline peer cleanup timed out", elapsed).into(),
                );
            let abort_requested = !peer.is_finished();
            if abort_requested {
                peer.abort();
            }

            let backup = match timeout(CLEANUP_LIMIT, &mut peer).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if abort_requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "runtime deadline peer backup join timed out",
                    elapsed,
                )
                .into()),
            };
            finish_with_cleanup(primary, backup)
        }
    }
}

#[derive(Debug)]
struct OperationFailure(Arc<()>);

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime request hook operation failed")
    }
}

impl Error for OperationFailure {}
