use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    sync::{Arc, Weak},
    time::Duration,
};

use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, Route, Socks5Proxy};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};

use super::{
    ORIGIN_NAME, TestIdentity, TestResult, client_builder, finish_local_route, forward_one_socks5,
    read_head,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A cancelled observation does not require another owner to wait.
            let _ = sender.send(());
        }
    }
}

#[derive(Debug)]
struct OriginFailure {
    _ownership: Arc<()>,
}

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven local origin failed")
    }
}

impl Error for OriginFailure {}

#[derive(Debug)]
struct ProxyFailure {
    _ownership: Arc<()>,
}

impl fmt::Display for ProxyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven local proxy failed")
    }
}

impl Error for ProxyFailure {}

#[derive(Debug)]
struct OperationFailure;

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("driven local operation failed")
    }
}

impl Error for OperationFailure {}

struct DrivenRoute {
    client: Client,
    origin: JoinHandle<TestResult<()>>,
    proxy: JoinHandle<TestResult<()>>,
    origin_destroyed: oneshot::Receiver<()>,
    proxy_destroyed: oneshot::Receiver<()>,
}

async fn driven_route(
    origin_failure: Option<OriginFailure>,
    proxy_failure: Option<ProxyFailure>,
) -> TestResult<DrivenRoute> {
    let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let (origin_dropped, origin_destroyed) = oneshot::channel();
    let (proxy_dropped, proxy_destroyed) = oneshot::channel();
    let (ready, driven) = oneshot::channel();
    let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
    let client = client_builder(&identity, false).route(route).build()?;

    let origin = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(origin_dropped));
        let (mut stream, _) = origin_listener.accept().await?;
        let request = read_head(&mut stream).await?;
        assert_eq!(
            request,
            format!(
                "GET /ownership HTTP/1.1\r\nHost: {ORIGIN_NAME}:{}\r\n\r\n",
                origin_address.port()
            )
            .as_bytes()
        );
        stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
        stream.flush().await?;
        ready
            .send(())
            .map_err(|_| "local readiness observer closed")?;

        let mut byte = [0_u8; 1];
        let amount = stream.read(&mut byte).await?;
        assert_eq!(
            amount, 0,
            "local client sent data after its completed request"
        );

        match origin_failure {
            Some(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
            None => Ok(()),
        }
    });
    let proxy = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(proxy_dropped));
        let observed = forward_one_socks5(proxy_listener, origin_address).await?;
        super::assert_local_target(observed, origin_address.port())?;

        match proxy_failure {
            Some(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
            None => Ok(()),
        }
    });
    let exchange = async {
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("http://{ORIGIN_NAME}:{}/ownership", origin_address.port()),
            )?
            .send()
            .await?;
        if response.status() != 204 {
            return Err("controlled local origin returned the wrong status".into());
        }

        if !response.into_body().collect().await?.to_bytes().is_empty() {
            return Err("controlled local origin returned an unexpected body".into());
        }

        driven.await?;
        Ok(())
    };
    let exchange: TestResult<()> = match timeout(CONTROL_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    if let Err(primary) = exchange {
        origin.abort();
        proxy.abort();
        let (origin_result, proxy_result) = tokio::join!(
            timeout(CONTROL_TIMEOUT, origin),
            timeout(CONTROL_TIMEOUT, proxy)
        );
        let cleanup = |result: Result<
            Result<TestResult<()>, tokio::task::JoinError>,
            tokio::time::error::Elapsed,
        >|
         -> TestResult<()> {
            match result? {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(error.into()),
            }
        };
        return finish_with_cleanup(
            finish_with_cleanup(Err(primary), cleanup(origin_result)),
            cleanup(proxy_result),
        );
    }

    Ok(DrivenRoute {
        client,
        origin,
        proxy,
        origin_destroyed,
        proxy_destroyed,
    })
}

async fn observe_destruction(receiver: &mut oneshot::Receiver<()>) -> TestResult<bool> {
    match timeout(CONTROL_TIMEOUT, receiver).await {
        Ok(result) => {
            result?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

async fn stop_backup(
    abort: AbortHandle,
    receiver: &mut oneshot::Receiver<()>,
    observed: bool,
) -> TestResult<()> {
    if !observed {
        abort.abort();
        timeout(CONTROL_TIMEOUT, receiver).await??;
    }

    Ok(())
}

async fn cancelled_route_destroys_peers(poll_before_drop: bool) -> TestResult<()> {
    let DrivenRoute {
        client,
        origin,
        proxy,
        mut origin_destroyed,
        mut proxy_destroyed,
    } = driven_route(None, None).await?;
    let origin_abort = origin.abort_handle();
    let proxy_abort = proxy.abort_handle();
    let mut completion = Box::pin(finish_local_route(Ok(()), origin, proxy));
    if poll_before_drop {
        assert!(futures_util::poll!(&mut completion).is_pending());
    }

    drop(completion);
    let (origin_observed, proxy_observed) = tokio::try_join!(
        observe_destruction(&mut origin_destroyed),
        observe_destruction(&mut proxy_destroyed)
    )?;
    // The client stays alive through both observations. Backup cancellation is
    // deliberately later and cannot make the ownership assertion pass.
    tokio::try_join!(
        stop_backup(origin_abort, &mut origin_destroyed, origin_observed),
        stop_backup(proxy_abort, &mut proxy_destroyed, proxy_observed)
    )?;
    drop(client);

    assert!(
        origin_observed,
        "cancelled local route retained its driven origin"
    );
    assert!(
        proxy_observed,
        "cancelled local route retained its driven proxy"
    );
    Ok(())
}

#[tokio::test]
async fn dropping_a_driven_local_route_destroys_both_peers() -> TestResult<()> {
    cancelled_route_destroys_peers(true).await
}

#[tokio::test]
async fn dropping_an_unpolled_local_route_destroys_both_transferred_peers() -> TestResult<()> {
    cancelled_route_destroys_peers(false).await
}

#[tokio::test]
async fn a_failed_local_operation_finishes_its_driven_peers() -> TestResult<()> {
    let DrivenRoute {
        client,
        origin,
        proxy,
        mut origin_destroyed,
        mut proxy_destroyed,
    } = driven_route(None, None).await?;
    let origin_abort = origin.abort_handle();
    let proxy_abort = proxy.abort_handle();
    let error = finish_local_route(Err(Box::new(OperationFailure)), origin, proxy)
        .await
        .err()
        .ok_or("failed local operation succeeded")?;

    let (origin_observed, proxy_observed) = tokio::try_join!(
        observe_destruction(&mut origin_destroyed),
        observe_destruction(&mut proxy_destroyed)
    )?;
    tokio::try_join!(
        stop_backup(origin_abort, &mut origin_destroyed, origin_observed),
        stop_backup(proxy_abort, &mut proxy_destroyed, proxy_observed)
    )?;
    drop(client);

    assert!(error.downcast_ref::<OperationFailure>().is_some());
    assert!(
        origin_observed,
        "failed local operation retained its driven origin"
    );
    assert!(
        proxy_observed,
        "failed local operation retained its driven proxy"
    );
    Ok(())
}

fn contains<T: Error + 'static>(error: &(dyn Error + 'static)) -> bool {
    if error.downcast_ref::<T>().is_some() {
        return true;
    }

    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return contains::<T>(failures.primary.as_ref())
            || contains::<T>(failures.cleanup.as_ref());
    }

    error.source().is_some_and(contains::<T>)
}

fn retained(token: &Weak<()>) -> bool {
    token.upgrade().is_some()
}

#[tokio::test]
async fn completed_local_peers_keep_both_distinct_typed_failures() -> TestResult<()> {
    let origin_token = Arc::new(());
    let proxy_token = Arc::new(());
    let origin_weak = Arc::downgrade(&origin_token);
    let proxy_weak = Arc::downgrade(&proxy_token);
    let DrivenRoute {
        client,
        origin,
        proxy,
        origin_destroyed,
        proxy_destroyed,
    } = driven_route(
        Some(OriginFailure {
            _ownership: origin_token,
        }),
        Some(ProxyFailure {
            _ownership: proxy_token,
        }),
    )
    .await?;
    drop(client);
    tokio::try_join!(
        async {
            timeout(CONTROL_TIMEOUT, origin_destroyed).await??;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        },
        async {
            timeout(CONTROL_TIMEOUT, proxy_destroyed).await??;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
    )?;

    let error = finish_local_route(Ok(()), origin, proxy)
        .await
        .err()
        .ok_or("failed local peers succeeded")?;
    assert!(
        retained(&origin_weak),
        "original typed origin object was discarded"
    );
    assert!(
        retained(&proxy_weak),
        "independent typed proxy object was discarded"
    );
    assert!(contains::<OriginFailure>(error.as_ref()));
    assert!(contains::<ProxyFailure>(error.as_ref()));
    Ok(())
}

#[tokio::test]
async fn completed_local_peers_preserve_a_successful_wire_exchange() -> TestResult<()> {
    let DrivenRoute {
        client,
        origin,
        proxy,
        origin_destroyed,
        proxy_destroyed,
    } = driven_route(None, None).await?;
    drop(client);
    let result = finish_local_route(Ok(()), origin, proxy).await?;
    assert_eq!(result, ((), ()));
    timeout(CONTROL_TIMEOUT, origin_destroyed).await??;
    timeout(CONTROL_TIMEOUT, proxy_destroyed).await??;
    Ok(())
}
