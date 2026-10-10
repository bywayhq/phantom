use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, HttpProxy, Route};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{
    H1_ALPN, TestIdentity, TestResult, assert_http1_cookie_fields, cookie_client_builder,
    cookie_peer_outcome, spawn_canonical_cookie_peer, spawn_cookie_proxy,
};

const EXCHANGE: Duration = Duration::from_secs(10);
const OBSERVE: Duration = Duration::from_millis(250);
const CLEANUP: Duration = Duration::from_secs(5);

#[tokio::test]
async fn explicit_cookie_peer_cancel_releases_the_actual_listener_after_traffic() -> TestResult<()>
{
    observe_owner(Owner::Origin, Exit::ExplicitCancel).await
}

#[tokio::test]
async fn explicit_cookie_proxy_cancel_releases_the_actual_listener_after_traffic() -> TestResult<()>
{
    observe_owner(Owner::Proxy, Exit::ExplicitCancel).await
}

#[tokio::test]
async fn a_cookie_operation_error_releases_its_actual_origin_task() -> TestResult<()> {
    observe_owner(Owner::Origin, Exit::OperationError).await
}

#[tokio::test]
async fn a_cookie_operation_error_releases_its_actual_connect_proxy_task() -> TestResult<()> {
    observe_owner(Owner::Proxy, Exit::OperationError).await
}

#[derive(Clone, Copy)]
enum Owner {
    Origin,
    Proxy,
}

#[derive(Clone, Copy)]
enum Exit {
    ExplicitCancel,
    OperationError,
}

pub(super) struct CookiePeerControl {
    pub(super) first_ready: oneshot::Sender<Vec<u8>>,
    pub(super) lifetime: DropSignal,
}

pub(super) struct ProxyPeerControl {
    pub(super) first_ready: oneshot::Sender<Vec<u8>>,
    pub(super) lifetime: DropSignal,
}

pub(super) struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // A cancelled observer cannot keep an actual fixture future alive.
            let _ = sender.send(());
        }
    }
}

struct CookieOwnerCase {
    session: Client,
    url: String,
    task: JoinHandle<TestResult<Vec<Vec<u8>>>>,
    origin: Option<ConnectionPeer<TestResult<Vec<Vec<u8>>>>>,
    first_ready: oneshot::Receiver<Vec<u8>>,
    connect_ready: Option<oneshot::Receiver<Vec<u8>>>,
    authority: SocketAddr,
    destroyed: oneshot::Receiver<()>,
    address: SocketAddr,
}

async fn observe_owner(owner: Owner, exit: Exit) -> TestResult<()> {
    let CookieOwnerCase {
        session,
        url,
        task,
        origin,
        first_ready,
        connect_ready,
        authority,
        mut destroyed,
        address,
    } = case(owner).await?;
    let backup = task.abort_handle();

    let operation = async {
        let response = session.get(HttpProtocol::Http1, &url)?.send().await?;
        if response.status() != StatusCode::NO_CONTENT {
            return Err("actual cookie control did not receive its 204 response".into());
        }

        if !response.into_body().collect().await?.to_bytes().is_empty() {
            return Err("actual cookie control response was not empty".into());
        }

        let head = first_ready.await?;
        if !std::str::from_utf8(&head)?.starts_with("GET /seed HTTP/1.1\r\n") {
            return Err("actual cookie readiness did not capture the seed request".into());
        }

        let connect = match connect_ready {
            Some(ready) => Some(ready.await?),
            None => None,
        };
        let cookie_count = session.cookie_jar().ok_or("cookie jar was disabled")?.len();
        let listener_live = TcpListener::bind(address).await.is_err();

        let primary = match exit {
            Exit::ExplicitCancel => {
                task.abort();
                let joined = timeout(CLEANUP, task).await?;
                match joined {
                    Err(error) if error.is_cancelled() => None,
                    Err(error) => return Err(error.into()),
                    Ok(result) => {
                        result?;
                        return Err(
                            "actual cookie peer finished before controlled cancellation".into()
                        );
                    }
                }
            }
            Exit::OperationError => {
                let error = cookie_peer_outcome(
                    Err(io::Error::new(io::ErrorKind::InvalidInput, CookieOperationFailure).into()),
                    task,
                )
                .await
                .err()
                .ok_or("controlled cookie operation unexpectedly succeeded")?;
                Some(error)
            }
        };

        let released = timeout(OBSERVE, &mut destroyed).await;
        Ok::<_, Box<dyn Error + Send + Sync>>((
            head,
            connect,
            cookie_count,
            listener_live,
            primary,
            released,
        ))
    };
    let result = match timeout(EXCHANGE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    // Backup cleanup starts only after the finite lifetime observation.
    backup.abort();
    let cleanup = async {
        wait_finished(&backup).await?;

        let rebound = TcpListener::bind(address).await?;
        if rebound.local_addr()? != address {
            return Err("cookie backup rebound a different listener address".into());
        }

        drop(rebound);
        Ok(())
    }
    .await;
    let origin_stop = match origin {
        Some(origin) => origin.stop().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(cleanup, origin_stop);
    let (head, connect, cookie_count, listener_live, primary, released) =
        finish_with_cleanup(result, cleanup)?;
    drop(session);

    if let Some(connect) = connect {
        assert!(
            std::str::from_utf8(&connect)?
                .starts_with(&format!("CONNECT {authority} HTTP/1.1\r\n"))
        );
    }

    assert_http1_cookie_fields(&head, &[])?;
    assert_eq!(cookie_count, 2);
    assert!(
        listener_live,
        "actual owner listener was not live before exit"
    );

    if let Some(error) = primary {
        let error = error
            .downcast_ref::<io::Error>()
            .ok_or("original cookie operation cause was lost")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .get_ref()
                .is_some_and(|source| source.is::<CookieOperationFailure>())
        );
    }

    assert!(
        matches!(released, Ok(Ok(()))),
        "actual cookie task survived its caller's operation error before backup cleanup"
    );
    Ok(())
}

async fn case(owner: Owner) -> TestResult<CookieOwnerCase> {
    let identity = TestIdentity::generate()?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let proxy_listener = if matches!(owner, Owner::Proxy) {
        Some(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?)
    } else {
        None
    };
    let mut builder = cookie_client_builder(&identity).cookies();
    let address = match &proxy_listener {
        Some(listener) => {
            let address = listener.local_addr()?;
            builder = builder.route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{address}"
            ))?));
            address
        }
        None => origin_address,
    };
    let session = builder.build()?;
    let (ready, first_ready) = oneshot::channel();
    let (dropped, destroyed) = oneshot::channel();
    let (task, origin, connect_ready) = match proxy_listener {
        Some(listener) => {
            let origin = ConnectionPeer::from_task(spawn_canonical_cookie_peer(
                origin_listener,
                acceptor,
                Some(CookiePeerControl {
                    first_ready: ready,
                    lifetime: DropSignal(None),
                }),
            ));
            let (connect, connect_ready) = oneshot::channel();
            let task = spawn_cookie_proxy(
                listener,
                origin_address,
                2,
                Some(ProxyPeerControl {
                    first_ready: connect,
                    lifetime: DropSignal(Some(dropped)),
                }),
            );
            (task, Some(origin), Some(connect_ready))
        }
        None => {
            let task = spawn_canonical_cookie_peer(
                origin_listener,
                acceptor,
                Some(CookiePeerControl {
                    first_ready: ready,
                    lifetime: DropSignal(Some(dropped)),
                }),
            );
            (task, None, None)
        }
    };

    Ok(CookieOwnerCase {
        session,
        url: format!("https://{origin_address}/seed"),
        task,
        origin,
        first_ready,
        connect_ready,
        authority: origin_address,
        destroyed,
        address,
    })
}

async fn wait_finished(task: &AbortHandle) -> TestResult<()> {
    timeout(CLEANUP, async {
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    Ok(())
}

#[derive(Debug)]
struct CookieOperationFailure;

impl fmt::Display for CookieOperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled cookie operation failure")
    }
}

impl Error for CookieOperationFailure {}
