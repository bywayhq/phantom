use std::{
    error::Error,
    fmt,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinHandle, JoinSet},
    time::timeout,
};

use super::{
    ORIGIN_NAME, ObservedSocks5Connect, TestResult, finish_socks_proxy, finish_socks_route,
    forward_one_socks5, read_head,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"GET /owned HTTP/1.1\r\nHost: origin.phantom.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nready";

struct PeerDestroyed(Option<oneshot::Sender<()>>);

impl Drop for PeerDestroyed {
    fn drop(&mut self) {
        if let Some(observer) = self.0.take() {
            // An enclosing failure may already have cancelled this observer.
            let _ = observer.send(());
        }
    }
}

struct RouteControl {
    origin_abort: AbortHandle,
    proxy_abort: AbortHandle,
    origin_destroyed: oneshot::Receiver<()>,
    proxy_destroyed: oneshot::Receiver<()>,
}

impl Drop for RouteControl {
    fn drop(&mut self) {
        // Independent fallback ownership remains live throughout observation.
        self.origin_abort.abort();
        self.proxy_abort.abort();
    }
}

impl RouteControl {
    async fn observe_destruction_before_fallback(&mut self) -> TestResult<bool> {
        let (origin, proxy) = tokio::join!(
            timeout(CONTROL_TIMEOUT, &mut self.origin_destroyed),
            timeout(CONTROL_TIMEOUT, &mut self.proxy_destroyed),
        );
        let origin_stopped = match origin {
            Ok(result) => {
                result?;
                true
            }
            Err(_) => false,
        };
        let proxy_stopped = match proxy {
            Ok(result) => {
                result?;
                true
            }
            Err(_) => false,
        };

        if !origin_stopped || !proxy_stopped {
            self.origin_abort.abort();
            self.proxy_abort.abort();
            if !origin_stopped {
                timeout(CONTROL_TIMEOUT, &mut self.origin_destroyed).await??;
            }
            if !proxy_stopped {
                timeout(CONTROL_TIMEOUT, &mut self.proxy_destroyed).await??;
            }
        }

        Ok(origin_stopped && proxy_stopped)
    }
}

struct DrivenRoute<P> {
    origin: JoinHandle<TestResult<Vec<u8>>>,
    proxy: JoinHandle<TestResult<P>>,
    client: TcpStream,
    control: RouteControl,
    port: u16,
}

async fn driven_route(
    origin_failure: Option<OriginFailure>,
    proxy_failure: Option<ProxyFailure>,
) -> TestResult<DrivenRoute<ObservedSocks5Connect>> {
    driven_route_with_proxy(
        origin_failure,
        proxy_failure,
        forward_one_socks5,
        Authentication::None,
    )
    .await
}

enum Authentication {
    None,
    UsernamePassword,
}

async fn driven_route_with_proxy<
    P: Send + 'static,
    F: Future<Output = TestResult<P>> + Send + 'static,
>(
    origin_failure: Option<OriginFailure>,
    proxy_failure: Option<ProxyFailure>,
    forward: impl FnOnce(TcpListener, SocketAddr) -> F,
    authentication: Authentication,
) -> TestResult<DrivenRoute<P>> {
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let (origin_stopped, origin_destroyed) = oneshot::channel();
    let (proxy_stopped, proxy_destroyed) = oneshot::channel();

    let origin = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(origin_stopped));
        let (mut stream, _) = origin_listener.accept().await?;
        let request = read_head(&mut stream).await?;
        assert_eq!(request, REQUEST);

        stream.write_all(RESPONSE).await?;
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await?, 0);

        match origin_failure {
            Some(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
            None => Ok(request),
        }
    });
    let forwarded = forward(proxy_listener, origin_address);
    let proxy = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(proxy_stopped));
        let observed = forwarded.await?;
        match proxy_failure {
            Some(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
            None => Ok(observed),
        }
    });
    let control = RouteControl {
        origin_abort: origin.abort_handle(),
        proxy_abort: proxy.abort_handle(),
        origin_destroyed,
        proxy_destroyed,
    };

    let mut client = TcpStream::connect(proxy_address).await?;
    match authentication {
        Authentication::None => {
            client.write_all(b"\x05\x01\x00").await?;
            let mut greeting = [0_u8; 2];
            client.read_exact(&mut greeting).await?;
            assert_eq!(&greeting, b"\x05\x00");
        }
        Authentication::UsernamePassword => {
            client.write_all(b"\x05\x02\x00\x02").await?;
            let mut greeting = [0_u8; 2];
            client.read_exact(&mut greeting).await?;
            assert_eq!(&greeting, b"\x05\x02");

            client.write_all(b"\x01\x04user\x04pass").await?;
            let mut accepted = [0_u8; 2];
            client.read_exact(&mut accepted).await?;
            assert_eq!(&accepted, b"\x01\x00");
        }
    }

    let mut connect = b"\x05\x01\x00\x03\x13origin.phantom.test".to_vec();
    connect.extend_from_slice(&origin_address.port().to_be_bytes());
    client.write_all(&connect).await?;
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00");

    client.write_all(REQUEST).await?;
    let mut response = vec![0_u8; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);

    Ok(DrivenRoute {
        origin,
        proxy,
        client,
        control,
        port: origin_address.port(),
    })
}

#[derive(Debug)]
struct OriginFailure(Arc<()>);

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled SOCKS origin failed")
    }
}

impl Error for OriginFailure {}

#[derive(Debug)]
struct ProxyFailure(Arc<()>);

impl fmt::Display for ProxyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled SOCKS proxy failed")
    }
}

impl Error for ProxyFailure {}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }

        error = error.source()?;
    }
}

async fn assert_closed(client: &mut TcpStream) -> TestResult<()> {
    let result = timeout(CONTROL_TIMEOUT, client.read(&mut [0_u8; 1])).await?;
    assert!(
        matches!(result, Ok(0))
            || matches!(result, Err(ref error) if super::tls::is_peer_gone(error))
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_a_driven_socks_proxy_owner_stops_its_peer_with_client_retained()
-> TestResult<()> {
    timeout(CONTROL_TIMEOUT * 3, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_route(None, None).await?;
        let mut owner = Box::pin(finish_socks_proxy(proxy));
        assert!(futures_util::poll!(&mut owner).is_pending());
        drop(owner);

        let stopped = control.observe_destruction_before_fallback().await?;
        assert_closed(&mut client).await?;
        // Explicitly observe the independently retained origin result.
        match timeout(CONTROL_TIMEOUT, origin).await? {
            Ok(result) => {
                result?;
            }
            Err(error) if !stopped && error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
        }
        assert!(stopped, "the SOCKS peer survived owner cancellation");
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_a_driven_socks_route_stops_both_peers_with_client_retained() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT * 3, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_route(None, None).await?;
        let mut owner = Box::pin(finish_socks_route(origin, proxy));
        assert!(futures_util::poll!(&mut owner).is_pending());
        drop(owner);

        let stopped = control.observe_destruction_before_fallback().await?;
        assert_closed(&mut client).await?;
        assert!(stopped, "the SOCKS route peers survived owner cancellation");
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn an_origin_failure_retains_a_completed_socks_proxy_failure() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let origin_retained = Arc::new(());
        let proxy_retained = Arc::new(());
        let origin_observed: Weak<()> = Arc::downgrade(&origin_retained);
        let proxy_observed: Weak<()> = Arc::downgrade(&proxy_retained);
        let proxy_failure = ProxyFailure(proxy_retained);
        assert_eq!(Arc::strong_count(&proxy_failure.0), 1);
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_route(Some(OriginFailure(origin_retained)), Some(proxy_failure)).await?;
        client.shutdown().await?;
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;

        let error = finish_socks_route(origin, proxy)
            .await
            .err()
            .ok_or("failed SOCKS route was accepted")?;
        let primary =
            find_source::<OriginFailure>(error.as_ref()).ok_or("typed origin cause was lost")?;
        assert_eq!(Arc::strong_count(&primary.0), 1);
        assert!(origin_observed.upgrade().is_some());
        assert!(
            proxy_observed.upgrade().is_some(),
            "the completed SOCKS proxy cause was discarded"
        );
        drop(error);
        assert!(origin_observed.upgrade().is_none());
        assert!(proxy_observed.upgrade().is_none());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_completed_socks_route_preserves_literal_handshake_and_http_observations()
-> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            port,
        } = driven_route(None, None).await?;
        client.shutdown().await?;
        let (request, observed) = finish_socks_route(origin, proxy).await?;
        assert_eq!(request, REQUEST);
        assert_eq!(
            observed,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port
            }
        );
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;
        assert_closed(&mut client).await?;
        Ok(())
    })
    .await?
}

async fn driven_authenticated_route(
    origin_failure: Option<OriginFailure>,
    proxy_failure: Option<ProxyFailure>,
) -> TestResult<DrivenRoute<super::socks5_support::ObservedAuthenticatedSocks5Connect>> {
    driven_route_with_proxy(
        origin_failure,
        proxy_failure,
        super::socks5_support::forward_one_authenticated_socks5,
        Authentication::UsernamePassword,
    )
    .await
}

#[tokio::test]
async fn cancelling_an_authenticated_route_stops_driven_peers_with_client_retained()
-> TestResult<()> {
    timeout(CONTROL_TIMEOUT * 3, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_authenticated_route(None, None).await?;
        let mut owner = Box::pin(finish_socks_route(origin, proxy));
        assert!(futures_util::poll!(&mut owner).is_pending());
        drop(owner);

        let stopped = control.observe_destruction_before_fallback().await?;
        assert_closed(&mut client).await?;
        assert!(
            stopped,
            "the authenticated SOCKS peers survived owner cancellation"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn an_authenticated_origin_failure_retains_its_completed_proxy_failure() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let origin_retained = Arc::new(());
        let proxy_retained = Arc::new(());
        let origin_observed = Arc::downgrade(&origin_retained);
        let proxy_observed = Arc::downgrade(&proxy_retained);
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_authenticated_route(
            Some(OriginFailure(origin_retained)),
            Some(ProxyFailure(proxy_retained)),
        )
        .await?;
        client.shutdown().await?;
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;

        let error = finish_socks_route(origin, proxy)
            .await
            .err()
            .ok_or("failed authenticated route was accepted")?;
        assert!(find_source::<OriginFailure>(error.as_ref()).is_some());
        assert!(origin_observed.upgrade().is_some());
        assert!(
            proxy_observed.upgrade().is_some(),
            "the completed authenticated proxy cause was discarded"
        );
        drop(error);
        assert!(origin_observed.upgrade().is_none());
        assert!(proxy_observed.upgrade().is_none());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn an_authenticated_route_retains_literal_credentials_connect_and_http_observations()
-> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            port,
        } = driven_authenticated_route(None, None).await?;
        client.shutdown().await?;
        let (request, observed) = finish_socks_route(origin, proxy).await?;
        assert_eq!(request, REQUEST);
        assert_eq!(observed.authentication.username, "user");
        assert_eq!(observed.authentication.password, "pass");
        assert_eq!(
            observed.connect,
            ObservedSocks5Connect {
                host: ORIGIN_NAME.to_owned(),
                port
            }
        );
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;
        assert_closed(&mut client).await?;
        Ok(())
    })
    .await?
}

async fn completed_authenticated_handlers(
    origin: JoinHandle<TestResult<Vec<u8>>>,
    proxy: JoinHandle<TestResult<super::socks5_support::ObservedAuthenticatedSocks5Connect>>,
) -> TestResult<JoinSet<TestResult<()>>> {
    let (origin_stopped, wait_origin) = oneshot::channel();
    let (proxy_stopped, wait_proxy) = oneshot::channel();
    let mut handlers = JoinSet::new();
    handlers.spawn(async move {
        let _destroyed = PeerDestroyed(Some(origin_stopped));
        let request = origin.await??;
        assert_eq!(request, REQUEST);
        Ok(())
    });
    handlers.spawn(async move {
        let _destroyed = PeerDestroyed(Some(proxy_stopped));
        let observed = proxy.await??;
        assert_eq!(observed.authentication.username, "user");
        assert_eq!(observed.authentication.password, "pass");
        assert_eq!(observed.connect.host, ORIGIN_NAME);
        Ok(())
    });

    // Each outer worker has completed, and owns its actual route outcome.
    wait_origin.await?;
    wait_proxy.await?;
    Ok(handlers)
}

#[tokio::test]
async fn a_handler_failure_retains_the_other_completed_authenticated_outcome() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let origin_retained = Arc::new(());
        let proxy_retained = Arc::new(());
        let origin_observed = Arc::downgrade(&origin_retained);
        let proxy_observed = Arc::downgrade(&proxy_retained);
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_authenticated_route(
            Some(OriginFailure(origin_retained)),
            Some(ProxyFailure(proxy_retained)),
        )
        .await?;
        client.shutdown().await?;
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;
        let handlers = completed_authenticated_handlers(origin, proxy).await?;

        let error = super::auth::finish_socks_handlers(handlers)
            .await
            .err()
            .ok_or("failed authenticated handlers were accepted")?;
        assert!(
            find_source::<OriginFailure>(error.as_ref()).is_some()
                || find_source::<ProxyFailure>(error.as_ref()).is_some()
        );
        assert!(
            origin_observed.upgrade().is_some(),
            "the completed origin outcome was discarded"
        );
        assert!(
            proxy_observed.upgrade().is_some(),
            "the completed proxy outcome was discarded"
        );
        drop(error);
        assert!(origin_observed.upgrade().is_none());
        assert!(proxy_observed.upgrade().is_none());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn successful_authenticated_handlers_preserve_both_completed_results() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let DrivenRoute {
            origin,
            proxy,
            mut client,
            mut control,
            ..
        } = driven_authenticated_route(None, None).await?;
        client.shutdown().await?;
        (&mut control.origin_destroyed).await?;
        (&mut control.proxy_destroyed).await?;
        let handlers = completed_authenticated_handlers(origin, proxy).await?;

        assert_eq!(
            super::auth::finish_socks_handlers(handlers).await?,
            [(), ()]
        );
        assert_closed(&mut client).await?;
        Ok(())
    })
    .await?
}
