use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
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

struct DrivenRoute {
    origin: JoinHandle<TestResult<Vec<u8>>>,
    proxy: JoinHandle<TestResult<ObservedSocks5Connect>>,
    client: TcpStream,
    control: RouteControl,
    port: u16,
}

async fn driven_route(
    origin_failure: Option<OriginFailure>,
    proxy_failure: Option<ProxyFailure>,
) -> TestResult<DrivenRoute> {
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
    let proxy = tokio::spawn(async move {
        let _destroyed = PeerDestroyed(Some(proxy_stopped));
        let observed = forward_one_socks5(proxy_listener, origin_address).await?;
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
    client.write_all(b"\x05\x01\x00").await?;
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    assert_eq!(&greeting, b"\x05\x00");

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
