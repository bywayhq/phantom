use btls::ssl::SslAcceptor;
use tokio::{sync::oneshot, task::JoinHandle};

use super::*;
use ownership_contract::{ObservedFailure, OriginLifetime, OriginObservation, observed_second_head};

type OriginOutcome = TestResult<[Vec<u8>; 2]>;
type ProxyOutcome = TestResult<(Vec<u8>, Vec<u8>, bool)>;

struct PeerReturns {
    origin: oneshot::Sender<Option<JoinHandle<OriginOutcome>>>,
    proxy: oneshot::Sender<Option<JoinHandle<ProxyOutcome>>>,
}

struct PeerControls {
    returns: PeerReturns,
    origin: OriginObservation,
    origin_fault: Option<ObservedFailure>,
    proxy_fault: Option<ObservedFailure>,
}

struct ProxyAuthPeers {
    origin_address: std::net::SocketAddr,
    origin: Option<JoinHandle<OriginOutcome>>,
    proxy: Option<JoinHandle<ProxyOutcome>>,
    returns: Option<PeerReturns>,
    proxy_fault: Option<ObservedFailure>,
}

impl ProxyAuthPeers {
    async fn start_origin(
        identity: &TestIdentity,
        controls: Option<PeerControls>,
    ) -> TestResult<Self> {
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let (returns, observation, origin_fault, proxy_fault) = match controls {
            Some(controls) => (
                Some(controls.returns),
                Some(controls.origin),
                controls.origin_fault,
                controls.proxy_fault,
            ),
            None => (None, None, None, None),
        };

        let lifetime = observation.as_ref().map(OriginObservation::lifetime);
        let origin = tokio::spawn(serve_origin(
            origin_listener,
            origin_acceptor,
            lifetime,
            observation,
            origin_fault,
        ));

        Ok(Self {
            origin_address,
            origin: Some(origin),
            proxy: None,
            returns,
            proxy_fault,
        })
    }

    async fn start_proxy(&mut self) -> TestResult<std::net::SocketAddr> {
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let origin = self.origin_address;
        let fault = self.proxy_fault.take();
        self.proxy = Some(tokio::spawn(async move {
            let result = challenge_then_forward(proxy_listener, origin).await?;
            if let Some(fault) = fault {
                return Err(fault.finish().into());
            }

            Ok(result)
        }));
        Ok(proxy_address)
    }

    async fn finish(mut self) -> TestResult<()> {
        let (anonymous, authorized, third_attempted) = self
            .proxy
            .take()
            .ok_or("proxy was not acquired")?
            .await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authorized,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        assert!(!third_attempted);
        let requests = self.origin.take().ok_or("origin was not acquired")?.await??;
        assert!(requests[0].starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /second HTTP/1.1\r\n"));
        Ok(())
    }
}

impl Drop for ProxyAuthPeers {
    fn drop(&mut self) {
        if let Some(returns) = self.returns.take() {
            if let Err(Some(task)) = returns.origin.send(self.origin.take()) {
                task.abort();
            }

            if let Err(Some(task)) = returns.proxy.send(self.proxy.take()) {
                task.abort();
            }
        }
    }
}

async fn serve_origin(
    origin_listener: TcpListener,
    origin_acceptor: SslAcceptor,
    _lifetime: Option<OriginLifetime>,
    observation: Option<OriginObservation>,
    fault: Option<ObservedFailure>,
) -> OriginOutcome {
    let mut stream = tls_support::accept_tls(origin_listener, origin_acceptor).await?;
    let first = read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.flush().await?;
    let second = observed_second_head(&mut stream, observation.as_ref()).await?;
    stream
        .write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
    stream.shutdown().await?;
    if let Some(fault) = fault {
        return Err(fault.finish().into());
    }

    Ok::<_, Box<dyn Error + Send + Sync>>([first, second])
}

#[tokio::test]
async fn authenticated_connect_tunnel_is_reused_by_http1_session() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut peers = ProxyAuthPeers::start_origin(&identity, None).await?;
        let origin_address = peers.origin_address;
        let proxy_address = peers.start_proxy().await?;
        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let session = client_builder(&identity, false).route(route).build()?;

        for path in ["first", "second"] {
            let response = session
                .get(
                    HttpProtocol::Http1,
                    &format!("https://{origin_address}/{path}"),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        drop(session);

        peers.finish().await
    })
    .await
}

async fn challenge_then_forward(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=session\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    second
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    second.flush().await?;
    copy_bidirectional(&mut second, &mut upstream).await?;
    let third_attempted = timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_ok();
    Ok((anonymous, authorized, third_attempted))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

mod ownership_contract;
