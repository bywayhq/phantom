use btls::ssl::SslAcceptor;
use tokio::sync::oneshot;

use super::*;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};
use ownership_contract::{ObservedFailure, OriginLifetime, OriginObservation, observed_second_head};

type OriginOutcome = TestResult<[Vec<u8>; 2]>;
type ProxyOutcome = TestResult<(Vec<u8>, Vec<u8>, bool)>;

const PEER_FINISH_LIMIT: Duration = Duration::from_secs(5);

struct OriginReturn {
    peer: ConnectionPeer<OriginOutcome>,
    stop_requested: bool,
}

struct ProxyReturn {
    peer: ConnectionPeer<ProxyOutcome>,
    stop_requested: bool,
}

struct PeerReturns {
    origin: oneshot::Sender<Option<OriginReturn>>,
    proxy: oneshot::Sender<Option<ProxyReturn>>,
}

struct PeerControls {
    returns: PeerReturns,
    origin: OriginObservation,
    origin_fault: Option<ObservedFailure>,
    proxy_fault: Option<ObservedFailure>,
}

struct ProxyAuthPeers {
    origin_address: std::net::SocketAddr,
    origin: Option<ConnectionPeer<OriginOutcome>>,
    proxy: Option<ConnectionPeer<ProxyOutcome>>,
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
        let origin = ConnectionPeer::spawn(serve_origin(
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
        self.proxy = Some(ConnectionPeer::spawn(async move {
            let result = challenge_then_forward(proxy_listener, origin).await?;
            if let Some(fault) = fault {
                return Err(fault.finish().into());
            }

            Ok(result)
        }));
        Ok(proxy_address)
    }

    async fn finish(self) -> TestResult<()> {
        self.finish_result(Ok(())).await
    }

    async fn finish_result(mut self, primary: TestResult<()>) -> TestResult<()> {
        let proxy_stop_requested = primary.is_err()
            && self.proxy.as_ref().is_some_and(|peer| !peer.is_finished());
        if proxy_stop_requested && let Some(peer) = &self.proxy {
            peer.abort();
        }

        let mut origin_stop_requested = primary.is_err()
            && self.origin.as_ref().is_some_and(|peer| !peer.is_finished());
        if origin_stop_requested && let Some(peer) = &self.origin {
            peer.abort();
        }

        let proxy = match self.proxy.as_mut() {
            Some(peer) => match timeout(PEER_FINISH_LIMIT, peer).await {
                Ok(Ok(result)) => result.map(Some),
                Ok(Err(error)) if proxy_stop_requested && error.is_cancelled() => Ok(None),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None if primary.is_err() => Ok(None),
            None => Err("proxy was not acquired".into()),
        };
        drop(self.proxy.take());

        if proxy.is_err()
            && !origin_stop_requested
            && let Some(peer) = &self.origin
            && !peer.is_finished()
        {
            origin_stop_requested = true;
            peer.abort();
        }

        let origin = match self.origin.as_mut() {
            Some(peer) => match timeout(PEER_FINISH_LIMIT, peer).await {
                Ok(Ok(result)) => result.map(Some),
                Ok(Err(error)) if origin_stop_requested && error.is_cancelled() => Ok(None),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None => Err("origin was not acquired".into()),
        };
        drop(self.origin.take());

        let proxy = proxy.map(|response| {
            if let Some((anonymous, authorized, third_attempted)) = response {
                assert!(!contains_ascii_case_insensitive(
                    &anonymous,
                    b"proxy-authorization"
                ));
                assert!(contains_ascii_case_insensitive(
                    &authorized,
                    b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
                ));
                assert!(!third_attempted);
            }
        });
        let origin = origin.map(|requests| {
            if let Some(requests) = requests {
                assert!(requests[0].starts_with(b"GET /first HTTP/1.1\r\n"));
                assert!(requests[1].starts_with(b"GET /second HTTP/1.1\r\n"));
            }
        });

        finish_with_cleanup(primary, finish_with_cleanup(proxy, origin))
    }
}

impl Drop for ProxyAuthPeers {
    fn drop(&mut self) {
        if let Some(returns) = self.returns.take() {
            let origin = self.origin.take().map(|peer| {
                let stop_requested = !peer.is_finished();
                if stop_requested {
                    peer.abort();
                }

                OriginReturn {
                    peer,
                    stop_requested,
                }
            });
            if let Err(peer) = returns.origin.send(origin) {
                drop(peer);
            }

            let proxy = self.proxy.take().map(|peer| {
                let stop_requested = !peer.is_finished();
                if stop_requested {
                    peer.abort();
                }

                ProxyReturn {
                    peer,
                    stop_requested,
                }
            });
            if let Err(peer) = returns.proxy.send(proxy) {
                drop(peer);
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
        let primary: TestResult<()> = async {
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

            Ok(())
        }
        .await;

        peers.finish_result(primary).await
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
