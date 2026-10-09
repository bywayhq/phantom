use std::{future::Future, io, time::Duration};

use super::*;
use tokio::task::JoinSet;

struct Peer {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: JoinSet<h3::error::ConnectionError>,
}

impl Peer {
    async fn connect(identity: &TestIdentity, address: SocketAddr) -> TestResult<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(identity.root_der.clone()))?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        // Await certificate verification and the completed QUIC handshake.
        let connection = endpoint.connect(address, "127.0.0.1")?.await?;
        let (mut h3, send) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_quinn::Connection::new(connection.clone()))
            .await?;
        let mut driver = JoinSet::new();
        driver.spawn(async move { poll_fn(|context| h3.poll_close(context)).await });
        send.peer_settings().ready().await?;
        assert!(connection.close_reason().is_none());
        Ok(Self {
            endpoint,
            connection,
            send,
            _driver: driver,
        })
    }

    async fn rejected(&mut self, address: SocketAddr, status: u16) -> TestResult<()> {
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(format!(
                "https://{address}/.well-known/masque/udp/127.0.0.1/9/"
            ))
            .extension(h3::ext::Protocol::CONNECT_UDP)
            .body(())?;
        let mut stream = self.send.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status().as_u16(), status);
        if status == 407 {
            assert_eq!(response.headers()["proxy-authenticate"], CHALLENGE);
        }
        assert!(stream.recv_data().await?.is_none());
        assert!(self.connection.close_reason().is_none());
        Ok(())
    }

    async fn closed_by_proxy(&self) -> TestResult<()> {
        let error = tokio::time::timeout(Duration::from_secs(5), self.connection.closed()).await?;
        assert!(matches!(
            error,
            quinn::ConnectionError::ApplicationClosed(ref close) if close.error_code == 0_u32.into()
        ));
        Ok(())
    }
}

async fn address_released(address: SocketAddr) -> TestResult<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match phantom_testkit::udp::bind(address) {
                Ok(socket) => {
                    assert_eq!(socket.local_addr()?, address);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await?
}

async fn owner_drop(mode: ProxyMode, rejection: Option<u16>) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy = MasqueProxy::spawn(&identity, mode)?;
    let address = proxy.address;
    let mut peer = Peer::connect(&identity, address).await?;
    if let Some(status) = rejection {
        peer.rejected(address, status).await?;
        assert_eq!(proxy.requests().len(), 1);
    } else {
        assert!(proxy.requests().is_empty());
    }

    drop(proxy);
    peer.closed_by_proxy().await?;
    // The peer endpoint and H3 driver remain alive through the real bind.
    address_released(address).await
}

async fn owner_close(mode: ProxyMode, rejection: Option<u16>) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy = MasqueProxy::spawn(&identity, mode)?;
    let address = proxy.address;
    let mut peer = Peer::connect(&identity, address).await?;
    if let Some(status) = rejection {
        peer.rejected(address, status).await?;
        assert_eq!(proxy.requests().len(), 1);
    } else {
        assert!(proxy.requests().is_empty());
    }

    proxy.close_connections();
    // Reopen immediately: old connections must retain the close generation.
    proxy.reopen();
    peer.closed_by_proxy().await?;
    let mut replacement = Peer::connect(&identity, address).await?;
    if let Some(status) = rejection {
        replacement.rejected(address, status).await?;
        assert_eq!(proxy.requests().len(), 2);
    }
    assert!(replacement.connection.close_reason().is_none());

    drop(proxy);
    replacement.closed_by_proxy().await?;
    address_released(address).await
}

async fn bounded(future: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    tokio::time::timeout(Duration::from_secs(30), future).await?
}

#[tokio::test]
async fn dropping_a_proxy_closes_an_authenticated_peer_before_connect() -> TestResult<()> {
    bounded(owner_drop(ProxyMode::Relay, None)).await
}

#[tokio::test]
async fn closing_a_proxy_reaches_a_peer_before_connect_and_allows_reopen() -> TestResult<()> {
    bounded(owner_close(ProxyMode::Relay, None)).await
}

#[tokio::test]
async fn dropping_a_proxy_closes_a_rejected_peer_that_stays_alive() -> TestResult<()> {
    bounded(owner_drop(ProxyMode::Reject(403), Some(403))).await
}

#[tokio::test]
async fn closing_a_proxy_reaches_a_rejected_peer_and_allows_reopen() -> TestResult<()> {
    bounded(owner_close(ProxyMode::Reject(403), Some(403))).await
}

#[tokio::test]
async fn dropping_a_proxy_closes_a_challenged_peer_that_stays_alive() -> TestResult<()> {
    bounded(owner_drop(ProxyMode::Challenge, Some(407))).await
}

#[tokio::test]
async fn closing_a_proxy_reaches_a_challenged_peer_and_allows_reopen() -> TestResult<()> {
    bounded(owner_close(ProxyMode::AlwaysChallenge, Some(407))).await
}

#[tokio::test]
async fn a_peer_close_allows_the_proxy_address_to_be_released() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy = MasqueProxy::spawn(&identity, ProxyMode::Reject(403))?;
        let address = proxy.address;
        let mut peer = Peer::connect(&identity, address).await?;
        peer.rejected(address, 403).await?;

        peer.connection
            .close(0_u32.into(), b"controlled peer teardown");
        peer.endpoint.wait_idle().await;
        drop(proxy);
        address_released(address).await
    })
    .await
}

#[tokio::test]
async fn a_duplicate_control_stream_retains_the_protocol_failure() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy = MasqueProxy::spawn(&identity, ProxyMode::Relay)?;
        let peer = Peer::connect(&identity, proxy.address).await?;

        let mut duplicate = peer.connection.open_uni().await?;
        // A second control stream is forbidden, even with valid SETTINGS.
        duplicate.write_all(&[0x00, 0x04, 0x00]).await?;
        let close = peer.connection.closed().await;
        assert!(matches!(
            close,
            quinn::ConnectionError::ApplicationClosed(ref error)
                if error.error_code.into_inner() == h3::error::Code::H3_STREAM_CREATION_ERROR.value()
        ));

        let failures = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let failures = proxy.take_failures();
                if !failures.is_empty() {
                    return failures;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(failures.len(), 1);
        let failure = failures.into_iter().next().ok_or("missing protocol failure")?;
        let failure = failure.downcast::<h3::error::ConnectionError>()?;
        assert!(matches!(
            *failure,
            h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application { code, .. },
                ..
            } if code == h3::error::Code::H3_STREAM_CREATION_ERROR
        ));
        Ok(())
    })
    .await
}
