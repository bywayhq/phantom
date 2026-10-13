use std::{error::Error, future::Future, io};

use rustls::pki_types::CertificateDer;

use super::*;
use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

struct Peer {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.connection.close(0_u32.into(), b"test peer cleanup");
        self.endpoint.close(0_u32.into(), b"test peer cleanup");
    }
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
        let connection = endpoint.connect(address, "127.0.0.1")?.await?;
        Ok(Self {
            endpoint,
            connection,
        })
    }
}

async fn ready(origin: &Origin, streams: usize) -> TestResult<()> {
    timeout(CLEANUP_TIMEOUT, async {
        loop {
            if origin.connections() == 1 && lock(&origin.log).streams == streams {
                return Ok::<_, Box<dyn Error + Send + Sync>>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

async fn released(address: SocketAddr) -> TestResult<()> {
    timeout(CLEANUP_TIMEOUT, async {
        loop {
            match phantom_testkit::udp::bind(address) {
                Ok(socket) => {
                    assert_eq!(socket.local_addr()?, address);
                    return Ok::<_, Box<dyn Error + Send + Sync>>(());
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await?
}

async fn bounded(future: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(Duration::from_secs(20), future).await?
}

#[tokio::test]
async fn dropping_origin_closes_original_connection_and_partial_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let address = origin.address;
        let peer = Peer::connect(&identity, address).await?;
        let (mut send, _recv) = peer.connection.open_bi().await?;
        send.write_all(&[HEADERS_FRAME as u8, 0x40]).await?;
        ready(&origin, 1).await?;

        drop(origin);
        let closed = peer.connection.closed().await;
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == 0)
        );
        released(address).await
    })
    .await
}

#[tokio::test]
async fn interrupted_finish_keeps_caller_and_original_accepted_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::spawn(&identity, Behavior::ECHO)?;
        let address = origin.address;
        let peer = Peer::connect(&identity, address).await?;
        ready(&origin, 0).await?;
        let primary = Box::new(io::Error::new(io::ErrorKind::PermissionDenied, "caller failed"));
        let original = (&*primary) as *const io::Error;
        {
            let finishing = origin.finish(Err(primary));
            tokio::pin!(finishing);
            assert!(futures_util::poll!(&mut finishing).is_pending());
        }
        assert!(origin.task.is_some());

        let error = origin.finish(Ok(())).await.unwrap_err();
        assert!(std::ptr::eq(error.downcast_ref::<io::Error>().unwrap(), original));
        assert!(origin.task.is_none());
        assert!(matches!(peer.connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0));
        released(address).await
    })
    .await
}

#[tokio::test]
async fn oversized_and_truncated_frame_lengths_keep_original_parser_and_caller_causes()
-> TestResult<()> {
    for (header, oversized) in [
        (
            vec![1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            true,
        ),
        (vec![1, 0x40], false),
    ] {
        bounded(async {
            let identity = TestIdentity::generate()?;
            let mut origin = Origin::spawn(&identity, Behavior::ECHO)?;
            let address = origin.address;
            let peer = Peer::connect(&identity, address).await?;
            let (mut send, _recv) = peer.connection.open_bi().await?;
            send.write_all(&header).await?;
            send.finish()?;
            // The original request fails and closes its connection before cleanup.
            peer.connection.closed().await;
            let primary = Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "caller failed",
            ));
            let original = (&*primary) as *const io::Error;
            let error = origin.finish(Err(primary)).await.unwrap_err();
            let failures = error.downcast_ref::<FixtureFailures>().unwrap();
            assert!(std::ptr::eq(
                failures.primary.downcast_ref::<io::Error>().unwrap(),
                original
            ));
            let ending = failures.cleanup.downcast_ref::<Ending>().unwrap();
            let cause = ending.source().unwrap();
            if oversized {
                let cause = cause.downcast_ref::<io::Error>().unwrap();
                assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
                assert_eq!(cause.to_string(), "HTTP/3 origin frame bound exceeded");
            } else {
                assert!(cause.downcast_ref::<quinn::ReadExactError>().is_some());
            }
            assert!(origin.task.is_none());
            released(address).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn websocket_frame_length_and_partial_eof_are_errors_before_payload_allocation()
-> TestResult<()> {
    for wire in [
        vec![0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x81],
    ] {
        let mut input = wire.as_slice();
        let error = read_client_frame(&mut input).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
        ));
    }
    let wire = [0x81, 0x81, 1, 2, 3, 4, b'a' ^ 1];
    let mut input = wire.as_slice();
    let frame = read_client_frame(&mut input).await?.unwrap();
    assert_eq!(frame.payload, b"a");
    assert!(read_client_frame(&mut input).await?.is_none());
    Ok(())
}
