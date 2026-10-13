use std::{io, net::SocketAddr, pin::Pin, time::Duration};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{H1_ALPN, TestIdentity, TestResult, read_head, serve_http1_replies};
use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const CONTROL_LIMIT: Duration = Duration::from_secs(5);
const HEAD_BOUND: usize = 32 * 1024;
const FIRST_REQUEST: &[u8] = b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n";
const REPLY: &str = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

#[derive(Clone, Copy)]
enum ReplyContract {
    OversizedHead,
    CleanEof,
}

struct ReplyBackup {
    peer: Option<ConnectionPeer<TestResult<usize>>>,
    client: Option<SslStream<TcpStream>>,
    address: Option<SocketAddr>,
}

impl ReplyBackup {
    fn prepare() -> Self {
        Self {
            peer: None,
            client: None,
            address: None,
        }
    }

    async fn connect(&mut self, identity: &TestIdentity) -> TestResult<()> {
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;

        let (url, task) = serve_http1_replies(identity, REPLY).await?;
        self.peer = Some(task);

        let uri: http::Uri = url.parse()?;
        let address: SocketAddr = uri
            .authority()
            .ok_or("reply fixture URL has no authority")?
            .as_str()
            .parse()?;
        self.address = Some(address);
        let tcp = timeout(CONTROL_LIMIT, TcpStream::connect(address)).await??;
        self.client = Some(SslStream::new(ssl, tcp)?);
        let stream = self.client()?;
        timeout(CONTROL_LIMIT, Pin::new(&mut *stream).connect()).await??;
        if stream.ssl().selected_alpn_protocol() != Some(&b"http/1.1"[..]) {
            return Err("trusted reply fixture did not negotiate HTTP/1.1".into());
        }

        Ok(())
    }

    fn client(&mut self) -> TestResult<&mut SslStream<TcpStream>> {
        self.client
            .as_mut()
            .ok_or_else(|| "reply client was not retained".into())
    }

    async fn observe(&mut self) -> TestResult<TestResult<usize>> {
        let peer = self.peer.as_mut().ok_or("reply worker was not retained")?;
        let joined = timeout(CONTROL_LIMIT, peer).await?;
        drop(self.peer.take());
        Ok(joined?)
    }

    async fn observe_closed(&mut self) -> TestResult<()> {
        let closed = timeout(CONTROL_LIMIT, self.client()?.read(&mut [0_u8; 1])).await?;
        match closed {
            Ok(0) => {}
            Err(error) if is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("reply fixture sent bytes after its completed response".into()),
        }

        let address = self
            .address
            .ok_or("reply listener address was not retained")?;
        let rebound = timeout(CONTROL_LIMIT, TcpListener::bind(address)).await??;
        if rebound.local_addr()? != address {
            return Err("reply listener did not release its original address".into());
        }

        Ok(())
    }

    async fn finish(mut self) -> TestResult<()> {
        let cleanup = if let Some(mut peer) = self.peer.take() {
            let requested_stop = !peer.is_finished();
            if requested_stop {
                peer.abort();
            }

            match timeout(CONTROL_LIMIT, &mut peer).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested_stop && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        } else {
            Ok(())
        };

        drop(self.client.take());
        cleanup
    }
}

async fn exercise(contract: ReplyContract) -> TestResult<()> {
    let mut backup = ReplyBackup::prepare();
    let primary: TestResult<()> = async {
        let identity = TestIdentity::generate()?;
        backup.connect(&identity).await?;
        let stream = backup.client()?;
        timeout(CONTROL_LIMIT, async {
            stream.write_all(FIRST_REQUEST).await?;
            stream.flush().await
        })
        .await??;
        let response = timeout(CONTROL_LIMIT, read_head(stream)).await??;
        if response != REPLY.as_bytes() {
            return Err("reply fixture did not return the literal first 204 response".into());
        }

        match contract {
            ReplyContract::OversizedHead => {
                let mut head = b"GET /second HTTP/1.1\r\nHost: localhost\r\nX-Large: ".to_vec();
                head.resize(HEAD_BOUND, b'x');
                timeout(CONTROL_LIMIT, async {
                    stream.write_all(&head).await?;
                    stream.flush().await
                })
                .await??;
            }
            ReplyContract::CleanEof => {
                timeout(CONTROL_LIMIT, stream.shutdown()).await??;
            }
        }

        let target = backup.observe().await?;
        if let Err(error) = backup.observe_closed().await {
            return finish_with_cleanup(target.map(|_| ()), Err(error));
        }

        validate_result(contract, target)
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

fn validate_result(contract: ReplyContract, target: TestResult<usize>) -> TestResult<()> {
    match check_result(contract, &target) {
        Ok(()) => Ok(()),
        Err(error) => finish_with_cleanup(target.map(|_| ()), Err(error)),
    }
}

fn check_result(contract: ReplyContract, target: &TestResult<usize>) -> TestResult<()> {
    match contract {
        ReplyContract::OversizedHead => {
            let error = target
                .as_ref()
                .err()
                .ok_or("HTTP/1 reply fixture discarded its actual oversized-head error")?;
            let io_error = error
                .downcast_ref::<io::Error>()
                .ok_or("reply fixture did not preserve the original I/O error")?;
            if io_error.kind() != io::ErrorKind::InvalidData {
                return Err("reply fixture returned the wrong I/O error kind".into());
            }

            if io_error.to_string() != "request head exceeded test bound" {
                return Err("reply fixture returned the wrong oversized-head cause".into());
            }
        }
        ReplyContract::CleanEof => {
            if target.as_ref().is_ok_and(|requests| *requests == 1) {
                return Ok(());
            }

            return Err("clean EOF did not preserve the one completed request".into());
        }
    }

    Ok(())
}

#[tokio::test]
async fn reply_fixture_preserves_the_actual_oversized_head_error() -> TestResult<()> {
    exercise(ReplyContract::OversizedHead).await
}

#[tokio::test]
async fn reply_fixture_counts_a_completed_request_before_clean_eof() -> TestResult<()> {
    exercise(ReplyContract::CleanEof).await
}

#[tokio::test]
async fn dropping_the_returned_reply_owner_releases_its_listener() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (url, peer) = serve_http1_replies(&identity, REPLY).await?;
    let uri: http::Uri = url.parse()?;
    let address: SocketAddr = uri
        .authority()
        .ok_or("reply fixture URL has no authority")?
        .as_str()
        .parse()?;
    let mut client = timeout(CONTROL_LIMIT, TcpStream::connect(address)).await??;

    drop(peer);
    let closed = timeout(CONTROL_LIMIT, client.read(&mut [0_u8; 1])).await?;
    match closed {
        Ok(0) => {}
        Err(error) if is_peer_gone(&error) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("dropped reply fixture sent an unexpected byte".into()),
    }

    let rebound = timeout(CONTROL_LIMIT, TcpListener::bind(address)).await??;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}
