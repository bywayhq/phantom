use std::{io, net::SocketAddr, pin::Pin, time::Duration};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{H2_ALPN, Http2Start, TestIdentity, TestResult, serve_raw_http2};
use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const LIMIT: Duration = Duration::from_secs(5);
const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: &[u8] = b"\x00\x01\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x04\x00\x60\x00\x00\x00\x06\x00\x04\x00\x00";

#[derive(Clone, Copy)]
enum Input {
    Valid,
    WrongPreface,
    SettingsOnRequest,
    PartialSetting,
}

struct WireCapture {
    peer: Option<ConnectionPeer<TestResult<Http2Start>>>,
    client: Option<SslStream<TcpStream>>,
    done: Option<oneshot::Sender<()>>,
    address: Option<SocketAddr>,
}

impl WireCapture {
    fn prepare() -> Self {
        Self {
            peer: None,
            client: None,
            done: None,
            address: None,
        }
    }

    async fn connect(&mut self) -> TestResult<()> {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H2_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;

        let (done, stopped) = oneshot::channel();
        self.done = Some(done);
        self.address = Some(address);
        self.peer = Some(ConnectionPeer::spawn(serve_raw_http2(
            listener, acceptor, stopped,
        )));

        let tcp = timeout(LIMIT, TcpStream::connect(address)).await??;
        self.client = Some(SslStream::new(ssl, tcp)?);
        let stream = self.client()?;
        timeout(LIMIT, Pin::new(&mut *stream).connect()).await??;
        if stream.ssl().selected_alpn_protocol() != Some(&b"h2"[..]) {
            return Err("wire fixture did not negotiate trusted HTTP/2".into());
        }

        Ok(())
    }

    fn client(&mut self) -> TestResult<&mut SslStream<TcpStream>> {
        self.client
            .as_mut()
            .ok_or_else(|| "wire client missing".into())
    }

    async fn observe(&mut self) -> TestResult<TestResult<Http2Start>> {
        // Either readiness or dropped sender releases the original post-response wait.
        drop(self.done.take());
        let peer = self.peer.as_mut().ok_or("wire worker missing")?;
        let joined = timeout(LIMIT, peer).await?;
        drop(self.peer.take());
        Ok(joined?)
    }

    async fn observe_closed(&mut self) -> TestResult<Vec<u8>> {
        let mut response = Vec::new();
        let mut buffer = [0_u8; 128];
        timeout(LIMIT, async {
            loop {
                match self.client()?.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => {
                        if response.len() + count > 256 {
                            return Err("wire fixture response exceeded its literal bound".into());
                        }
                        response.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if is_peer_gone(&error) => break,
                    Err(error) => return Err(error.into()),
                }
            }
            TestResult::<()>::Ok(())
        })
        .await??;

        let address = self.address.ok_or("wire listener address missing")?;
        let rebound = timeout(LIMIT, TcpListener::bind(address)).await??;
        if rebound.local_addr()? != address {
            return Err("wire listener address was not released".into());
        }

        Ok(response)
    }

    async fn finish(mut self) -> TestResult<()> {
        drop(self.done.take());
        let cleanup = if let Some(mut peer) = self.peer.take() {
            let requested_stop = !peer.is_finished();
            if requested_stop {
                peer.abort();
            }

            match timeout(LIMIT, &mut peer).await {
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

async fn exercise(input: Input) -> TestResult<()> {
    let mut capture = WireCapture::prepare();
    let primary = async {
        capture.connect().await?;
        let mut wire = Vec::from(match input {
            Input::WrongPreface => &b"XXXXXXXXXXXXXXXXXXXXXXXX"[..],
            _ => &PREFACE[..],
        });
        match input {
            Input::SettingsOnRequest => {
                wire.extend_from_slice(b"\x00\x00\x18\x04\x00\x00\x00\x00\x01");
                wire.extend_from_slice(SETTINGS);
            }
            Input::PartialSetting => {
                wire.extend_from_slice(b"\x00\x00\x19\x04\x00\x00\x00\x00\x00");
                wire.extend_from_slice(SETTINGS);
                wire.push(0);
            }
            _ => {
                wire.extend_from_slice(b"\x00\x00\x18\x04\x00\x00\x00\x00\x00");
                wire.extend_from_slice(SETTINGS);
            }
        }
        // A literal request HEADERS frame on stream1 with PRIORITY and END_HEADERS.
        wire.extend_from_slice(b"\x00\x00\x13\x01\x25\x00\x00\x00\x01\x00\x00\x00\x00\x0f\x82\x87\x84\x01\x09localhost");
        timeout(LIMIT, async {
            let stream = capture.client()?;
            stream.write_all(&wire).await?;
            stream.flush().await?;
            TestResult::<()>::Ok(())
        })
        .await??;

        let target = capture.observe().await?;
        let response = match capture.observe_closed().await {
            Ok(response) => response,
            Err(error) => return finish_with_cleanup(target.map(|_| ()), Err(error)),
        };
        match validate(input, &target, &response) {
            Ok(()) => Ok(()),
            Err(error) => finish_with_cleanup(target.map(|_| ()), Err(error)),
        }
    }
    .await;

    finish_with_cleanup(primary, capture.finish().await)
}

fn validate(input: Input, target: &TestResult<Http2Start>, response: &[u8]) -> TestResult<()> {
    if matches!(input, Input::Valid) {
        let start = target
            .as_ref()
            .map_err(|_| "valid literal HTTP/2 input was rejected")?;
        if start.settings != SETTINGS || start.headers_flags != 0x25 {
            return Err("valid wire recipe lost SETTINGS order or HEADERS priority".into());
        }
        // Empty SETTINGS, SETTINGS ACK, indexed200 HEADERS with END_STREAM/END_HEADERS.
        if response != b"\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x04\x01\x00\x00\x00\x00\x00\x00\x01\x01\x05\x00\x00\x00\x01\x88" {
            return Err("valid wire fixture did not send the literal HTTP/2 response".into());
        }
        return Ok(());
    }

    let error = target
        .as_ref()
        .err()
        .ok_or("HTTP/2 recipe observer accepted malformed wire input")?;
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("observer omitted its original I/O error")?;
    if error.kind() != io::ErrorKind::InvalidData {
        return Err("malformed wire input did not return InvalidData".into());
    }
    Ok(())
}

#[tokio::test]
async fn literal_http2_recipe_keeps_order_priority_and_response() -> TestResult<()> {
    exercise(Input::Valid).await
}

#[tokio::test]
async fn recipe_observer_rejects_a_wrong_connection_preface() -> TestResult<()> {
    exercise(Input::WrongPreface).await
}

#[tokio::test]
async fn recipe_observer_rejects_settings_on_a_request_stream() -> TestResult<()> {
    exercise(Input::SettingsOnRequest).await
}

#[tokio::test]
async fn recipe_observer_rejects_a_trailing_partial_setting() -> TestResult<()> {
    exercise(Input::PartialSetting).await
}
