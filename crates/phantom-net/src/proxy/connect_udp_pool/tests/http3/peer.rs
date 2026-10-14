//! A real verified QUIC peer that echoes one accepted CONNECT-UDP flow.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

use super::{TestIdentity, TestResult};

pub(super) struct Observed {
    pub(super) outer: usize,
    pub(super) stream: u64,
    request: http::Request<()>,
}

impl Observed {
    pub(super) fn assert_request(&self, authority: &str, path: &str) {
        assert_eq!(self.request.method(), http::Method::CONNECT);
        assert_eq!(self.request.uri().scheme_str(), Some("https"));
        assert_eq!(
            self.request.uri().authority().map(|value| value.as_str()),
            Some(authority)
        );
        assert_eq!(self.request.uri().path(), path);
        assert_eq!(self.request.headers()["capsule-protocol"], "?1");
        assert_eq!(
            self.request
                .extensions()
                .get::<h3::ext::Protocol>()
                .map(|protocol| protocol.as_str()),
            Some("connect-udp")
        );
    }
}

pub(super) struct Peer {
    pub(super) address: SocketAddr,
    stop: watch::Sender<bool>,
    retire: Option<oneshot::Sender<()>>,
    sent: Option<oneshot::Receiver<()>>,
    requests: mpsc::Receiver<Observed>,
    task: Option<JoinHandle<TestResult>>,
}

impl Peer {
    pub(super) fn spawn(identity: &TestIdentity) -> TestResult<Self> {
        let certificate = CertificateDer::from(identity.leaf_der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            identity.private_key_der().to_vec(),
        ));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(1400).min_mtu(1400);
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let address = endpoint.local_addr()?;
        let (stop, stopped) = watch::channel(false);
        let (retire, retired) = oneshot::channel();
        let (sent, received) = oneshot::channel();
        let (observed, requests) = mpsc::channel(3);
        let task = tokio::spawn(coordinate(endpoint, stopped, retired, sent, observed));
        Ok(Self {
            address,
            stop,
            retire: Some(retire),
            sent: Some(received),
            requests,
            task: Some(task),
        })
    }

    pub(super) async fn next_request(&mut self) -> TestResult<Observed> {
        self.requests
            .recv()
            .await
            .ok_or_else(|| "GOAWAY peer request channel closed".into())
    }

    pub(super) async fn send_goaway(&mut self) -> TestResult {
        self.retire
            .take()
            .ok_or("GOAWAY command already consumed")?
            .send(())
            .map_err(|_| "GOAWAY worker disappeared")?;
        self.sent
            .take()
            .ok_or("GOAWAY acknowledgement already consumed")?
            .await?;
        Ok(())
    }

    pub(super) fn assert_no_extra_request(&mut self) -> TestResult {
        match self.requests.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => Ok(()),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err("GOAWAY peer stopped unexpectedly".into())
            }
            Ok(_) => Err("GOAWAY control opened an extra CONNECT stream".into()),
        }
    }

    pub(super) async fn finish(&mut self) -> TestResult {
        self.stop.send_replace(true);
        let Some(mut task) = self.task.take() else {
            return Err("GOAWAY peer already finished".into());
        };
        match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
            Ok(result) => result?,
            Err(error) => {
                task.abort();
                match task.await {
                    Err(joined) if joined.is_cancelled() => Err(error.into()),
                    Err(joined) => Err(format!(
                        "GOAWAY peer cleanup timed out: {error}; join failed: {joined}"
                    )
                    .into()),
                    Ok(Err(peer)) => Err(format!(
                        "GOAWAY peer cleanup timed out: {error}; peer failed: {peer}"
                    )
                    .into()),
                    Ok(Ok(())) => Err(error.into()),
                }
            }
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn stopping(stopped: &mut watch::Receiver<bool>) {
    while !*stopped.borrow_and_update() {
        if stopped.changed().await.is_err() {
            break;
        }
    }
}

async fn coordinate(
    endpoint: quinn::Endpoint,
    mut stopped: watch::Receiver<bool>,
    retired: oneshot::Receiver<()>,
    sent: oneshot::Sender<()>,
    observed: mpsc::Sender<Observed>,
) -> TestResult {
    let mut retire = Some((retired, sent));
    let mut workers = JoinSet::new();
    let mut connections = 0;
    let outcome: TestResult = loop {
        tokio::select! {
            biased;
            () = stopping(&mut stopped) => break Ok(()),
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break Err("GOAWAY endpoint stopped before cleanup".into()); };
                connections += 1;
                if connections > 2 { break Err("GOAWAY control opened a third outer".into()); }
                workers.spawn(serve(incoming, stopped.clone(), retire.take(), observed.clone()));
            },
            joined = workers.join_next(), if !workers.is_empty() => match joined {
                Some(Ok(Ok(()))) => {},
                Some(Ok(Err(error))) => break Err(error),
                Some(Err(error)) => break Err(error.into()),
                None => break Err("GOAWAY peer worker disappeared".into()),
            },
        }
    };
    endpoint.close(0_u32.into(), b"GOAWAY test cleanup");
    let mut failures = Vec::new();
    if let Err(error) = outcome {
        failures.push(error.to_string());
    }
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(error.to_string()),
            Err(error) => failures.push(error.to_string()),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

async fn serve(
    incoming: quinn::Incoming,
    mut stopped: watch::Receiver<bool>,
    mut retire: Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>,
    observed: mpsc::Sender<Observed>,
) -> TestResult {
    let quinn = tokio::select! { biased; () = stopping(&mut stopped) => return Ok(()), connection = incoming => connection? };
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut connection = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(quinn.clone()))
        .await?;
    let resolver = tokio::select! { biased; () = stopping(&mut stopped) => return Ok(()), accepted = connection.accept() => accepted?.ok_or("CONNECT stream absent")? };
    let (request, mut stream) = resolver.resolve_request().await?;
    let stream_id = stream.id().into_inner();
    observed
        .send(Observed {
            outer: quinn.stable_id(),
            stream: stream_id,
            request,
        })
        .await?;
    stream
        .send_response(
            http::Response::builder()
                .status(200)
                .header("capsule-protocol", "?1")
                .body(())?,
        )
        .await?;
    let mut accepting = true;
    let mut receiving = true;
    loop {
        tokio::select! {
            biased;
            () = stopping(&mut stopped) => return Ok(()),
            command = async { match &mut retire { Some((receiver, _)) => receiver.await, None => std::future::pending().await } }, if retire.is_some() => {
                command?;
                connection.shutdown(0).await?;
                let (_, sent) = retire.take().ok_or("GOAWAY command lost")?;
                sent.send(()).map_err(|_| "GOAWAY caller disappeared")?;
            },
            accepted = connection.accept(), if accepting => match accepted {
                Ok(None) => accepting = false,
                Ok(Some(_)) => return Err("GOAWAY peer accepted a second CONNECT on one outer".into()),
                Err(error) if error.is_h3_no_error() => return Ok(()),
                Err(error) => return Err(error.into()),
            },
            packet = quinn.read_datagram() => match packet {
                Ok(packet) => {
                    let mut payload = packet.clone();
                    let id = varint(&mut payload)?;
                    let context = varint(&mut payload)?;
                    if id != stream_id / 4 || context != 0 || payload.is_empty() { return Err("GOAWAY peer received a different flow or context".into()); }
                    quinn.send_datagram(packet)?;
                },
                Err(quinn::ConnectionError::ApplicationClosed(close)) if close.error_code == 0_u32.into() => return Ok(()),
                Err(error) => return Err(error.into()),
            },
            data = stream.recv_data(), if receiving => match data {
                Ok(None) => receiving = false,
                Ok(Some(_)) => return Err("GOAWAY marker unexpectedly used DATA".into()),
                Err(h3::error::StreamError::RemoteTerminate { code }) if code == h3::error::Code::H3_NO_ERROR || code == h3::error::Code::H3_REQUEST_CANCELLED => receiving = false,
                Err(error) => return Err(error.into()),
            },
        }
    }
}

fn varint(input: &mut Bytes) -> TestResult<u64> {
    let first = *input.first().ok_or("HTTP Datagram lacks a varint")?;
    let length = 1_usize << (first >> 6);
    if input.len() < length {
        return Err("HTTP Datagram has a truncated varint".into());
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    input.advance(length);
    Ok(value)
}
