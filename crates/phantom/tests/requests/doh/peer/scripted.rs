//! Every H2 stream remains owned while the test selects its reply or reset.

use std::{future::poll_fn, io, net::Ipv4Addr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};

use crate::support::{
    tls::{H2_ALPN, TestIdentity, TestResult, accept_tls},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::wire::Question;

const MAX_EXCHANGES: usize = 64;
// BoringSSL ssl.h reason codes for the peer's certificate rejection alerts.
const CERTIFICATE_UNKNOWN: i32 = 1046;
const UNKNOWN_CA: i32 = 1048;

pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) bytes: Vec<u8>,
    pub(crate) delay: Duration,
    pub(crate) unfinished: bool,
    pub(crate) reset: bool,
}

impl Reply {
    pub(crate) fn dns(bytes: Vec<u8>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            http::HeaderValue::from_static("application/dns-message"),
        );
        Self {
            status: 200,
            headers,
            bytes,
            delay: Duration::ZERO,
            unfinished: false,
            reset: false,
        }
    }

    pub(crate) fn age(mut self, seconds: u64) -> TestResult<Self> {
        self.headers.insert("age", seconds.to_string().parse()?);
        Ok(self)
    }
}

pub(crate) struct Request {
    pub(crate) question: Question,
    reply: oneshot::Sender<Reply>,
}

impl Request {
    pub(crate) fn reply(self, reply: Reply) -> TestResult<()> {
        self.reply
            .send(reply)
            .map_err(|_| "DNS reply worker disappeared".into())
    }
}

pub(crate) struct Peer {
    pub(crate) port: u16,
    pub(crate) requests: mpsc::Receiver<Request>,
    pub(crate) resets: mpsc::Receiver<::http2::Reason>,
    owner: ConnectionPeer<TestResult<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl Peer {
    pub(crate) async fn start(identity: &TestIdentity) -> TestResult<Self> {
        Self::start_with_verification_failure(identity, false).await
    }

    pub(crate) async fn start_with_verification_failure(
        identity: &TestIdentity,
        expected: bool,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (requests_tx, requests) = mpsc::channel(MAX_EXCHANGES);
        let (resets_tx, resets) = mpsc::channel(MAX_EXCHANGES);
        let (stop, mut stopped) = oneshot::channel();
        let owner = ConnectionPeer::spawn(async move {
            let accepted = tokio::select! {
                result = accept_tls(listener, acceptor) => result,
                _ = &mut stopped => return Ok(()),
            };
            let stream = match accepted {
                Ok(stream) if !expected => stream,
                Ok(_) => return Err("untrusted DNS TLS handshake unexpectedly succeeded".into()),
                Err(error) if expected => {
                    if !error
                        .downcast_ref::<btls::ssl::Error>()
                        .is_some_and(|error| {
                            error
                                .io_error()
                                .is_some_and(crate::support::tls::is_peer_gone)
                                || error.ssl_error().is_some_and(|stack| {
                                    !stack.errors().is_empty()
                                        && stack.errors().iter().all(|error| {
                                            error.library() == Some("SSL routines")
                                                && matches!(
                                                    error.reason_code(),
                                                    CERTIFICATE_UNKNOWN | UNKNOWN_CA
                                                )
                                        })
                                })
                        })
                    {
                        return Err(error);
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let mut connection = tokio::select! {
                result = ::http2::server::handshake(stream) => result?,
                _ = &mut stopped => return Ok(()),
            };
            let mut workers = JoinSet::new();
            let mut exchanges = 0;
            let primary = async {
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        incoming = connection.accept() => {
                            let Some(incoming) = incoming else { break };
                            let (request, respond) = incoming?;
                            exchanges += 1;
                            if exchanges > MAX_EXCHANGES { return Err("DNS fixture exchange bound exceeded".into()); }
                            let requests = requests_tx.clone();
                            let resets = resets_tx.clone();
                            workers.spawn(serve_stream(request, respond, requests, resets));
                        }
                        joined = workers.join_next(), if !workers.is_empty() => {
                            joined.ok_or("DNS worker disappeared")???;
                        }
                    }
                }
                Ok(())
            }.await;
            workers.abort_all();
            let mut cleanup = Ok(());
            while let Some(joined) = workers.join_next().await {
                let result = match joined {
                    Ok(result) => result,
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(error) => Err(error.into()),
                };
                cleanup = finish_with_cleanup(cleanup, result);
            }
            finish_with_cleanup(primary, cleanup)
        });
        Ok(Self {
            port,
            requests,
            resets,
            owner,
            stop: Some(stop),
        })
    }

    pub(crate) async fn finish(&mut self, primary: TestResult<()>) -> TestResult<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let joined = match timeout(Duration::from_secs(5), self.owner.join()).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };
        let joined = finish_with_cleanup(joined, self.owner.shutdown().await);
        finish_with_cleanup(primary, joined)
    }
}

async fn serve_stream(
    request: http::Request<::http2::RecvStream>,
    mut respond: ::http2::server::SendResponse<Bytes>,
    requests: mpsc::Sender<Request>,
    resets: mpsc::Sender<::http2::Reason>,
) -> TestResult<()> {
    let (parts, mut body) = request.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > 65_535 {
            return Err("oversized DNS fixture query".into());
        }
        bytes.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len())?;
    }
    if parts.method == Method::GET {
        let url = url::Url::parse(&parts.uri.to_string())?;
        let values = url
            .query_pairs()
            .filter(|(name, _)| name == "dns")
            .map(|(_, value)| value.into_owned())
            .collect::<Vec<_>>();
        if values.len() != 1 || !bytes.is_empty() {
            return Err("invalid fixture DoH GET".into());
        }
        bytes = URL_SAFE_NO_PAD.decode(&values[0])?;
    } else if parts.method != Method::POST {
        return Err("unexpected DoH method".into());
    }
    let question = Question::read(&bytes)?;
    let (reply, mut requested) = oneshot::channel();
    requests
        .send(Request { question, reply })
        .await
        .map_err(io::Error::other)?;
    let reply = tokio::select! {
        biased;
        reset = poll_fn(|context| respond.poll_reset(context)) => {
            resets.send(reset?).await.map_err(io::Error::other)?;
            return Ok(());
        }
        reply = &mut requested => reply.map_err(io::Error::other)?,
    };
    if reply.reset {
        respond.send_reset(::http2::Reason::INTERNAL_ERROR);
        return Ok(());
    }
    if !reply.delay.is_zero() {
        tokio::select! {
            reset = poll_fn(|context| respond.poll_reset(context)) => {
                resets.send(reset?).await.map_err(io::Error::other)?;
                return Ok(());
            }
            _ = tokio::time::sleep(reply.delay) => {}
        }
    }
    let mut response = Response::builder().status(reply.status).body(())?;
    *response.headers_mut() = reply.headers;
    let mut send = match respond.send_response(response, false) {
        Ok(send) => send,
        Err(error) => return retain_reset(error, &resets).await,
    };
    // Flow-control the oversize body as well, so the bound is tested by bytes
    // delivered to the client, not by a server-side buffering failure.
    let mut remaining = reply.bytes.as_slice();
    while !remaining.is_empty() {
        send.reserve_capacity(remaining.len().min(16_384));
        let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return retain_reset(error, &resets).await,
            None => {
                // h2 reports None when a reset closes the sending state.
                // Read its typed reason rather than losing that reset while
                // exercising the response-size bound.
                let reset = timeout(
                    Duration::from_secs(5),
                    poll_fn(|context| send.poll_reset(context)),
                )
                .await??;
                resets.send(reset).await.map_err(io::Error::other)?;
                return Ok(());
            }
        };
        let count = capacity.min(remaining.len()).min(16_384);
        if count == 0 {
            continue;
        }
        if let Err(error) = send.send_data(Bytes::copy_from_slice(&remaining[..count]), false) {
            return retain_reset(error, &resets).await;
        }
        remaining = &remaining[count..];
    }
    if reply.unfinished {
        let reset = poll_fn(|context| send.poll_reset(context)).await?;
        resets.send(reset).await.map_err(io::Error::other)?;
    } else if let Err(error) = send.send_data(Bytes::new(), true) {
        return retain_reset(error, &resets).await;
    }
    Ok(())
}

async fn retain_reset(
    error: ::http2::Error,
    resets: &mpsc::Sender<::http2::Reason>,
) -> TestResult<()> {
    if !error.is_reset() {
        return Err(error.into());
    }
    let reason = error.reason().ok_or("reset lost its typed reason")?;
    resets.send(reason).await.map_err(io::Error::other)?;
    Ok(())
}
