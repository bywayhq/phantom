use std::{io, net::Ipv4Addr};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, Method, Response, Uri};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};

use crate::support::{
    tls::{H2_ALPN, TestIdentity, TestResult, accept_tls},
    tunnel_proxy::ConnectionPeer,
};

pub(super) mod application;
pub(super) mod scripted;
pub(super) mod wire;

pub(super) struct ObservedQuery {
    pub(super) method: Method,
    pub(super) uri: Uri,
    pub(super) headers: HeaderMap,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct DnsPeer {
    pub(super) port: u16,
    pub(super) queries: mpsc::Receiver<ObservedQuery>,
    owner: ConnectionPeer<TestResult<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl DnsPeer {
    pub(super) async fn finish(&mut self) -> TestResult<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let primary = match timeout(std::time::Duration::from_secs(5), self.owner.join()).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };
        crate::support::tunnel_proxy::finish_with_cleanup(primary, self.owner.shutdown().await)
    }
}

pub(super) async fn start(identity: &TestIdentity, status: u16) -> TestResult<DnsPeer> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (observations, queries) = mpsc::channel(8);
    let (stop, mut stopped) = oneshot::channel();
    let owner = ConnectionPeer::spawn(async move {
        let stream = tokio::select! {
            result = accept_tls(listener, acceptor) => result?,
            _ = &mut stopped => return Ok(()),
        };
        let mut connection = tokio::select! {
            result = ::http2::server::handshake(stream) => result?,
            _ = &mut stopped => return Ok(()),
        };
        let mut workers = JoinSet::new();
        let primary = async { loop {
            tokio::select! {
                _ = &mut stopped => break,
                incoming = connection.accept() => {
                    let Some(incoming) = incoming else { break };
                    let (request, mut reply) = incoming?;
                    let observations = observations.clone();
                    workers.spawn(async move {
                        let (parts, mut body) = request.into_parts();
                        let mut bytes = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk?;
                            if bytes.len().saturating_add(chunk.len()) > 65_535 {
                                return Err("DNS request exceeded fixture bound".into());
                            }
                            bytes.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len())?;
                        }
                        if parts.method == Method::GET {
                            let url = url::Url::parse(&parts.uri.to_string())?;
                            let values = url.query_pairs()
                                .filter(|(name, _)| name == "dns")
                                .map(|(_, value)| value.into_owned())
                                .collect::<Vec<_>>();
                            if values.len() != 1 || !bytes.is_empty() {
                                return Err("GET did not carry exactly one DNS parameter".into());
                            }
                            bytes = URL_SAFE_NO_PAD.decode(&values[0])?;
                        }
                        let answer = ipv4_answer(&bytes)?;
                        observations.send(ObservedQuery {
                            method: parts.method,
                            uri: parts.uri,
                            headers: parts.headers,
                            bytes,
                        }).await.map_err(io::Error::other)?;
                        let response = Response::builder().status(status)
                            .header("content-type", "Application/DNS-Message; fixture=\"yes\"")
                            .header("accept-ch", "Sec-CH-UA-Platform-Version")
                            .header("critical-ch", "Sec-CH-UA-Platform-Version")
                            .header("set-cookie", "resolver=private")
                            .body(())?;
                        let mut send = reply.send_response(response, false)?;
                        send.send_data(Bytes::from(answer), true)?;
                        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                    });
                }
                completed = workers.join_next(), if !workers.is_empty() => {
                    completed.ok_or("DNS worker disappeared")???;
                }
            }
        } Ok(()) }.await;
        // Pending body/response workers remain owned on every exit path.
        workers.abort_all();
        let mut cleanup = Ok(());
        while let Some(completed) = workers.join_next().await {
            let result = match completed {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(error.into()),
            };
            cleanup = crate::support::tunnel_proxy::finish_with_cleanup(cleanup, result);
        }
        crate::support::tunnel_proxy::finish_with_cleanup(primary, cleanup)
    });
    Ok(DnsPeer {
        port,
        queries,
        owner,
        stop: Some(stop),
    })
}

// Construct the response independently of Phantom's DNS encoder/parser.
fn ipv4_answer(query: &[u8]) -> TestResult<Vec<u8>> {
    if query.len() < 12 || query[4..6] != [0, 1] {
        return Err("fixture expected one DNS question".into());
    }
    let mut end = 12;
    loop {
        let length = usize::from(*query.get(end).ok_or("truncated DNS name")?);
        end += 1;
        if length == 0 {
            break;
        }
        if length > 63 || end.saturating_add(length) > query.len() {
            return Err("invalid fixture query label".into());
        }
        end += length;
    }
    let question_end = end.checked_add(4).ok_or("question overflow")?;
    if query.get(end..question_end) != Some(&[0, 1, 0, 1]) {
        return Err("fixture expected an IN A query".into());
    }
    let mut answer = query[..2].to_vec();
    answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..question_end]);
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    Ok(answer)
}
