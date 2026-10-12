use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
};

use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{oneshot, watch},
    task::AbortHandle,
};

use super::{
    H1_ALPN, TestIdentity, TestResult, accept_one_observed, bounded, read_head, test_client,
};

#[derive(Clone, Debug, Default)]
struct State {
    address: Option<SocketAddr>,
    server: Option<AbortHandle>,
    accepted: bool,
    handshake_pending: bool,
    caller_pending: bool,
    destroyed: bool,
    completed_tls_error: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct Observation(watch::Sender<State>);

impl Observation {
    pub(super) fn accepted(&self) {
        self.0.send_modify(|state| state.accepted = true);
    }

    pub(super) fn handshake_pending(&self) {
        self.0.send_modify(|state| state.handshake_pending = true);
    }

    fn completed(&self, result: &TestResult) {
        if let Err(error) = result
            && let Some(error) = error.downcast_ref::<btls::ssl::Error>()
        {
            self.0
                .send_modify(|state| state.completed_tls_error = Some(error.to_string()));
        }
    }
}

struct PeerLife(Option<Observation>);

impl Drop for PeerLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed.0.send_modify(|state| state.destroyed = true);
        }
    }
}

pub(super) struct Control {
    observed: Observation,
    start: oneshot::Receiver<()>,
    first_target: Option<String>,
}

pub(super) async fn reuse_requests(control: Option<Control>) -> TestResult {
    let (observed, start, mut first_target) = match control {
        Some(control) => (
            Some(control.observed),
            Some(control.start),
            control.first_target,
        ),
        None => (None, None, None),
    };

    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let peer_observed = observed.clone();
        let server = tokio::spawn(async move {
            let _life = PeerLife(peer_observed.clone());

            let result: TestResult = async {
                let mut stream =
                    accept_one_observed(&listener, &acceptor, peer_observed.as_ref()).await?;

                for _ in 0..2 {
                    read_head(&mut stream).await?;
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                }

                Ok::<_, Box<dyn Error + Send + Sync>>(())
            }
            .await;

            if let Some(observed) = peer_observed {
                observed.completed(&result);
            }

            result
        });

        if let Some(observed) = &observed {
            observed.0.send_modify(|state| {
                state.address = Some(address);
                state.server = Some(server.abort_handle());
            });
        }

        if let Some(start) = start {
            start.await?;
        }

        let client = test_client(&identity, false)?;
        for path in ["first", "second"] {
            let target = first_target
                .take()
                .unwrap_or_else(|| format!("https://{address}/{path}"));
            let sending = client.get(HttpProtocol::Http1, &target)?.send();

            let response = if let Some(observed) = &observed {
                tokio::pin!(sending);
                poll_fn(|context| {
                    let result = sending.as_mut().poll(context);
                    if result.is_pending() {
                        observed.0.send_modify(|state| state.caller_pending = true);
                    }

                    result
                })
                .await?
            } else {
                sending.await?
            };

            response.into_body().collect().await?;
        }

        server.await??;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests;
