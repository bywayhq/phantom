use std::{error::Error, fmt, future::poll_fn, net::SocketAddr, num::NonZeroUsize};

use btls::ssl::SslAcceptor;
use http::{Response, StatusCode};
use phantom::{Client, HttpProtocol, ResponseBody, RetryPolicy};
use tokio::{
    net::TcpListener,
    sync::watch,
    time::{Instant, error::Elapsed, timeout},
};
use tracing::instrument::WithSubscriber;

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{
    OutcomeSubscriber, RETRY_DELAY, SECOND_CONNECTION_WINDOW, TEST_TIMEOUT, TestResult,
    accept_tls_stream,
};

type ServerOutput = (String, bool);

pub(super) struct Exchange {
    progress: Progress,
    request: Option<ConnectionPeer<TestResult<Response<ResponseBody>>>>,
    server: Option<ConnectionPeer<TestResult<ServerOutput>>>,
    output: Option<ServerOutput>,
}

impl Exchange {
    pub(super) fn new() -> Self {
        let progress = Progress {
            started: Instant::now(),
            events: watch::channel(Vec::new()).0,
        };
        progress.mark("preparing certificate and client");
        Self {
            progress,
            request: None,
            server: None,
            output: None,
        }
    }

    pub(super) fn deadline(&self) -> Instant {
        self.progress.started + TEST_TIMEOUT
    }

    pub(super) fn mark(&self, phase: &'static str) {
        self.progress.mark(phase);
    }

    pub(super) fn deadline_error(&self, elapsed: Elapsed) -> Box<dyn Error + Send + Sync> {
        Box::new(RetryDeadline {
            elapsed,
            events: self.progress.events.borrow().clone(),
        })
    }

    pub(super) fn start(
        &mut self,
        address: SocketAddr,
        client: &Client,
        subscriber: &OutcomeSubscriber,
    ) -> TestResult {
        let request = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/retried-h2"),
            )?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ));
        self.mark("request started; waiting for refused connection");
        self.request = Some(ConnectionPeer::spawn(
            async move { request.send().await.map_err(Into::into) }
                .with_subscriber(subscriber.dispatch()),
        ));
        Ok(())
    }

    pub(super) fn listen(&mut self, listener: TcpListener, acceptor: SslAcceptor) {
        self.mark("listener enabled");
        self.server = Some(ConnectionPeer::spawn(serve(
            listener,
            acceptor,
            self.progress.clone(),
        )));
    }

    pub(super) async fn wait_for_retry_reason(
        &mut self,
        subscriber: &OutcomeSubscriber,
    ) -> TestResult {
        let request = self
            .request
            .as_mut()
            .ok_or("original HTTP/2 retry request task missing")?;
        tokio::select! {
            biased;
            joined = request.join() => {
                self.request = None;
                let _response = joined??;
                Err("HTTP/2 retry request finished before the listener was enabled".into())
            }
            result = super::wait_for_retry_reason(subscriber) => {
                result?;
                self.mark("retry reason observed");
                Ok(())
            }
        }
    }

    pub(super) async fn response(&mut self) -> TestResult<Response<ResponseBody>> {
        self.mark("waiting for response head");
        let request = self
            .request
            .as_mut()
            .ok_or("original HTTP/2 retry request task missing")?;
        if let Some(server) = self.server.as_mut() {
            tokio::select! {
                biased;
                joined = request.join() => {
                    self.request = None;
                    let response = joined??;
                    self.mark("response head returned");
                    return Ok(response);
                }
                joined = server.join() => {
                    self.server = None;
                    self.output = Some(joined??);
                }
            }
        }
        let request = self
            .request
            .as_mut()
            .ok_or("original HTTP/2 retry request task missing")?;
        let joined = request.join().await;
        self.request = None;
        let response = joined??;
        self.mark("response head returned");
        Ok(response)
    }

    pub(super) async fn peer_output(&mut self) -> TestResult<ServerOutput> {
        if let Some(output) = self.output.take() {
            return Ok(output);
        }
        let server = self
            .server
            .as_mut()
            .ok_or("original HTTP/2 retry peer task missing")?;
        let joined = server.join().await;
        self.server = None;
        joined?
    }

    pub(super) async fn finish(&mut self, caller: TestResult) -> TestResult {
        // Cleanup is outside the operation deadline; an expired operation stays
        // failed while both original tasks are stopped and joined.
        let request = match self.request.as_mut() {
            Some(request) => request.shutdown().await,
            None => Ok(()),
        };
        let server = match self.server.as_mut() {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        eprintln!("HTTP/2 retry phases: {:?}", self.progress.events.borrow());
        finish_with_cleanup(finish_with_cleanup(caller, request), server)
    }
}

#[derive(Clone)]
struct Progress {
    started: Instant,
    events: watch::Sender<Vec<(&'static str, std::time::Duration)>>,
}

impl Progress {
    fn mark(&self, phase: &'static str) {
        self.events
            .send_modify(|events| events.push((phase, self.started.elapsed())));
    }
}

#[derive(Debug)]
struct RetryDeadline {
    elapsed: Elapsed,
    events: Vec<(&'static str, std::time::Duration)>,
}

impl fmt::Display for RetryDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP/2 connection retry test exceeded its deadline; phases: {:?}",
            self.events
        )
    }
}

impl Error for RetryDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.elapsed)
    }
}

async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    progress: Progress,
) -> TestResult<ServerOutput> {
    progress.mark("waiting for retried TCP connection");
    let (tcp, _) = listener.accept().await?;
    progress.mark("retried TCP accepted; waiting for TLS");
    let stream = accept_tls_stream(tcp, acceptor).await?;
    progress.mark("TLS accepted; waiting for HTTP/2 handshake");
    let mut connection = ::http2::server::handshake(stream).await?;
    progress.mark("HTTP/2 handshake complete; waiting for request");
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("HTTP/2 connection closed before retried request")??;
    respond.send_response(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())?,
        true,
    )?;
    let path = request.uri().path().to_owned();
    drop(request);
    drop(respond);
    progress.mark("response queued; waiting for peer close");
    poll_fn(|context| connection.poll_closed(context)).await?;
    progress.mark("peer closed; checking for a second connection");
    let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
    progress.mark("second connection check complete");
    Ok((path, second.is_err()))
}

#[cfg(test)]
mod tests {
    use std::{future::pending, io};

    use tokio::{sync::oneshot, time::timeout_at};

    use super::*;

    struct Lifetime(Option<oneshot::Sender<()>>);

    impl Drop for Lifetime {
        fn drop(&mut self) {
            if let Some(dropped) = self.0.take() {
                // A test assertion may have already dropped its receiver.
                let _ = dropped.send(());
            }
        }
    }

    #[tokio::test]
    async fn completed_peer_failure_is_observed_while_request_is_pending() -> TestResult {
        let mut exchange = Exchange::new();
        let (dropped, retired) = oneshot::channel();
        let lifetime = Lifetime(Some(dropped));
        exchange.request = Some(ConnectionPeer::spawn(async move {
            let _lifetime = lifetime;
            pending().await
        }));
        exchange.server = Some(ConnectionPeer::spawn(async {
            Err(io::Error::new(io::ErrorKind::InvalidData, "injected peer failure").into())
        }));
        let abort = exchange
            .request
            .as_ref()
            .ok_or("request not installed")?
            .abort_handle();

        let result = timeout_at(exchange.deadline(), exchange.response()).await?;
        let error = exchange
            .finish(result.map(|_| ()))
            .await
            .err()
            .ok_or("original peer failure was lost")?;

        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(error.to_string(), "injected peer failure");
        assert!(abort.is_finished());
        retired.await?;
        Ok(())
    }

    #[tokio::test]
    async fn timed_out_response_names_its_phase_and_joins_both_original_tasks() -> TestResult {
        let mut exchange = Exchange::new();
        let (request_dropped, request_retired) = oneshot::channel();
        let request_lifetime = Lifetime(Some(request_dropped));
        exchange.request = Some(ConnectionPeer::spawn(async move {
            let _lifetime = request_lifetime;
            pending().await
        }));
        let (server_dropped, server_retired) = oneshot::channel();
        let server_lifetime = Lifetime(Some(server_dropped));
        exchange.server = Some(ConnectionPeer::spawn(async move {
            let _lifetime = server_lifetime;
            pending().await
        }));
        exchange.mark("retried TCP accepted; waiting for TLS");
        let request_abort = exchange
            .request
            .as_ref()
            .ok_or("request not installed")?
            .abort_handle();
        let server_abort = exchange
            .server
            .as_ref()
            .ok_or("server not installed")?
            .abort_handle();

        let elapsed = timeout_at(Instant::now(), exchange.response())
            .await
            .err()
            .ok_or("pending response did not exceed the control deadline")?;
        let error = exchange
            .finish(Err(exchange.deadline_error(elapsed)))
            .await
            .err()
            .ok_or("operation timeout was lost during cleanup")?;

        let deadline = error
            .downcast_ref::<RetryDeadline>()
            .ok_or("deadline error omitted typed phase information")?;
        assert!(
            deadline
                .source()
                .is_some_and(|source| source.is::<Elapsed>())
        );
        assert!(
            deadline
                .to_string()
                .contains("retried TCP accepted; waiting for TLS")
        );
        assert!(request_abort.is_finished());
        assert!(server_abort.is_finished());
        request_retired.await?;
        server_retired.await?;
        Ok(())
    }
}
