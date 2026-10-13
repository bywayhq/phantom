use std::{error::Error, fmt, sync::Arc};

use bytes::Bytes;
use tokio::{sync::watch, task::JoinSet};

use super::{ActiveResponse, OriginObservations, TestResult, presented_leaf, respond};

type Failures = Vec<Box<dyn Error + Send + Sync>>;

pub(super) async fn listen(
    endpoint: quinn::Endpoint,
    observations: OriginObservations,
    mut stop: watch::Receiver<bool>,
) -> Failures {
    let endpoint = EndpointOwner(endpoint);
    let mut connections = JoinSet::new();
    let mut failures = Vec::new();

    loop {
        tokio::select! {
            biased;
            completed = connections.join_next(), if !connections.is_empty() => {
                retain_connection(completed, &mut failures);
            }
            () = stopped(&mut stop) => break,
            incoming = endpoint.0.accept() => {
                let Some(incoming) = incoming else { break };
                connections.spawn(serve(incoming, observations.clone(), stop.clone()));
            }
        }
    }

    endpoint.0.close(0_u32.into(), b"test origin stopped");
    while let Some(completed) = connections.join_next().await {
        retain_connection(Some(completed), &mut failures);
    }
    failures
}

fn retain_connection(
    completed: Option<Result<Failures, tokio::task::JoinError>>,
    failures: &mut Failures,
) {
    match completed {
        Some(Ok(mut child_failures)) => failures.append(&mut child_failures),
        Some(Err(error)) => failures.push(context("origin connection task", error)),
        None => {}
    }
}

async fn serve(
    incoming: quinn::Incoming,
    observations: OriginObservations,
    mut stop: watch::Receiver<bool>,
) -> Failures {
    let connected = tokio::select! {
        biased;
        result = incoming => result,
        () = stopped(&mut stop) => return Vec::new(),
    };
    let quinn = match connected {
        Ok(connection) => connection,
        Err(quinn::ConnectionError::LocallyClosed) if *stop.borrow() => return Vec::new(),
        Err(error) => return vec![context("origin QUIC handshake", error)],
    };

    observations
        .connections
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    observations
        .presented
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(presented_leaf(&quinn));

    let mut responders = JoinSet::new();
    let mut failures = Vec::new();
    {
        let serving = requests(&quinn, &observations, &mut responders);
        tokio::pin!(serving);
        // Close QUIC before the pinned H3 future is dropped. H3's Drop sends
        // H3_NO_ERROR; the explicit owner close must retain precedence.
        let _connection = ConnectionOwner(&quinn);
        tokio::select! {
            biased;
            result = &mut serving => {
                if let Err(error) = result
                    && !(*stop.borrow() && is_local_close(error.as_ref()))
                {
                    failures.push(error);
                }
            }
            () = stopped(&mut stop) => {}
        }
    }

    responders.abort_all();
    while let Some(completed) = responders.join_next().await {
        match completed {
            Ok(Ok(())) => {}
            Ok(Err(error)) if is_local_close(error.as_ref()) => {}
            Ok(Err(error)) => failures.push(error),
            Err(error) if error.is_cancelled() => {}
            Err(error) => failures.push(context("origin response task", error)),
        }
    }
    failures
}

async fn requests(
    quinn: &quinn::Connection,
    observations: &OriginObservations,
    responders: &mut JoinSet<TestResult<()>>,
) -> TestResult<()> {
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quinn.clone()))
            .await
            .map_err(|error| context("origin H3 setup", error))?;

    loop {
        tokio::select! {
            biased;
            completed = responders.join_next(), if !responders.is_empty() => {
                match completed {
                    Some(Ok(result)) => result?,
                    Some(Err(error)) => return Err(context("origin response task", error)),
                    None => {}
                }
            }
            accepted = connection.accept() => {
                let resolver = match accepted {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => return Ok(()),
                    Err(error) if is_clean_h3_close(&error) => return Ok(()),
                    Err(error) => return Err(context("origin H3 request acceptance", error)),
                };

                let (request, stream) = resolver.resolve_request().await
                    .map_err(|error| context("origin request HEADERS", error))?;

                let path = request.uri().path().to_owned();
                observations.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(path.clone());

                let response = ActiveResponse::new(Arc::clone(&observations.responses));
                responders.spawn(async move {
                    let _response = response;
                    match respond(stream, path).await {
                        Ok(()) => Ok(()),
                        Err(error) if is_expected_response_end(error.as_ref()) => Ok(()),
                        Err(error) => Err(context("origin response writes", error)),
                    }
                });
            }
        }
    }
}

fn is_expected_response_end(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<h3::error::StreamError>(),
        Some(h3::error::StreamError::RemoteTerminate { code, .. })
            if *code == h3::error::Code::H3_REQUEST_CANCELLED
    ) || matches!(
        error.downcast_ref::<h3::error::StreamError>(),
        Some(h3::error::StreamError::ConnectionError(error, ..)) if is_clean_h3_close(error)
    )
}

fn is_clean_h3_close(error: &h3::error::ConnectionError) -> bool {
    error.is_h3_no_error()
        || matches!(
            error,
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0 },
                ..
            )
        )
}

fn is_local_close(error: &(dyn Error + 'static)) -> bool {
    if matches!(
        error.downcast_ref::<quinn::ConnectionError>(),
        Some(quinn::ConnectionError::LocallyClosed)
    ) {
        return true;
    }

    if let Some(h3::error::ConnectionError::Remote(
        h3::quic::ConnectionErrorIncoming::Undefined(error),
        ..,
    )) = error.downcast_ref::<h3::error::ConnectionError>()
    {
        return matches!(
            error.downcast_ref::<quinn::ConnectionError>(),
            Some(quinn::ConnectionError::LocallyClosed)
        );
    }

    if let Some(h3::error::StreamError::ConnectionError(error, ..)) =
        error.downcast_ref::<h3::error::StreamError>()
    {
        return is_local_close(error);
    }
    error.source().is_some_and(is_local_close)
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

struct EndpointOwner(quinn::Endpoint);

impl Drop for EndpointOwner {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"test origin owner dropped");
    }
}

struct ConnectionOwner<'a>(&'a quinn::Connection);

impl Drop for ConnectionOwner<'_> {
    fn drop(&mut self) {
        self.0.close(0_u32.into(), b"test origin connection ended");
    }
}

pub(super) fn context(
    operation: &'static str,
    source: impl Into<Box<dyn Error + Send + Sync>>,
) -> Box<dyn Error + Send + Sync> {
    Box::new(OriginFailure {
        operation,
        source: source.into(),
    })
}

#[derive(Debug)]
struct OriginFailure {
    operation: &'static str,
    source: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.operation, self.source)
    }
}

impl Error for OriginFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
