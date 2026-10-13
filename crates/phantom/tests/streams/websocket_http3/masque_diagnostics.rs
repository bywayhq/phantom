use std::{error::Error, fmt, time::Duration};

use bytes::Bytes;
use phantom::{WebSocket, WebSocketError, WebSocketMessage};
use tokio::time::{error::Elapsed, timeout};

use super::{MasqueProxy, Origin, TestResult};

struct ExchangeFailure {
    step: &'static str,
    primary: WebSocketError,
    proxy_failures: Vec<Box<dyn Error + Send + Sync>>,
    proxy_failure_observation: Option<Elapsed>,
    proxy_connections: usize,
    proxy_requests: usize,
    origin_attempts: usize,
    origin_connections: usize,
    origin_methods: Vec<String>,
}

impl fmt::Debug for ExchangeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for ExchangeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "HTTP/3 proxy WebSocket {} failed", self.step)?;
        write_causes(formatter, &self.primary)?;

        writeln!(
            formatter,
            "proxy connections={}, requests={}; origin attempts={}, connections={}, methods={:?}",
            self.proxy_connections,
            self.proxy_requests,
            self.origin_attempts,
            self.origin_connections,
            self.origin_methods,
        )?;
        for error in &self.proxy_failures {
            writeln!(formatter, "completed proxy failure:")?;
            write_causes(formatter, error.as_ref())?;
        }

        if let Some(error) = &self.proxy_failure_observation {
            writeln!(
                formatter,
                "no proxy failure published within the observation: {error}"
            )?;
        }
        Ok(())
    }
}

impl Error for ExchangeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

fn write_causes(formatter: &mut fmt::Formatter<'_>, error: &dyn Error) -> fmt::Result {
    writeln!(formatter, "{error}; {error:?}")?;
    let mut source = error.source();
    while let Some(error) = source {
        writeln!(formatter, "caused by: {error}; {error:?}")?;
        source = error.source();
    }
    Ok(())
}

pub(super) async fn observe<T>(
    step: &'static str,
    result: Result<T, WebSocketError>,
    origin: &Origin,
    proxy: &MasqueProxy,
) -> TestResult<T> {
    let primary = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };

    // A relay can already have returned its error while the listener has not
    // yet harvested its join. Bound that publication observation separately.
    let observed = timeout(Duration::from_millis(100), async {
        loop {
            let failures = proxy.take_failures();
            if !failures.is_empty() {
                return failures;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let (proxy_failures, proxy_failure_observation) = match observed {
        Ok(failures) => (failures, None),
        Err(error) => (Vec::new(), Some(error)),
    };

    Err(Box::new(ExchangeFailure {
        step,
        primary,
        proxy_failures,
        proxy_failure_observation,
        proxy_connections: proxy.connections(),
        proxy_requests: proxy.requests().len(),
        origin_attempts: origin.attempts(),
        origin_connections: origin.connections(),
        origin_methods: origin.methods(),
    }))
}

pub(super) async fn assert_echoes(
    socket: &mut WebSocket,
    origin: &Origin,
    proxy: &MasqueProxy,
) -> TestResult<()> {
    let sent = socket.send(WebSocketMessage::Text("over h3".into())).await;
    observe("text send", sent, origin, proxy).await?;
    let received = socket.receive().await;
    assert_eq!(
        observe("text receive", received, origin, proxy).await?,
        WebSocketMessage::Text("over h3".into())
    );

    let binary = Bytes::from_static(&[0, 1, 2, 0xff]);
    let sent = socket.send(WebSocketMessage::Binary(binary.clone())).await;
    observe("binary send", sent, origin, proxy).await?;
    let received = socket.receive().await;
    assert_eq!(
        observe("binary receive", received, origin, proxy).await?,
        WebSocketMessage::Binary(binary)
    );
    Ok(())
}
