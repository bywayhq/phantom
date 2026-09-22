use std::{error::Error, future::Future, time::Duration};

use tokio::{
    io::{AsyncReadExt, DuplexStream},
    time::timeout,
};

use super::{OriginForm, RequestHeader};
use crate::{request::InvalidOriginForm, tracing_test::OutcomeSubscriber};

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(2);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

async fn bounded_peer_test<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    // Callsite interest is process-global and is computed from the dispatchers
    // that are live when a span callsite is first reached. A parallel test that
    // reaches an HTTP/1 callsite first with no subscriber installed caches
    // `Interest::never` for it, and every later span at that callsite is
    // disabled until some thread rebuilds the cache. Assertions on captured
    // spans then see nothing. The global fallback returns `Interest::sometimes`
    // for every callsite, so `enabled` stays dynamic and per-test dispatchers
    // are always consulted.
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    // One deadline covers all peer I/O and task joins; making progress does
    // not restart it and therefore cannot extend a hung test indefinitely.
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/1 peer test exceeded its absolute deadline".into()),
    }
}

async fn read_head(stream: &mut DuplexStream) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}

async fn wait_for_driver_outcome(
    subscriber: &OutcomeSubscriber,
    expected: &'static str,
) -> TestResult {
    timeout(Duration::from_secs(1), async {
        while subscriber
            .outcomes_for("http1.connection_driver")
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| format!("HTTP/1 connection driver did not record {expected}"))?;
    assert_eq!(
        subscriber.outcomes_for("http1.connection_driver"),
        [expected]
    );
    tokio::task::yield_now().await;
    assert_eq!(
        subscriber.outcomes_for("http1.connection_driver"),
        [expected]
    );
    Ok(())
}

fn target() -> Result<OriginForm, InvalidOriginForm> {
    OriginForm::parse("/resource?item=1")
}

fn host() -> RequestHeader {
    RequestHeader::new("Host", "example.test")
}

mod driver_lifecycle;
mod request_wire;
mod response_body;
mod response_limits;
mod reuse;
mod upgrade;
