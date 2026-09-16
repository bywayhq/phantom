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
mod reuse;
mod upgrade;
