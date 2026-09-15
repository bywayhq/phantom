use std::{error::Error, future::Future, time::Duration};

use tokio::time::timeout;

use super::{OriginForm, RequestHeader};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn bounded_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/2 peer test exceeded its absolute deadline".into()),
    }
}

fn target() -> Result<OriginForm, crate::request::InvalidOriginForm> {
    OriginForm::parse("/resource?item=1")
}

fn headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("accept", "*/*"),
        RequestHeader::new("x-repeat", "alpha"),
        RequestHeader::new("x-middle", "between"),
        RequestHeader::new("x-repeat", "beta"),
        RequestHeader::new("te", "trailers"),
    ]
}

mod body_lifecycle;
mod request_wire;
