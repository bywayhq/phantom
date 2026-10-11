use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseBody, ResponseInfo};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};
use tracing::instrument::WithSubscriber;

use super::{OutcomeSubscriber, SECOND_CONNECTION_WINDOW, TestResult, read_head};

const RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
type Output = (Vec<u8>, bool);
type Peer = JoinHandle<TestResult<Output>>;

pub(super) fn spawn(listener: TcpListener, control: Option<ownership::Control>) -> Peer {
    let lifetime = control.as_ref().map(ownership::Control::lifetime);
    tokio::spawn(async move {
        let _lifetime = lifetime;
        let (stream, _) = listener.accept().await?;
        let mut stream = ownership::ObservedStream::new(stream, control);
        let head = read_head(&mut stream).await?;
        stream.write_all(RESPONSE).await?;
        stream.flush().await?;
        let second = timeout(SECOND_CONNECTION_WINDOW, stream.second_accept(&listener)).await;
        Ok((head, second.is_err()))
    })
}

pub(super) async fn caller(
    client: &Client,
    target: &str,
    subscriber: &OutcomeSubscriber,
) -> TestResult<ResponseBody> {
    let response = client
        .get(HttpProtocol::Http1, target)?
        .send()
        .with_subscriber(subscriber.dispatch())
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted retry metadata")?;
    assert_eq!(info.protocol(), HttpProtocol::Http1);
    assert_eq!(info.retries_performed(), 0);
    let mut body = response.into_body();
    (&mut body).collect().await?;
    Ok(body)
}

pub(super) async fn collect<T>(caller: TestResult<T>, peer: Peer) -> TestResult<(T, Output)> {
    let caller = caller?;
    let output = peer.await??;
    Ok((caller, output))
}

mod ownership;
