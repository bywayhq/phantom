use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseBody, ResponseInfo};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinError, time::timeout};
use tracing::instrument::WithSubscriber;

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{OutcomeSubscriber, SECOND_CONNECTION_WINDOW, TEST_TIMEOUT, TestResult, read_head};

const RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
type Output = (Vec<u8>, bool);
type Peer = ConnectionPeer<TestResult<Output>>;

pub(super) fn spawn(listener: TcpListener, control: Option<ownership::Control>) -> Peer {
    let lifetime = control.as_ref().map(ownership::Control::lifetime);
    ConnectionPeer::spawn(async move {
        let _lifetime = lifetime;
        let (stream, _) = listener.accept().await?;
        let mut stream = ownership::ObservedStream::new(stream, control);
        let head = read_head(&mut stream).await?;
        stream.write_all(RESPONSE).await?;
        stream.flush().await?;

        match timeout(SECOND_CONNECTION_WINDOW, stream.second_accept(&listener)).await {
            Err(_) => Ok((head, true)),
            Ok(Ok(_)) => Err("terminal status opened a second connection".into()),
            Ok(Err(error)) => Err(error.into()),
        }
    })
}

pub(super) async fn caller(
    client: &Client,
    target: &str,
    subscriber: &OutcomeSubscriber,
) -> TestResult<ResponseBody> {
    let response = client
        .get_with_protocol(HttpProtocol::Http1, target)?
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

pub(super) async fn collect<T>(caller: TestResult<T>, mut peer: Peer) -> TestResult<(T, Output)> {
    let mut requested = caller.is_err() && !peer.is_finished();
    if requested {
        peer.abort();
    }

    let serving = match timeout(TEST_TIMEOUT, &mut peer).await {
        Ok(joined) => joined_outcome(joined, requested),
        Err(elapsed) => {
            if !peer.is_finished() {
                peer.abort();
                requested = true;
            }

            let cleanup = match timeout(TEST_TIMEOUT, &mut peer).await {
                Ok(joined) => joined_outcome(joined, requested).map(|_| ()),
                Err(elapsed) => {
                    Err(FixtureDeadline::new("terminal-status peer did not finish", elapsed).into())
                }
            };
            finish_with_cleanup(
                Err(FixtureDeadline::new("terminal-status peer did not finish", elapsed).into()),
                cleanup,
            )
        }
    };

    let (output, cleanup) = match serving {
        Ok(output) => (output, Ok(())),
        Err(error) => (None, Err(error)),
    };

    let value = finish_with_cleanup(caller, cleanup)?;
    Ok((
        value,
        output.ok_or("original terminal peer output missing")?,
    ))
}

fn joined_outcome(
    joined: Result<TestResult<Output>, JoinError>,
    requested: bool,
) -> TestResult<Option<Output>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

mod ownership;
