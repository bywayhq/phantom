use std::net::SocketAddr;

use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};

use super::{TEST_TIMEOUT, TestResult};

mod ownership;

pub(super) type Peer = JoinHandle<Result<SocketAddr, String>>;

#[derive(Debug)]
pub(super) enum Outcome {
    Answered,
    CapabilityUnavailable,
}

pub(super) async fn answer_one(
    listener: &TcpListener,
    mut control: Option<ownership::Control>,
) -> TestResult<SocketAddr> {
    let (mut stream, peer) = listener.accept().await?;
    let _life = control.as_ref().map(ownership::Control::life);
    ownership::read_head(&mut stream, &mut control).await?;
    stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
    Ok(peer)
}

pub(super) fn spawn(listener: TcpListener, control: Option<ownership::Control>) -> Peer {
    tokio::spawn(async move {
        answer_one(&listener, control)
            .await
            .map_err(|error| error.to_string())
    })
}

pub(super) async fn collect(
    caller: TestResult<Outcome>,
    peer: Peer,
) -> TestResult<Option<SocketAddr>> {
    match caller? {
        Outcome::Answered => Ok(Some(timeout(TEST_TIMEOUT, peer).await???)),
        Outcome::CapabilityUnavailable => {
            peer.abort();
            Ok(None)
        }
    }
}
