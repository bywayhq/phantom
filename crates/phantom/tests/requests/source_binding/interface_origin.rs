use std::net::SocketAddr;

use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use super::{TEST_TIMEOUT, TestResult};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

mod ownership;

pub(super) type Peer = ConnectionPeer<TestResult<SocketAddr>>;

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
    ConnectionPeer::spawn(async move { answer_one(&listener, control).await })
}

pub(super) async fn collect(
    caller: TestResult<Outcome>,
    mut peer: Peer,
) -> TestResult<Option<SocketAddr>> {
    let requested = !matches!(&caller, Ok(Outcome::Answered)) && !peer.is_finished();
    if requested {
        peer.abort();
    }

    let joined: TestResult<Option<SocketAddr>> = match timeout(TEST_TIMEOUT, &mut peer).await {
        Ok(Ok(result)) => result.map(Some),
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(None),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    };

    match caller {
        Ok(Outcome::Answered) => joined,
        Ok(Outcome::CapabilityUnavailable) => joined.map(|_| None),
        Err(error) => finish_with_cleanup(Err(error), joined.map(|_| ())),
    }
}
