use btls::ssl::SslAcceptor;
use phantom::{Client, SseEventSource};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinError, time::timeout};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{TestResult, accept_tls};

mod ownership;

pub(super) type Peer = ConnectionPeer<TestResult<Vec<String>>>;
// Keep successful caller resources alive through joins and header assertions.
pub(super) type Caller = Option<(SseEventSource, Client)>;

pub(super) fn spawn(
    listener: TcpListener,
    acceptor: SslAcceptor,
    mut control: Option<ownership::Control>,
) -> Peer {
    let lifetime = control.as_ref().map(ownership::Control::lifetime);
    ConnectionPeer::spawn(async move {
        let _lifetime = lifetime;
        let mut stream = accept_tls(listener, acceptor).await?;
        let mut heads = Vec::new();
        for body in ["id: first\ndata: one\n\n", "id:\ndata: two\n\n"] {
            heads.push(String::from_utf8(
                ownership::read_head(&mut stream, control.as_ref()).await?,
            )?);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                 Accept-CH: last-event-id\r\nCritical-CH: last-event-id\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
            stream.flush().await?;
            ownership::written(control.as_ref());
        }
        heads.push(String::from_utf8(
            ownership::read_head(&mut stream, control.as_ref()).await?,
        )?);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        stream.shutdown().await?;
        ownership::after_shutdown(control.as_mut())?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(heads)
    })
}

pub(super) async fn collect(
    caller: TestResult<Caller>,
    mut peer: Peer,
) -> TestResult<(Caller, Vec<String>)> {
    let mut requested = caller.is_err() && !peer.is_finished();
    if requested {
        peer.abort();
    }

    let result = match timeout(super::super::TEST_TIMEOUT, &mut peer).await {
        Ok(joined) => join_outcome(joined, requested),
        Err(elapsed) => {
            if !peer.is_finished() {
                requested = true;
                peer.abort();
            }

            let cleanup = match timeout(super::super::TEST_TIMEOUT, &mut peer).await {
                Ok(joined) => join_outcome(joined, requested).map(|_| ()),
                Err(elapsed) => {
                    Err(FixtureDeadline::new("managed-ID peer did not finish", elapsed).into())
                }
            };
            finish_with_cleanup(
                Err(FixtureDeadline::new("managed-ID peer did not finish", elapsed).into()),
                cleanup,
            )
        }
    };

    let mut heads = None;
    let cleanup = match result {
        Ok(value) => {
            heads = value;
            Ok(())
        }
        Err(error) => Err(error),
    };
    let caller = finish_with_cleanup(caller, cleanup)?;
    let heads = heads.ok_or("managed-ID peer cancelled without a failure")?;
    Ok((caller, heads))
}

fn join_outcome(
    joined: Result<TestResult<Vec<String>>, JoinError>,
    requested: bool,
) -> TestResult<Option<Vec<String>>> {
    match joined {
        Ok(result) => result.map(Some),
        Err(error) if requested && error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}
