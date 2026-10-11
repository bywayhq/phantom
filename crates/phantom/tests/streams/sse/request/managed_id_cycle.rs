use btls::ssl::SslAcceptor;
use phantom::{Client, SseEventSource};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

use super::{TestResult, accept_tls};

mod ownership;

pub(super) type Peer = JoinHandle<TestResult<Vec<String>>>;
// Keep successful caller resources alive through joins and header assertions.
pub(super) type Caller = Option<(SseEventSource, Client)>;

pub(super) fn spawn(
    listener: TcpListener,
    acceptor: SslAcceptor,
    mut control: Option<ownership::Control>,
) -> Peer {
    let lifetime = control.as_ref().map(ownership::Control::lifetime);
    tokio::spawn(async move {
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

pub(super) async fn collect(caller: TestResult<Caller>, peer: Peer) -> TestResult<(Caller, Vec<String>)> {
    let caller = caller?;
    let heads = peer.await??;
    Ok((caller, heads))
}
