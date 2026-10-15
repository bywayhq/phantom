use std::time::Duration;

use btls::ssl::SslAcceptor;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    ech::{ORIGIN_NAME, PUBLIC_NAME, Replayed, handshake},
    tls::{TestResult, is_peer_gone, read_head},
    websocket::{append_and_write_server_frame, header_value, read_client_frame, websocket_accept},
};

const QUIET: Duration = Duration::from_millis(200);

async fn authenticated(tcp: TcpStream, acceptor: &SslAcceptor) -> TestResult<SslStream<Replayed>> {
    let (observed, stream) = handshake(tcp, acceptor).await?;
    assert_eq!(observed.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(observed.ech_accepted);
    assert_eq!(observed.inner_server_name.as_deref(), Some(ORIGIN_NAME));
    Ok(stream)
}

async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0; 1];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error) if is_peer_gone(&error) => Ok(()),
        Ok(_) => Err("closed client sent an unexpected application byte".into()),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn serve(
    listener: TcpListener,
    acceptor: SslAcceptor,
    authority: String,
    ready: oneshot::Sender<()>,
    release_101: oneshot::Receiver<()>,
) -> TestResult<()> {
    let (winner, _) = listener.accept().await?;
    // Hold winner authentication until the real slower TCP attempt connects.
    // Its work must be driven during the winning ECH handshake.
    let (spare, _) = listener.accept().await?;
    let (winner, spare) = tokio::try_join!(
        authenticated(winner, &acceptor),
        authenticated(spare, &acceptor)
    )?;
    exchange(listener, winner, spare, authority, ready, release_101).await
}

pub(super) async fn serve_plaintext(
    listener: TcpListener,
    authority: String,
    ready: oneshot::Sender<()>,
    release_101: oneshot::Receiver<()>,
) -> TestResult<()> {
    let (winner, _) = listener.accept().await?;
    let (spare, _) = listener.accept().await?;
    exchange(listener, winner, spare, authority, ready, release_101).await
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    listener: TcpListener,
    mut winner: S,
    mut spare: S,
    authority: String,
    ready: oneshot::Sender<()>,
    release_101: oneshot::Receiver<()>,
) -> TestResult<()> {
    let request = read_head(&mut winner).await?;
    let key = header_value(&request, "sec-websocket-key").ok_or("missing WebSocket nonce")?;
    assert_eq!(request, format!(
        "GET /events HTTP/1.1\r\nHost: {authority}\r\nX-Order: first\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).as_bytes());
    let mut byte = [0; 1];
    assert!(
        timeout(QUIET, spare.read(&mut byte)).await.is_err(),
        "spare sent HTTP or closed before claim"
    );
    ready
        .send(())
        .map_err(|()| "opening observer ended before spare readiness")?;
    let ordinary = read_head(&mut spare).await?;
    assert!(ordinary.starts_with(b"GET /page HTTP/1.1\r\n"));
    spare
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
        .await?;
    spare.flush().await?;
    release_101.await?;
    assert!(
        timeout(QUIET, listener.accept()).await.is_err(),
        "ordinary request opened a third TCP connection"
    );
    let accept = websocket_accept(key);
    winner.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
    winner.flush().await?;
    let frame = read_client_frame(&mut winner).await?;
    assert!(!frame.rsv1);
    assert_eq!(frame.opcode, 0x2);
    assert_eq!(frame.payload, b"client");
    append_and_write_server_frame(&mut winner, true, 0x2, b"peer").await?;
    tokio::try_join!(closed(&mut winner), closed(&mut spare))?;
    Ok(())
}
