use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::support::{tls::is_peer_gone, tunnel_proxy::ConnectionPeer};

use super::{TestResult, read_head};

mod ownership;

pub(super) type PeerTask = ConnectionPeer<TestResult>;

pub(super) fn spawn(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> PeerTask {
    ConnectionPeer::spawn(serve(stream))
}

async fn serve(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> TestResult {
    loop {
        match read_head(&mut stream).await {
            Ok(_) => {}
            Err(error) if is_peer_gone(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        }

        match stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await
        {
            Ok(()) => {}
            Err(error) if is_peer_gone(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}
