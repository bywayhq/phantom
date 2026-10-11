use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
};

use super::{TestResult, read_head};

mod ownership;

pub(super) type PeerTask = JoinHandle<TestResult>;

pub(super) fn spawn(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> PeerTask {
    tokio::spawn(serve(stream))
}

async fn serve(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> TestResult {
    while read_head(&mut stream).await.is_ok() {
        if stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    Ok(())
}
