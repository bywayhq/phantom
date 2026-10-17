//! Bounded, ordered propagation delay for the client-to-proxy link only.

use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::{Instant, sleep_until},
};

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    delay: Duration,
) -> std::io::Result<()> {
    let (sender, mut receiver) = mpsc::channel(16);
    let send = async {
        loop {
            let mut bytes = vec![0; 16 * 1024];
            let read = reader.read(&mut bytes).await?;
            if read == 0 {
                break;
            }
            bytes.truncate(read);
            sender
                .send((Instant::now() + delay, bytes))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "delay relay closed")
                })?;
        }
        drop(sender);
        std::io::Result::Ok(())
    };
    let receive = async {
        while let Some((at, bytes)) = receiver.recv().await {
            sleep_until(at).await;
            writer.write_all(&bytes).await?;
        }
        writer.shutdown().await
    };
    tokio::try_join!(send, receive)?;
    Ok(())
}

pub(super) async fn relay(
    socket: tokio::net::TcpStream,
    stream: tokio::io::DuplexStream,
    delay: Duration,
) -> std::io::Result<()> {
    let (socket_read, socket_write) = socket.into_split();
    let (stream_read, stream_write) = tokio::io::split(stream);
    tokio::try_join!(
        copy(socket_read, stream_write, delay),
        copy(stream_read, socket_write, delay)
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queued_chunks_preserve_bytes_and_eof() -> std::io::Result<()> {
        let (mut input, source) = tokio::io::duplex(4093);
        let (sink, mut output) = tokio::io::duplex(4099);
        let expected = (0..100_003)
            .map(|value| (value % 251) as u8)
            .collect::<Vec<_>>();
        let write = async {
            input.write_all(&expected).await?;
            input.shutdown().await
        };
        let relay = copy(source, sink, Duration::from_millis(1));
        let read = async {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, expected);
            std::io::Result::Ok(())
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(write, relay, read)?;
            std::io::Result::Ok(())
        })
        .await??;
        Ok(())
    }
}
