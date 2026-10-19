use super::{Body, Result};
use std::{
    error::Error,
    io,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

fn disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

pub(super) async fn http1_body<S: AsyncRead + AsyncWrite + Unpin>(
    stream: BufReader<S>,
    body: &Body,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut byte = [0];
    let written = AtomicUsize::new(0);
    // Observe the peer's close while the response is incomplete. A successful
    // write can mean only that the local kernel accepted the bytes.
    let closed = async {
        match reader.read(&mut byte).await {
            Ok(0) if written.load(Ordering::Relaxed) < body.bytes.len() => Ok(()),
            Err(error)
                if disconnect(&error) && written.load(Ordering::Relaxed) < body.bytes.len() =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(0) => Err("selected H1 response finished before peer disconnect".into()),
            Ok(_) => Err("unexpected request bytes during cancelled H1 response".into()),
        }
    };
    let sending = async {
        for chunk in body.bytes.chunks(body.chunk_bytes) {
            body.before_chunk().await;
            match writer.write_all(chunk).await {
                Ok(()) => {
                    written.fetch_add(chunk.len(), Ordering::Relaxed);
                }
                Err(error) if disconnect(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        writer.flush().await?;
        Err("selected H1 response finished before peer disconnect".into())
    };
    tokio::select! {
        result = closed => result,
        result = sending => result,
    }
}

pub(super) fn quic_stream_cancelled(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<h3::error::StreamError>(),
        Some(h3::error::StreamError::RemoteTerminate {
            code: h3::error::Code::H3_REQUEST_CANCELLED,
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::time::Duration;

    #[tokio::test]
    async fn http1_cancel_requires_a_disconnect_before_the_full_body() -> Result<()> {
        let body = Body::new(&Config {
            bytes: 8192,
            chunk_bytes: 1024,
            chunk_delay_ms: 1,
            ..Config::default()
        })?;
        for abandon in [true, false] {
            let (mut client, server) = tokio::io::duplex(1024);
            let body = body.clone();
            let peer = tokio::spawn(async move { http1_body(BufReader::new(server), &body).await });
            if abandon {
                let mut prefix = [0; 1024];
                client.read_exact(&mut prefix).await?;
                assert!(prefix.iter().all(|byte| *byte == b'Z'));
                drop(client);
            } else {
                let mut whole = [0; 8192];
                client.read_exact(&mut whole).await?;
                assert!(whole.iter().all(|byte| *byte == b'Z'));
                // Keep the client alive until the sender rejects full delivery.
                let result = tokio::time::timeout(Duration::from_secs(5), peer).await??;
                assert!(result.is_err());
                continue;
            }
            tokio::time::timeout(Duration::from_secs(5), peer).await???;
        }
        Ok(())
    }

    #[test]
    fn quic_cancel_only_accepts_the_remote_stream_code() {
        use h3::error::{Code, ConnectionError, StreamError};
        assert!(quic_stream_cancelled(&StreamError::RemoteTerminate {
            code: Code::H3_REQUEST_CANCELLED,
        }));
        for code in [Code::H3_INTERNAL_ERROR, Code::H3_NO_ERROR] {
            assert!(!quic_stream_cancelled(&StreamError::RemoteTerminate {
                code
            }));
        }
        assert!(!quic_stream_cancelled(&StreamError::StreamError {
            code: Code::H3_REQUEST_CANCELLED,
            reason: "local error".into(),
        }));
        assert!(!quic_stream_cancelled(&StreamError::ConnectionError(
            ConnectionError::Timeout
        )));
        assert!(!quic_stream_cancelled(&StreamError::ConnectionError(
            ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose {
                error_code: Code::H3_REQUEST_CANCELLED.value(),
            })
        )));
        assert!(!quic_stream_cancelled(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }
}
