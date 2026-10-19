use http_body::{Body, Frame, SizeHint};
use phantom::Bytes;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

pub(super) struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
    buffer: Box<[u8; 8192]>,
    done: bool,
}

impl FileBody {
    pub(super) async fn open(path: std::path::PathBuf) -> io::Result<Self> {
        let file = tokio::fs::File::open(path).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload must be a regular file",
            ));
        }
        let remaining = metadata.len();
        Ok(Self {
            file,
            remaining,
            buffer: Box::new([0; 8192]),
            done: false,
        })
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.done || this.remaining == 0 {
            return Poll::Ready(None);
        }
        let maximum = this.remaining.min(this.buffer.len() as u64) as usize;
        let mut buffer = ReadBuf::new(&mut this.buffer[..maximum]);
        match Pin::new(&mut this.file).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Ok(())) => {
                let bytes = buffer.filled();
                if bytes.is_empty() {
                    this.done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upload ended before its declared length",
                    ))));
                }
                this.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(bytes)))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::{
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Upload(PathBuf);
    impl Drop for Upload {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    async fn file() -> io::Result<(Upload, FileBody)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "phantom-python-upload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?
            .write_all(b"abcd")?;
        let body = FileBody::open(path.clone()).await?;
        Ok((Upload(path), body))
    }

    #[test]
    fn uploads_keep_their_declared_length_when_a_file_changes() -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (path, body) = file().await?;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path.0)?
                    .write_all(b"extra")?;
                assert_eq!(body.collect().await?.to_bytes(), &b"abcd"[..]);
                let (path, mut body) = file().await?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path.0)?
                    .set_len(0)?;
                let error = body
                    .frame()
                    .await
                    .transpose()
                    .err()
                    .ok_or_else(|| io::Error::other("missing upload EOF error"))?;
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                assert!(body.frame().await.is_none());
                Ok(())
            })
    }
}
