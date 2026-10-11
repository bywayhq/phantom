use std::{
    future::poll_fn,
    io,
    net::{Ipv4Addr, Shutdown, TcpStream as StdTcpStream},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Request};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

use super::{TestResult, collect_h2_request_body};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const LIMIT: Duration = Duration::from_secs(5);
const PAYLOAD: &[u8] = b"complete-upload";

struct UploadObservation {
    collected: TestResult<Bytes>,
    remaining: Poll<Option<Result<Bytes, ::http2::Error>>>,
}

struct ObservedIo {
    stream: TcpStream,
    armed: Arc<AtomicBool>,
    pending: watch::Sender<bool>,
    eof: watch::Sender<bool>,
}

impl AsyncRead for ObservedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let had_capacity = buffer.remaining() != 0;
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        if this.armed.load(Ordering::Acquire) {
            if result.is_pending() {
                this.pending.send_replace(true);
            } else if had_capacity
                && matches!(&result, Poll::Ready(Ok(())))
                && buffer.filled().len() == before
            {
                this.eof.send_replace(true);
            }
        }
        result
    }
}

impl AsyncWrite for ObservedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

struct Exchange {
    server: Option<ConnectionPeer<TestResult<UploadObservation>>>,
    driver: Option<ConnectionPeer<TestResult<()>>>,
    sender: Option<::http2::client::SendRequest<Bytes>>,
    upload: Option<::http2::SendStream<Bytes>>,
    response: Option<::http2::client::ResponseFuture>,
    writer: Option<StdTcpStream>,
    pending: watch::Receiver<bool>,
    eof: watch::Receiver<bool>,
}

impl Exchange {
    async fn start(&mut self) -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (pending, pending_receiver) = watch::channel(false);
        let (eof, eof_receiver) = watch::channel(false);
        self.pending = pending_receiver;
        self.eof = eof_receiver;
        self.server = Some(ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            drop(listener);
            let armed = Arc::new(AtomicBool::new(false));
            let stream = ObservedIo {
                stream,
                armed: Arc::clone(&armed),
                pending,
                eof,
            };
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, _response) = connection
                .accept()
                .await
                .ok_or("connection closed before upload headers")??;
            if request.method() != Method::POST || request.uri().path() != "/upload" {
                return Err("actual upload request changed".into());
            }

            let mut body = request.into_body();
            // Only the original collector drives this I/O after arming.
            armed.store(true, Ordering::Release);
            let collected = collect_h2_request_body(&mut connection, &mut body).await;
            let remaining = poll_fn(|context| Poll::Ready(body.poll_data(context))).await;
            Ok(UploadObservation { collected, remaining })
        }));

        let stream = timeout(LIMIT, TcpStream::connect(address)).await??;
        let stream = stream.into_std()?;
        // Both descriptors refer to one connection; this owner can send a real FIN.
        self.writer = Some(stream.try_clone()?);
        let stream = TcpStream::from_std(stream)?;
        let (sender, connection) = timeout(
            LIMIT,
            ::http2::client::Builder::new().handshake::<_, Bytes>(stream),
        )
        .await??;
        self.driver = Some(ConnectionPeer::spawn(async move {
            connection.await?;
            Ok(())
        }));
        self.sender = Some(timeout(LIMIT, sender.ready()).await??);

        let request = Request::builder()
            .method(Method::POST)
            .uri("http://upload.test/upload")
            .body(())?;
        let (response, upload) = self
            .sender
            .as_mut()
            .ok_or("upload sender missing")?
            .send_request(request, false)?;
        self.response = Some(response);
        self.upload = Some(upload);
        timeout(LIMIT, self.pending.wait_for(|pending| *pending)).await??;
        Ok(())
    }

    async fn observation(&mut self) -> TestResult<UploadObservation> {
        let server = self.server.as_mut().ok_or("upload server missing")?;
        let joined = timeout(LIMIT, server).await?;
        self.server.take();
        joined?
    }

    async fn stop(&mut self) -> TestResult<()> {
        let server_requested = self.server.as_ref().is_some_and(|server| !server.is_finished());
        if let Some(server) = &self.server
            && server_requested
        {
            server.abort();
        }
        if let Some(driver) = &self.driver {
            driver.abort();
        }

        let server = match self.server.take() {
            Some(mut server) => match timeout(LIMIT, &mut server).await {
                Ok(Ok(Ok(observation))) => match observation.collected {
                    Err(error) => Err(error),
                    Ok(_) => match observation.remaining {
                        Poll::Ready(Some(Err(error))) => Err(error.into()),
                        _ => Ok(()),
                    },
                },
                Ok(Ok(Err(error))) => Err(error),
                Ok(Err(error)) if server_requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None => Ok(()),
        };
        let driver = match self.driver.take() {
            Some(driver) => driver.stop().await,
            None => Ok(()),
        };
        self.response.take();
        self.upload.take();
        self.sender.take();
        self.writer.take();
        finish_with_cleanup(server, driver)
    }
}

impl Default for Exchange {
    fn default() -> Self {
        let (_, pending) = watch::channel(false);
        let (_, eof) = watch::channel(false);
        Self {
            server: None,
            driver: None,
            sender: None,
            upload: None,
            response: None,
            writer: None,
            pending,
            eof,
        }
    }
}

#[tokio::test]
async fn complete_upload_retains_its_literal_body_and_normal_stream_end() -> TestResult<()> {
    let mut exchange = Exchange::default();
    let primary = async {
        exchange.start().await?;
        exchange
            .upload
            .as_mut()
            .ok_or("upload stream missing")?
            .send_data(Bytes::from_static(PAYLOAD), true)?;
        let observation = exchange.observation().await?;
        let body = observation.collected?;
        if body.as_ref() != PAYLOAD {
            return Err("complete upload body changed".into());
        }
        if !matches!(observation.remaining, Poll::Ready(None)) {
            return Err("complete upload did not reach normal stream end".into());
        }
        Ok(())
    }
    .await;

    let cleanup = exchange.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn incomplete_upload_retains_its_stream_error_after_actual_tcp_eof() -> TestResult<()> {
    let mut exchange = Exchange::default();
    let primary = async {
        exchange.start().await?;
        exchange
            .writer
            .as_ref()
            .ok_or("client socket missing")?
            .shutdown(Shutdown::Write)?;
        timeout(LIMIT, exchange.eof.wait_for(|eof| *eof)).await??;
        let UploadObservation { collected, remaining } = exchange.observation().await?;
        let stream_error = match remaining {
            Poll::Ready(Some(Err(error))) => error,
            _ => {
                return finish_with_cleanup(
                    collected.map(|_| ()),
                    Err("actual stream did not retain the incomplete-upload error".into()),
                );
            }
        };
        if stream_error.get_io().map(io::Error::kind) != Some(io::ErrorKind::BrokenPipe) {
            return finish_with_cleanup(collected.map(|_| ()), Err(stream_error.into()));
        }

        let collected_error = match collected {
            Err(error) => error,
            Ok(_) => {
                return Err("collector discarded the original incomplete-upload stream error".into());
            }
        };
        let Some(collected_error_view) = collected_error.downcast_ref::<::http2::Error>() else {
            return Err(collected_error);
        };
        if collected_error_view.get_io().map(io::Error::kind) != Some(io::ErrorKind::BrokenPipe)
            || collected_error_view.to_string() != stream_error.to_string()
        {
            return finish_with_cleanup(Err(collected_error), Err(stream_error.into()));
        }
        Ok(())
    }
    .await;

    let cleanup = exchange.stop().await;
    finish_with_cleanup(primary, cleanup)
}
