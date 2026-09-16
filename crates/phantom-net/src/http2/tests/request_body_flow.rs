use std::{
    future::poll_fn,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_macos_http2;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
    time::timeout,
};

use super::{PEER_TEST_TIMEOUT, TestResult, bounded_peer_test};
use crate::http2::{Http2Connection, OriginForm};

const BODY_LEN: usize = 70_000;
const CONNECTION_WINDOW: usize = 65_535;
const REMAINDER: usize = BODY_LEN - CONNECTION_WINDOW;
const CLIENT_PREFACE_LEN: usize = 24;
const PHASE_STALL: Duration = Duration::from_millis(40);
const MAX_CAPTURE_BYTES: usize = 128 * 1024;

#[tokio::test]
async fn reaper_request_body_obeys_ordered_flow_control_and_reuses_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(256 * 1024);
        let (finish_tx, finish_rx) = oneshot::channel();
        let peer = tokio::spawn(run_flow_control_peer(server, finish_rx));
        let connection = Http2Connection::connect(client, &v152_macos_http2()).await?;

        let root = connection
            .send_get("example.test", OriginForm::parse("/")?, Vec::new())
            .await?;
        assert_eq!(root.status(), 204);
        assert!(root.into_body().collect().await?.to_bytes().is_empty());

        let response = connection
            .send_request(
                Method::POST,
                "example.test",
                OriginForm::parse("/.well-known/reaper/flow")?,
                Vec::new(),
                Some(Bytes::from(vec![b'R'; BODY_LEN])),
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let followup = connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-flow-control")?,
                Vec::new(),
            )
            .await?;
        assert_eq!(followup.status(), 204);
        assert!(followup.into_body().collect().await?.to_bytes().is_empty());
        assert!(!connection.is_closed());

        finish_tx
            .send(())
            .map_err(|_| "flow-control peer stopped before reuse was confirmed")?;
        drop(connection);
        let report = peer.await??;
        assert_eq!(report.pre_release_bytes, 0);
        assert_eq!(report.stream_phase_bytes, CONNECTION_WINDOW);
        assert_eq!(report.connection_phase_bytes, REMAINDER);
        assert_eq!(
            report.data_frame_lengths,
            [16_384, 16_384, 16_384, 16_383, 4_465]
        );
        assert_eq!(report.end_stream_flags, [false, false, false, false, true]);
        assert!(report.settings_ack_preceded_data);
        Ok(())
    })
    .await
}

async fn run_flow_control_peer(
    stream: DuplexStream,
    finish: oneshot::Receiver<()>,
) -> TestResult<FlowReport> {
    let capture = ClientCapture::default();
    let io = CapturingIo {
        inner: stream,
        capture: capture.clone(),
    };
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake(io).await?;

    let (root, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the root request")??;
    assert_eq!(root.method(), Method::GET);
    assert_eq!(root.uri().path(), "/");
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (request, mut respond) = timeout(PEER_TEST_TIMEOUT, connection.accept())
        .await
        .map_err(|_| "flow-control request headers timed out")?
        .ok_or("connection closed before the flow-control request")??;
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/.well-known/reaper/flow");
    assert_eq!(
        request
            .headers()
            .get("content-length")
            .map(http::HeaderValue::as_bytes),
        Some(b"70000".as_slice())
    );
    let mut body = request.into_body();

    let before = next_body_chunk(&mut connection, &mut body, PHASE_STALL).await?;
    let pre_release_bytes = before.as_ref().map_or(0, Bytes::len);
    assert_eq!(pre_release_bytes, 0);
    assert!(settings_ack_preceded_data(&capture.snapshot()));

    connection.set_initial_window_size(BODY_LEN as u32)?;
    let mut stream_phase_bytes = 0;
    while stream_phase_bytes < CONNECTION_WINDOW {
        let chunk = next_body_chunk(&mut connection, &mut body, PEER_TEST_TIMEOUT)
            .await?
            .ok_or("request body stalled before exhausting the connection window")?;
        assert!(chunk.iter().all(|byte| *byte == b'R'));
        stream_phase_bytes += chunk.len();
        if stream_phase_bytes > CONNECTION_WINDOW {
            return Err("request body exceeded the connection window before release".into());
        }
    }
    assert!(!body.is_end_stream());
    assert!(
        next_body_chunk(&mut connection, &mut body, PHASE_STALL)
            .await?
            .is_none()
    );

    body.flow_control().release_capacity(stream_phase_bytes)?;
    let mut connection_phase_bytes = 0;
    while !body.is_end_stream() {
        let chunk = next_body_chunk(&mut connection, &mut body, PEER_TEST_TIMEOUT)
            .await?
            .ok_or("request body ended before END_STREAM")?;
        assert!(chunk.iter().all(|byte| *byte == b'R'));
        connection_phase_bytes += chunk.len();
        body.flow_control().release_capacity(chunk.len())?;
    }
    assert_eq!(connection_phase_bytes, REMAINDER);
    respond.send_response(Response::builder().status(204).body(())?, true)?;

    let (followup, mut respond) = timeout(PEER_TEST_TIMEOUT, connection.accept())
        .await
        .map_err(|_| "follow-up request timed out")?
        .ok_or("connection closed before the follow-up request")??;
    assert_eq!(followup.method(), Method::GET);
    assert_eq!(followup.uri().path(), "/after-flow-control");
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    tokio::select! {
        result = finish => {
            result.map_err(|_| "client stopped before confirming connection reuse")?;
        }
        result = poll_fn(|context| connection.poll_closed(context)) => {
            result?;
            return Err("connection closed before the client confirmed reuse".into());
        }
    }

    let frames = data_frames(&capture.snapshot(), 3)?;
    Ok(FlowReport {
        pre_release_bytes,
        stream_phase_bytes,
        connection_phase_bytes,
        data_frame_lengths: frames.iter().map(|frame| frame.length).collect(),
        end_stream_flags: frames.iter().map(|frame| frame.end_stream).collect(),
        settings_ack_preceded_data: settings_ack_preceded_data(&capture.snapshot()),
    })
}

async fn next_body_chunk<T>(
    connection: &mut ::http2::server::Connection<T, Bytes>,
    body: &mut ::http2::RecvStream,
    wait: Duration,
) -> TestResult<Option<Bytes>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match timeout(
        wait,
        poll_fn(|context| {
            if let Poll::Ready(item) = body.poll_data(context) {
                return Poll::Ready(item);
            }
            match connection.poll_closed(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Ready(Ok(())) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await
    {
        Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
        Ok(Some(Err(error))) => Err(error.into()),
        Ok(None) | Err(_) => Ok(None),
    }
}

#[derive(Clone, Default)]
struct ClientCapture(Arc<Mutex<Vec<u8>>>);

impl ClientCapture {
    fn push(&self, bytes: &[u8]) {
        let mut capture = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(capture.len());
        capture.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

struct CapturingIo<T> {
    inner: T,
    capture: ClientCapture,
}

impl<T: AsyncRead + Unpin> AsyncRead for CapturingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &result {
            self.capture.push(&buffer.filled()[before..]);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CapturingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct FlowReport {
    pre_release_bytes: usize,
    stream_phase_bytes: usize,
    connection_phase_bytes: usize,
    data_frame_lengths: Vec<usize>,
    end_stream_flags: Vec<bool>,
    settings_ack_preceded_data: bool,
}

struct DataFrame {
    length: usize,
    end_stream: bool,
}

fn settings_ack_preceded_data(capture: &[u8]) -> bool {
    let mut cursor = CLIENT_PREFACE_LEN;
    while let Some((frame, next)) = parse_frame(capture, cursor) {
        if frame.frame_type == 0x04 && frame.flags & 0x01 != 0 && frame.stream_id == 0 {
            return frame.length == 0;
        }
        if frame.frame_type == 0x00 && frame.length != 0 {
            return false;
        }
        cursor = next;
    }
    false
}

fn data_frames(capture: &[u8], stream_id: u32) -> TestResult<Vec<DataFrame>> {
    let mut cursor = CLIENT_PREFACE_LEN;
    let mut frames = Vec::new();
    while let Some((frame, next)) = parse_frame(capture, cursor) {
        if frame.frame_type == 0x00 && frame.stream_id == stream_id {
            frames.push(DataFrame {
                length: frame.length,
                end_stream: frame.flags & 0x01 != 0,
            });
        }
        cursor = next;
    }
    if frames.is_empty() {
        return Err("capture contained no request DATA frames".into());
    }
    Ok(frames)
}

struct ParsedFrame {
    length: usize,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
}

fn parse_frame(capture: &[u8], cursor: usize) -> Option<(ParsedFrame, usize)> {
    let header = capture.get(cursor..cursor.checked_add(9)?)?;
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let next = cursor.checked_add(9)?.checked_add(length)?;
    capture.get(cursor..next)?;
    Some((
        ParsedFrame {
            length,
            frame_type: header[3],
            flags: header[4],
            stream_id: u32::from_be_bytes(header[5..9].try_into().ok()?) & 0x7fff_ffff,
        },
        next,
    ))
}
