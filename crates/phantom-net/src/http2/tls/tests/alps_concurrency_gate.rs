use std::{
    error::Error,
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot,
    time::timeout,
};

use super::{
    RawFrame, TEST_SERVER_NAME, TestIdentity, TestResult, accept_alps, alps_acceptor,
    alps_test_connector, bounded_tls_test, loopback_listener, read_raw_frame, request_and_collect,
    write_raw_frame,
};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const QUIET_WINDOW: Duration = Duration::from_millis(100);
const ALPS_THREE_PROFILE_FINAL_ZERO: &[u8] = &[
    0x00, 0x00, 0x6c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // SETTINGS frame
    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
    0x00, 0x03, 0x00, 0x00, 0x00, 0x80, // MAX_CONCURRENT_STREAMS = 128
    0x00, 0x04, 0x00, 0x00, 0xff, 0xff, // INITIAL_WINDOW_SIZE = 65535
    0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE = 16384
    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 262144
    0x00, 0x01, 0x00, 0x00, 0x20, 0x00, // HEADER_TABLE_SIZE = 8192
    0x00, 0x03, 0x00, 0x00, 0x01, 0x00, // MAX_CONCURRENT_STREAMS = 256
    0x00, 0x04, 0x00, 0x10, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 1048576
    0x00, 0x05, 0x00, 0x00, 0x80, 0x00, // MAX_FRAME_SIZE = 32768
    0x00, 0x06, 0x00, 0x08, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 524288
    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE = 4096
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, // MAX_CONCURRENT_STREAMS = 0
    0x00, 0x04, 0x00, 0x00, 0xff, 0xff, // INITIAL_WINDOW_SIZE = 65535
    0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // MAX_FRAME_SIZE = 16384
    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 262144
    0x00, 0x08, 0x00, 0x00, 0x00, 0x00, // ENABLE_CONNECT_PROTOCOL = 0
    0x00, 0x09, 0x00, 0x00, 0x00, 0x00, // NO_RFC7540_PRIORITIES = 0
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
];
const RELEASE_CONCURRENCY: &[u8] = &[
    0x00, 0x03, 0x00, 0x00, 0x00, 0x80, // MAX_CONCURRENT_STREAMS = 128
];

#[tokio::test]
async fn final_alps_zero_concurrency_holds_headers_until_wire_update_and_reuses_connection()
-> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = alps_acceptor(&identity)?;
        let (request_polled_tx, request_polled_rx) = oneshot::channel();
        let (reuse_checked_tx, reuse_checked_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_alps(listener, acceptor, ALPS_THREE_PROFILE_FINAL_ZERO).await?;
            let mut preface = [0_u8; CLIENT_PREFACE.len()];
            stream.read_exact(&mut preface).await?;
            assert_eq!(preface.as_slice(), CLIENT_PREFACE);
            read_and_ack_client_startup(&mut stream).await?;

            request_polled_rx.await?;
            match timeout(QUIET_WINDOW, stream.read_u8()).await {
                Err(_) => {}
                Ok(Ok(byte)) => {
                    return Err(format!(
                        "client emitted HTTP/2 byte {byte:#04x} while ALPS allowed zero streams"
                    )
                    .into());
                }
                Ok(Err(error)) => return Err(error.into()),
            }

            write_raw_frame(&mut stream, 0x04, 0x00, 0, RELEASE_CONCURRENCY).await?;
            stream.flush().await?;
            let (first, settings_acks) = read_request_headers(&mut stream).await?;
            assert_eq!(first.stream_id, 1);
            assert_eq!(settings_acks, 1, "wire SETTINGS was not acknowledged");
            write_no_content_response(&mut stream, first.stream_id).await?;

            let (second, settings_acks) = read_request_headers(&mut stream).await?;
            assert_eq!(second.stream_id, 3);
            assert_eq!(settings_acks, 0, "wire SETTINGS was acknowledged twice");
            write_no_content_response(&mut stream, second.stream_id).await?;

            reuse_checked_rx.await?;
            Ok::<_, Box<dyn Error + Send + Sync>>([first.stream_id, second.stream_id])
        });

        let connector = alps_test_connector(&identity)?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let connection = connector.connect(tcp, TEST_SERVER_NAME).await?;
        let mut first = Box::pin(request_and_collect(&connection, "/first", vec![]));
        let first_poll = poll_fn(|context| Poll::Ready(first.as_mut().poll(context))).await;
        assert!(
            first_poll.is_pending(),
            "first request completed during its initial poll"
        );
        request_polled_tx
            .send(())
            .map_err(|_| "server stopped before the blocked request was observed")?;
        first.await?;

        request_and_collect(&connection, "/second", vec![]).await?;
        assert!(!connection.is_closed());
        reuse_checked_tx
            .send(())
            .map_err(|_| "server stopped before connection reuse was checked")?;
        drop(connection);
        assert_eq!(server.await??, [1, 3]);
        Ok(())
    })
    .await
}

async fn read_and_ack_client_startup<S>(stream: &mut S) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut saw_settings = false;
    let mut saw_connection_window = false;
    while !saw_settings || !saw_connection_window {
        let frame = read_raw_frame(stream).await?;
        match frame.kind {
            0x04 if frame.flags == 0 && frame.stream_id == 0 && !saw_settings => {
                saw_settings = true;
                write_raw_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            0x08 if frame.flags == 0 && frame.stream_id == 0 && !saw_connection_window => {
                if frame.payload.len() != 4 {
                    return Err("client emitted a malformed connection WINDOW_UPDATE".into());
                }
                saw_connection_window = true;
            }
            0x01 => {
                return Err(
                    "client emitted request HEADERS before startup frames completed".into(),
                );
            }
            _ => return Err("client emitted an unexpected HTTP/2 startup frame".into()),
        }
    }
    Ok(())
}

async fn read_request_headers<S>(stream: &mut S) -> TestResult<(RawFrame, usize)>
where
    S: AsyncRead + Unpin,
{
    let mut settings_acks = 0;
    loop {
        let frame = read_raw_frame(stream).await?;
        match frame.kind {
            0x04 if frame.flags == 0x01 && frame.stream_id == 0 && frame.payload.is_empty() => {
                settings_acks += 1;
            }
            0x01 if frame.flags & 0x04 != 0 => return Ok((frame, settings_acks)),
            0x01 => return Err("request HEADERS omitted END_HEADERS".into()),
            _ => return Err("client emitted an unexpected frame while opening a request".into()),
        }
    }
}

async fn write_no_content_response<S>(stream: &mut S, stream_id: u32) -> TestResult<()>
where
    S: AsyncWrite + Unpin,
{
    write_raw_frame(stream, 0x01, 0x05, stream_id, &[0x89]).await?;
    stream.flush().await?;
    Ok(())
}
