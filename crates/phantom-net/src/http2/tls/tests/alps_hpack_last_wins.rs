use std::error::Error;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot,
};

use super::{
    RawFrame, TEST_SERVER_NAME, TestIdentity, TestResult, accept_alps, alps_acceptor,
    alps_test_connector, bounded_tls_test, loopback_listener, read_raw_frame, request_and_collect,
    write_raw_frame,
};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FINAL_TABLE_SIZE_PREFIX: &[u8] = &[0x3f, 0xe1, 0x01];
const SEQUENTIAL_TABLE_SIZE_PREFIX: &[u8] = &[0x20, 0x3f, 0xe1, 0x01];
const TWO_HEADER_TABLE_SIZE_FRAMES: &[u8] = &[
    0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // SETTINGS frame
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // HEADER_TABLE_SIZE = 0
    0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // SETTINGS frame
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, // HEADER_TABLE_SIZE = 256
];

#[tokio::test]
async fn current_alps_codepoint_uses_last_table_size_without_wire_ack_and_reuses_connection()
-> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = alps_acceptor(&identity)?;
        let (reuse_checked_tx, reuse_checked_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_alps(listener, acceptor, TWO_HEADER_TABLE_SIZE_FRAMES).await?;
            let mut preface = [0_u8; CLIENT_PREFACE.len()];
            stream.read_exact(&mut preface).await?;
            assert_eq!(preface.as_slice(), CLIENT_PREFACE);

            let mut settings_acks = 0;
            let first = read_header_block(&mut stream, 1, &mut settings_acks).await?;
            assert!(
                first.starts_with(FINAL_TABLE_SIZE_PREFIX),
                "first HPACK block started with {:02x?}, expected {:02x?}",
                first.get(..FINAL_TABLE_SIZE_PREFIX.len()),
                FINAL_TABLE_SIZE_PREFIX,
            );
            assert!(
                !first.starts_with(SEQUENTIAL_TABLE_SIZE_PREFIX),
                "first HPACK block retained the superseded zero table size"
            );
            write_no_content_response(&mut stream, 1).await?;

            let second = read_header_block(&mut stream, 3, &mut settings_acks).await?;
            assert!(!second.is_empty(), "stream 3 carried an empty HPACK block");
            assert_eq!(settings_acks, 0, "negotiated ALPS was acknowledged");
            write_no_content_response(&mut stream, 3).await?;

            reuse_checked_rx.await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let connector = alps_test_connector(&identity)?;
        let tcp = tokio::net::TcpStream::connect(address).await?;
        let connection = connector.connect(tcp, TEST_SERVER_NAME).await?;
        request_and_collect(&connection, "/first", vec![]).await?;
        request_and_collect(&connection, "/second", vec![]).await?;
        assert!(!connection.is_closed());
        reuse_checked_tx
            .send(())
            .map_err(|_| "server stopped before connection reuse was checked")?;
        drop(connection);
        server.await??;
        Ok(())
    })
    .await
}

async fn read_header_block<S>(
    stream: &mut S,
    expected_stream_id: u32,
    settings_acks: &mut usize,
) -> TestResult<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let headers = loop {
        let frame = read_raw_frame(stream).await?;
        match frame.kind {
            0x04 if frame.flags & 0x01 != 0 => {
                if frame.stream_id != 0 || !frame.payload.is_empty() {
                    return Err("client emitted an invalid SETTINGS acknowledgement".into());
                }
                *settings_acks += 1;
            }
            0x04 => {
                if frame.stream_id != 0 || frame.payload.len() % 6 != 0 {
                    return Err("client emitted invalid initial SETTINGS".into());
                }
                write_raw_frame(stream, 0x04, 0x01, 0, &[]).await?;
                stream.flush().await?;
            }
            0x01 => break frame,
            _ => {}
        }
    };
    if headers.stream_id != expected_stream_id {
        return Err(format!(
            "received HEADERS on stream {}, expected stream {expected_stream_id}",
            headers.stream_id
        )
        .into());
    }

    let mut block = headers_fragment(&headers)?;
    if headers.flags & 0x04 != 0 {
        return Ok(block);
    }
    loop {
        let continuation = read_raw_frame(stream).await?;
        if continuation.kind != 0x09 || continuation.stream_id != expected_stream_id {
            return Err("HEADERS block was interrupted before END_HEADERS".into());
        }
        block.extend_from_slice(&continuation.payload);
        if continuation.flags & 0x04 != 0 {
            return Ok(block);
        }
    }
}

fn headers_fragment(frame: &RawFrame) -> TestResult<Vec<u8>> {
    let mut start = 0;
    let padding = if frame.flags & 0x08 != 0 {
        start = 1;
        usize::from(
            *frame
                .payload
                .first()
                .ok_or("padded HEADERS omitted the pad length")?,
        )
    } else {
        0
    };
    if frame.flags & 0x20 != 0 {
        start += 5;
    }
    let end = frame
        .payload
        .len()
        .checked_sub(padding)
        .ok_or("HEADERS padding exceeded its payload")?;
    if start > end {
        return Err("HEADERS metadata exceeded its payload".into());
    }
    Ok(frame.payload[start..end].to_vec())
}

async fn write_no_content_response<S>(stream: &mut S, stream_id: u32) -> TestResult<()>
where
    S: AsyncWrite + Unpin,
{
    write_raw_frame(stream, 0x01, 0x05, stream_id, &[0x89]).await?;
    stream.flush().await?;
    Ok(())
}
