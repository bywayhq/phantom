use std::{
    io::Cursor,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use super::{CaptureError, CaptureLimits, TLS_PLAINTEXT_FRAGMENT_LIMIT, capture_client_hello};

const GENEROUS_LIMITS: CaptureLimits = CaptureLimits::new(64 * 1024, 128 * 1024, 16);

fn handshake(body: &[u8]) -> Vec<u8> {
    let length = body.len();
    assert!(length <= 0x00ff_ffff);
    let mut message = vec![
        1,
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ];
    message.extend_from_slice(body);
    message
}

fn record(content_type: u8, legacy_version: u16, fragment: &[u8]) -> Vec<u8> {
    let Ok(length) = u16::try_from(fragment.len()) else {
        panic!("test record length must fit in u16");
    };
    let mut record = vec![content_type];
    record.extend_from_slice(&legacy_version.to_be_bytes());
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(fragment);
    record
}

async fn capture(bytes: Vec<u8>) -> Result<super::ClientHelloCapture, CaptureError> {
    let mut reader = OneByteReader::new(bytes, usize::MAX);
    capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
    )
    .await
}

#[tokio::test]
async fn captures_single_record_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let hello = handshake(&[0x03, 0x03, 0xaa, 0xbb]);
    let wire = record(22, 0x0301, &hello);

    let captured = capture(wire.clone()).await?;

    assert_eq!(captured.handshake_bytes(), hello);
    assert_eq!(captured.records().len(), 1);
    assert_eq!(captured.records()[0].wire_bytes(), wire);
    assert_eq!(captured.records()[0].content_type(), 22);
    assert_eq!(captured.records()[0].fragment(), hello);
    Ok(())
}

#[tokio::test]
async fn summarizes_captured_client_hello() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x42; 32]);
    body.extend_from_slice(&[0]);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&[0, 7, 0, 43, 0, 3, 2, 0x03, 0x04]);
    let captured = capture(record(22, 0x0301, &handshake(&body))).await?;

    let summary = captured.summary()?;

    assert_eq!(summary.legacy_version(), 0x0303);
    assert_eq!(summary.cipher_suites(), &[0x1301]);
    assert_eq!(summary.extension_types(), &[43]);
    assert_eq!(summary.supported_versions(), &[0x0304]);
    Ok(())
}

#[tokio::test]
async fn reassembles_handshake_header_split_across_records()
-> Result<(), Box<dyn std::error::Error>> {
    let hello = handshake(&[1, 2, 3]);
    let first = record(22, 0x0301, &hello[..2]);
    let second = record(22, 0x0303, &hello[2..]);
    let mut wire = first.clone();
    wire.extend_from_slice(&second);

    let captured = capture(wire).await?;

    assert_eq!(captured.handshake_bytes(), hello);
    assert_eq!(captured.records()[0].wire_bytes(), first);
    assert_eq!(captured.records()[1].wire_bytes(), second);
    Ok(())
}

#[tokio::test]
async fn reassembles_multi_record_body_from_one_byte_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let hello = handshake(&[1, 2, 3, 4, 5, 6]);
    let first = record(22, 0x0301, &hello[..5]);
    let second = record(22, 0x0301, &hello[5..]);
    let mut wire = first.clone();
    wire.extend_from_slice(&second);
    let mut reader = OneByteReader::new(wire, 1);

    let captured = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
    )
    .await?;

    assert_eq!(captured.handshake_bytes(), hello);
    assert_eq!(captured.records()[0].wire_bytes(), first);
    assert_eq!(captured.records()[1].wire_bytes(), second);
    Ok(())
}

#[tokio::test]
async fn rejects_non_client_hello_first_handshake() {
    let wire = record(22, 0x0303, &[2, 0, 0, 0]);

    assert!(matches!(
        capture(wire).await,
        Err(CaptureError::UnexpectedHandshakeType { handshake_type: 2 })
    ));
}

#[tokio::test]
async fn rejects_non_handshake_record_interleaving() {
    let hello = handshake(&[1, 2, 3, 4]);
    let mut wire = record(22, 0x0303, &hello[..5]);
    wire.extend_from_slice(&record(23, 0x0303, &[9]));

    assert!(matches!(
        capture(wire).await,
        Err(CaptureError::NonHandshakeRecord { content_type: 23 })
    ));
}

#[tokio::test]
async fn rejects_empty_handshake_fragment() {
    let wire = record(22, 0x0303, &[]);

    assert!(matches!(
        capture(wire).await,
        Err(CaptureError::EmptyHandshakeFragment)
    ));
}

#[tokio::test]
async fn rejects_record_over_tls_plaintext_limit_before_reading_fragment() {
    let oversized = TLS_PLAINTEXT_FRAGMENT_LIMIT + 1;
    let Ok(length) = u16::try_from(oversized) else {
        panic!("TLSPlaintext limit must fit in u16");
    };
    let mut wire = vec![22, 0x03, 0x03];
    wire.extend_from_slice(&length.to_be_bytes());
    let mut reader = OneByteReader::new(wire, usize::MAX);

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::RecordTooLarge { length, maximum })
            if length == oversized && maximum == TLS_PLAINTEXT_FRAGMENT_LIMIT
    ));
}

#[tokio::test]
async fn enforces_declared_handshake_limit() {
    let wire = record(22, 0x0303, &[1, 0, 0, 8]);
    let mut reader = OneByteReader::new(wire, usize::MAX);

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(11, 100, 2),
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::HandshakeLimitExceeded {
            attempted: 12,
            maximum: 11
        })
    ));
}

#[tokio::test]
async fn enforces_wire_byte_limit_before_allocating_fragment() {
    let hello = handshake(&[1, 2]);
    let wire = record(22, 0x0303, &hello);
    let maximum = wire.len() - 1;
    let mut reader = OneByteReader::new(wire.clone(), usize::MAX);

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(100, maximum, 2),
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::WireLimitExceeded { attempted, maximum: found })
            if attempted == wire.len() && found == maximum
    ));
}

#[tokio::test]
async fn enforces_record_count_limit() {
    let hello = handshake(&[1, 2]);
    let mut wire = record(22, 0x0303, &hello[..4]);
    wire.extend_from_slice(&record(22, 0x0303, &hello[4..]));
    let mut reader = OneByteReader::new(wire, usize::MAX);

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_secs(1),
        CaptureLimits::new(100, 100, 1),
    )
    .await;

    assert!(matches!(
        result,
        Err(CaptureError::RecordLimitExceeded { maximum: 1 })
    ));
}

#[tokio::test]
async fn rejects_truncated_record_header_and_fragment() {
    for wire in [vec![22, 3], vec![22, 3, 3, 0, 4, 1, 0]] {
        assert!(matches!(
            capture(wire).await,
            Err(CaptureError::TruncatedInput)
        ));
    }
}

#[tokio::test]
async fn applies_one_deadline_to_the_whole_capture() {
    let (mut reader, _writer) = tokio::io::duplex(16);

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_millis(25),
        GENEROUS_LIMITS,
    )
    .await;

    assert!(matches!(result, Err(CaptureError::DeadlineExceeded)));
}

#[tokio::test]
async fn deadline_does_not_restart_when_reads_keep_making_progress() {
    let (mut reader, mut writer) = tokio::io::duplex(16);
    let wire = record(22, 0x0303, &handshake(&[1, 2, 3, 4]));
    let writes = Arc::new(AtomicUsize::new(0));
    let observed_writes = Arc::clone(&writes);
    let writer_task = tokio::spawn(async move {
        for byte in wire {
            if writer.write_all(&[byte]).await.is_err() {
                break;
            }
            observed_writes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let result = capture_client_hello(
        &mut reader,
        tokio::time::Instant::now() + Duration::from_millis(55),
        GENEROUS_LIMITS,
    )
    .await;
    writer_task.abort();
    let _ = writer_task.await;

    assert!(writes.load(Ordering::SeqCst) > 1);
    assert!(matches!(result, Err(CaptureError::DeadlineExceeded)));
}

#[tokio::test]
async fn rejects_bytes_after_client_hello_in_final_record() {
    let mut hello = handshake(&[1, 2]);
    hello.extend_from_slice(&[0xaa, 0xbb]);

    assert!(matches!(
        capture(record(22, 0x0303, &hello)).await,
        Err(CaptureError::TrailingBytes { count: 2 })
    ));
}

#[tokio::test]
async fn preserves_legacy_record_version() -> Result<(), Box<dyn std::error::Error>> {
    let captured = capture(record(22, 0x0301, &handshake(&[]))).await?;

    assert_eq!(captured.records()[0].legacy_version(), 0x0301);
    assert_eq!(&captured.records()[0].wire_bytes()[1..3], &[0x03, 0x01]);
    Ok(())
}

#[tokio::test]
async fn captures_from_loopback_tcp_stream() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let hello = handshake(&[0x03, 0x03, 1, 2, 3]);
    let wire = record(22, 0x0301, &hello);
    let sent = wire.clone();

    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream.write_all(&sent).await?;
        Ok::<_, std::io::Error>(())
    });
    let (mut stream, _) = listener.accept().await?;
    let captured = capture_client_hello(
        &mut stream,
        tokio::time::Instant::now() + Duration::from_secs(1),
        GENEROUS_LIMITS,
    )
    .await?;

    client.await??;
    assert_eq!(captured.handshake_bytes(), hello);
    assert_eq!(captured.records()[0].wire_bytes(), wire);
    Ok(())
}

struct OneByteReader {
    bytes: Cursor<Vec<u8>>,
    max_read: usize,
}

impl OneByteReader {
    fn new(bytes: Vec<u8>, max_read: usize) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            max_read,
        }
    }
}

impl AsyncRead for OneByteReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = usize::try_from(self.bytes.position()).unwrap_or(usize::MAX);
        let available = self.bytes.get_ref().len().saturating_sub(start);
        let count = available.min(buffer.remaining()).min(self.max_read);
        if count > 0 {
            buffer.put_slice(&self.bytes.get_ref()[start..start + count]);
            self.bytes.set_position((start + count) as u64);
        }
        Poll::Ready(Ok(()))
    }
}
