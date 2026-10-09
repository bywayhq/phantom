# Phantom testkit

You can capture protocol bytes in a local test and compare an HTTP/1 request
with a retained browser request. Captures keep wire order and duplicate headers.

## Compare an HTTP/1 request

Select a recorded run and request, then compare the received head. The limits
bound the fixture document, request head, line lengths, and header count.

```rust
use phantom_testkit::http1::{
    CaptureLimits, RequestHeadCapture,
    expectation::{AdjustableHeader, RequestExpectation},
};

fn check_request(received: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/http1/chrome-154-windows-h1-accept.txt",
    ));
    let limits = CaptureLimits::new(32 * 1024, 8 * 1024, 128);
    let mut expected = RequestExpectation::from_retained(
        fixture, 0, 0, 64 * 1024, limits,
    )?;
    expected.replace_target(b"/ws.html?run=local-test")?;
    expected.replace_header_value(0, AdjustableHeader::Host, b" 127.0.0.1:12345")?;

    let actual = RequestHeadCapture::parse(received, limits)?;
    expected.compare(&actual)?;
    Ok(())
}
```

The selected request retains its browser name, exact build, platform, run,
request index, request kind, launch mode, and capture timestamp. The included
requests use headless browsers. A match covers that request head only. It does
not establish TLS, HTTP/2, HTTP/3, or server acceptance.

Adjustments are explicit. You can replace the target or one indexed Host or
User-Agent value. Header names and positions stay unchanged. Value bytes
include whitespace after the colon. Comparison does not drop Host, rewrite
headless User-Agent values, trim whitespace, or reorder headers.

Mismatch errors identify a request-line byte, header-name byte, header-value
byte, or header count. Error formatting omits request bytes.

## Capture a head from a stream

Use one deadline for the whole head. The reader stops at CRLFCRLF and leaves
the body in your stream. A buffered reader avoids a socket read for each byte.

```rust
use phantom_testkit::http1::{CaptureLimits, RequestHeadCapture, capture_request_head};
use tokio::{io::AsyncRead, time::{Duration, Instant}};

async fn read_request(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<RequestHeadCapture, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let limits = CaptureLimits::new(32 * 1024, 8 * 1024, 128);
    Ok(capture_request_head(reader, deadline, limits).await?)
}
```

A failed or cancelled capture may consume part of the head. Discard the
stream or restore a known boundary before using it again.

## Capture initial HTTP/2 frames

Choose the event that ends the capture. This example stops after the
client's initial SETTINGS and connection WINDOW_UPDATE.

```rust
use phantom_testkit::http2::{
    CaptureCompletion, CaptureLimits, ClientFrameCapture, capture_client_frames,
};
use tokio::{io::AsyncRead, time::{Duration, Instant}};

async fn read_http2(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<ClientFrameCapture, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let limits = CaptureLimits::new(16 * 1024, 64 * 1024, 16);
    Ok(capture_client_frames(
        reader, deadline, limits,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    ).await?)
}
```

The result keeps the exact preface and frame bytes, in wire order. Capture
validates SETTINGS and WINDOW_UPDATE. Other frame payloads stay undecoded.
Use `CapturedFrame::settings` or `window_update` to inspect a known frame.
They return `Ok(None)` for another frame type and an error for malformed
bytes of the requested type. Frames after completion remain unread.

## Capture and summarize a TLS handshake

Capture the records carrying the first ClientHello, then check its fields
with `summary`.

```rust
use phantom_testkit::tls::{CaptureLimits, ClientHelloSummary, capture_client_hello};
use tokio::{io::AsyncRead, time::{Duration, Instant}};

async fn read_client_hello(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<ClientHelloSummary, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let limits = CaptureLimits::new(64 * 1024, 128 * 1024, 16);
    let captured = capture_client_hello(reader, deadline, limits).await?;
    Ok(captured.summary()?)
}
```

Capture checks record and handshake framing. The summary checks inner
lengths and extensions and keeps their order. Later records remain unread.
Extra bytes after ClientHello within its final record return an error.
The summary describes the ClientHello, rather than completing a TLS handshake.

## Run asynchronous helpers

Poll deadline-based captures in a Tokio runtime with its timer enabled.
Socket readers and `DnsServer::spawn` also need runtime I/O. Delayed DNS
replies need the timer. A manually built runtime can enable both:

```rust
let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
# drop(runtime);
# Ok::<(), std::io::Error>(())
```

A missing runtime driver can panic. Read, syntax, bounds, and deadline
failures return typed errors. A failed or cancelled stream capture may
consume input. Discard the stream or restore a known boundary before reuse.

## Other captures

- TLS records and decoded handshake summaries: `phantom_testkit::tls`
- HTTP/2 prefaces and ordered initial frames: `phantom_testkit::http2`
- Scripted DNS queries: `phantom_testkit::dns`
- Loopback TCP and UDP helpers: `phantom_testkit::tcp` and `phantom_testkit::udp`

## Next

- [HTTP/1 fixture provenance](https://github.com/bywayhq/phantom/blob/main/crates/phantom-testkit/fixtures/http1/README.md): original capture
  locations and hashes.
- [API reference](https://docs.rs/phantom-testkit): capture types and errors.
