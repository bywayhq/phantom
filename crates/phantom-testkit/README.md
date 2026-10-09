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

## Other captures

- TLS records and decoded handshake summaries: `phantom_testkit::tls`
- HTTP/2 prefaces and ordered initial frames: `phantom_testkit::http2`
- Scripted DNS queries: `phantom_testkit::dns`
- Loopback TCP and UDP helpers: `phantom_testkit::tcp` and `phantom_testkit::udp`

## Next

- [HTTP/1 fixture provenance](https://github.com/bywayhq/phantom/blob/main/crates/phantom-testkit/fixtures/http1/README.md): original capture
  locations and hashes.
- [API reference](https://docs.rs/phantom-testkit): capture types and errors.
