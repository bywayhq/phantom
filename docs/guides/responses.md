# Responses and errors

Read a response's fields in wire order, find out what happened on the wire,
collect a bounded body, sort failures by kind, and let a server answer
before a body is sent.

> For builders who have read [Using the client](client.md).

## Read the response

Read the fields in wire order, what happened on the wire, and a bounded body.

```rust
use phantom::{Client, HttpProtocol, OrderedResponseHeaders, ResponseInfo};

async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    if let Some(fields) = response.extensions().get::<OrderedResponseHeaders>() {
        for field in fields.iter() {
            println!("{}: {:?}", field.name(), field.value());
        }
    }
    if let Some(info) = response.extensions().get::<ResponseInfo>() {
        println!("{} after {} redirects", info.effective_uri(), info.redirects_followed());
    }
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

- `OrderedResponseHeaders` keeps wire order and interleaved duplicates on
  every protocol, and name spelling on H1.
- `ResponseInfo` also reports `protocol`, `decoded_content_codings`, and
  `retries_performed`, which counts connection-setup retries only
  ([Retry when a connection fails to open](retries.md#retry-when-a-connection-fails-to-open)).
- `ResponseBody` is an `http_body::Body<Data = Bytes>` with backpressure,
  undecoded unless you opt in ([Content decoding](content-decoding.md)).
  `collect_with_limit` fails with `RequestErrorKind::ResponseBodyLimit` before
  keeping a chunk past the inclusive limit, and discards trailers.

## Handle errors

Sort failures into stable categories.

```rust
use phantom::{RequestError, RequestErrorKind};

fn classify(error: &RequestError) -> &'static str {
    match error.kind() {
        RequestErrorKind::Timeout => "timeout",
        RequestErrorKind::Capacity => "local capacity",
        RequestErrorKind::Proxy => "proxy",
        RequestErrorKind::Tls => "tls",
        _ => "request",
    }
}
```

- `BuildError::kind` and `RequestError::kind` return non-exhaustive enums;
  keep a fallback arm. Body errors use `RequestError` too, and
  `RequestError::protocol` and `timeout_phase` report what is known.
- Messages and debug output leave out credentials, cookies, payloads, and
  endpoints. To investigate further, use bounded tracing or diagnostics.

## Let the server answer before the body

Send `Expect: 100-continue` so a server can refuse a large body before any
of it is sent.

```rust
use std::time::Duration;

use phantom::{Client, HttpProtocol, Method};

async fn upload(client: &Client, file: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .request(HttpProtocol::Http1, Method::PUT, "https://example.com/upload")?
        .body(file)
        .expect_continue(Duration::from_secs(1))
        .send()
        .await?;
    if response.status().as_u16() == 417 {
        // Unless the wait had ended, the body was not sent; send the request
        // again without the expectation.
    }
    Ok(())
}
```

- The body waits until the server answers `100 Continue` or the wait ends,
  on every protocol and on every attempt, including a redirect that keeps
  the body. The wait counts toward the response head and total timeouts.
- Phantom appends `Expect: 100-continue` after every other field. A field
  of yours named `Expect` keeps its position and must be `100-continue`;
  another value fails before I/O with `RequestErrorKind::InvalidHeader`.
- A request without a body, or with a body of known length zero, sends no
  expectation. No recipe sends one
  ([evidence](../explanation/validation.md#revalidation-and-upload-evidence)).

## Limits

- Dropping an unfinished H1 body can close its connection; dropping an H2 or
  H3 body cancels its stream.
- A final response that arrives while the body still waits, such as `401`
  or `417`, is returned and the body is never sent; Phantom does not repeat
  the request. An H1 connection then closes, and an H2 or H3 stream is
  cancelled.

## Next

- [Troubleshooting](troubleshooting.md): each error kind, its cause, and the
  fix.
- [Content decoding](content-decoding.md): decode compressed bodies.
- [Retries and replays](retries.md): which failures Phantom repeats for you.
