# Responses and errors

Read a response's headers and body, find out what happened on the way, and
handle errors. You can also let a server turn down a large upload before
you send it.

> Read [Using the client](client.md) first.

## Read the response

Read the headers in the order the server sent them, see which URL answered,
and read the body with a size limit.

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
    let response = phantom::response_bytes(response, 1 << 20).await?;
    println!("{}: {} bytes", response.status(), response.body().len());
    Ok(())
}
```

`OrderedResponseHeaders` keeps the server's order and any duplicates.
`ResponseInfo` also reports the protocol and connection-setup retry count.

The body arrives as the server sent it, compressed or not
([Content decoding](content-decoding.md)). `response_bytes` keeps the
status, headers and extensions while collecting the body. It drops trailers.
`response_text` does the same and requires UTF-8. With the `json` feature,
`response_json::<YourType>` reads JSON into your type. Each takes an explicit
byte limit and fails when the decoded body passes it.

A read failure keeps the response metadata in `ResponseReadError::response`.
The incomplete body is dropped. For frame-by-frame reading, use
`ResponseBody` directly.

## Check an HTTP error status

A successful send can return an HTTP error status. Opt in to a status check
and recover its body when you need to read the server's explanation.

```rust
use phantom::{Client, HttpProtocol, error_for_status, response_text};

async fn read_error(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/")?
        .send().await?;
    let response = match error_for_status(response) {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    let response = response_text(response, 1 << 20).await?;
    println!("{}: {}", response.status(), response.body());
    Ok(())
}
```

The check rejects 4xx and 5xx statuses. It leaves the response body unread.

## Handle errors

Sort failures into categories you can act on.

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

`RequestErrorKind` may gain variants, so keep a fallback arm. Error messages
leave out credentials, cookies and request bodies.

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
        // The server refused the expectation. If the body was still
        // waiting, it wasn't sent. Decide whether to try without Expect.
    }
    Ok(())
}
```

The body waits until the server answers `100 Continue` or the wait ends.
The wait counts toward the `response_head` and `total` timeouts. If the
server sends a final status while the body still waits, such as `401` or
`417`, Phantom returns it without sending the body.

## Limits

- Dropping a body before you finish reading it can close an HTTP/1.1
  connection. On HTTP/2 and HTTP/3 it cancels only that request.

## Next

- [Troubleshooting](troubleshooting.md): each error kind, its cause, and the
  fix.
- [Content decoding](content-decoding.md): decode compressed bodies.
- [Retries and replays](retries.md): which failures Phantom repeats for you.
