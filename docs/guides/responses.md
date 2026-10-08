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
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

`OrderedResponseHeaders` keeps the server's order and any duplicates.
`ResponseInfo` also reports the protocol used and the number of retries.

The body arrives as the server sent it, compressed or not
([Content decoding](content-decoding.md)). `collect_with_limit` fails once
the body passes the limit, and drops any trailers.

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
        // The server refused the expectation. Send the request again
        // without it.
    }
    Ok(())
}
```

The body waits until the server answers `100 Continue` or the wait ends.
The wait counts toward the `response_head` and `total` timeouts. If the
server answers with a final status first, such as `401` or `417`, Phantom
returns it and never sends the body.

## Limits

- Dropping a body before you finish reading it can close an HTTP/1.1
  connection. On HTTP/2 and HTTP/3 it cancels only that request.

## Next

- [Troubleshooting](troubleshooting.md): each error kind, its cause, and the
  fix.
- [Content decoding](content-decoding.md): decode compressed bodies.
- [Retries and replays](retries.md): which failures Phantom repeats for you.
