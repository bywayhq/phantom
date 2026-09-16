# Server-sent events

The optional `sse` feature adds a pull-based decoder over Phantom's existing
streaming response body. It does not create another connection, background
task, channel, or event queue.

```rust,no_run
use phantom::{Client, HttpProtocol, SseStream};

# async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let response = client
    .get(HttpProtocol::Http2, "https://example.com/events")?
    .send()
    .await?;
let mut events = SseStream::from_response(response)?.into_body();

while let Some(event) = events.next_event().await? {
    println!("{}: {}", event.event(), event.data());
}
# Ok(())
# }
```

`from_response` requires status 200, a `text/event-stream` content-type
essence, and no content encoding other than `identity`. Decoding follows the
WHATWG event-stream rules for UTF-8 replacement, a leading byte-order mark,
CR/LF/CRLF line endings, comments, fields, persistent event IDs, and retry
durations. An event without its terminating blank line is discarded at end of
body.

The default limits are 64 KiB per line and 1 MiB across one event block.
`SseLimits` configures both before decoding begins. Exceeding either limit, or
an underlying response-body failure, returns a typed `SseError` and releases
the body immediately.

`next_event` is cancellation-safe and retains partial decoder state for the
next call. Dropping `SseStream` delegates cancellation to the underlying H1,
H2, or H3 body. The decoder does not reconnect, add `Last-Event-ID`, set
request headers, decode compressed content, or impose an idle timeout; those
belong to later request and session policy.
