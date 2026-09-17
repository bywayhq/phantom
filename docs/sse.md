# Server-sent events

The optional `sse` feature adds a pull-based decoder and a client-owned,
bounded reconnect controller over Phantom's existing streaming response body.
Neither API creates a background task, channel, or event queue.

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

Use `Client::event_source` when reconnect behavior is required:

```rust,no_run
use std::time::Duration;

use phantom::{Client, HttpProtocol};

# async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let response = client
    .event_source(HttpProtocol::Http2, "https://example.com/events")?
    .idle_timeout(Duration::from_secs(30))
    .initial_retry(Duration::from_secs(3))
    .max_reconnects(4)
    .connect()
    .await?;
let mut events = response.into_body();

while let Some(event) = events.next_event().await? {
    println!("{}: {}", event.event(), event.data());
}
# Ok(())
# }
```

The EventSource builder starts with ordered `Accept: text/event-stream` and
`Cache-Control: no-cache` fields, using lowercase names for HTTP/2 and HTTP/3.
`header` appends after those defaults. `headers` replaces the complete list so
callers can reproduce a different request shape exactly.

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

Both `next_event` methods are cancellation-safe. `SseStream` retains partial
decoder state for the next call and remains a single-response primitive.
`SseEventSource` preserves a scheduled reconnect deadline across a cancelled
read, including an active idle deadline, and retains an in-flight reconnect
request for the next read. It carries committed `id` and `retry` state across
responses, adds one `Last-Event-ID` field when the committed ID is nonempty,
and stops permanently on 204. Initial transport failures, later disconnects,
and idle responses use the same finite attempt budget. Reconnects use the same
exact protocol, client cookies, redirect policy, ordered caller fields, and
route. A caller-supplied `Last-Event-ID` is rejected so reconnects cannot emit
duplicates.

The initial reconnect delay and finite reconnect count are explicit builder
settings; their defaults are three seconds and three reconnect requests.
The optional idle timeout is disabled by default. It starts when a response is
accepted and resets on every HTTP DATA frame, including comments, partial
events, and empty frames. Reaching it releases the response and reconnects when
the budget permits; without a remaining attempt it returns
`SseErrorKind::IdleTimeout`. Exhausting the budget after transport failures or
ordinary end-of-body returns `SseErrorKind::ReconnectLimit`. The controller
does not decode compressed content, add reconnect jitter, or model browser
renderer events.
