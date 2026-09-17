# Server-sent events

The optional `sse` feature adds a pull-based decoder and a session-owned,
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

Use `Session::event_source` when reconnect behavior is required:

```rust,no_run
use std::time::Duration;

use phantom::{Client, HttpProtocol};

# async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let response = client
    .session()
    .event_source(HttpProtocol::Http2, "https://example.com/events")?
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
read and retains an in-flight reconnect request for the next read. It carries
committed `id` and `retry` state across responses, adds one `Last-Event-ID`
field when the committed ID is nonempty, and stops permanently on 204. Initial
transport failures and later disconnects use the same finite attempt budget.
Reconnects use the same exact protocol, session cookies, redirect policy,
ordered caller fields, and route. A caller-supplied `Last-Event-ID` is rejected
so reconnects cannot emit duplicates.

The initial reconnect delay and finite reconnect count are explicit builder
settings; their defaults are three seconds and three reconnect requests.
Exhausting the budget returns `SseErrorKind::ReconnectLimit`. The controller
does not decode compressed content, impose an idle timeout, add jitter, or
model browser renderer events.
