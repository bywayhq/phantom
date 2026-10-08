# Server-sent events

Read a stream of server-sent events (SSE), or reconnect after it closes.
Enable the optional `sse` feature to use these APIs.

## Read an event stream

Use `SseStream` to read events from one response without reconnecting:

```rust
use phantom::{Client, HttpProtocol, SseStream};

async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/events")?
        .send()
        .await?;
    let mut events = SseStream::from_response(response)?.into_body();

    while let Some(event) = events.next_event().await? {
        println!("{}: {}", event.event(), event.data());
    }
    Ok(())
}
```

The response must have status 200 and content type `text/event-stream`.
It must be uncompressed, even if you enabled `ContentDecoding`.

Nothing runs between calls to `next_event`. You can cancel a pending call
in `tokio::select!` and read again without losing data.

## Reconnect with Last-Event-ID

Use `Client::event_source` to reconnect after a disconnect:

```rust
use std::time::Duration;

use phantom::{Client, HttpProtocol};

async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}
```

The source remembers the last `id` and sends it as `Last-Event-ID` when
nonempty. It waits `initial_retry` before reconnecting until the server
sends a valid `retry` value. The default delay is 3 seconds.

Each attempt uses your client's cookies, retry policy and redirect policy.
The route and requested protocol stay the same. An enabled HTTP/2 fallback
can send an HTTP/3 attempt over HTTP/2.

Initial failures, disconnects and idle timeouts share the `max_reconnects`
budget, which defaults to 3. A `204` response closes the source permanently.

## Place Last-Event-ID among your own fields

Use `SseHeader::last_event_id` to choose the ID header's position and spelling:

```rust
use phantom::{Client, HttpProtocol, RequestHeader, SseHeader};

async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .event_source(HttpProtocol::Http1, "https://example.com/events")?
        .headers(vec![
            SseHeader::field(RequestHeader::new("Accept", "text/event-stream")),
            SseHeader::last_event_id("Last-Event-ID"),
            SseHeader::field(RequestHeader::new("Pragma", "no-cache")),
            SseHeader::field(RequestHeader::new("Cache-Control", "no-cache")),
        ])
        .connect()
        .await?;
    let mut events = response.into_body();
    while let Some(event) = events.next_event().await? {
        println!("{}", event.data());
    }
    Ok(())
}
```

`headers` replaces the whole list, including the default
`Accept: text/event-stream` and `Cache-Control: no-cache` headers.
Use `header` to append one header instead.

Use one placeholder rather than a literal `Last-Event-ID` header.
Spell its name in lowercase for HTTP/2 and HTTP/3. It emits nothing while
the ID is empty. Without a placeholder, the ID goes after your other headers.

## Reconnect like Chrome or Firefox

For HTTP/1.1, the default delays match Chrome 154. To use Firefox 157's
delays, start at 5 seconds and raise shorter server values to 500 ms:

```rust
use std::time::Duration;

use phantom::{Client, HttpProtocol, SseEventSource};

async fn firefox_like(
    client: &Client,
) -> Result<SseEventSource, Box<dyn std::error::Error>> {
    let response = client
        .event_source(HttpProtocol::Http1, "https://example.com/events")?
        .initial_retry(Duration::from_secs(5))
        .min_retry(Duration::from_millis(500))
        .connect()
        .await?;
    Ok(response.into_body())
}
```

`min_retry` raises every shorter delay, including retries of the initial
request. `SseEventSource::retry_delay` returns the resulting delay.

Browsers also send `Pragma: no-cache` and other headers that describe the
page making the request. Supply those with `headers`. Chrome places
`Last-Event-ID` after `sec-ch-ua-mobile`. Firefox places it after
`Accept-Encoding`.

For Firefox's cookie position, use `firefox::v157_cookie_placement`
([Cookie field position](cookies.md#place-the-cookie-field-where-a-browser-does)).

## Limits

- Browsers reconnect without a limit. Phantom stops after `max_reconnects`.
  Raise the budget if you need more attempts.
- A redirected stream reconnects to the original URL and follows redirects
  again.
- Once connected, the source uses `idle_timeout` rather than the client's
  body and total timeouts. It defaults to off. Comments and empty DATA frames
  count as activity.
- An event needs a terminating blank line. Use `SseLimits` to change the
  line and event size limits
  ([Defaults and limits](../reference/limits.md#server-sent-events)).

## Next

- [SSE browser reconnect evidence](../explanation/validation.md#sse-browser-reconnect-evidence):
  Chrome and Firefox behavior and differences.
- [Retries and replays](retries.md): the retry policy the reconnect resend
  uses.
- [WebSocket](websocket.md): two-way messages instead of a server stream.
