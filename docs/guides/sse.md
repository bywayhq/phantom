# Server-sent events

Read a server-sent event (SSE) stream, the protocol behind the browser
`EventSource` API, and reconnect it the way a browser does. Both APIs need the
optional `sse` feature.

> For builders who have read [Getting started](../getting-started.md).

## Read an event stream

`SseStream` decodes events from one response and never reconnects:

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

`from_response` accepts a response only when it has:

- status 200;
- a `text/event-stream` content type (parameters such as `charset` are
  ignored); and
- no content encoding other than `identity`, even when the request enabled
  `ContentDecoding`.

Nothing runs unless you call `next_event`: there is no background task,
channel, or event queue. `next_event` is cancellation-safe, so you can drop a
pending call in `tokio::select!` without losing data.

## Reconnect with Last-Event-ID

`Client::event_source` resumes the stream after a disconnect, as a browser's
`EventSource` does:

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

- The source carries the last `id` and `retry` values across reconnects and
  sends `Last-Event-ID` when the ID is nonempty. Reconnects keep the same
  exact protocol, client cookies, redirect policy, ordered fields, and route.
- It waits `initial_retry` (default 3 seconds) before each reconnect until
  the server sends `retry`. It adds no jitter.
- Initial failures, disconnects, and idle timeouts share one budget of
  `max_reconnects` (default 3). Only resolution, connection, proxy,
  capacity, timeout, TLS, and protocol failures are retried. When the budget
  runs out, `next_event` returns `SseErrorKind::ReconnectLimit`, or
  `SseErrorKind::IdleTimeout` if the idle timeout fired last. Other failures,
  and a committed ID that is not a valid field value, return
  `SseErrorKind::Request` at once.
- A `204` response stops the source permanently.

## Place Last-Event-ID among your own fields

By default the source sends `Accept: text/event-stream` and
`Cache-Control: no-cache`, lowercase on HTTP/2 and HTTP/3. `header` appends
one field. `headers` replaces the list, and `SseHeader::last_event_id` marks
where the ID goes and how its name is spelled:

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

- The placeholder emits nothing while the ID is empty.
- A list holds at most one placeholder. Its name must spell `Last-Event-ID`
  in any case, or in lowercase for HTTP/2 and HTTP/3.
- Without a placeholder, a nonempty ID goes after every other field.
- `connect` rejects a literal `Last-Event-ID` field or an invalid placeholder
  with `SseErrorKind::InvalidRequestHeader` before any I/O.

## Reconnect like Chrome or Firefox

The default delays match Chrome 154. For Firefox 156, wait 5 seconds before
the first reconnect and raise short server `retry` values to 500 ms:

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

- `min_retry` raises every shorter delay: the initial delay, a server value,
  and the wait before retrying the initial request.
  `SseEventSource::retry_delay` reports the raised value.
- Browsers send `Pragma: no-cache` and their navigation-context fields too.
  Supply them in order with `headers`, and place `Last-Event-ID` where the
  browser does: 10th of 16 fields in Chrome, 6th of 14 in Firefox.
- `Cookie` goes after every caller field, where Chrome sends it. For
  Firefox's position, use a profile with `firefox::v156_cookie_placement`;
  see [Cookie field position](cookies.md#place-the-cookie-field-where-a-browser-does).

## Limits

- The browser comparison covers HTTP/1.1 captures only.
- Browsers reconnect without a limit; Phantom stops after `max_reconnects`.
  Raise it to keep reconnecting.
- The source's idle timeout is off by default, as in browsers. When set, it
  starts when a response is accepted and resets on every HTTP DATA frame,
  including comments and empty frames.
- `request_timeouts` on the event-source builder replaces the client's
  request timeouts for each attempt. The read-idle and total timers stop once
  a stream is established.
- A redirected stream reconnects to the original URL and follows the redirect
  policy again. No setting changes this;
  [Validation](../explanation/validation.md#sse-browser-reconnect-evidence)
  shows where Chrome differs.
- The source waits the retry delay after every failed attempt. After a reused
  HTTP/1 connection closes before a response,
  `RetryPolicy::with_reused_connection_replay` resends once without waiting.
- Decoding follows the WHATWG event-stream rules. An event without its
  terminating blank line is discarded at the end of the body.
- Lines over 64 KiB or events over 1 MiB fail with a typed `SseError` and
  release the body. Set other limits with `SseLimits`; see
  [Defaults and limits](../reference/limits.md#server-sent-events).
- The source does not decode compressed content or model browser renderer
  events.

## Next

- [SSE browser reconnect evidence](../explanation/validation.md#sse-browser-reconnect-evidence):
  the Chrome and Firefox captures behind these settings.
- [Retries and replays](retries.md): the retry policy the reconnect resend
  uses.
- [WebSocket](websocket.md): two-way messages instead of a server stream.
