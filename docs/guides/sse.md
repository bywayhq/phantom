# Server-sent events

Server-sent events (SSE) are a stream of text events sent over one long-lived
HTTP response. They are the protocol behind the browser `EventSource` API.
The optional `sse` feature adds two APIs on top of Phantom's streaming
response body:

- `SseStream` decodes events from one response. You pull each event.
- `Client::event_source` also reconnects when the stream ends or fails, within
  limits you set.

Neither API creates a background task, channel, or event queue: nothing runs
unless you read from it. Default limits are listed in
[Defaults and limits](../reference/limits.md#server-sent-events).

## Reading a response

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

## Reconnecting with an event source

Use `Client::event_source` when you want the stream to resume after a
disconnect, as a browser's `EventSource` does:

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

[Reconnect behavior](#reconnect-behavior) describes what the event source
carries across reconnects and when it gives up.

## Request fields

The event source sends these fields in order by default:

- `Accept: text/event-stream`
- `Cache-Control: no-cache`

Names are lowercase for HTTP/2 and HTTP/3. You can change the list two ways:

- `header` appends one literal field.
- `headers` replaces the whole list with `SseHeader` entries, so you can
  reproduce another request shape exactly.

When reconnecting, the event source sends `Last-Event-ID`, the ID of the last
event it received. `SseHeader::last_event_id` marks where that field goes and
how its name is spelled:

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

Placeholder rules:

- The placeholder emits the current event ID at its position, and nothing
  while the ID is empty.
- A list may hold at most one placeholder. Its name must spell
  `Last-Event-ID` in any case, or in lowercase for HTTP/2 and HTTP/3.
- Without a placeholder, a nonempty ID is appended after every other field.
- `connect` rejects a literal `Last-Event-ID` field or an invalid placeholder
  with `SseErrorKind::InvalidRequestHeader` before any I/O. This keeps a
  reconnect from sending the field twice.

## Decoding and limits

Decoding follows the WHATWG event-stream rules for UTF-8 replacement, a
leading byte-order mark, CR, LF, and CRLF line endings, comments, fields,
persistent event IDs, and retry durations. An event missing its terminating
blank line is discarded at the end of the body.

The default limits are 64 KiB per line and 1 MiB per event. Set both with
`SseLimits` before decoding begins. Exceeding a limit, or a failure in the
underlying response body, returns a typed `SseError` and releases the body at
once.

## Reconnect behavior

### Cancellation

Both `next_event` methods are cancellation-safe: you can drop a pending call,
for example in `tokio::select!`, without losing data.

- `SseStream` keeps partial decoder state for the next call. It reads a
  single response and never reconnects.
- `SseEventSource` keeps a scheduled reconnect deadline, including an active
  idle deadline, across a cancelled read. An in-flight reconnect request is
  kept for the next read.

### What carries across reconnects

The event source carries the last committed `id` and `retry` values from one
response to the next. It sends one `Last-Event-ID` field when the ID is
nonempty. Reconnects use the same exact protocol, client cookies, redirect
policy, ordered caller fields, and route.

A `204` response stops the source permanently.

### Which failures are retried

Initial transport failures, later disconnects, and idle timeouts all draw on
the same finite reconnect budget. The event source retries only resolution,
connection, proxy, capacity, timeout, TLS, and protocol failures.

Input, policy, route, and runtime failures return `SseErrorKind::Request` at
once, because the same request would fail the same way. So does a committed
event ID that cannot be sent as a `Last-Event-ID` field value; the source
ends before sending another request.

### Delays

| Setting | Default | Effect |
| --- | --- | --- |
| `initial_retry` | 3 seconds | Delay before a reconnect until the server sends `retry`. |
| `max_reconnects` | 3 | Number of reconnect requests allowed. |
| `min_retry` | Unset | Floor for every delay. |

With `min_retry` unset, every valid server `retry` value is used exactly.
When set, any shorter delay is raised to it: the initial delay, a server
value, or the wait before retrying the initial request.
`SseEventSource::retry_delay` reports the raised value.

The event source adds no reconnect jitter.

### Timeouts

`SseRequestBuilder::request_timeouts` replaces the client's ordinary request
timeouts for every initial or reconnect attempt. Pool-admission, connection,
and response-head limits apply to each attempt separately. The general
read-idle and total timers stop once an event-stream response is
established, because an SSE stream is meant to outlive an ordinary request.

The event source's own idle timeout is off by default. When set, it starts
when a response is accepted and resets on every HTTP DATA frame, including
comments, partial events, and empty frames. When it fires, the response is
released and the source reconnects if the budget allows.

### Errors when the budget runs out

- `SseErrorKind::IdleTimeout`: the idle timeout fired with no reconnect
  left.
- `SseErrorKind::ReconnectLimit`: the budget ran out after transport
  failures or an ordinary end of body.

The controller does not decode compressed content or model browser renderer
events.

## Differences from captured browsers

[SSE browser reconnect evidence](../explanation/validation.md#sse-browser-reconnect-evidence)
compares this controller with Chrome 153 and Firefox 156 over HTTP/1.1.

The `id`, `retry`, termination, cookie, and no-jitter behavior match both
browsers. The three-second default delay matches Chrome. `min_retry` and a
placeholder list reproduce the Firefox clamp and either browser's
`Last-Event-ID` position. `crates/phantom/tests/sse_browser_reconnect.rs`
replays the retained captures against those settings.

The remaining differences:

| Behavior | Phantom | Browsers | To match |
| --- | --- | --- | --- |
| Reconnect budget | Stops after a finite, configurable count. | Reconnected every time. The captures show at most three reconnects, so they do not show whether a browser limit exists. | Raise `max_reconnects`. |
| Idle timeout | Optional, off by default. | Kept an idle stream open. | Leave it off. |
| `Last-Event-ID` position | Without a placeholder, after every caller field. | Chrome sends it 9th of 16 fields; Firefox 5th of 14. | `SseHeader::last_event_id` |
| `Cookie` position | After every caller field by default, where Chrome sends it. | Firefox sends it after `Referer` and before `Sec-Fetch-Dest`. | A profile with `firefox::v156_cookie_placement`; see [Cookie field position](connections-and-state.md#cookie-field-position). |
| Small `retry` values | Honors any value, as Chrome does. | Firefox raises values below 500 ms. | `min_retry(500 ms)` |
| Redirected streams | Reconnects to the original URL and follows the redirect policy again, as Firefox does. | Chrome reconnects to the redirected URL. | No setting. |
| Default fields | `Accept` and `Cache-Control`. | Both also send `Pragma: no-cache` and their navigation-context fields. | Supply them in order with `SseRequestBuilder::headers`. |

### Network errors before a response

Phantom's event source waits the retry delay after every failed attempt, as
Chrome's does. The browsers also made some immediate requests, but those are
resends inside the HTTP stack, within one EventSource request, not
EventSource reconnects:

- Chrome resends once after a reused keep-alive connection closes before a
  response.
- Firefox also restarts the transaction on fresh connections.

By default, Phantom's HTTP/1 layer does not resend after such a close, so the
next request waits the retry delay.
`RetryPolicy::with_reused_connection_replay` opts into one resend.
