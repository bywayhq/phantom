# Retries and replays

Decide when Phantom sends a request again: after a connection fails to open,
after a connection closes under it, or after a status such as 503.

> Read [Using the client](client.md) first.

Each kind of retry has its own setting and its own limit. Apart from the
HTTP/2 fallback, a retry keeps the request's protocol and route
([Design](../explanation/design.md#retries-and-replays)). Most kinds are off
until you turn them on.

| Retry | Repeats after | Default | Setting |
| --- | --- | --- | --- |
| Connection setup | A connection that failed to open | Off | `RetryPolicy::connection_failures` |
| `GOAWAY` replay | A bodyless GET without trailers refused by `GOAWAY(NO_ERROR)` | On, once | None |
| PING resend | An HTTP/2 connection lost to an unanswered PING | 2 in Chromium recipes, 0 in Firefox | `Http2Settings::ping_failure_retries` |
| Reused connection | An idle HTTP/1.1 connection that closed | Off | `with_reused_connection_replay` |
| Unprocessed request | A request the server didn't process | Off | `with_unprocessed_replay` |
| Status | 408, 425, 429, 500, 502, 503 or 504 | Off | `with_status_retry` |
| HTTP/2 fallback | A failed HTTP/3 connection | Off | `with_http2_fallback` ([HTTP/3](http3.md#fall-back-to-http2-when-quic-fails)) |
| WebSocket setup | A WebSocket connect that failed to open | Off | `WebSocketRetryPolicy` ([WebSocket](websocket.md#retry-a-connect-that-fails-to-open)) |

Phantom also repeats a request once after a proxy asks for credentials
([Routes and proxies](routes-and-proxies.md#send-a-request-through-an-http-proxy)),
and repeats safe methods once when a server asks for missing client hints
([Send client hints](request-templates.md#send-client-hints)). A streaming
body can only be sent again if you
[buffer it](redirects.md#send-a-streaming-body-again).

## Retry when a connection fails to open

Retry DNS, TCP and QUIC failures that happen before anything is sent.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{ClientProfile, browser::chrome};
use phantom::{Client, RetryPolicy};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let retries = RetryPolicy::connection_failures(
        NonZeroUsize::new(3).expect("three is nonzero"),
        Duration::from_millis(200),
    );
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(chrome::v154_http2());
    Ok(Client::builder(profile).retry_policy(retries).build()?)
}
```

Phantom tries up to `maximum` more times and waits `delay` before each try.
Nothing from the request has been sent yet, so this is safe for every
method and body. A TLS error, or a proxy that refuses the request, isn't
retried.

`ResponseInfo::retries_performed` tells you how many of these retries ran.

## Replay a request after a reused connection closes

Send a request once more when an idle HTTP/1.1 connection closes as the
request goes out on it.

```rust
use phantom::RetryPolicy;

fn policy() -> RetryPolicy {
    RetryPolicy::none().with_reused_connection_replay(true)
}
```

Phantom sends the request again on a new connection when the old one closed
before any of the response arrived. It does this once, for GET, HEAD,
OPTIONS, TRACE, PUT and DELETE.

The first request may already have reached the server, which is why this is
off by default. Chrome retries in the same way.

## Replay a request the server did not process

Send an HTTP/2 or HTTP/3 request again when the server says it didn't
process it.

```rust
use std::num::NonZeroUsize;

use phantom::RetryPolicy;

fn policy() -> RetryPolicy {
    RetryPolicy::none().with_unprocessed_replay(NonZeroUsize::new(2))
}
```

The server says so by refusing the stream or by sending `GOAWAY` before it
handled the request. Since the server did nothing with it, Phantom replays
any method, on another connection and without delay.

## Retry when the server returns a retryable status

Repeat a request after a status such as 503 or 429, and wait as long as
`Retry-After` asks.

```rust
use std::{num::NonZeroUsize, time::Duration};

use http::StatusCode;
use phantom::{RetryPolicy, StatusRetry};

fn policy() -> Result<RetryPolicy, phantom::StatusRetryError> {
    let status_retry = StatusRetry::new(
        &[StatusCode::SERVICE_UNAVAILABLE, StatusCode::TOO_MANY_REQUESTS],
        NonZeroUsize::new(2).expect("two is nonzero"),
        Duration::from_millis(250),
    )?
    .honor_retry_after(Duration::from_secs(10));
    Ok(RetryPolicy::none().with_status_retry(status_retry))
}
```

`StatusRetry::new` takes the statuses, the number of retries and a fixed
delay. It accepts only 408, 425, 429, 500, 502, 503 and 504.

Only GET, HEAD, OPTIONS, TRACE, PUT and DELETE are retried. When the
retries run out, Phantom returns the last response.

`honor_retry_after(maximum)` waits as long as the server's `Retry-After`
asks, up to `maximum`. If the server asks for longer, Phantom returns the
response at once.

## Limits

- `RequestBuilder::retry_policy` replaces the client's whole policy for one
  request. It doesn't add to it.
- The `total` timeout covers every retry and delay.
- The PING resend in the Chromium recipes repeats any method, so a server
  can receive a buffered `POST` twice.

## Next

- [Design](../explanation/design.md#retries-and-replays): what each kind of
  retry keeps fixed, and why.
- [Routes and proxies](routes-and-proxies.md): choose the route every
  attempt uses.
- [Validation](../explanation/validation.md#connection-retry-evidence): the
  tests behind these rules.
