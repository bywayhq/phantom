# Retries and replays

Choose when Phantom may send a request again: after a failed connection, a
closed or refusing connection, or a retryable status.

> For builders who have read [Using the client](client.md).

A retry can change what a server sees, so every retry keeps the request's
route and its [exact protocol](../reference/glossary.md#exact-protocol) or
negotiated selection rule, and each class has its own bound
([Design](../explanation/design.md#retries-and-replays)). Retries are your
policy, so no browser recipe includes them.

| Class | Default | Configure with | Applies when |
| --- | --- | --- | --- |
| Connection-setup retry | Off | `RetryPolicy::connection_failures` | Setup failed before any request byte was sent |
| Graceful `GOAWAY` replay | Always on | Not configurable | A bodyless H2 GET refused by `GOAWAY(NO_ERROR)` |
| Reused-connection replay | Off | `with_reused_connection_replay` | An H1 keep-alive connection closed before any response byte |
| Unprocessed-request replay | Off | `with_unprocessed_replay` | The H2 or H3 peer reported it did not process the request |
| Status retry | Off | `with_status_retry` | The status is 408, 425, 429, 500, 502, 503, or 504 |

Two more replays sit outside `RetryPolicy`: one after a proxy's Basic `407`
challenge ([Routes and proxies](routes-and-proxies.md#send-a-request-through-an-http-proxy))
and one `Critical-CH` retry when the profile has client hints
([Send client hints](request-templates.md#send-client-hints)).

## Retry when a connection fails to open

Retry DNS, TCP, and QUIC setup failures that happen before anything is sent.

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, RetryPolicy};

fn build() -> Result<Client, Box<dyn std::error::Error>> {
    let retries = RetryPolicy::connection_failures(
        NonZeroUsize::new(3).expect("three is nonzero"),
        Duration::from_millis(200),
    );
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2());
    Ok(Client::builder(profile).retry_policy(retries).build()?)
}
```

- It retries up to `maximum` times, waiting `delay` before each attempt, for
  exact H1, H2, and H3 and for negotiated requests. No request bytes are
  replayed, so it is safe for every method and for streaming bodies.
- A failure qualifies only when its typed error proves nothing was sent: DNS
  resolution; a direct, forward-proxy, or SOCKS TCP connection; SOCKS local
  resolution; direct or SOCKS5-carried QUIC setup; or resolving or connecting
  to a CONNECT-UDP proxy. A negotiated request retries only a failed direct,
  HTTP proxy, or SOCKS5 connect, before origin TLS and ALPN.
- One budget covers redirects, H2 replacement connections, and the
  connections opened for proxy-authentication and client-hint replays. Each
  attempt gets a fresh connect timeout; the total timeout stays absolute.
- `ResponseInfo::retries_performed` counts these retries, summed across
  redirect hops and counted when each starts. It counts no other class.

`RequestBuilder::retry_policy` replaces the client's whole policy for one
request; it does not add to it.

## Replay a request after a reused connection closes

Send an idempotent request once more when an idle HTTP/1.1 keep-alive
connection closes as the request is sent on it.

```rust
use phantom::RetryPolicy;

fn policy() -> RetryPolicy {
    RetryPolicy::none().with_reused_connection_replay(true)
}
```

The request, exact or negotiated, is sent once more on a fresh connection
over the same route when all of these hold:

- it was written to a keep-alive connection that had already delivered a
  response;
- that connection closed or was reset before any byte of the new response;
- the method is idempotent (RFC 9110, section 9.2.2: GET, HEAD, OPTIONS,
  TRACE, PUT, or DELETE); and
- the body is absent or owned bytes.

Chrome 154 restarts such a request once on a new connection
([evidence](../explanation/validation.md#sse-browser-reconnect-evidence)). The
request may already have reached the origin, which is why this replay is
opt-in.

## Replay a request the server did not process

Replay an H2 or H3 request, with any method, when the server reports that it
did not process it.

```rust
use std::num::NonZeroUsize;

use phantom::RetryPolicy;

fn policy() -> RetryPolicy {
    RetryPolicy::none().with_unprocessed_replay(NonZeroUsize::new(2))
}
```

Only these signals, received before any response head, qualify:

- H2 `RST_STREAM(REFUSED_STREAM)` on the request stream (RFC 9113, section
  8.7);
- an H2 `GOAWAY` with any error code whose last-stream-id is below the
  request's stream, or that arrived before the stream opened (RFC 9113,
  sections 6.8 and 8.7);
- an H3 request stream reset or stopped with `H3_REQUEST_REJECTED` (RFC 9114,
  section 4.1.1);
- an H3 `GOAWAY` received before the request opened its stream (RFC 9114,
  section 5.2).

The replay is sent at once on a fresh or different connection; while the
policy is on, the pool stops reusing a connection that refused a stream. One
budget covers every redirect hop and is not shared with any other class.

## Retry when the server returns a retryable status

Repeat an idempotent request after a status such as 503 or 429, optionally
waiting as long as `Retry-After` asks.

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

- `StatusRetry::new` takes the statuses, a request-wide maximum, and a
  constant delay. It accepts only 408, 425, 429, 500, 502, 503, and 504; any
  other status, including 421, or an empty list returns `StatusRetryError`.
- A response is retried only when its status is listed, the method is
  idempotent, and the body is absent or owned bytes. Otherwise it is returned
  unchanged. When the budget runs out, Phantom returns the last response.
- `honor_retry_after(maximum)` uses a valid `Retry-After` (delta-seconds or
  an IMF-fixdate read against the system clock, RFC 9110 section 10.2.3)
  instead of the constant delay. A requested delay above `maximum` returns
  the response at once.
- If a delay cannot finish before the total timeout, Phantom returns the
  response at once and sends nothing more.

## Limits

- Never retried: TLS, certificate, ALPN, proxy negotiation, proxy
  authentication or rejection, timeouts, HTTP responses, and protocol or
  post-dispatch failures. When setup retries run out, the last original error
  is returned.
- A negotiated request holds a bounded per-origin admission slot across the
  retry delay; a request past that bound fails with
  `RequestErrorKind::Capacity` and no protocol
  ([Design](../explanation/design.md#connection-setup-retries)).
- The graceful `GOAWAY` replay covers exact H2 and negotiated requests that
  selected H2, once, outside every budget. Any other method, a body,
  trailers, or a second `GOAWAY` returns the typed H2 error. It runs first
  and does not use the unprocessed-replay budget.
- Reused-connection replay returns the original typed H1 error for a fresh
  connection, a failure after any response byte, a streaming body, POST or
  PATCH, and a second close. It runs at most once per hop, with no delay and
  outside the setup-retry budget; a negotiated replay goes through admission
  and ALPN again.
- Unprocessed-request replay does not cover an H2 stream at or below a
  `GOAWAY` last-stream-id, which fails with a transport error when the
  connection closes, or an H3 stream already open when `GOAWAY` arrived: the
  H3 backend does not expose the identifier needed to prove it unprocessed. A
  streaming body returns the original error without another connection.
- Status retry runs after proxy `407` and `Critical-CH` handling. The
  intermediate response updates cookies, client hints, and Alt-Svc, then its
  body is dropped unread, which retires an incomplete H1 connection or
  cancels an H2 or H3 stream. A missing, repeated, malformed, RFC 850, or
  asctime `Retry-After` falls back to the constant delay.
- The `client.request` tracing span records `reused_connection_replays`,
  `unprocessed_replays`, and `status_retries`; each status retry also emits a
  debug event with its status and delay.
- Retries never change an Alt-Svc alternative already in use.

## Next

- [Connection-retry evidence](../explanation/validation.md#connection-retry-evidence):
  the tests behind these rules and the paths they do not exercise, such as H2
  and H3 status retry.
- [Design](../explanation/design.md#retries-and-replays): the boundary each
  class keeps.
- [Routes and proxies](routes-and-proxies.md): what a retry keeps fixed.
