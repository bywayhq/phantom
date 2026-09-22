# Retries and replays

A retry can change what a server sees. A retry that switches protocol or
route looks like a different client, and repeating a request that already
reached the server can apply it twice.

Phantom retries a request only when one of the rules on this page allows it.
Every retry keeps the request's route and its exact protocol or negotiated
selection rule. Two retries need no opt-in: the graceful `GOAWAY` replay,
and one `Critical-CH` retry when the profile has client hints. You turn on
every other rule yourself.

## Retry classes at a glance

| Class | Default | Configure with | When it applies |
| --- | --- | --- | --- |
| Connection-setup retry | Off | `RetryPolicy::connection_failures` | Connection setup failed before any request byte was sent |
| Graceful `GOAWAY` replay | Always on | Not configurable | A bodyless H2 GET refused by `GOAWAY(NO_ERROR)` |
| Reused-connection replay | Off | `RetryPolicy::with_reused_connection_replay` | An H1 keep-alive connection closed before any response byte |
| Unprocessed-request replay | Off | `RetryPolicy::with_unprocessed_replay` | The H2 or H3 peer reported that it did not process the request |
| Status retry | Off | `RetryPolicy::with_status_retry` | The response status is 408, 425, 429, 500, 502, 503, or 504 |

Two other replays exist outside `RetryPolicy`: one proxy-authentication
replay after a Basic `407` challenge (see
[Routes and proxies](routes-and-proxies.md#basic-proxy-authentication)) and
one `Critical-CH` retry (see [Browser profiles](profiles.md#client-hints)).

Start from `RetryPolicy::none()`, the default, and set the result with
`ClientBuilder::retry_policy` or, for one request,
`RequestBuilder::retry_policy`. A request-level policy replaces the client's
policy rather than adding to it. Retries are your policy, not browser
behavior, so no named browser recipe includes them.

Terms such as H1, H2, H3, exact, and negotiated are defined in
[Key terms](client.md#key-terms).

## Connection-setup retries

`RetryPolicy::connection_failures(maximum, delay)` retries failed connection
setup up to `maximum` times, waiting `delay` before each attempt. It applies
to exact H1, H2, and H3 requests and to negotiated H1/H2 requests.

The retry happens inside the selected protocol's pool, after the request is
admitted and before anything is sent to the origin. A failure qualifies only
when its typed error proves that nothing was sent yet:

- DNS resolution;
- a direct TCP, forward-proxy TCP, or proxy TCP connection;
- a SOCKS TCP connection or local resolution;
- direct or SOCKS5-carried QUIC setup; and
- resolving or connecting to a CONNECT-UDP proxy.

These failures are never retried: TLS, certificate, ALPN, proxy negotiation,
proxy authentication or rejection, timeouts, HTTP responses, and protocol or
post-dispatch failures. The route and exact protocol never change. When the
retries run out, the request returns the last original error.

### Negotiated requests

A negotiated request retries only a failed direct TCP connect. That failure
happens before TLS starts, and so before ALPN chooses H1 or H2; the error
therefore reports no protocol. TLS, certificate, and ALPN failures are not
retried.

Before ALPN selects a protocol, the request holds a bounded per-origin
admission slot. Its active and waiting limits are the larger of the H1 and H2
limits, and the request keeps the slot across the retry delay. After ALPN,
the slot converts to the selected protocol's admission. A request beyond the
pre-selection bound fails with `RequestErrorKind::Capacity` and no protocol.
The connection lock is released during the delay, so another request may
install a connection that the delayed request then reuses.

### Budget and timing

A setup retry happens before the body is read or moved to a protocol stream.
No request bytes are replayed, so the retry is safe for every method and for
one-shot streaming bodies.

- One retry budget covers redirects, connection attempts for proxy
  authentication or client-hint replays, and H2 replacement connections.
  Negotiated requests share the same budget across redirects and client-hint
  replays.
- Each setup attempt gets a fresh connect-phase timeout. The total timeout
  stays absolute across delays and attempts.
- `ResponseInfo::retries_performed` counts these retries, summed across
  redirect hops. It counts no other retry class.

## Graceful `GOAWAY` replay

This replay is always on and does not use `RetryPolicy`. When an H2 server
refuses a bodyless GET without trailers with `GOAWAY(NO_ERROR)`, Phantom
sends it once more on a replacement connection. It applies to exact H2 and to
negotiated requests that selected H2; a negotiated replacement is admitted and
selected by ALPN again. The replay does not use the setup-retry budget. Any
other method, a request body, trailers, or a second `GOAWAY` returns the typed
H2 error.

## Reused-connection replay

`RetryPolicy::with_reused_connection_replay(true)` turns on this replay. It
covers an idle HTTP/1.1 keep-alive connection that closes at the moment a
request is sent on it. The request, exact or negotiated, is sent once more on
a fresh connection over the same route when all of these hold:

- it was written to a keep-alive connection that had already delivered a
  response;
- that connection closed or was reset before any byte of the new response
  arrived;
- the method is idempotent (RFC 9110, section 9.2.2: GET, HEAD, OPTIONS,
  TRACE, PUT, or DELETE); and
- the body is absent or owned bytes.

Chrome 153 restarts such a request once on a new connection (see
[validation](../explanation/validation.md#sse-browser-reconnect-evidence)).
The request may already have reached the origin, which is why this replay is
opt-in and limited to idempotent methods.

These cases return the original typed HTTP/1 error instead: a request on a
fresh connection, a failure after any response byte, a one-shot streaming
body, POST or PATCH, and a second close.

The replay happens at most once per redirect hop, adds no delay, and does not
use the setup-retry budget. The `client.request` tracing span records the
count as `reused_connection_replays`. A negotiated replay retires the failed
H1 connection generation and is admitted and selected by ALPN again, like the
negotiated `GOAWAY` replay.

## Unprocessed-request replay

`RetryPolicy::with_unprocessed_replay(Some(maximum))` replays an H2 or H3
request that the server reported it did not process. Only these signals,
received before any response head, qualify:

- H2 `RST_STREAM(REFUSED_STREAM)` on the request stream (RFC 9113, section
  8.7);
- an H2 `GOAWAY` with any error code whose last-stream-id is below the
  request's stream, or that arrived before the stream opened (RFC 9113,
  sections 6.8 and 8.7);
- an H3 request stream reset or stopped with `H3_REQUEST_REJECTED` (RFC 9114,
  section 4.1.1);
- an H3 `GOAWAY` received before the request opened its stream, so no request
  byte was sent (RFC 9114, section 5.2).

Because the server did nothing with the request, any method may be replayed.
The body must be absent or owned bytes; a one-shot streaming body returns the
original typed error without opening another connection.

- The replay is sent at once, without a delay, on a fresh or different
  connection. While this policy is on, the pool stops reusing a connection
  that refused a stream.
- The route, the exact protocol or negotiated selection rule, and an Alt-Svc
  alternative already in use never change.
- One budget of `maximum` replays covers every redirect hop and is not shared
  with any other retry class. The `client.request` span records the count as
  `unprocessed_replays`.

Two cases are not replayed, because the server may have processed the
request:

- An H2 stream at or below a `GOAWAY` last-stream-id. When the connection
  then closes, that stream fails with a transport error.
- An H3 stream that was already open when `GOAWAY` arrived. The H3 backend
  does not expose the `GOAWAY` identifier needed to prove the stream
  unprocessed; only `H3_REQUEST_REJECTED` covers it.

The built-in graceful `GOAWAY` replay works the same with or without this
policy. With it, the graceful replay still runs first and does not use the
unprocessed-replay budget.

## Status retry

`RetryPolicy::with_status_retry` repeats a request after a retryable response
status. `StatusRetry::new` takes the statuses to retry, a request-wide
maximum, and a constant delay. It accepts only 408, 425, 429, 500, 502, 503,
and 504, which report conditions that a later identical request can clear.
Any other status, including 421, or an empty list returns
`StatusRetryError`. A 421 is excluded because repeating it on the same route
and connection target cannot succeed.

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

A response is retried only when its status is listed, the method is
idempotent (RFC 9110, section 9.2.2), and the body is absent or owned bytes.
Otherwise, including for a one-shot streaming body, the response is returned
unchanged.

- The check runs after forward-proxy `407` and Critical-CH handling for the
  same response.
- The intermediate response updates cookies, client hints, and Alt-Svc
  exactly as a returned response would. Phantom then drops its body unread,
  so an incomplete H1 body retires that connection and an H2 or H3 body
  cancels its stream.
- One budget covers every redirect hop. When it runs out, Phantom returns the
  last response.
- The retry keeps the route, the exact protocol or negotiated selection rule,
  and an Alt-Svc alternative already in use.

### Delays and `Retry-After`

Each retry waits for the constant delay. If a total timeout is set and the
delay cannot finish before that deadline, Phantom returns the response at
once and sends no further request. This applies to a delay from
`Retry-After` as well.

`honor_retry_after(maximum)` uses a valid `Retry-After` field instead of the
constant delay. The field may be delta-seconds or an IMF-fixdate, which is
converted against the system clock (RFC 9110, section 10.2.3). A requested
delay above `maximum` returns the response at once. A missing, repeated,
malformed, or obsolete RFC 850 or asctime value falls back to the constant
delay.

The `client.request` span records the count as `status_retries`, and each
retry emits a debug event with its status and delay.

## Evidence

[Connection-retry evidence](../explanation/validation.md#connection-retry-evidence)
lists the tests behind these rules and the paths they do not exercise, such
as H2 and H3 status retry.
