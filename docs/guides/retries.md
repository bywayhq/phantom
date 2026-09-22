# Retries and replays

Phantom never retries a request unless a rule below allows it. Every retry
keeps the request's route and its exact protocol or negotiated selection rule.
This guide explains each retry class and when it applies.

## Retry classes at a glance

| Class | Default | Configure with | When it applies |
| --- | --- | --- | --- |
| Connection-setup retry | Off | `RetryPolicy::connection_failures` | Connection setup failed before any request byte was sent |
| Graceful `GOAWAY` replay | Always on | Not configurable | A bodyless H2 GET refused by `GOAWAY(NO_ERROR)` |
| Reused-connection replay | Off | `RetryPolicy::with_reused_connection_replay` | An H1 keep-alive connection closed before any response byte |
| Unprocessed-request replay | Off | `RetryPolicy::with_unprocessed_replay` | The H2 or H3 peer reported that it did not process the request |
| Status retry | Off | `RetryPolicy::with_status_retry` | The response status is 408, 425, 429, 500, 502, 503, or 504 |

Two other replays exist outside `RetryPolicy`: one proxy-authentication replay
after a Basic `407` challenge (see [Routes and proxies](routes-and-proxies.md))
and one `Critical-CH` retry (see [Browser profiles](profiles.md#client-hints)).

The default policy is `RetryPolicy::none()`. A request-level policy replaces
the client's default. Retries are caller policy: they never become part of a
named browser recipe.

## Connection-setup retries

`RetryPolicy::connection_failures` opts exact H1, H2, and H3 requests and
negotiated H1/H2 requests into a finite number of connection-setup retries with
a constant caller-selected delay.

The retry boundary is inside the selected protocol pool, after admission and
before origin request dispatch.

**Eligible** only when the typed error proves that dispatch has not begun:

- DNS resolution;
- direct TCP, forward-proxy TCP, and proxy TCP connection;
- SOCKS TCP connection and local resolution;
- direct or SOCKS5-carried QUIC setup; and
- CONNECT-UDP outer-proxy resolution and connection.

**Terminal**: TLS, certificate, ALPN, proxy negotiation, authentication, or
rejection, timeouts, HTTP responses, and protocol or post-dispatch failures.
The route and exact protocol never change, and exhaustion returns the last
original error.

### Negotiated requests

A negotiated request retries only a direct TCP connect failure, before TLS
starts and therefore before ALPN selects H1 or H2; the error reports no
protocol. TLS, certificate, and ALPN failures are terminal.

The request first takes a bounded per-origin pre-selection admission, whose
active and waiting limits are the larger of the H1 and H2 limits, and keeps it
across the retry delay. After ALPN it converts to the selected protocol's
admission. A request beyond the pre-selection bound fails with
`RequestErrorKind::Capacity` and no protocol. The connection lock is released
during the delay, so another request may install a connection that the delayed
request then reuses.

### Budget and timing

Because a setup retry occurs before the body is polled or moved to a protocol
stream, it is safe for every method and for one-shot streaming bodies; Phantom
does not replay request bytes.

- One retry budget spans redirects, proxy-auth or client-hint connection
  attempts, and H2 replacement connections. Negotiated requests share the same
  budget, including across redirects and client-hint replays.
- Each setup attempt receives a fresh connect-phase timeout, while the total
  timeout remains absolute across delays and attempts.

## Graceful `GOAWAY` replay

Independently of `RetryPolicy`, a bodyless GET without trailers whose H2
stream is refused by `GOAWAY(NO_ERROR)` is repeated once on a replacement
connection. This applies to exact H2 and to negotiated requests that selected
H2; the negotiated replacement is admitted and selected by ALPN again. The
replay does not consume the setup-retry budget. Any other method, a request
body, trailers, or a second `GOAWAY` returns the typed H2 error.

## Reused-connection replay

`RetryPolicy::with_reused_connection_replay(true)` opts into a post-dispatch
replay class. It is off by default. An HTTP/1.1 request, exact or negotiated,
is sent once more on a fresh connection over the same route when all of these
hold:

- it was written to a keep-alive connection that had already delivered a
  response;
- that connection closed or was reset before any byte of the new response
  arrived;
- the method is idempotent (RFC 9110, section 9.2.2: GET, HEAD, OPTIONS,
  TRACE, PUT, or DELETE); and
- the body is absent or owned bytes.

Chrome 153 restarts such a request once on a new connection (see
[validation](../explanation/validation.md#sse-browser-reconnect-evidence)). The
request may already have reached the origin, which is why the class is opt-in
and limited to idempotent methods.

These cases return the original typed HTTP/1 error instead: a request on a
fresh connection, a failure after any response byte, a one-shot streaming body,
POST or PATCH, and a second close.

The replay happens at most once per redirect hop, adds no delay, and does not
consume the setup-retry budget; `ResponseInfo::retries_performed` still counts
only setup retries. The `client.request` span records the count as
`reused_connection_replays`. A negotiated replay retires the failed H1
generation and is admitted and selected by ALPN again, like the negotiated
`GOAWAY` replay.

## Unprocessed-request replay

`RetryPolicy::with_unprocessed_replay(Some(maximum))` opts into replaying an
H2 or H3 request that the peer reported as not processed. It is off by
default. Only these signals, received before any response head, qualify:

- H2 `RST_STREAM(REFUSED_STREAM)` on the request stream (RFC 9113, section
  8.7);
- an H2 `GOAWAY` with any error code whose last-stream-id is below the
  request's stream, or that arrived before the stream opened (RFC 9113,
  sections 6.8 and 8.7);
- an H3 request stream reset or stopped with `H3_REQUEST_REJECTED` (RFC 9114,
  section 4.1.1);
- an H3 `GOAWAY` received before the request opened its stream, so no request
  byte was sent (RFC 9114, section 5.2).

Because the server did nothing with the request, any method may be replayed,
but the body must be absent or owned bytes: a one-shot streaming body returns
the original typed error without opening another connection.

- The replay is sent at once, without a delay, on a fresh or different
  connection: when the policy is on, the pool stops reusing a connection that
  refused a stream.
- The route, the exact protocol or negotiated selection rule, and an Alt-Svc
  alternative already in use never change.
- One budget of `maximum` replays spans every redirect hop and is shared with
  no other retry class. `ResponseInfo::retries_performed` still counts only
  setup retries, and the `client.request` span records `unprocessed_replays`.

What is not replayed:

- An H2 stream at or below a `GOAWAY` last-stream-id may have been processed.
  When the connection then closes, that stream fails with a transport error
  and is never replayed.
- An H3 stream that was already open when `GOAWAY` arrived is not replayed
  either, because the H3 backend does not expose the `GOAWAY` identifier
  needed to prove it unprocessed; only `H3_REQUEST_REJECTED` covers it.

Without this policy, the built-in graceful `GOAWAY` replay is unchanged. With
it, that replay still runs first without consuming the unprocessed budget.

## Status retry

`RetryPolicy::with_status_retry` opts into repeating a request after a
retryable response status. It is off by default. `StatusRetry::new` takes the
statuses to retry, a request-wide maximum, and a constant delay. It accepts
only 408, 425, 429, 500, 502, 503, and 504, and returns `StatusRetryError` for
anything else, including 421, or for an empty list.

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
Otherwise, including for a one-shot streaming body, it is returned unchanged.

- The check runs after forward-proxy `407` and Critical-CH handling for the
  same response.
- The intermediate response updates cookies, client hints, and Alt-Svc exactly
  as a returned response would. Its body is then dropped unread, so an
  incomplete H1 body retires that connection and an H2 or H3 body cancels its
  stream.
- One budget spans every redirect hop, and exhaustion returns the last
  response.
- The retry keeps the route, the exact protocol or negotiated selection rule,
  and an Alt-Svc alternative already in use.

### Delays and `Retry-After`

Each retry waits for the constant delay. When a total timeout is set and the
delay, constant or from `Retry-After`, cannot finish before that deadline, the
response is returned immediately and no further request is sent.

`honor_retry_after(maximum)` instead uses a valid `Retry-After` field, either
delta-seconds or an IMF-fixdate converted against the system clock (RFC 9110,
section 10.2.3). A requested delay above `maximum` returns the response
immediately. A missing, repeated, malformed, or obsolete RFC 850 or asctime
value falls back to the constant delay.

`ResponseInfo::retries_performed` still counts only setup retries; the
`client.request` span records `status_retries`, and each retry emits a debug
event with its status and delay.

## Evidence

[Connection-retry evidence](../explanation/validation.md#connection-retry-evidence)
lists the tests behind these rules and the paths they do not exercise, such as
H2 and H3 status retry.
