# Session state and multiplexed reuse

`Client` is immutable transport configuration. `Session` is an isolated,
cloneable owner for state that intentionally crosses requests. Creating two
sessions from one client creates two connection pools and, when enabled, two
cookie identities. Cloning one session shares its state.

```rust,no_run
use phantom::{Client, HttpProtocol};
use phantom::profile::{ClientProfile, chromium};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2());
let client = Client::builder(profile).build()?;
let session = client.session();

let first = session
    .get(HttpProtocol::Http2, "https://example.com/first")?
    .send()
    .await?;
drop(first);
let second = session
    .get(HttpProtocol::Http2, "https://example.com/second")?
    .send()
    .await?;
drop(second);
# Ok(())
# }
```

Bare `Client::get` remains one-shot. `Session::get` reuses eligible HTTP/1.1,
HTTP/2, and direct HTTP/3 connections. When the profile defines client hints,
the session also retains bounded exact-origin `Accept-CH` state.

## Client hints

Client-hint values and relative order come from `ClientHintSettings` in the
immutable profile. Default fields are emitted on every request. Fields marked
`AcceptCh` are emitted only after that exact HTTPS origin requests them. A
valid response value replaces the prior selection; an empty or
unsupported-only value clears it; malformed input leaves prior state intact.
The effective port is part of the origin.

The store is bounded by `SessionBuilder::max_client_hint_origins`. Session
clones share it, new sessions do not, and `Session::clear_client_hints` removes
all learned selections. Bare `Client` requests emit profile defaults without
retaining response state. Caller-supplied configured hint fields override
automatic values without being moved.

An H2 or H3 connection may also supply `ACCEPT_CH` in authenticated ALPS. Its
exact-origin selection is applied after connection choice, including to the
first request, and augments response-learned session state. It remains
immutable connection metadata: it is not persisted, inherited by a replacement
connection, or cleared through `Session::clear_client_hints`.

`Critical-CH` may replay the current owned request once when a supported
requested hint was missing and the method is safe. It cannot loop or
change the selected route or protocol. Cross-origin redirects remove configured
caller hint fields and rebuild the automatic set for the new origin. Live
post-handshake `ACCEPT_CH` frames, persistence, full-navigation restart across
an already-followed redirect chain, and browsing-context delegation are not
part of this slice.

## Redirect policy

Automatic redirects are disabled by default. A session can enable a finite
hop budget explicitly:

```rust,no_run
use std::num::NonZeroUsize;
use phantom::{Client, RedirectPolicy};

# fn example(client: &Client) {
let session = client
    .session_builder()
    .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
    .build();
# let _ = session;
# }
```

The transaction keeps the selected protocol and route. It resolves each
`Location` using WHATWG URL rules, applies the standard 301/302/303/307/308
method and replayable-body transitions, and stops with a typed redirect error
when the budget is exhausted. Redirects never trigger protocol fallback or a
transport-failure retry.

On a cross-origin hop, caller-supplied authorization, proxy authorization, and
cookie fields are removed. With the `cookies` feature, every intermediate
response is learned before the jar is evaluated for the next target. The final
response contains `ResponseInfo` in its extensions with the effective URI and
number of followed hops. Bare `Client` requests remain one-shot.

For H1 and H2, each retained pool entry also owns a bounded TLS ticket cache.
Connection replacement for the same canonical origin, complete route, protocol,
profile, and TLS context can resume. Tickets never cross pool entries or
sessions, expired entries are discarded, and TLS 1.3 single-use tickets are
consumed. One-shot client requests do not retain tickets. Early data remains
disabled, and QUIC resumption is separate future work.

## Pool boundary

One session retains at most one current H1, H2, or H3 connection for each
canonical host, port, complete route value, and forwarding/tunnel mode. Because
the session owns one
immutable client, the wire profile, trust roots, and protocol are structural
parts of the boundary. Different origins, routes, ordered CONNECT fields,
clients, and sessions never share a connection. Cross-origin coalescing is
disabled. H3 reuse is direct-only until a UDP-capable proxy route exists.

Simultaneous first requests for one key share connection setup. Unrelated keys
can connect concurrently. A connection-fatal error invalidates only the exact
generation that failed; a stream reset does not discard sibling streams.
Automatic transport replay is limited to the graceful H2 GOAWAY case described
below.

The `max_retained_http{1,2,3}_connections` builder settings bound retained pool
entries. Least-recently selected entries are evicted. An outstanding response
body keeps its own connection lease until completion or drop, so eviction
never cancels a body already returned to the caller.

HTTP/1.1 admits one active exchange per origin and route. It never pipelines.
The `max_pending_http1_requests_per_origin` setting bounds additional waiters.
Reuse begins only after a self-delimited body completes. Incomplete bodies,
protocol failures, HTTP/1.0, close-delimited responses, and either side's
`Connection: close` retire the connection. A stale-idle race is returned to
the caller and is never replayed automatically.

HTTP/2 and HTTP/3 admission are independently bounded by their
`max_concurrent_http{2,3}_requests_per_origin` settings; at most the matching
`max_pending_http{2,3}_requests_per_origin` additional requests may wait. The
bounds apply per origin and selected route and span a draining generation and
its replacement. Excess work returns `RequestErrorKind::Capacity`, and
cancelling a waiter releases its queue slot.

An H2 active slot remains held until its response stream completes or is
dropped. The H2 engine independently enforces the peer's advertised concurrent
stream limit. H3 retains its active slot through stream completion, including
bounded reset cleanup after an incomplete body is dropped. A GOAWAY or closed
generation is not selected for new work, while eligible response bodies retain
the old generation. When `GOAWAY(NO_ERROR)` rejects a bodyless GET, Phantom
invalidates that generation and retries the request once on its replacement.
The retry keeps the same origin, route, protocol, session, ordered fields, and
admission slot. Requests with bodies, other methods, other failures, and a
second GOAWAY are returned to the caller without replay.

Graceful public shutdown, a configurable broader retry policy, and coalescing
are later pool work.

## Optional cookies

The default Cargo feature set is empty. Compile `cookies`, then activate a jar
explicitly:

```rust,no_run
# use phantom::{Client, CookieJar};
# fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let session = client.session_builder().cookies().build();

let jar = CookieJar::default();
jar.set_cookie("https://example.com/", "session=seeded; Secure; Path=/")?;
let seeded = client.session_builder().cookie_jar(jar).build();
# let _ = (session, seeded);
# Ok(())
# }
```

The jar delegates cookie parsing plus domain, path, expiry, `Secure`, and
`HttpOnly` matching to `cookie_store`. Phantom adds a current static public
suffix list, `__Secure-`/`__Host-` checks, rejection of unsupported
`Partitioned` cookies, configurable memory bounds, and deterministic outbound
ordering: longer paths first, then earlier creation time.

Response `Set-Cookie` fields are processed independently in received order as
soon as final response headers arrive. Invalid fields do not suppress later
valid fields, and body cancellation does not roll back committed cookies. A
caller-supplied `Cookie` field suppresses jar injection for that request while
response learning remains active. Jar locks are never held across network
awaits, and tracing records only bounded outcome categories—not URLs, cookie
names, or values.

SameSite `Strict` and `Lax` require navigation/initiator context that the
current request API does not expose, so they are rejected. `SameSite=None` is
accepted only with `Secure`; an omitted SameSite attribute receives no
context-dependent filtering in this slice. Partitioned cookies need a
top-level-site key and remain unsupported. Persistence, browser-specific cookie
eviction priority, general retries, QUIC tickets, DNS/HTTPS answers, and
Alt-Svc state are also outside this slice.
