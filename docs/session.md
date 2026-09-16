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

Bare `Client::get` remains one-shot. `Session::get` reuses HTTP/2 and direct
HTTP/3 connections. HTTP/1 retains its one-shot lifecycle.

## Pool boundary

One session retains at most one current H2 or H3 connection for each canonical
host, port, and complete route value. Because the session owns one immutable
client, the wire profile, trust roots, and protocol are structural parts of
the boundary. Different origins, routes, ordered CONNECT fields, clients, and
sessions never share a connection. Cross-origin coalescing is disabled. H3
reuse is direct-only until a UDP-capable proxy route exists.

Simultaneous first requests for one key share connection setup. Unrelated keys
can connect concurrently. A connection-fatal error invalidates only the exact
generation that failed; a stream reset does not discard sibling streams. The
failed request is returned to the caller and is never replayed automatically.

`SessionBuilder::max_retained_http2_connections` and
`max_retained_http3_connections` bound retained pool entries. Least-recently
selected entries are evicted. An outstanding response body keeps its own
connection lease until completion or drop, so eviction never cancels a body
already returned to the caller.

H3 admission is bounded by `max_concurrent_http3_requests_per_origin`; at most
`max_pending_http3_requests_per_origin` additional requests may wait. These
bounds span a draining generation and its replacement for the same origin.
An active slot remains held through stream completion, including bounded reset
cleanup after an incomplete body is dropped. Excess work returns
`RequestErrorKind::Capacity`. A GOAWAY or closed H3 generation is not selected
for new work, while response bodies retain the old generation. Requests are
never replayed automatically.

Peer-aware H2 admission, graceful public shutdown, H1 reuse, retries, and
coalescing are later pool work.

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
top-level-site key and remain unsupported. Persistence,
browser-specific eviction priority, redirects, retries, client hints, tickets,
DNS/HTTPS answers, and Alt-Svc state are also outside this slice.
