# Phantom

Phantom is an experimental Rust HTTP client focused on observable,
profile-driven wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The current vertical slices implement certificate- and hostname-checked TLS,
ordered streaming HTTP/1.1, and reusable multiplexed HTTP/2 and direct HTTP/3.
A cloneable public session retains compatible H1, H2, and H3 connections by
exact origin and route while bare-client requests remain one-shot. Chrome 152
macOS has TLS and HTTP/2 recipes with direct retained
fixture differentials. Safari 18.5 and Firefox 154 macOS now have retained TLS
recipes; Firefox also has an HTTP/2 startup recipe. Safari HTTP/2 remains
uncaptured. The forced HTTP/3 slice performs direct requests over the
BoringSSL Quinn provider, verifies exact `h3` ALPN, multiplexes session-owned
streams, propagates stream-scoped cancellation, and applies a capture-backed
Chrome QUIC transport recipe to live Quinn state and the exact TLS extension
bytes. Its separate Chrome H3 TLS recipe emits the retained ClientHello shape,
including the final H3 ALPS codepoint, and carries authenticated peer
application settings into the H3 engine. A typed Chrome H3 recipe emits the
captured nonzero QPACK limits,
maximum field-section size, H3 DATAGRAM setting, ascending setting order, and
randomized GREASE. The receive path bounds dynamic QPACK state and treats a
datagram on an ordinary request as an H3 protocol error. The isolated outbound
dynamic QPACK encoder reproduces the retained Chrome request bytes. Its live
connection-owned path now waits for peer SETTINGS, applies bounded
backpressure, sends encoder instructions before dependent HEADERS, and matches
the retained Chrome encoder-stream and HEADERS bytes. Captured pseudo-header
order, ordinary-field order, duplicates, and sensitivity survive request
construction and QPACK encoding. The public `phantom::Client` now provides a
small facade for exact H1, H2, or direct H3 requests, additive private trust
roots, typed direct, plaintext-HTTP-CONNECT, and local- or remote-DNS SOCKS5 routes, and
one unified streaming response body. CONNECT fields preserve caller-declared
order, proxy rejection never falls back direct, and coalesced tunnel bytes
survive negotiation. The SOCKS5 URI scheme selects explicit DNS ownership. H3 uses a
separate protocol-specific TLS profile and rejects both TCP-only proxy routes
before network I/O. The optional `cookies` capability adds a bounded, explicit
session jar with public-suffix, prefix, expiry, and deterministic ordering
rules. Profiles may also define ordered client-hint fields; sessions retain
bounded exact-origin `Accept-CH` state and perform at most one idempotent
`Critical-CH` replay. Feature-gated SSE support provides both a bounded
single-response decoder and a finite, pull-driven session reconnect controller
without a background task. Feature-gated WebSocket support performs an exact ordered H1
Upgrade over the same TLS and selected TCP route, then exposes bounded message
I/O through Phantom-owned types. HTTPS proxies, SOCKS5 authentication,
UDP-capable proxies, general retry policy, WebSocket extensions, and extended
CONNECT remain planned. The project does not make broad client-compatibility
claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current client slice

```rust,no_run
use phantom::{Client, HttpProtocol, Method, RequestHeader};
use phantom::profile::{ClientProfile, chromium};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2())
    .with_client_hints(chromium::v152_macos_client_hints());
let client = Client::builder(profile).build()?;
let response = client
    .get(HttpProtocol::Http2, "https://example.com/resource")?
    .header(RequestHeader::new("accept", "*/*"))
    .send()
    .await?;

println!("{}", response.status());

let upload = client
    .request(HttpProtocol::Http2, Method::POST, "https://example.com/upload")?
    .body("payload")
    .send()
    .await?;
println!("{}", upload.status());

// HeaderMap remains available for semantic lookup. This extension retains
// global field order, duplicates, and HTTP/1 field-name spelling.
let ordered = response
    .extensions()
    .get::<phantom::OrderedResponseHeaders>()
    .expect("Phantom responses contain ordered fields");
for field in ordered.iter() {
    println!("{}", field.name());
}
# Ok(())
# }
```

The selected protocol is exact. Bare-client requests open one connection per
request and never negotiate another version or retry through another route.
`get` is convenience sugar for `request` with `Method::GET`; ordinary
non-CONNECT methods may carry one finite owned byte body. Phantom validates a
caller-supplied `Content-Length` exactly or appends one for a non-empty body.
Streaming uploads and a configurable general retry policy remain unavailable.
A session retries one bodyless H2 GET when `GOAWAY(NO_ERROR)` identifies it as
unprocessed; the replacement keeps the same origin, route, protocol, and
ordered fields. Redirects are an explicit session policy configured with
`RedirectPolicy::limited`; they keep the selected protocol and route, apply a
finite hop budget, and replay only the current owned byte body. Every
successful response includes `OrderedResponseHeaders` and `ResponseInfo` in
its extensions; the ordinary `HeaderMap` remains the normalized semantic view.
The ordered view retains
duplicate interleaving on every protocol and received HTTP/1 field-name
spelling. HTTP/2 and HTTP/3 names are lowercase by protocol. Use
`client.session()` for session-owned HTTP/1.1, HTTP/2, and direct HTTP/3 reuse,
or enable bounded cookie state explicitly with
`client.session_builder().cookies().build()` when the `cookies` feature is
compiled. A profile with client hints emits default fields for bare requests;
a session additionally retains exact-origin `Accept-CH` state. Use
`ClientBuilder::route` for an immutable default route or
`RequestBuilder::route` for an owned per-request override.

## Current workspace

- `phantom`: the public exact-protocol client facade, session-owned H1, H2, and H3 reuse,
  direct routes, plaintext HTTP CONNECT and local- or remote-DNS SOCKS5 for H1/H2 and H1
  WebSocket, opt-in bounded redirects, streaming responses, and optional
  bounded cookie and client-hint state, plus SSE and WebSocket capabilities
- `phantom-profile`: browser-neutral profile identity, public typed TLS,
  HTTP/2, HTTP/3, and QUIC settings, and narrow
  fixture-backed Chrome, Safari, and Firefox recipes
- `phantom-net`: ordered streaming HTTP/1.1, reusable multiplexed HTTP/2 with
  exact-`h2` TLS and ALPS, and reusable direct forced-H3 connections with streaming
  response bodies, lossless ordinary response-field ordering, and bounded
  cancellation
- `phantom-quic-btls`: the isolated, audited BoringSSL crypto provider for
  Quinn, including verified TLS 1.3 handshakes, owned peer identity and QUIC
  parameters, Initial and Retry handling, packet/header protection, endpoint
  HMAC, exporters, and repeated traffic-key updates
- `phantom-testkit`: bounded TLS ClientHello and HTTP/2 frame capture with
  strict decoding for deterministic differentials

The provenance-tracked H3 fork is an active runtime dependency for ordered
SETTINGS, bounded dynamic QPACK receive support, immediate stream cancellation
through the Quinn adapter, and bounded connection-owned outbound dynamic QPACK
with capture-matching live request bytes. Stateless encoding remains the
default for profiles that do not opt into the dynamic policy.

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md),
[validation model](docs/validation.md),
[configuration model](docs/configuration.md),
[proxy routing](docs/proxy-routing.md),
[TLS security boundary](docs/tls-security-boundary.md),
[scope and coverage](docs/scope-and-coverage.md),
[async and feature policy](docs/async-and-features.md),
[session state and pooling](docs/session.md),
[SSE decoder](docs/sse.md),
[WebSocket](docs/websocket.md),
[Rust quality review](docs/rust-quality.md),
[adversarial testing](docs/adversarial-testing.md),
[dynamic QPACK design](docs/qpack-design.md),
[ecosystem lessons](docs/ecosystem-review.md),
[ecosystem architecture and API audit](docs/ecosystem-architecture-pr-audit.md),
and
[performance guide](docs/performance.md). Dependency forks and the Linux,
macOS, and Windows gates are described in
[dependency maintenance](docs/dependency-maintenance.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
uvx ruff@0.16.7 check scripts/capture
uvx ruff@0.16.7 format --check scripts/capture
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
```

Vendored patch checks are available through
`scripts/ci/check-vendor.sh {btls|http2|quinn-proto|h3}` and run in CI.
