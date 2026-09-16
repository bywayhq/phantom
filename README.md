# Phantom

Phantom is an experimental Rust HTTP client focused on observable,
profile-driven wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The current vertical slices implement certificate- and hostname-checked TLS,
ordered streaming HTTP/1.1, and reusable multiplexed HTTP/2 over an exact `h2`
TLS negotiation. The public client still opens one connection per request;
connection-pool and session ownership have not landed. Chrome 152 macOS has
TLS and HTTP/2 recipes with direct retained
fixture differentials. Safari 18.5 and Firefox 154 macOS now have retained TLS
recipes; Firefox also has an HTTP/2 startup recipe. Safari HTTP/2 remains
uncaptured. The first forced HTTP/3 slice now performs a direct, one-shot
request over the BoringSSL Quinn provider, verifies exact `h3` ALPN, streams
data and trailers, propagates body cancellation, and applies a capture-backed
Chrome QUIC transport recipe to live Quinn state and the exact TLS extension
bytes. A typed Chrome H3 recipe emits the captured nonzero QPACK limits,
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
roots, a typed direct-or-plaintext-HTTP-CONNECT route, and one unified
streaming response body. CONNECT fields preserve caller-declared order, proxy
rejection never falls back direct, and coalesced tunnel bytes survive
negotiation. H3 uses a separate protocol-specific TLS profile and rejects the
TCP-only CONNECT route before network I/O. It has no pool or mutable session
state yet. A feature-gated, bounded SSE decoder consumes the same response
body without a background task; reconnection remains session policy. HTTPS
proxies, SOCKS, UDP-capable proxies, reusable sessions, and WebSocket remain
planned. The project does not make broad
client-compatibility claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current client slice

```rust,no_run
use phantom::{Client, HttpProtocol, RequestHeader};
use phantom::profile::{ClientProfile, chromium};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2());
let client = Client::builder(profile).build()?;
let response = client
    .get(HttpProtocol::Http2, "https://example.com/resource")?
    .header(RequestHeader::new("accept", "*/*"))
    .send()
    .await?;

println!("{}", response.status());
# Ok(())
# }
```

The selected protocol is exact. This slice opens one connection per request;
it does not negotiate another HTTP version or retry through another route.
Use `ClientBuilder::route` for an immutable default route or
`RequestBuilder::route` for an owned per-request override.

## Current workspace

- `phantom`: the public exact-protocol client facade for one-shot H1/H2/H3
  requests, direct routes, plaintext HTTP CONNECT for H1/H2, and streaming
  responses, with an optional SSE decoder
- `phantom-profile`: browser-neutral profile identity, public typed TLS,
  HTTP/2, HTTP/3, and QUIC settings, and narrow
  fixture-backed Chrome, Safari, and Firefox recipes
- `phantom-net`: ordered streaming HTTP/1.1, reusable multiplexed HTTP/2 with
  exact-`h2` TLS and ALPS, and a direct forced-H3 connector with streaming
  response bodies and bounded cancellation
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
[TLS security boundary](docs/tls-security-boundary.md),
[scope and coverage](docs/scope-and-coverage.md),
[async and feature policy](docs/async-and-features.md),
[SSE decoder](docs/sse.md),
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
