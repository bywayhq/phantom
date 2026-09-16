# Phantom

Phantom is an experimental Rust HTTP client focused on observable,
profile-driven wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The current vertical slices implement certificate- and hostname-checked TLS,
ordered streaming HTTP/1.1, and one-shot HTTP/2 over an exact `h2` TLS
negotiation. Chrome 152 macOS has TLS and HTTP/2 recipes with direct retained
fixture differentials. Safari 18.5 and Firefox 154 macOS now have retained TLS
recipes; Firefox also has an HTTP/2 startup recipe. Safari HTTP/2 remains
uncaptured. The first forced HTTP/3 slice now performs a direct, one-shot
request over the BoringSSL Quinn provider, verifies exact `h3` ALPN, streams
data and trailers, propagates body cancellation, and applies a capture-backed
Chrome QUIC transport recipe to live Quinn state and the exact TLS extension
bytes. A typed Chrome H3 recipe emits the captured nonzero QPACK limits,
maximum field-section size, H3 DATAGRAM setting, ascending setting order, and
randomized GREASE. The receive path bounds dynamic QPACK state and treats a
datagram on an ordinary request as an H3 protocol error. Outbound dynamic
QPACK, reusable sessions, typed proxy routing, SSE, and WebSocket remain
planned. The project does not make broad client-compatibility claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current workspace

- `phantom`: the future public client facade
- `phantom-profile`: browser-neutral profile identity, public typed TLS,
  HTTP/2, HTTP/3, and QUIC settings, and narrow
  fixture-backed Chrome, Safari, and Firefox recipes
- `phantom-net`: ordered streaming HTTP/1.1, one-shot HTTP/2 with exact-`h2`
  TLS and ALPS, and a direct forced-H3 transaction path with streaming response
  bodies and bounded cancellation
- `phantom-quic-btls`: the isolated, audited BoringSSL crypto provider for
  Quinn, including verified TLS 1.3 handshakes, owned peer identity and QUIC
  parameters, Initial and Retry handling, packet/header protection, endpoint
  HMAC, exporters, and repeated traffic-key updates
- `phantom-testkit`: bounded TLS ClientHello and HTTP/2 frame capture with
  strict decoding for deterministic differentials

The provenance-tracked H3 fork is an active runtime dependency for ordered
SETTINGS, bounded dynamic QPACK receive support, and immediate stream
cancellation through the Quinn adapter. Outbound request encoding remains
stateless and is tracked as a separate directional capability.

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md),
[validation model](docs/validation.md),
[configuration model](docs/configuration.md),
[TLS security boundary](docs/tls-security-boundary.md),
[scope and coverage](docs/scope-and-coverage.md),
[async and feature policy](docs/async-and-features.md),
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
python3 -m unittest discover -s scripts/capture/tests -p 'test_*.py'
```

Vendored patch checks are available through
`scripts/ci/check-vendor.sh {btls|http2|quinn-proto|h3}` and run in CI.
