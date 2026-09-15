# Phantom

Phantom is an experimental Rust HTTP client focused on observable,
profile-driven wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The current vertical slices implement certificate- and hostname-checked TLS,
ordered streaming HTTP/1.1, and one-shot HTTP/2 over an exact `h2` TLS
negotiation. Chrome 152 macOS has TLS and HTTP/2 recipes with direct retained
fixture differentials. Safari 18.5 and Firefox 154 macOS now have retained TLS
recipes; Firefox also has an HTTP/2 startup recipe. Safari HTTP/2 remains
uncaptured. Forced HTTP/3 implementation is in progress from a retained Chrome
QUIC/H3 capture; reusable sessions, typed proxy routing, SSE, and WebSocket
remain planned. The project does not make broad client-compatibility claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current workspace

- `phantom`: the future public client facade
- `phantom-profile`: browser-neutral profile identity, typed TLS and HTTP/2
  settings, and narrow fixture-backed Chrome, Safari, and Firefox recipes
- `phantom-net`: the private BoringSSL adapter plus ordered streaming HTTP/1.1
  and one-shot HTTP/2 request paths, including exact-`h2` TLS and ALPS handling
- `phantom-quic-btls`: the isolated, audited BoringSSL packet-cryptography
  boundary for the in-progress Quinn HTTP/3 provider
- `phantom-testkit`: bounded TLS ClientHello and HTTP/2 frame capture with
  strict decoding for deterministic differentials

The vendored H3 SETTINGS patch is provenance-tracked groundwork, not an active
runtime dependency. Chrome H3 remains gated on complete, bounded dynamic QPACK
receive support rather than advertising capabilities the engine cannot honor.

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md),
[validation model](docs/validation.md),
[adversarial testing](docs/adversarial-testing.md),
[dynamic QPACK design](docs/qpack-design.md),
[ecosystem lessons](docs/ecosystem-review.md), and
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
```
