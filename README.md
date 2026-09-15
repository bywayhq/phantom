# Phantom

Phantom is an experimental Rust HTTP client focused on observable browser-compatible wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The first complete TLS and streaming HTTP/1.1 transport slice is implemented.
Its Chrome 152 macOS TLS recipe is checked against a retained local
ClientHello; HTTP/2, HTTP/3, WebSocket, SSE, Firefox, and Safari remain planned.
The project does not yet make broad compatibility or impersonation claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current workspace

- `phantom`: the future public client facade
- `phantom-profile`: browser-neutral profile identity, typed TLS settings, and
  the evidence-backed Chrome 152 macOS TLS recipe
- `phantom-net`: concrete protocol transports; currently streaming HTTP/1.1
  over a private BoringSSL TLS adapter
- `phantom-testkit`: bounded TLS ClientHello capture and strict semantic
  decoding for deterministic differentials

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md), and [validation model](docs/validation.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```
