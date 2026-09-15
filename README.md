# Phantom

Phantom is an experimental Rust HTTP client focused on observable browser-compatible wire behavior across TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3.

The project is at the foundation stage. It does not yet make compatibility or impersonation claims.

## Principles

- Wire evidence is the specification.
- Browser behavior is represented by validated profiles rather than transport conditionals.
- Built-in and user-customized profiles use the same typed model.
- Unsupported behavior produces an explicit error instead of a silent fallback.
- Features land as small, runnable vertical slices.

## Current workspace

- `phantom`: the future public client facade
- `phantom-profile`: browser-neutral profile identity and metadata
- `phantom-testkit`: bounded, exact TLS ClientHello capture for deterministic tests

The production networking crate will be added with its first working transport rather than as an empty placeholder.

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md), and [validation model](docs/validation.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
```
