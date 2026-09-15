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

Networking and capture crates will be added with their first working implementations rather than as empty placeholders.

See [the roadmap](docs/roadmap.md), [architecture](docs/architecture.md), and [validation model](docs/validation.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## License

No license has been selected yet. Until one is added, all rights are reserved.
External contributions are not currently accepted.
