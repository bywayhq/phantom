# Fuzzing

These targets exercise Phantom-owned, bounded wire decoders. They do not fuzz
the BoringSSL, HTTP/2, QUIC, or WebSocket engines already owned by upstream
dependencies.

Run one target with the pinned `cargo-fuzz` version and a nightly toolchain:

```console
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run client_hello -- -max_len=65536
cargo +nightly fuzz run http2_frame -- -max_len=262144
```

The targets exercise arbitrary input and valid structural seeds perturbed by
the same input. A crash or timeout must be minimized and promoted into an
ordinary deterministic regression before its generated artifact is removed.
Generated corpora, artifacts, coverage output, and build products stay local.
Relevant pull requests run each target for 15 seconds; scheduled and manually
dispatched jobs run each target for five minutes.
The scheduled 256 KiB HTTP/2 bound favors mutation throughput; dedicated runs
may raise it to the protocol's 16,777,215-byte payload ceiling plus its
nine-byte header.
