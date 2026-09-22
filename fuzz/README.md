# Fuzzing

These `cargo-fuzz` targets feed arbitrary bytes to parsers that read data from
a peer or proxy. They cover Phantom-owned bounded wire decoders, Quinn's QUIC
transport-parameter decoder as Phantom uses it, and the production proxy
parsers reachable through `phantom-net`'s public API. They are not general
fuzz coverage of the BoringSSL, HTTP/2, QUIC, or WebSocket engines.

| Target | Parser | Entry point |
| --- | --- | --- |
| `client_hello` | Test-kit TLS ClientHello summary | `phantom_testkit::tls` |
| `http2_frame` | Test-kit HTTP/2 frame capture | `phantom_testkit::http2` |
| `quic_transport_parameters` | Quinn transport parameters (production) | `TransportParameters::read` |
| `http_connect_response` | HTTP CONNECT proxy response heads (production) | `connect_http_tunnel` over an in-memory stream |
| `proxy_basic_challenge` | `Proxy-Authenticate` challenge lists (production) | `validate_basic_proxy_challenge` |

## Run a target

Install the pinned `cargo-fuzz` version, then run a target from `fuzz/` with a
nightly toolchain. Each command uses the input-size limit (`-max_len`) that CI
uses for that target:

```console
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run client_hello -- -max_len=65536
cargo +nightly fuzz run http_connect_response -- -max_len=65536
cargo +nightly fuzz run http2_frame -- -max_len=262144
cargo +nightly fuzz run proxy_basic_challenge -- -max_len=16384
cargo +nightly fuzz run quic_transport_parameters -- -max_len=65536
```

Targets that link `phantom-net` also build BoringSSL, so they need the native
prerequisites in [CONTRIBUTING.md](../CONTRIBUTING.md#development-setup).

The 256 KiB limit for `http2_frame` keeps mutation throughput high. A
dedicated run may raise it to the largest HTTP/2 frame: a 16,777,215-byte
payload plus the nine-byte frame header.

## What the targets feed

Each target decodes the raw input, then also uses the input to perturb valid
structural seeds, so mutations also exercise nearly valid messages. The QUIC
target calls Quinn's real decoder in both endpoint roles. Its seeds cover
ordered, reordered, duplicate, truncated, and malformed-varint parameters,
including the shape from Quinn advisory
[GHSA-6xvm-j4wr-6v98](https://github.com/quinn-rs/quinn/security/advisories/GHSA-6xvm-j4wr-6v98).

## When a target fails

Minimize a crash or timeout, and add the minimized input as an ordinary
deterministic regression test before you delete the generated artifact.

Generated corpora, artifacts, coverage output, and build products are never
committed.

## CI

The [Parser fuzzing](../.github/workflows/fuzz.yml) workflow runs every target
under AddressSanitizer:

- pull requests and pushes to `main` that change parser paths: 15 seconds per
  target;
- the weekly schedule and manual dispatch: five minutes per target.

CI keeps one corpus per target in the Actions cache. Every run starts from the
newest saved corpus, and only scheduled runs save it back.

## Not fuzzed yet

These peer-facing production parsers have no pure public entry point. Fuzzing
them needs a reviewed fuzzing seam, not new public API:

- the SSE decoder;
- the Alt-Svc field parser;
- SOCKS5 negotiation replies (the public API is TCP-only);
- the HTTP/2 and HTTP/3 ALPS decoders;
- the `Content-Encoding` and `Accept-Encoding` field grammar.
