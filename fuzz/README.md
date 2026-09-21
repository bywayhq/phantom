# Fuzzing

These targets exercise Phantom-owned, bounded wire decoders, the selected
Quinn transport-parameter decoder at Phantom's QUIC TLS boundary, and the
production proxy parsers reachable through `phantom-net`'s public API. They do
not claim general fuzz coverage of BoringSSL, HTTP/2, QUIC, or WebSocket
engines.

| Target | Parser | Entry point |
| --- | --- | --- |
| `client_hello` | Test-kit TLS ClientHello summary | `phantom_testkit::tls` |
| `http2_frame` | Test-kit HTTP/2 frame capture | `phantom_testkit::http2` |
| `quic_transport_parameters` | Quinn transport parameters (production) | `TransportParameters::read` |
| `http_connect_response` | HTTP CONNECT proxy response heads (production) | `connect_http_tunnel` over an in-memory stream |
| `proxy_basic_challenge` | `Proxy-Authenticate` challenge lists (production) | `validate_basic_proxy_challenge` |

Peer-facing production parsers without a pure public entry point are not
fuzzed yet; covering them needs a reviewed fuzzing seam rather than new public
API: the SSE decoder, the Alt-Svc field parser, SOCKS5 negotiation replies
(TCP-only public API), the HTTP/2 and HTTP/3 ALPS decoders, and the
`Content-Encoding`/`Accept-Encoding` field grammar.

Run one target with the pinned `cargo-fuzz` version and a nightly toolchain:

```console
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run client_hello -- -max_len=65536
cargo +nightly fuzz run http_connect_response -- -max_len=65536
cargo +nightly fuzz run http2_frame -- -max_len=262144
cargo +nightly fuzz run proxy_basic_challenge -- -max_len=16384
cargo +nightly fuzz run quic_transport_parameters -- -max_len=65536
```

The targets exercise arbitrary input and valid structural seeds perturbed by
the same input. The QUIC target invokes Quinn's real decoder in both endpoint
roles and embeds ordered, reordered, duplicate, truncated, and malformed
varint seeds, including the shape from GHSA-6xvm-j4wr-6v98. A crash or timeout
must be minimized and promoted into an ordinary deterministic regression before
its generated artifact is removed.
Generated corpora, artifacts, coverage output, and build products are not
committed. CI keeps one corpus per target in the Actions cache: every run
restores the newest saved corpus, and only scheduled runs save it back.
Relevant pull requests run each target for 15 seconds; scheduled and manually
dispatched jobs run each target for five minutes. Targets that link
`phantom-net` also build BoringSSL, so they need the native prerequisites
listed in the contributing guide.
The scheduled 256 KiB HTTP/2 bound favors mutation throughput; dedicated runs
may raise it to the protocol's 16,777,215-byte payload ceiling plus its
nine-byte header.
