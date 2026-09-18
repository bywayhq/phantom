# Phantom

**A wire-evidenced, browser-compatible HTTP client for Rust.**

Phantom gives applications explicit control over observable TLS, HTTP/1.1,
HTTP/2, QUIC, and HTTP/3 behavior. Browser behavior lives in typed, validated
profiles rather than hidden transport branches.

> **Status:** Phantom is experimental, under active development, and not
> published to crates.io. It supports source-based evaluation and integration;
> it does not claim complete browser impersonation.

## Why Phantom?

A matching TLS ClientHello is only one part of a client's wire identity. HTTP
settings, header order, QUIC parameters, connection reuse, and cross-request
state are observable too.

Phantom treats captured wire behavior as the specification:

- profiles control concrete TLS, H2, H3, QUIC, and client-hint behavior;
- request fields, duplicates, pseudo-headers, static or body-produced trailers, and settings
  retain their order;
- exact protocol and route choices never silently fall back;
- client-owned state and admission queues are bounded; and
- compatibility claims name the captured layer and supporting differential.

Phantom is an HTTP client, not a browser engine. It does not emulate the DOM,
JavaScript, rendering, canvas, fonts, WebRTC, or device fingerprints.

## Current support

| Area | Available today |
| --- | --- |
| Protocols | Ordered streaming H1, multiplexed H2, exact H3 over direct or SOCKS5-carried QUIC, one-handshake direct H1/H2 negotiation with opt-in bounded Alt-Svc upgrade to H3, and ordered static or streaming-body-produced request trailers |
| Profiles | Chrome 152 macOS across TLS, H2, H3, QUIC, and client hints; Firefox 154 macOS TLS and H2; Safari 18.5 macOS TLS |
| Routing | Direct; HTTP/1.1 forwarding over plaintext or independently configured TLS proxies for `http://` origins, including challenge-driven Basic authentication; HTTP/HTTPS CONNECT; local- or remote-DNS SOCKS5 for H1/H2; and exact H3 over local- or remote-DNS SOCKS5 using RFC 1928 UDP ASSOCIATE |
| State | Isolated bounded pools, redirects, opt-in exact-protocol setup retries, timeouts, client hints, TLS sessions, bounded opt-in Alt-Svc, and opt-in cookies |
| Optional APIs | Server-sent events, H1 WebSocket over direct, HTTP-forward, HTTP-CONNECT, or SOCKS5 routes as applicable, and opt-in `permessage-deflate` |
| Evidence | Retained capture differentials, hostile-peer tests, fuzzing, external suites, and cross-platform gates |

See [Coverage](docs/coverage.md) for the exact supported and planned lifecycle
at each layer.

## A first request

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v152_macos_tls())
        .with_http2(chromium::v152_macos_http2())
        .with_client_hints(chromium::v152_macos_client_hints());

    let client = Client::builder(profile).build()?;
    let response = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .header(RequestHeader::new("accept", "*/*"))
        .send()
        .await?;

    println!("{}", response.status());
    Ok(())
}
```

This request selects exactly HTTP/2. `get_negotiated` instead performs one
direct TLS handshake and may select H1 or H2. With `ClientBuilder::alt_svc`, a
later negotiated request may use a fresh `h3` alternative learned from that
origin. H3 uses a separate QUIC profile and exact H3 also supports direct
routing or local-/remote-DNS SOCKS5 through RFC 1928 UDP ASSOCIATE.

Every response uses the standard `http::Response` view and carries
`ResponseInfo` plus `OrderedResponseHeaders` in its extensions.

[Getting started](docs/getting-started.md) covers the source build and feature
flags. [Using the client](docs/client.md) covers profiles, routes, state,
timeouts, bodies, and responses.

## Deliberate limits

- Exact-protocol requests never downgrade.
- Proxy failure never falls back direct.
- Forward proxy routes send HTTP/1.1 absolute-form requests only; they do not
  switch to CONNECT, negotiated H1/H2, H2, or H3.
- Basic forward-proxy authentication starts every logical request anonymously
  and permits one challenge-driven replay on a fresh same-route connection; no
  challenge state is learned across requests. The same lifecycle applies to
  plaintext WebSocket Upgrade requests sent through a forward proxy.
- H3 accepts direct, local-DNS `socks5://`, or remote-DNS `socks5h://` routes.
  It rejects HTTP forwarding and HTTP CONNECT before origin I/O.
- Streaming request bodies are one-shot and are not replayed implicitly.
- Broader status, post-dispatch, and negotiated-protocol retry policies;
  CONNECT-UDP/MASQUE; Alt-Svc connection racing, persistence, `Alt-Used`, and
  H2 ALTSVC frames; extended CONNECT; and H2/H3 WebSocket remain planned.

These limits make Phantom narrower than a general-purpose client, but keep its
behavior explicit and testable.

## Documentation

The [documentation map](docs/README.md) routes readers by audience and task.

- [Getting started](docs/getting-started.md) — first build and request
- [Using the client](docs/client.md) — integration guide
- [Coverage](docs/coverage.md) — authoritative support contract
- [Design](docs/design.md) — architecture and invariants
- [Validation](docs/validation.md) — evidence and contributor gates
- [HTTP/3 internals](docs/http3.md) — QUIC, QPACK, capture, and diagnostics
- [Roadmap](docs/roadmap.md) — now, next, and later

SSE and WebSocket have focused guides under [`docs/`](docs/). Contributors
should read [CONTRIBUTING.md](CONTRIBUTING.md); suspected vulnerabilities follow
[SECURITY.md](SECURITY.md).
