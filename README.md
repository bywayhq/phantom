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
- request fields, duplicates, pseudo-headers, static trailers, and settings
  retain their order;
- exact protocol and route choices never silently fall back;
- client-owned state and admission queues are bounded; and
- compatibility claims name the captured layer and supporting differential.

Phantom is an HTTP client, not a browser engine. It does not emulate the DOM,
JavaScript, rendering, canvas, fonts, WebRTC, or device fingerprints.

## Current support

| Area | Available today |
| --- | --- |
| Protocols | Ordered streaming H1, multiplexed H2, direct H3 over QUIC, one-handshake direct H1/H2 negotiation, and ordered static request trailers |
| Profiles | Chrome 152 macOS across TLS, H2, H3, QUIC, and client hints; Firefox 154 macOS TLS and H2; Safari 18.5 macOS TLS |
| Routing | Direct; unauthenticated HTTP/1.1 forwarding over plaintext or independently configured TLS proxies for `http://` origins; HTTP/HTTPS CONNECT; and local- or remote-DNS SOCKS5 |
| State | Isolated bounded pools, redirects, timeouts, client hints, TLS sessions, and opt-in cookies |
| Optional APIs | Server-sent events, H1 WebSocket, and opt-in `permessage-deflate` |
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
direct TLS handshake and may select H1 or H2. H3 uses a separate QUIC profile
and remains direct-only.

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
- H3 rejects TCP-only proxy routes before network I/O.
- Streaming request bodies are one-shot and are not replayed implicitly.
- General retry policy, trailers produced dynamically by streaming bodies,
  UDP-capable proxies, and H2/H3 WebSocket remain planned.

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
