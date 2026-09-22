# Phantom documentation

## What Phantom does

A server can tell HTTP clients apart without trusting any header value. It
also sees the TLS handshake, the HTTP/2 settings, and the order of the fields.
Those details differ between Chrome, Firefox, curl, and a Rust library, and
together they form the client's fingerprint.

Phantom lets you choose that fingerprint. You pick a browser profile, and
Phantom reproduces the layers its recipes cover. Most recipes come from
recordings of a real browser and are compared with them in tests.

These terms appear throughout the documentation:

| Term | Meaning |
| --- | --- |
| Profile | Everything a server can observe about how the client connects |
| Recipe | A ready-made part of a profile, such as `chromium::v152_tls()`. Most come from browser captures; TCP recipes come from browser source |
| Capture | A recording of a real browser's traffic that a recipe is compared with |
| H1, H2, H3 | HTTP/1.1, HTTP/2, and HTTP/3 |
| Route | How the client reaches a server: directly or through a proxy |

## Where to start

- To try Phantom, read [Getting started](getting-started.md), then
  [Using the client](guides/client.md).
- To decide whether Phantom fits, read [Coverage](reference/coverage.md) for
  what works today and [Validation](explanation/validation.md) for the
  evidence behind it.
- To look up an API, build the rustdoc of the `phantom-http` crate with
  `cargo doc -p phantom-http --all-features --no-deps --open`.

## Learn

- [Getting started](getting-started.md): build Phantom and send your first
  request.

## Guides

Task-focused pages for using Phantom in an application.

- [Using the client](guides/client.md): profiles, clients, protocols, bodies,
  trailers, timeouts, responses, and errors.
- [Browser profiles](guides/profiles.md): built-in recipes, custom profiles,
  and client hints.
- [Routes and proxies](guides/routes-and-proxies.md): HTTP, SOCKS5, and
  CONNECT-UDP proxies, authentication, and trust roots.
- [Retries and replays](guides/retries.md): when Phantom may send a request
  again, and when it never will.
- [Connections, redirects, and cookies](guides/connections-and-state.md):
  pools, redirects, cookies, and other client-owned state.
- [HTTP/3 and Alt-Svc](guides/http3.md): exact HTTP/3 and opt-in Alt-Svc
  upgrade.
- [Content decoding](guides/content-decoding.md): opt-in decompression of
  response bodies.
- [Server-sent events](guides/sse.md): the `sse` feature.
- [WebSocket](guides/websocket.md): the `websocket` and `websocket-deflate`
  features.
- [Adding Phantom to a project](guides/downstream.md): git and path
  dependencies, and why another crate cannot swap out Phantom's patched
  dependencies.

## Reference

- [Coverage](reference/coverage.md): the detailed support contract, layer by
  layer, with planned work.
- [Route matrix](reference/route-matrix.md): every scheme, protocol, and route
  combination.
- [Defaults and limits](reference/limits.md): default bounds and off-by-default
  policies.

## Explanation

- [Design](explanation/design.md): principles, ownership, and safety
  boundaries.
- [Validation](explanation/validation.md): how claims are proved, and the
  evidence behind each feature.

## Project

- [Roadmap](roadmap.md): current and planned phases.
- [Contributing](../CONTRIBUTING.md): setup, change discipline, gates, and pull
  requests.
- [Security policy](../SECURITY.md): how to report a vulnerability.

## Internals (for contributors)

- [HTTP/3 internals](internals/http3.md): QUIC, QPACK, CONNECT-UDP, capture,
  and diagnostics.
- [Vendored forks](internals/vendoring.md): patched dependencies and
  downstream CI.
- [Capture tooling](../scripts/capture/README.md): how to record and compare
  browser captures.
- [Development helpers](../scripts/dev/README.md): the shared Cargo lock and
  parallel worktree lanes.

## Writing rules

- Guides describe behavior that exists today and lead with a usable path.
- Design defines stable invariants, not usage steps.
- Coverage is the single detailed support contract.
- Validation explains how claims are proved, not what the product promises.
- Internals contain specialist detail that would distract most readers.
- Planned work appears in the roadmap or the planned lists of coverage.
- Content is linked rather than repeated.
- Rust examples in `README.md`, `getting-started.md`, and every guide compile
  as doctests.

Reproducible bugs use the repository's
[bug-report form](https://github.com/bywayhq/phantom/issues/new?template=bug_report.yml).
