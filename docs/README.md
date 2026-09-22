# Phantom documentation

Start with the page that matches what you need. The API reference is the
rustdoc of the `phantom-http` crate: build it with
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
- [Retries and replays](guides/retries.md): connection-setup retries, replay
  classes, and status retry.
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
  dependencies, and fingerprint safety of the dependency graph.

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
