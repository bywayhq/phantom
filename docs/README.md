# Phantom documentation

Phantom is a Rust HTTP client that reproduces a chosen browser's network
fingerprint; [How servers recognize a client](fingerprinting.md) explains what
that means. This index lists every page by what you want to do.

> For anyone looking for a page. New readers start at the top.

## Start here

- [How servers recognize a client](fingerprinting.md): how a server tells
  clients apart without reading headers.
- [Why Phantom](why-phantom.md): when Phantom fits, when it does not, and how
  it compares with other clients.
- [Getting started](getting-started.md): build Phantom and send your first
  request.

## Build

Task guides for using Phantom in an application.

- [Using the client](guides/client.md): clients, protocols, bodies,
  trailers, timeouts, responses, and errors.
- [Browser profiles](guides/profiles.md): built-in recipes, request
  templates, custom profiles, and client hints.
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

## Look up

- [Coverage](reference/coverage.md): the support contract, layer by layer,
  with planned work.
- [Profiles](reference/profiles.md): every built-in recipe and what it
  covers.
- [Route matrix](reference/route-matrix.md): every scheme, protocol, and
  route combination.
- [Defaults and limits](reference/limits.md): default bounds and
  off-by-default policies.
- [Glossary](reference/glossary.md): the terms these pages use.
- API reference: run `cargo doc -p phantom-http --all-features --no-deps
  --open` in a checkout.

## Understand the evidence

- [Validation](explanation/validation.md): how each claim is proved, and the
  captures and tests behind it.
- [Design](explanation/design.md): principles, ownership, and safety
  boundaries.

## Contribute

- [Contributing](../CONTRIBUTING.md): setup, change discipline, checks, and
  pull requests.
- [Roadmap](roadmap.md): what comes next.
- [Writing the documentation](internals/documentation.md): readers, page
  types, and prose rules for these pages.
- [Browser recipes](internals/browser-recipes.md): how a browser recipe is
  captured and added.
- [HTTP/3 internals](internals/http3.md): QUIC, QPACK, CONNECT-UDP, capture,
  and diagnostics.
- [Vendored forks](internals/vendoring.md): patched dependencies and
  downstream CI.
- [Capture tooling](../scripts/capture/README.md): how to record and compare
  browser captures.
- [Development helpers](../scripts/dev/README.md): the shared Cargo lock and
  parallel worktree lanes.
- [Security policy](../SECURITY.md): how to report a vulnerability.

Report a reproducible bug with the
[bug-report form](https://github.com/bywayhq/phantom/issues/new?template=bug_report.yml).

## For coding agents

- [`llms.txt`](../llms.txt): what an agent must do and never do with
  Phantom's API, with links to the pages above.

## Next

- [How servers recognize a client](fingerprinting.md): the place to start if
  fingerprinting is new to you.
- [Getting started](getting-started.md): the fastest path to a working
  request.
