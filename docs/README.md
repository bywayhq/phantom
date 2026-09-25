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

- [Using the client](guides/client.md): clients, protocols, fields, bodies,
  trailers, and timeouts.
- [Responses and errors](guides/responses.md): response fields in wire
  order, bounded bodies, and error kinds.
- [Browser profiles](guides/profiles.md): built-in recipes and custom
  profiles.
- [Request templates and client hints](guides/request-templates.md): a
  browser's request fields in its order, and its client hints.
- [Routes and proxies](guides/routes-and-proxies.md): routes, HTTP proxies,
  proxy authentication, and trust roots.
- [SOCKS5 and CONNECT-UDP proxies](guides/socks-and-connect-udp.md): SOCKS5
  tunnels, and HTTP/3 through SOCKS5 or CONNECT-UDP.
- [Retries and replays](guides/retries.md): when Phantom may send a request
  again, and when it never will.
- [Connections and client state](guides/connections-and-state.md): pools,
  the address cache, sessions, and clearing learned state.
- [Redirects](guides/redirects.md): follow a bounded number of redirects.
- [Cookies](guides/cookies.md): keep, save, and place cookies.
- [HTTP/3 and Alt-Svc](guides/http3.md): exact HTTP/3, early data, and
  opt-in Alt-Svc upgrade.
- [HTTP/3 discovery](guides/http3-discovery.md): Alt-Svc racing, HTTPS DNS
  records, and Alt-Svc state across restarts.
- [Content decoding](guides/content-decoding.md): opt-in decompression of
  response bodies.
- [Tune throughput and latency](guides/performance.md): per-origin
  concurrency, extra HTTP/2 connections, shorter waits, and what a server
  can observe for each.
- [Server-sent events](guides/sse.md): the `sse` feature.
- [WebSocket](guides/websocket.md): the `websocket` feature over HTTP/1.1
  and HTTP/2.
- [WebSocket fields and compression](guides/websocket-fields.md):
  caller-ordered openings and the `websocket-deflate` feature.
- [Adding Phantom to a project](guides/downstream.md): git and path
  dependencies, and why another crate cannot swap out Phantom's patched
  dependencies.
- [Coming from reqwest](guides/coming-from-reqwest.md): reqwest tasks side by
  side with Phantom, and what behaves differently.
- [Troubleshooting](guides/troubleshooting.md): each error kind, its cause,
  and the fix.
- [Examples](../crates/phantom/examples/README.md): runnable programs, one per
  guide task.
- [Changelog](../CHANGELOG.md): what changed between commits, with a
  migration note for each breaking change.

## Look up

- [Coverage](reference/coverage.md): the support contract, layer by layer,
  with planned work.
- [Profile reference](reference/profiles.md): every built-in recipe and what it
  covers.
- [Route matrix](reference/route-matrix.md): every scheme, protocol, and
  route combination.
- [Defaults and limits](reference/limits.md): default bounds and
  off-by-default policies.
- [WebSocket reference](reference/websocket.md): WebSocket routes,
  templates, response checks, recipes, and compression.
- [Cookie jar rules](reference/cookies.md): what the cookie jar stores,
  sends, rejects, and evicts.
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
- [Capture tools](../scripts/capture/README.md): how to record and compare
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
- [Getting started](getting-started.md): one path from zero to a working
  request.
