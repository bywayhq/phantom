# Phantom documentation

Phantom is a Rust HTTP client that connects the way a real browser does.
Find the page you need below. If you're new, start at the top.

## Start here

- [How servers recognize a client](fingerprinting.md): what a server sees
  besides your headers.
- [Why Phantom](why-phantom.md): when to use Phantom and when not to.
- [Getting started](getting-started.md): install and send your first request.

## Guides

- [Using the client](guides/client.md): requests, protocols, bodies, timeouts.
- [Responses and errors](guides/responses.md): read responses and handle
  errors.
- [Browser profiles](guides/profiles.md): pick a browser or build your own.
- [Request templates and client hints](guides/request-templates.md): send a
  browser's headers.
- [Request bodies](guides/request-bodies.md): bounded form, JSON, and multipart
  uploads with explicit header placement.
- [Routes and proxies](guides/routes-and-proxies.md): HTTP proxies and trust
  roots.
- [SOCKS5 and CONNECT-UDP proxies](guides/socks-and-connect-udp.md): SOCKS5,
  and HTTP/3 through a proxy.
- [Retries and replays](guides/retries.md): when a request is sent again.
- [Connections and client state](guides/connections-and-state.md): pools,
  sessions, and source addresses.
- [Resolve host names](guides/name-resolution.md): DNS, overrides, and your
  own resolver.
- [Redirects](guides/redirects.md): follow redirects.
- [Cookies](guides/cookies.md): keep, save, and send cookies.
- [HTTP/3 and Alt-Svc](guides/http3.md): send requests over HTTP/3.
- [HTTP/3 discovery](guides/http3-discovery.md): find HTTP/3 servers
  automatically.
- [Content decoding](guides/content-decoding.md): decompress response bodies.
- [Tune throughput and latency](guides/performance.md): more connections,
  shorter waits.
- [Server-sent events](guides/sse.md): read an event stream.
- [WebSocket](guides/websocket.md): open a WebSocket.
- [WebSocket fields and compression](guides/websocket-fields.md): custom
  WebSocket headers and compression.
- [Adding Phantom to a project](guides/downstream.md): the git dependency.
- [Coming from reqwest](guides/coming-from-reqwest.md): reqwest tasks in
  Phantom.
- [Troubleshooting](guides/troubleshooting.md): errors and their fixes.
- [Examples](../crates/phantom/examples/README.md): runnable programs.
- [Changelog](../CHANGELOG.md): changes and migration notes.

## Reference

- [Coverage](reference/coverage.md): what each browser recipe covers.
- [Profile reference](reference/profiles.md): every built-in recipe.
- [Route matrix](reference/route-matrix.md): schemes, protocols, and proxies.
- [Environment proxies](reference/environment-proxies.md): snapshot variables,
  route precedence, and bypass rules.
- [Tracing](reference/tracing.md): request spans, fields, and outcomes.
- [Defaults and limits](reference/limits.md): default values and bounds.
- [WebSocket reference](reference/websocket.md): WebSocket details.
- [Cookie jar rules](reference/cookies.md): how the cookie jar behaves.
- [Glossary](reference/glossary.md): terms used in these pages.
- API reference: run `cargo doc -p phantom-http --all-features --no-deps
  --open` in a checkout.

## Background

- [Validation](explanation/validation.md): how each recipe is tested.
- [Design](explanation/design.md): why Phantom works the way it does.

## Contribute

- [Contributing](../CONTRIBUTING.md): setup, checks, and pull requests.
- [Roadmap](roadmap.md): what comes next.
- [Phase 2 checklist](internals/phase2.md): API milestones and completion
  criteria.
- [Writing the documentation](internals/documentation.md): how these pages
  are written.
- [Browser recipes](internals/browser-recipes.md): add a browser recipe.
- [HTTP/3 internals](internals/http3.md): how the HTTP/3 stack fits
  together.
- [Vendored forks](internals/vendoring.md): patched dependencies.
- [Capture tools](../scripts/capture/README.md): record browser traffic.
- [Development helpers](../scripts/dev/README.md): parallel work and the
  gate.
- [Security policy](../SECURITY.md): report a vulnerability.
- [Bug report](https://github.com/bywayhq/phantom/issues/new?template=bug_report.yml):
  report a bug.

Coding agents should read [`llms.txt`](../llms.txt).

## Next

- [Getting started](getting-started.md): send your first request.
