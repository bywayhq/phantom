# Why Phantom

Decide whether Phantom fits your project, and see which tools fit better when
it does not.

> For evaluators who have read [How servers recognize a client](fingerprinting.md).

## When to use Phantom

Phantom fits when you need a Rust HTTP client whose traffic matches a named
browser build at more than one layer, and you want to know what each claim
rests on.

- A [profile](reference/glossary.md#profile) can carry the TCP socket
  options, TLS ClientHello, HTTP/2 SETTINGS and priority, QUIC transport
  parameters, HTTP/3 SETTINGS, client hints, request field order, and
  WebSocket opening of one browser build.
  [Consistency](fingerprinting.md#consistency) explains why all layers should
  name the same browser.
- Most browser recipes come from traffic recorded from a real browser and
  retained under `fixtures/`, and tests compare Phantom's output with those
  recordings. Where a recording cannot show a detail, such as TCP socket
  options, the recipe comes from browser source and
  [Validation](explanation/validation.md) says so.
- Phantom never falls back to another protocol or route. A request for
  HTTP/3 never retries over HTTP/2, and a failed proxy never gives way to a
  direct connection: Phantom uses the protocol and
  [route](reference/glossary.md#route) you chose or returns a typed error.
- Header fields, duplicates, and trailers go out in the order you add them,
  and SETTINGS and pseudo-header fields in the order the profile lists them.
- Connection pools, cookies, Alt-Svc entries, and TLS session caches belong
  to one `Client`, each with a size limit. Nothing is global to the process.
- The workspace forbids `unsafe` code, except in one private, documented
  module that calls BoringSSL's QUIC API.

## When not to use Phantom

Phantom is a network client, and it covers few browser builds. Another tool
is a better choice in these cases:

- You need JavaScript to run. Phantom is not a browser (see
  [Coverage](reference/coverage.md#at-a-glance)); use a browser automation
  tool such as Playwright.
- You need a browser Phantom has no recipe for. Phantom ships Chrome 154,
  Edge 153, and Firefox 156, one build each, all captured on Windows 11. It
  has no Safari, mobile, macOS, or Linux captures, and no Firefox HTTP/3
  recipe. [Coverage](reference/coverage.md#browser-profiles) has the details.
- You need many browser versions or operating systems. Phantom retires a
  browser version when it adds the next one. Tools that ship more targets
  are listed [below](#compared-with-other-clients).
- You need a stable API from crates.io today. Phantom is pre-1.0, is not
  published on crates.io, and its API can change between commits. You pin a
  git revision; see [Adding Phantom to a project](guides/downstream.md).
- You cannot build C and C++ code. Phantom builds BoringSSL from source,
  which needs CMake, Clang, and a C++ toolchain; see
  [Prerequisites](getting-started.md#prerequisites).
- You need a general-purpose HTTP client. If no server you talk to
  checks fingerprints, a general-purpose client such as reqwest fits better.

## Compared with other clients

The table records what each project's own documentation states, as of
2026-09-24. It does not rank the projects or measure their output.

| Project | Language | Layers its documentation names | Browser targets its documentation lists |
| --- | --- | --- | --- |
| Phantom | Rust | TCP socket options, TLS, HTTP/1.1, HTTP/2, QUIC, HTTP/3, client hints, request templates, WebSocket openings | 3 builds: Chrome 154, Edge 153, Firefox 156 |
| [curl-impersonate](https://github.com/lexiforest/curl-impersonate) | C (a curl fork) | TLS, HTTP/2, HTTP/3 | Chrome, Edge, Safari, Firefox, and Tor targets |
| [curl_cffi](https://github.com/lexiforest/curl_cffi) | Python (bindings to curl-impersonate) | TLS, HTTP/2, HTTP/3 | Preset fingerprints in the open-source release |
| [wreq](https://github.com/0x676e67/wreq) | Rust | TLS, HTTP/2 | Emulation profiles, kept in the separate `wreq-util` crate |
| [tls-client](https://github.com/bogdanfinn/tls-client) | Go, with Node.js, Python, and C# bindings | TLS, HTTP/2, HTTP/3 and QUIC, custom header order | A `profiles` package covering Chrome, Firefox, Safari, and others |
| [uTLS](https://github.com/refraction-networking/utls) | Go | TLS ClientHello only; its README states there is "no parroting beyond ClientHello" | Built-in ClientHello specifications |
| [reqwest](https://docs.rs/reqwest) | Rust | General-purpose HTTP client; its documentation does not aim to match a browser | None |

### Where Phantom differs

- Its documentation ties each layer's claim to a retained capture and the
  test that replays it, in [Validation](explanation/validation.md).
- It refuses to fall back to another protocol or route.
- It ships fewer browser builds than curl-impersonate, curl_cffi, or wreq,
  and it is not on crates.io, while wreq is.

## Next

- [Getting started](getting-started.md): build Phantom and send a request.
- [Coverage](reference/coverage.md): the support contract, layer by layer.
- [Validation](explanation/validation.md): the evidence behind each claim.
