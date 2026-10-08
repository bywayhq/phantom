# Why Phantom

Decide whether Phantom fits your project, and which tool to use if it
doesn't.

## When to use Phantom

Use Phantom when you need a Rust HTTP client whose traffic looks like a
specific browser version to the server, at every layer and not only in the
TLS handshake.

- One [profile](reference/glossary.md#profile), Phantom's description of a
  browser, sets the TCP socket options, TLS handshake, HTTP/2 and HTTP/3
  settings, client hints, header order, and WebSocket handshake.
  [Consistency](fingerprinting.md#consistency) explains why all of these
  should name the same browser.
- Phantom uses the protocol and proxy you choose. If it can't, it returns an
  error instead of quietly switching to something else. Falling back from
  HTTP/3 to HTTP/2 is an option you turn on.
- Headers go out in the order you add them.
- Each `Client` keeps its own connections, cookies, and TLS sessions, each
  with a size limit. Nothing is shared across the process.

## When not to use Phantom

You probably want something else if one of these applies:

- You need JavaScript to run. Phantom isn't a browser. Use a browser
  automation tool such as Playwright.
- You need a browser Phantom doesn't have. Phantom has one desktop and one
  Android version each of Chrome, Edge, Brave, Opera, and Firefox. It has no
  Safari, no iOS, and no Linux captures.
- You need many browser versions at once. Phantom drops a browser version
  when it adds the next one. The tools in the
  [comparison below](#compared-with-other-clients) carry more.
- You need a crates.io dependency. Phantom uses a Git or path dependency
  today.
- You can't build C and C++ code. Phantom builds BoringSSL from source, which
  needs CMake, Clang, and a C++ compiler
  ([Prerequisites](getting-started.md#prerequisites)).
- No server you talk to checks fingerprints. A general-purpose client such
  as reqwest is simpler.

## Compared with other clients

This table summarizes what each project's own documentation says, as of
2026-09-24. It doesn't rank the projects or test their output.

| Project | Language | Layers it names | Browsers |
| --- | --- | --- | --- |
| Phantom | Rust | TCP options, TLS, HTTP/1.1, HTTP/2, QUIC, HTTP/3, client hints, header order, WebSocket | Chrome, Edge, Brave, Opera, Firefox: one desktop and one Android version each |
| [curl-impersonate](https://github.com/lexiforest/curl-impersonate) | C (a curl fork) | TLS, HTTP/2, HTTP/3 | Chrome, Edge, Safari, Firefox, Tor |
| [curl_cffi](https://github.com/lexiforest/curl_cffi) | Python (bindings to curl-impersonate) | TLS, HTTP/2, HTTP/3 | Preset fingerprints |
| [wreq](https://github.com/0x676e67/wreq) | Rust | TLS, HTTP/2 | Profiles in the separate `wreq-util` crate |
| [tls-client](https://github.com/bogdanfinn/tls-client) | Go, with Node.js, Python, and C# bindings | TLS, HTTP/2, HTTP/3, QUIC, header order | Chrome, Firefox, Safari, and others |
| [uTLS](https://github.com/refraction-networking/utls) | Go | TLS handshake only ("no parroting beyond ClientHello") | Built-in handshake specs |
| [reqwest](https://docs.rs/reqwest) | Rust | General-purpose client | None |

Phantom names more layers per browser than the others here. It carries fewer
browser versions than curl-impersonate, curl_cffi, or wreq, and unlike wreq
it isn't on crates.io.

## Next

- [Getting started](getting-started.md): build Phantom and send a request.
- [Coverage](reference/coverage.md): browser versions and supported layers.
