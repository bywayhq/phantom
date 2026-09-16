# Ecosystem architecture and pull-request audit

Status: research snapshot, 2026-09-15. This document informs design; it does not
make the planned API public.

## Method and evidence boundaries

This audit read the named projects' source trees and public API declarations,
then sampled tests, examples, benchmarks, and pull-request discussions that
changed or challenged architecture. It compared them with Phantom's actual
exports and the contracts in [architecture.md](architecture.md),
[configuration.md](configuration.md), and [rust-quality.md](rust-quality.md).
Repository observations below are pinned to these revisions:

| Project | Revision inspected |
|---|---|
| `sardanioss/httpcloak` | [`3037912`](https://github.com/sardanioss/httpcloak/tree/3037912) |
| `unreleased/hellojs` | [`588380d`](https://github.com/unreleased/hellojs/tree/588380d) |
| `0x676e67/wreq` | [`cd76bcd`](https://github.com/0x676e67/wreq/tree/cd76bcd) |
| `bogdanfinn/tls-client` | [`34718e1`](https://github.com/bogdanfinn/tls-client/tree/34718e1) |
| `0xARYA/playground`, `integrate/wave-46` | [`b56c755`](https://github.com/0xARYA/playground/tree/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3) |
| `sleeyax/cronet-rs` | [`6c36703`](https://github.com/sleeyax/cronet-rs/tree/6c36703) |
| `yfedoseev/browser_oxide` | [`9cd4af3`](https://github.com/yfedoseev/browser_oxide/tree/9cd4af3) |
| `h4ckf0r0day/obscura` | [`4b70288`](https://github.com/h4ckf0r0day/obscura/tree/4b70288) |
| `WeAreMaven/prism` | [`bc1fe13`](https://github.com/WeAreMaven/prism/tree/bc1fe13) |
| `refraction-networking/utls` | [`23b1dac`](https://github.com/refraction-networking/utls/tree/23b1dac) |
| `Noooste/azuretls-client` | [`756acc9`](https://github.com/Noooste/azuretls-client/tree/756acc9) |

“Observed” means source, documentation, test, or PR text directly supports the
statement. “Inference” marks an architectural conclusion drawn from those
facts. A closed PR is not treated as a rejected design unless its discussion
says so.

Explicit gaps:

- Curlium is described by Scrapfly's public product and release pages, but no
  public source tree, callable library API, tests, benchmark corpus, or PR
  history was available for inspection. Curlium statements are therefore
  vendor claims, not source-verified implementation facts.
- `hellojs` had one open PR and no merged or closed PRs; Prism had no PRs. There
  is no representative rejection history to invent for either project.
- The inspected `playground` branch commit was not associated with a public PR.
  Its branch source and decision records, not an inferred review decision, are
  the evidence.
- Several closed PRs had no maintainer rationale. They are listed as gaps, not
  evidence that maintainers rejected the underlying architecture.
- This is a design audit, not a reproducible performance comparison. Benchmark
  harness structure was inspected where present; benchmarks were not run.
- GitHub API access was authenticated and did not rate-limit this pass. Source
  may nevertheless have moved after the pinned revisions.

## Phantom baseline: what exists and what does not

Observed: the `phantom` facade currently re-exports only profile identity
types; its rustdoc explicitly says the reusable client, sessions, and protocol
routing are planned ([facade source](../crates/phantom/src/lib.rs)). The actual
request surface is in `phantom-net`: public HTTP/1 and HTTP/2 modules expose
one-shot empty-body `send_get` functions, ordered `Vec<RequestHeader>`, parsed
`OriginForm`, streaming response bodies, protocol-specific TLS connectors, and
typed errors ([module](../crates/phantom-net/src/lib.rs),
[HTTP/1](../crates/phantom-net/src/http1/mod.rs),
[HTTP/2](../crates/phantom-net/src/http2/mod.rs),
[request primitives](../crates/phantom-net/src/request.rs)). The profile crate
publicly exposes concrete ordered TLS and HTTP/2 recipes; a QUIC recipe exists
only as a private, test-covered module. The public runtime path is TLS plus
HTTP/1 and HTTP/2, not HTTP/3
([profile exports](../crates/phantom-profile/src/lib.rs)).

The intended boundary is already explicit: profile and route are independent;
session state owns cookies, tickets, DNS, and Alt-Svc; the pool owns physical
connections and admission; the pool key includes route, origin/SNI, protocol,
complete profile identity, proxy identity, DNS mode, and local binding; failure
must not silently escape to a direct route. HTTP/3, SSE, WebSocket, `Client`,
`Session`, and `Route` are planned, not shipped
([architecture](architecture.md)). Configuration must be concrete, applied,
and verified rather than an opaque option bag
([configuration](configuration.md)); runtime failures must not panic, task and
cancellation ownership must be explicit, and observability must not expose
secrets by default ([Rust quality](rust-quality.md)).

## Architecture comparison

| Project | Role and engine | Lifecycle, protocols, and state | Architectural evidence and Phantom reading |
|---|---|---|---|
| **httpcloak** | Go browser-shaped HTTP stack over forks of `net`, HTTP, uTLS, QUIC, and QPACK ([dependencies](https://github.com/sardanioss/httpcloak/blob/3037912/go.mod), [architecture](https://github.com/sardanioss/httpcloak/blob/3037912/docs/docs/reference/architecture.md)). | Root facade → goroutine-safe session → per-host H1/H2/H3 transports; session owns cookies, DNS, TLS cache/tickets, Alt-Svc/protocol knowledge, warmup/fork/save/restore; proxy modes include CONNECT, SOCKS5, and MASQUE. | Strongest end-to-end reference for keeping profile, DNS, route, protocol racing, header order, redirects, resumption, and pooling coherent. Its large root `Request` and option surface is useful evidence of capability, not a model for Phantom's initial API ([root API](https://github.com/sardanioss/httpcloak/blob/3037912/httpcloak.go), [session](https://github.com/sardanioss/httpcloak/blob/3037912/session/session.go)). |
| **hellojs** | Pure JavaScript TLS 1.2/1.3, HTTP/1, HTTP/2, QUIC/HTTP/3 implementation; only `fzstd` and `mlkem` runtime dependencies are declared ([package](https://github.com/unreleased/hellojs/blob/588380d/package.json), [client](https://github.com/unreleased/hellojs/blob/588380d/lib/client.js)). | Request-shaped facade, pool, cookies, TLS sessions, Alt-Svc, automatic H3/TCP selection, proxy CONNECT, retries, early data, event hooks. H1 is serialized; H2 responses stream; the inspected H3 path returns a buffered body ([types](https://github.com/unreleased/hellojs/blob/588380d/index.d.ts), [pool](https://github.com/unreleased/hellojs/blob/588380d/lib/pool.js)). | Valuable executable protocol reference and tests, especially for pool/session-cache concurrency. Avoid deriving a Phantom profile from its Peet converter: its own comments distinguish mirrored from unavailable fields and synthesize ECH GREASE ([converter](https://github.com/unreleased/hellojs/blob/588380d/lib/profiles/from-peet.js)). |
| **wreq** | Rust client on `btls`/BoringSSL, `wreq-proto`, Tokio or Compio, and Tower; supports HTTP/1 and HTTP/2, not HTTP/3 ([manifest](https://github.com/0x676e67/wreq/blob/cd76bcd/Cargo.toml), [exports](https://github.com/0x676e67/wreq/blob/cd76bcd/src/lib.rs)). | Cloneable `Client` around shared internals, builder-owned pool, ordered emulation profiles, cookies, redirects/retries, compression, HTTP/HTTPS/SOCKS/UDS proxies, custom resolver/socket choices, streaming bodies, H1/H2 WebSocket, and Tower layers ([client](https://github.com/0x676e67/wreq/blob/cd76bcd/src/client.rs), [emulation](https://github.com/0x676e67/wreq/blob/cd76bcd/src/client/emulate.rs), [proxy](https://github.com/0x676e67/wreq/blob/cd76bcd/src/proxy.rs), [WebSocket](https://github.com/0x676e67/wreq/blob/cd76bcd/src/client/ws.rs)). | Best near-term Rust implementation substrate and request/body/error reference. Inference: importing its entire builder or layer model would leak backend policy and create the speculative surface Phantom forbids; adapt it behind Phantom-owned types. Its H1/H2 benchmark matrix and integration tests are useful gate patterns ([benchmarks](https://github.com/0x676e67/wreq/tree/cd76bcd/bench), [tests](https://github.com/0x676e67/wreq/tree/cd76bcd/tests)). |
| **tls-client** | Go facade over forked `fhttp`, uTLS, and QUIC plus WebSocket support ([dependencies](https://github.com/bogdanfinn/tls-client/blob/34718e1/go.mod), [client](https://github.com/bogdanfinn/tls-client/blob/34718e1/client.go)). | Option-built client with cookie jar, shared transports, H1/H2/H3 profiles, request hooks, custom dialer, proxy mutation, cert pins, session tickets, protocol racing, and H1 WebSocket ([options](https://github.com/bogdanfinn/tls-client/blob/34718e1/client_options.go), [profiles](https://github.com/bogdanfinn/tls-client/blob/34718e1/profiles/profiles.go)). | Particularly relevant route rule: configuration rejects protocol racing through proxies that cannot carry H3 rather than allowing QUIC to bypass the proxy. Profiles without captured H3 settings can receive minimal defaults, so support must not be confused with browser parity ([client validation](https://github.com/bogdanfinn/tls-client/blob/34718e1/client.go), [H3 tests](https://github.com/bogdanfinn/tls-client/tree/34718e1/tests)). |
| **Curlium** | Vendor-described curl distribution patched around BoringSSL, nghttp2/nghttp3, and ngtcp2, with browser TLS/H2/H3 emulation ([product](https://scrapfly.io/curlium)). | Vendor claims include session resumption/0-RTT, localized DNS/IP cache, proxy coherence, ordered QUIC transport parameters and SETTINGS, GREASE, ECH, and UDP-capable proxy modes ([release notes](https://scrapfly.io/docs/release-notes?view=markdown)). | Treat its cross-layer coherence checklist as requirements evidence, not verified implementation or API evidence. Defer any design conclusion that depends on its internals. |
| **playground `crates/egress`** | Rust engine-independent synchronous `Transport` seam; feature-gated Wreq adapter bridges to an async runtime ([trait](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/crates/types/src/transport.rs), [adapter](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/crates/egress/src/live.rs)). | A jar-bound wrapper is the sole cookie owner and implements bounded redirects; the Wreq adapter aligns TLS/H2 priorities, ordered headers, UA/client hints, proxies, Accept-CH/Critical-CH, and caps buffered responses at 64 MiB. Realtime SSE/WS is a typed but unimplemented seam; no H3 path exists ([jar/redirect wrapper](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/crates/egress/src/transport.rs), [realtime seam](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/crates/egress/src/lib.rs)). | Strong evidence for one cookie owner, bounded redirect transactions, and client-hint/profile cohesion. Its `Rc<RefCell<_>>` session and sync/`block_on` bridge are browser-embedding choices, not a `Send + Sync` network-client model. |
| **cronet-rs** | Rust FFI wrapper over Cronet C API plus a small blocking `http::Request` client ([exports](https://github.com/sleeyax/cronet-rs/blob/6c36703/src/lib.rs), [client](https://github.com/sleeyax/cronet-rs/blob/6c36703/src/client/client.rs)). | Raw engine exposes QUIC/H2/cache/storage/UA/language/pinning/hints/experimental options; lower request API is callback-driven with cancel/status/metrics. The high-level client uses threads/channels and assembles a buffered response ([engine parameters](https://github.com/sleeyax/cronet-rs/blob/6c36703/src/engine_params.rs), [raw request](https://github.com/sleeyax/cronet-rs/blob/6c36703/src/url_request.rs)). | A possible future backend reference, but it publicly leaks FFI types, necessarily uses `unsafe`, contains recoverable-path `unwrap`/unfinished listener code, needs external Cronet binaries, and is marked no longer maintained ([README](https://github.com/sleeyax/cronet-rs/blob/6c36703/README.md)). This conflicts with Phantom's present safety and backend-isolation rules. |
| **browser_oxide** | Rust headless browser: BoringSSL H1/H2, Quinn/rustls H3, V8 through `deno_core`, WebSocket through `tokio-tungstenite` ([manifest](https://github.com/yfedoseev/browser_oxide/blob/9cd4af3/crates/browser_oxide/Cargo.toml), [network facade](https://github.com/yfedoseev/browser_oxide/blob/9cd4af3/crates/browser_oxide/src/net/mod.rs)). | Process-shared session holds cookies/DNS/Alt-Svc; H2 and QUIC pools key connections by host/port; `Page` is current-thread/`LocalSet` oriented. Responses are buffered and methods are narrow. Invalid proxy parsing logs and proceeds without a proxy; HTTPS proxy documentation notes plain CONNECT behavior ([pool](https://github.com/yfedoseev/browser_oxide/blob/9cd4af3/crates/browser_oxide/src/net/pool.rs), [proxy](https://github.com/yfedoseev/browser_oxide/blob/9cd4af3/crates/browser_oxide/src/net/proxy.rs)). | Inference: host/port-only pool identity and process-global state are too coarse for Phantom profiles/routes. Silent direct continuation on bad proxy input is explicitly unsuitable. Mixed TLS engines across H2/H3 also require parity proof before adoption. |
| **obscura** | Full Rust browser. Public API is `Browser`/`Page`; networking selects ordinary Reqwest or feature-gated Wreq stealth transport ([facade](https://github.com/h4ckf0r0day/obscura/blob/4b70288/crates/obscura/src/lib.rs), [stealth client](https://github.com/h4ckf0r0day/obscura/blob/4b70288/crates/obscura-net/src/wreq_client.rs)). | Browser builder configures stealth, proxy, UA, and storage; page exposes navigation, evaluation, DOM, interception, and browser-level cookies. Network responses are deliberately bounded/buffered; JS/browser subsystems own WebSocket and SSE semantics ([browser](https://github.com/h4ckf0r0day/obscura/blob/4b70288/crates/obscura/src/browser.rs), [network client](https://github.com/h4ckf0r0day/obscura/blob/4b70288/crates/obscura-net/src/client.rs)). | Useful consumer of Wreq and model for routing subresources through one policy surface; not evidence for making Phantom a browser or for exposing page/interception APIs. |
| **Prism** | Observer, not an HTTP client: passive eBPF/capture plus TLS, HTTP/2, and QUIC parsing and an H1/H2/H3 server ([workspace](https://github.com/WeAreMaven/prism/blob/bc1fe13/Cargo.toml), [README](https://github.com/WeAreMaven/prism/blob/bc1fe13/README.md)). | Streaming TLS inspection is bounded; signal extraction covers TLS, H2 settings/priority/pseudo-order and QUIC/transport data; project includes fuzzing, tests, and profiling scripts ([TLS capture](https://github.com/WeAreMaven/prism/blob/bc1fe13/crates/capture/src/tls.rs), [extractor](https://github.com/WeAreMaven/prism/blob/bc1fe13/crates/server/src/extractor.rs), [fuzzing](https://github.com/WeAreMaven/prism/tree/bc1fe13/fuzz)). | Adopt as a local validation-observer pattern. Its normalized JA3/JA4/Akamai/Peet-style outputs are derived views, not a complete profile recipe or an oracle. |
| **uTLS** | Go TLS implementation/fork only: it shapes ClientHello; it is not an HTTP, proxy, cookie, session, or pool facade ([README](https://github.com/refraction-networking/utls/blob/23b1dac/README.md), [connection API](https://github.com/refraction-networking/utls/blob/23b1dac/u_conn.go)). | `UClient` selects a preset/random/custom `ClientHelloID`; ordered `ClientHelloSpec` extensions, captured-hello fingerprinting, session tickets/cache, `HandshakeContext`, and QUIC TLS hooks are exposed. QUIC hooks do not constitute a QUIC transport ([common types](https://github.com/refraction-networking/utls/blob/23b1dac/u_common.go), [QUIC](https://github.com/refraction-networking/utls/blob/23b1dac/u_quic.go)). | Its explicit ordered recipe and capture workflow are valuable. Its generic extensions and mutable handshake internals are too low-level for Phantom's public facade; the README itself warns that parroting is imperfect and recommends packet inspection. |
| **azuretls-client** | Go stateful session over custom HTTP/TLS/QUIC transports ([session](https://github.com/Noooste/azuretls-client/blob/756acc9/session.go), [transport](https://github.com/Noooste/azuretls-client/blob/756acc9/transport.go)). | Public mutable session carries browser/TLS specs, H1/H2/H3 transports and settings, headers, cookies, proxy, hooks, timeouts, and dial/config callbacks. `Do` accepts heterogeneous `...any` modifiers; default responses buffer bytes, while `IgnoreBody` exposes a raw body; H1 WebSocket is separate ([structs](https://github.com/Noooste/azuretls-client/blob/756acc9/structs.go), [request](https://github.com/Noooste/azuretls-client/blob/756acc9/request.go), [response](https://github.com/Noooste/azuretls-client/blob/756acc9/response.go), [WebSocket](https://github.com/Noooste/azuretls-client/blob/756acc9/websocket.go)). | Broad functionality, but runtime type switching, public mutable backend state, insecure proxy-TLS escape paths, and a panic for unsupported browser H3 profile construction are direct anti-patterns for Phantom ([profiles](https://github.com/Noooste/azuretls-client/blob/756acc9/profiles.go), [proxy](https://github.com/Noooste/azuretls-client/blob/756acc9/proxy.go)). |

## Public API-surface matrix

“Yes” means an actual inspected public surface, not merely an internal type.
“Partial” identifies a meaningful limit. Phantom's planned entries are not
counted as current.

| Project | Construction and ownership | Request/response surface | Profiles and protocols | Route, DNS, state | Streaming/realtime | Cancellation, errors, concurrency, observability | Escape hatches / defaults |
|---|---|---|---|---|---|---|---|
| **Phantom current** | No facade client/session/pool; profile IDs at facade | `send_get`; ordered headers; streaming H1/H2 body | Public TLS/H2 recipes; private QUIC recipe; runtime H1/H2 only | No public route/DNS/cookies/client hints yet | Response body yes; upload, WS, SSE no | Typed errors; body drop/completion cancels; connectors own protocol tasks | No backend escape; unsupported surfaces absent |
| **httpcloak** | `New(preset, options...)`; `Client`/goroutine-safe `Session`; fork/persist/close | Rich `Request`, ordered exact headers, replay factory, streaming response | TLS + H1/H2/H3; presets plus custom fingerprint | CONNECT/SOCKS5/MASQUE, DNS/ECH, cookies, hints, tickets | Body streams; no distinct SSE API; WebSocket not a core surface | Context/timeouts, typed transport errors, hooks/metrics; graceful and hard close | Many options/callbacks; root facade defaults to managed state |
| **hellojs** | `request()` plus shared `Pool`; implicit state | request-compatible object; stream flag; body/json/form/query | TLS + H1/H2/H3; JS profile objects/from-Peet conversion | CONNECT, pool-keyed route, cookies, sessions, Alt-Svc | H1/H2 response streams; H3 response buffered; no WS/SSE API | Abort/timeout/error codes; event emitter; concurrency semaphores | Broad option bag and low-level TLS/Pool exports |
| **wreq** | `ClientBuilder` → cloneable `Client` with shared pool | Request builder, upload/download streams, multipart, upgrades | TLS + H1/H2; detailed emulation/TLS/H2 builders; no H3 | HTTP(S)/SOCKS/UDS, custom DNS/socket, cookies | Streams; H1/H2 WebSocket; no SSE helper | Futures/timeouts, typed `Error`, `Client` shared; Tower hooks | Public backend-shaped TLS and connector/layer controls; redirects off by default |
| **tls-client** | option-built `HttpClient`; shared transports/jar | net/http-style request/response and helpers | TLS + H1/H2/H3; concrete/custom profiles | proxy mutation, custom dialer, cookies, tickets; SOCKS5 can carry H3 | body streams; H1 WebSocket; no SSE helper | request contexts, client timeout, logger/hooks; concurrent-use tests | Numerous client options; validates incompatible protocol/proxy choices |
| **Curlium** | Unknown public library API | Product CLI/API claims only | Vendor-claimed TLS + H1/H2/H3 | Vendor-claimed proxy/DNS/session coherence | Not source-verifiable | Not source-verifiable | Not source-verifiable |
| **playground egress** | trait-injected transport; jar-bound page/session owner | owned request/response, bounded buffered response | Wreq TLS + H1/H2; aligned profile/headers; no H3 | proxy + single cookie owner + redirects + client hints | WS/SSE seam only, no implementation | sync trait; `Rc<RefCell>` owner is not `Send`; explicit bounds | Wreq feature is private to adapter; stub default |
| **cronet-rs** | `Engine`/callbacks or blocking `Client` | raw `UrlRequest` plus blocking `http::Request`; buffered high-level result | Cronet H1/H2/QUIC, not ordered browser recipe API | Cronet cache/storage/DNS internals; no session facade | raw callback reads; high-level buffers; no WS/SSE | raw cancel/status/metrics; high-level thread/channel; error enum | Raw C/FFI objects and experimental-options string are public |
| **browser_oxide** | `HttpClient`; process `SharedSession`; browser `PagePool` | GET/POST-shaped buffered network result; page navigation | profile-backed H1/H2/H3, split TLS engines | env/profile proxy, DNS, global cookies/Alt-Svc/Accept-CH | browser WS; buffered HTTP; no standalone SSE client | Tokio; pages require current-thread local execution; logging | Browser/network modules exposed; invalid proxy can become direct |
| **obscura** | `Browser::builder`; `Page`; internal transport choice | page navigation/interception; bounded buffered net result | ordinary or Wreq stealth H1/H2 | browser storage/cookies/proxy/SSRF resolver | browser JS WS/SSE; bounded download handles proposed | async browser errors; page/isolate lifecycle; tracing | Browser options, not low-level TLS; stealth is feature gated |
| **Prism** | observer/server builders, not a client | capture/extraction surfaces | observes TLS/H2/QUIC fingerprints | observes peer traffic; no client state | bounded capture stream | cancellation/drain and metrics primitives | raw capture plus normalized fingerprint formats |
| **uTLS** | `UClient(conn, config, id)` → `UConn` | TLS connection only | ClientHello preset/random/custom; TLS + QUIC hooks, no HTTP | session cache/tickets; no routes/DNS/cookies/hints | TLS connection I/O only | `HandshakeContext`, TLS errors; Go connection concurrency rules | Extensive mutable TLS internals and generic extensions |
| **azuretls-client** | `NewSession`; public mutable `Session` | `Do(Request, ...any)` + helpers; buffered or raw body | TLS + H1/H2/H3; browser/custom specs | proxy/chains, cookies, hooks, public transports | raw body opt-out; H1 WebSocket; no SSE helper | context/timeouts, hooks/dumps/logging; CFFI session locking | Very broad backend state/callback surface; some unsafe defaults/panics |

Cross-cutting observations:

- No inspected competitor exposes a single surface that simultaneously proves
  exact TLS, H1, H2, H3, proxy-route, DNS, redirect, cookie/client-hint,
  bidirectional-stream, cancellation, and pool-identity fidelity. Inference:
  Phantom should make those owners composable and test their joins, not advertise
  a monolithic “browser fingerprint” switch.
- Response streaming is common, but “streaming” is not uniform: hellojs H3,
  browser_oxide, Cronet's high-level client, Obscura, and playground's egress
  surface buffer at least one important path. Upload replay is a separate
  contract from upload streaming.
- `Send + Sync` cannot be inferred from “async.” Wreq and httpcloak design for a
  shared client/session; playground intentionally uses `Rc<RefCell<_>>`, and
  browser page/V8 execution is local-thread constrained.
- Hook/event payloads can expose URLs, headers, proxy credentials, and cookies.
  Phantom's redaction-by-default requirement is stronger than the generic
  event/dump hooks in several projects.

## Pull-request decisions and non-decisions

These are representative because they expose ownership and compatibility
trade-offs, not because they are a complete project history.

| Project | PR evidence | Design consequence for Phantom |
|---|---|---|
| httpcloak | [#102](https://github.com/sardanioss/httpcloak/pull/102) merged a body replay factory for redirects so replay preserves concrete-reader length rather than changing the wire shape; [#105](https://github.com/sardanioss/httpcloak/pull/105) kept hard close as the default and added a distinct graceful close, with H3 still hard-closing because in-flight tracking was incomplete; [#84](https://github.com/sardanioss/httpcloak/pull/84) closed after the maintainer agreed with the diagnosis but replaced the patch with one bounded mechanism spanning both H2 pools. | Body replayability, close mode, and abandoned-body recovery are explicit contracts. Do not bolt them onto retries/pools implicitly. |
| hellojs | [#1](https://github.com/unreleased/hellojs/pull/1) remains open: it proposes real ECH behind one option, partitions pools/tickets by ECH identity, and documents HRR/resumption limitations. No merged/closed PRs existed. | ECH identity belongs in connection/session keys; defer it until retry/resumption behavior is evidenced. |
| wreq | [#1273](https://github.com/0x676e67/wreq/pull/1273) merged Chromium trust-anchor support and [#1285](https://github.com/0x676e67/wreq/pull/1285) merged rejection of poisoned H2 pooled connections. [#1237](https://github.com/0x676e67/wreq/pull/1237), a C ABI plus higher-level facade, closed without recorded maintainer rationale. | Trust state and pool health affect the wire/runtime contract. #1237 is not evidence that a facade is architecturally wrong. |
| tls-client | [#229](https://github.com/bogdanfinn/tls-client/pull/229) was closed in favor of [#265](https://github.com/bogdanfinn/tls-client/pull/265) after newer Chrome captures demonstrated trust-anchor IDs; [#269](https://github.com/bogdanfinn/tls-client/pull/269) merged H3 proxy transport; [#218](https://github.com/bogdanfinn/tls-client/pull/218) merged custom dialing. | Captures outrank assumptions; route capability must be checked before protocol racing; dialing is a route seam, not profile identity. |
| Curlium | No public PR history was available. Release notes describe continuing Chrome/ML-DSA/trust-anchor/QUIC updates ([notes](https://scrapfly.io/docs/release-notes?view=markdown)). | Treat cadence as drift evidence only. It cannot validate an implementation choice. |
| playground | No public PR was associated with the inspected branch commit. The checked-in decision says ML-DSA advertisement belongs in a narrow `btls-sys` patch, not runtime mutation ([decision](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/docs/decisions/0159-the-ml-dsa-sigalgs-gap-is-closed-by-patching-btls-sys-not-by.md), [patch](https://github.com/0xARYA/playground/blob/b56c7556ab6a52ff2da5d71eba82a7215e5d29e3/vendor/patches/btls-sys-0001-mldsa-tls-sigalgs.patch)). | A vendor patch can close an otherwise unreachable wire gap, but it needs its own regression vector and vendor check; do not expose a generic signature-algorithm escape hatch. |
| cronet-rs | [#2](https://github.com/sleeyax/cronet-rs/pull/2) merged the blocking high-level client while explicitly leaving a proper async client for later. All inspected PRs were merged. | A blocking facade over callbacks is not proof of async cancellation/task ownership. Defer a Cronet backend rather than inheriting the wrapper's public FFI shape. |
| browser_oxide | [#1](https://github.com/yfedoseev/browser_oxide/pull/1) merged profile-driven client-hint/plugin consistency; [#35](https://github.com/yfedoseev/browser_oxide/pull/35) merged warm-reuse/leak fixes after [#34](https://github.com/yfedoseev/browser_oxide/pull/34) closed only because it was superseded; [#39](https://github.com/yfedoseev/browser_oxide/pull/39) closed because the work was not ready for the public tree. | Client hints share profile/session ownership. Superseded or release-scope closures are not design rejections. |
| obscura | [#927](https://github.com/h4ckf0r0day/obscura/pull/927) fixed concurrent-page V8-isolate lifetime; [#949](https://github.com/h4ckf0r0day/obscura/pull/949) routed rendered subresources through the page transport so proxy/cookie/CORS/SSRF/redirect/interception rules remain coherent and bounded; [#943](https://github.com/h4ckf0r0day/obscura/pull/943) closed as superseded by [#946](https://github.com/h4ckf0r0day/obscura/pull/946). [#982](https://github.com/h4ckf0r0day/obscura/pull/982) is open and proposes bounded native downloads/diagnostics, not true incremental receive streaming. | One route/policy path per session is more important than transport convenience. Bound queues, bodies, and lifetimes. |
| Prism | No PRs existed in the inspected public repository. | Use its source/tests as observer evidence; do not invent governance conclusions. |
| uTLS | [#331](https://github.com/refraction-networking/utls/pull/331) merged real ECH for custom specs. [#333](https://github.com/refraction-networking/utls/pull/333) merged Chrome 133+ application-settings support only after compatibility discussion preserved existing custom specs. [#403](https://github.com/refraction-networking/utls/pull/403) closed because it targeted the wrong branch, not because CFNetwork profiles were rejected. | Preserve typed-profile compatibility; ECH and new code points are profile-version work. Administrative closure is not architectural evidence. |
| azuretls-client | [#363](https://github.com/Noooste/azuretls-client/pull/363) merged a TLS-config callback, [#406](https://github.com/Noooste/azuretls-client/pull/406) custom H3 ClientHello specs, [#347](https://github.com/Noooste/azuretls-client/pull/347) proxy chains/QUIC work, and [#371](https://github.com/Noooste/azuretls-client/pull/371) thread-safe CFFI sessions. No reviewed closed PR supplied a documented architectural rejection. | These demonstrate demand for escape hatches and foreign-session locking, not that Phantom should make either part of its first Rust facade. |

## Adopt, adapt, avoid, defer

### Adopt at existing Phantom seams

| Phantom seam | Decision | Evidence/rationale |
|---|---|---|
| **Profile** | Keep concrete, ordered, versioned TLS/H1/H2/H3 recipe types; require a capture/vector for every applied field. | uTLS and Wreq show the value of ordered concrete recipes; tls-client #229/#265 and uTLS #333 show why captures and compatibility matter. This reinforces, rather than expands, [configuration.md](configuration.md). |
| **Route** | Make route capability validation occur before I/O. Never let failed/invalid proxy configuration become direct traffic. Include DNS mode, proxy auth identity, UDP/H3 ability, and local bind in route/pool identity. | tls-client prevents H3 race leakage; browser_oxide's direct continuation is the counterexample; httpcloak/Curlium show that UDP proxying is a separate capability. |
| **Session** | Give one session sole ownership of cookies, TLS tickets, DNS/HTTPS answers, Alt-Svc, Accept-CH, and protocol knowledge. Partition all of it by the profile/route identities that affect the wire. | httpcloak, hellojs #1, playground's jar wrapper, and browser_oxide #1 converge on this ownership. |
| **Pool** | Keep physical connection/admission ownership separate. Key by the complete architecture key already documented; reject poisoned/draining connections; bound abandoned-body cleanup and graceful drain. | Wreq #1285 and httpcloak #84/#105 provide concrete failure cases. Browser_oxide's host/port key is the counterexample. |
| **Request/body** | Distinguish streamable, replayable, and non-replayable bodies. Redirect/retry code may replay only through an explicit factory. Preserve ordered duplicate headers through every protocol encoder. | httpcloak #102 demonstrates that replay can change framing/fingerprint even when bytes match. Phantom already preserves header order in H1/H2. |
| **Validation** | Retain raw captures and normalized observer output; compare every protocol layer and negative behavior (fallback, cancel, proxy failure), not only JA3/JA4. | Prism exposes multiple layers; uTLS explicitly warns ClientHello mimicry is incomplete. |

### Adapt behind Phantom-owned types

- Use Wreq as the likely H1/H2 implementation substrate where it satisfies
  vectors, but translate Phantom profiles, routes, errors, and bodies privately.
  Do not re-export Wreq's builder, Tower layers, proxy matcher, or BoringSSL
  types.
- Copy httpcloak's separation of hard versus graceful close and its explicit
  replay factory semantics, but start with fewer methods and only the protocol
  behavior Phantom can verify.
- Follow playground's bounded redirect transaction and sole cookie-owner model,
  while using thread-safe ownership suitable for a cloneable Rust session.
- Use uTLS and Curlium only as behavior/capture references. Their low-level
  extension controls or vendor claims do not justify an opaque public escape
  hatch.
- Borrow Prism's bounded, multi-layer observation model for local test fixtures;
  keep the observer outside runtime API ownership.

### Avoid

- A public “all knobs” options struct, `...any` modifiers, or publicly mutable
  session/backend fields (azuretls-client and the broadest Go/JS facades).
- Pool keys based only on host/port, process-global session state, or a pool that
  owns cookies/profile policy.
- Silent protocol substitution, silent minimal H3 settings, or direct-network
  fallback after route/proxy failure.
- Calling buffered reception “streaming,” or conflating a replayable upload with
  a streamable one.
- Recoverable-path panics, public FFI/`unsafe` leakage, generic experimental JSON
  strings, or arbitrary raw TLS extensions in the stable facade.
- Default observability hooks that emit full URLs, cookies, authorization,
  proxy credentials, or raw headers.
- Using an observer-generated summary (JA3/JA4/Peet JSON) as a complete source
  profile. It omits ordering/state that only raw packets and protocol traces
  retain.

### Defer until a vertical slice is capture-proven

- HTTP/3/QUIC, including UDP proxying, QPACK receive behavior, migration,
  Alt-Svc expiry, 0-RTT replay policy, graceful drain, and the same-profile TLS
  story across TCP and QUIC.
- ECH, trust-anchor advertisement, and resumption knobs as public customization.
  Ship them first as versioned built-in profile data.
- WebSocket and SSE conveniences. SSE should remain a response-body consumer;
  WebSocket needs a handshake and frame lifecycle. Neither should distort the
  base request API.
- Cronet or another backend abstraction. A second proven implementation, not a
  hypothetical need, should force the private backend seam.
- Public retry policy. First establish replayability, idempotency, route
  stability, and protocol-specific failure taxonomy.

## Minimal proposed Phantom API shape

This is a shape constraint, not a commitment to names or a request to implement
all rows. “Current” is source-observed; “planned” maps only the smallest complete
facade already described by Phantom's architecture.

| Status | Minimal surface | Ownership and exclusions |
|---|---|---|
| **Current** | `phantom::profile::{ClientFamily, Platform, ProfileId, ProfileMetadata, ...}` | Identity only; no implied network behavior. |
| **Current** | `phantom_net::request::{OriginForm, RequestHeader}` | Parsed origin-form and byte-preserving ordered header entry. |
| **Current** | `phantom_net::http1::send_get(...) -> Response<Http1Body>` and `phantom_net::http2::send_get(...) -> Response<Http2Body>` plus protocol TLS connectors/errors | One-shot GET, explicit stream ownership, no facade pool/session/route. |
| **Current** | `phantom_profile::{TlsSettings, Http2Settings, ...}` | Concrete public TLS/H2 recipes. QUIC recipe code is private and does not mean H3 runtime support. |
| **Planned, first facade slice** | `Client::builder(profile).route(route).build() -> Result<Client, BuildError>` | Exactly one required profile and one explicit route. No generic backend, arbitrary extension map, callback forest, or exposed pool builder. |
| **Planned, first facade slice** | `Client::session() -> Session`; cloneable `Session` if and only if its state is `Send + Sync` | Session owns cookies, tickets, DNS/HTTPS answers, Alt-Svc, client hints, and protocol knowledge. Client/pool owns physical connections and admission. |
| **Planned, first facade slice** | `Session::request(method, uri) -> RequestBuilder`; builder initially needs only ordered headers, a typed body, request timeout, and explicit `ProtocolPolicy` | Body type exposes whether it is replayable. Redirect/retry is absent until it can honor that fact. Unsupported forced protocol returns an error before I/O. |
| **Planned, first facade slice** | `send() -> Result<Response<ResponseBody>, RequestError>`; `ResponseBody` is an async byte stream with explicit drop/cancel behavior | No default buffering disguised as streaming. Convenience `bytes(limit)` may be a consumer with a mandatory bound. |
| **Planned policy vocabulary** | `ProtocolPolicy::{Auto, Http1, Http2, Http3}` and a closed `Route` vocabulary beginning with `Direct`, `HttpProxy`, and `Socks5` only when implemented | `Auto` may negotiate only among profile-and-route-supported protocols. It never changes route or substitutes an unprofiled protocol. Do not publish MASQUE, custom DNS, local bind, or H3 variants before they are applied and verified. |
| **Planned lifecycle** | `Session::close_gracefully()` separate from immediate drop/close | Its per-protocol drain semantics must be documented; do not claim graceful H3 close before in-flight tracking exists. |

Deliberately absent from the minimal slice: a backend trait, arbitrary TLS
extension bytes, request hooks, public connector layers, retry knobs, cache
storage, certificate-bypass switches, WebSocket/SSE helpers, ECH/0-RTT toggles,
and protocol-specific builders. Each should enter only with a concrete use case,
an owner, and capture-backed verification.

## Validation observers are witnesses, not oracles

The live TLS endpoint
[`/api/client-fingerprint`](https://tls.tlsfingerprint.io/api/client-fingerprint)
returned structured TLS/HTTP fingerprint data when queried over TLS/TCP during
this audit. The QUIC endpoint
[`/api/client-fingerprint-quic`](https://quic.tlsfingerprint.io/api/client-fingerprint-quic)
returned an empty body when reached by an HTTP/2 client while advertising H3,
which is a useful reminder that the observer must be reached through the
protocol being tested.

For every validation run Phantom should retain together:

1. the observer's raw response bytes and response metadata;
2. a packet capture, plus QUIC key log/qlog where applicable;
3. Phantom profile ID/version, route identity, requested protocol policy, build
   revision, observer URL, timestamp, and resolver outcome; and
4. the normalized assertion result produced by Phantom's own test tooling.

External observer schemas, capture stacks, server TLS/HTTP implementations,
network paths, and fingerprint algorithms can drift without Phantom changing.
A passing observer label therefore cannot prove browser equivalence, and a
changed label is not by itself a regression. Local packet evidence and
protocol-specific vectors remain authoritative; the external endpoints and
Prism-style servers are supplemental, independently drifting witnesses.
