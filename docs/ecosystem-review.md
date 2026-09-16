# Ecosystem lessons

This review records recurring failures in adjacent impersonation clients so
Phantom can turn them into design and CI constraints. It is evidence for
decisions, not a claim that another project is generally unsafe or incorrect.
The exposed configuration surfaces and Phantom's ownership decisions are
compared separately in [the configuration model](configuration.md).

## Wire fidelity

- TLS parity alone is insufficient. `tls-client` has separate open failures for
  [HTTP/2 SETTINGS GREASE](https://github.com/bogdanfinn/tls-client/issues/260)
  and [HTTP/3 header ordering](https://github.com/bogdanfinn/tls-client/issues/264).
  `wreq` has independently regressed
  [header order](https://github.com/0x676e67/wreq/issues/751),
  [ALPN/ALPS order](https://github.com/0x676e67/wreq/issues/657), and
  [OkHttp profiles](https://github.com/0x676e67/wreq/issues/961).
- BrowserOxide deliberately omits H3 because stock Quinn transport behavior is
  [more identifying than the omission](https://github.com/yfedoseev/browser_oxide/blob/9cd4af36b744bc8f9047bcceeb341610a6f32109/README.md#L58-L64).
- HttpCloak's protocol controls and headers have diverged across layers:
  [H1-only disabled only H3](https://github.com/sardanioss/httpcloak/issues/6)
  and [ALPN changed header behavior](https://github.com/sardanioss/httpcloak/issues/19).

Phantom therefore preserves ordered vectors end to end, routes every request
through one profile-aware connection path, and tests TLS, startup frames,
request headers, QUIC transport parameters, H3 SETTINGS, and QPACK separately.
Exact protocol policies fail rather than downgrade.

## Profiles and generic stacks

Hard-coded profiles create a recurring update burden, as noted in
[HttpCloak issue 17](https://github.com/sardanioss/httpcloak/issues/17).
Browser-specific synthesis can also contaminate other clients; HttpCloak once
added `Sec-Fetch-*` where a profile declared none
([issue 90](https://github.com/sardanioss/httpcloak/issues/90)).

Profiles in Phantom are client-neutral data. `ClientFamily::Other` represents
arbitrary captured stacks without name-based transport branches. Scheduled
capture updates produce reviewable changes backed by local differentials and
supplemental Peet/Pingly observations; generated profile changes are not
auto-merged.

uTLS shows both the value and the maintenance cost of ClientHello presets. Its
issue history includes an outdated automatic Chrome profile
([issue 373](https://github.com/refraction-networking/utls/issues/373)) and a
new fingerprint-visible `trust_anchors` difference
([issue 397](https://github.com/refraction-networking/utls/issues/397)). A raw
ClientHello template must also remain consistent with the handshake engine's
internal state, which was the central concern in
[issue 54](https://github.com/refraction-networking/utls/issues/54).

Phantom therefore keeps named versions instead of a floating `latest` recipe,
and retained bytes are evidence rather than replay templates. Import tooling
must decode into typed settings, validate the complete combination, and then
prove a fresh emitted handshake. It must not inject opaque ClientHello bytes
that the TLS state machine does not understand.

## Correlated variability

Random-looking fields are not independent. uTLS fixed a detectable Chrome
GREASE-ECH mismatch where the outer cipher preference followed AES hardware
while the ECH cipher choice was random
([GHSA-7m29-f4hw-g2vx](https://github.com/refraction-networking/utls/security/advisories/GHSA-7m29-f4hw-g2vx)).
Chrome's extension permutation also required explicit support rather than a
new fixed preset
([issue 132](https://github.com/refraction-networking/utls/issues/132)).
AzureTLS exposes the inverse API problem: applying a JA3 string loses its
normal Chrome extension shuffling unless callers replace a callback
([issue 442](https://github.com/Noooste/azuretls-client/issues/442)).

Phantom treats those choices as one connection-resolution problem. AES
capability, cipher preference, ECH GREASE, extension permutation, GREASE
values, and padding must derive from the same resolved context. Tests use
deterministic entropy to assert exact bytes, then multiple seeds to assert
allowed variation and cross-field invariants. A profile will remain stable
session identity even when its captured client intentionally varies some
per-connection fields.

## TLS and HTTP engine coupling

uTLS users hit an HTTP/1 client speaking to a server-selected H2 connection
when a custom TLS dial hook bypassed Go's protocol routing
([issue 16](https://github.com/refraction-networking/utls/issues/16)).
Handshake failures have also occurred when a preset's offer and the TLS state
machine diverged from what a peer accepted
([issue 104](https://github.com/refraction-networking/utls/issues/104)).

Phantom treats negotiated ALPN as a checked transition. The current H1 path
accepts absent ALPN or `http/1.1`, and H2 requires `h2`; the H3 path will
require `h3`. A negotiated connection is never handed to the wrong HTTP engine
or used to silently try another protocol.

## Proxies and pooling

The issue histories show proxy correctness is cross-cutting:

- HttpCloak: [SOCKS5 slowdown](https://github.com/sardanioss/httpcloak/issues/68),
  [disposal deadlock](https://github.com/sardanioss/httpcloak/issues/33), and
  [incorrect pool identity](https://github.com/sardanioss/httpcloak/issues/27).
- `wreq`: [per-request proxy auth](https://github.com/0x676e67/wreq/issues/531),
  [rotation and custom headers](https://github.com/0x676e67/wreq/issues/489),
  and [proxy error classification](https://github.com/0x676e67/wreq/issues/1012).
- `tls-client`: [CONNECT header order](https://github.com/bogdanfinn/tls-client/issues/181),
  [`socks5h` semantics](https://github.com/bogdanfinn/tls-client/issues/67),
  and [H3 proxying](https://github.com/bogdanfinn/tls-client/issues/242).
- `wreq` replaced serialization-derived pool IDs with owned configuration IDs
  after [issue 1086](https://github.com/0x676e67/wreq/issues/1086).

Phantom makes direct, plaintext HTTP CONNECT, and local-/remote-DNS SOCKS5 owned,
typed choices at the client or request boundary. CONNECT fields are ordered,
request validation occurs before opening the proxy socket, and proxy failure
never falls back to a direct connection. The HTTP tunnel wrapper also
retains bytes read past the CONNECT response head; dropping that prefix is a
known implementation trap in
[`wreq`](https://github.com/0x676e67/wreq/blob/cd76bcdf1307153de289d34e072528bdf0510a3b/src/conn/proxy/tunnel.rs#L145-L197),
[`hyper-util`](https://github.com/hyperium/hyper-util/blob/d480d9f802c7062cb0aeece9ee0020ecce840521/src/client/legacy/connect/proxy/tunnel.rs#L166-L230),
and
[`tls-client`](https://github.com/bogdanfinn/tls-client/blob/34718e1b514b446b95bc68dc4f096247e69c7939/connect.go#L235-L275).
HttpCloak's buffered handoff is a useful positive reference
([source](https://github.com/sardanioss/httpcloak/blob/30379124605d212efe5240aacd60bd4b9ab7c6cf/transport/http1_transport.go#L1020-L1067)).

Later route slices add HTTP forwarding, HTTPS proxies, SOCKS5 authentication,
rotation, and local binding as explicit policy. H3 requires a separately
proven UDP route—SOCKS5 UDP ASSOCIATE, then CONNECT-UDP/MASQUE—not ordinary
CONNECT.

## Streaming and lifecycle

- A flow-control accounting bug broke slow large H2 responses around 46 MiB in
  [`tls-client`](https://github.com/bogdanfinn/tls-client/issues/257); the
  [fhttp fix](https://github.com/bogdanfinn/fhttp/pull/24) was one line.
- Obscura leaked abandoned response streams
  ([issue 386](https://github.com/h4ckf0r0day/obscura/issues/386)) and shared
  cookies/headers between clients
  ([issue 449](https://github.com/h4ckf0r0day/obscura/issues/449)).
- BrowserOxide measured substantial warm-pool state retention
  ([issue 33](https://github.com/yfedoseev/browser_oxide/issues/33)).
- Cronet-rs is archived with unresolved unsafe destruction and async API work
  ([issues 4](https://github.com/sleeyax/cronet-rs/issues/4) and
  [3](https://github.com/sleeyax/cronet-rs/issues/3)).

Bodies remain bounded, backpressured streams. Drop cancels and releases flow
control; shutdown is idempotent and deadline-bounded. Tests cover one-byte
readers, stalled consumers, early drop, large bodies, disconnects, and soak
behavior. Native ownership remains isolated behind small audited wrappers.

AzureTLS has an open timeout when an H3 connection is reused after an idle
period against some peers
([issue 447](https://github.com/Noooste/azuretls-client/issues/447)). Its H3
ClientHello customization also omits associated HTTP/3 and Initial-packet
settings
([issue 410](https://github.com/Noooste/azuretls-client/issues/410)). These are
the failure modes Phantom's connection identity and vertical profile slices
are intended to prevent. H3 soak tests must cross peer idle expiry, observe
close and draining state, evict stale connections, and bound a replacement
attempt without turning a forced-H3 request into TCP fallback.

AzureTLS issue 428 demonstrates a second lifecycle trap: duplicate H2 SETTINGS
can trigger peer `PROTOCOL_ERROR`, while an ignored GOAWAY can become repeated
connection churn
([issue 428](https://github.com/Noooste/azuretls-client/issues/428)). Phantom
rejects duplicate known profile settings before I/O and tests GOAWAY draining,
admission, and retry boundaries independently.

Session mutation is another panic boundary. uTLS has an open report of a
low-reproducibility PSK state panic that terminates the process
([issue 369](https://github.com/refraction-networking/utls/issues/369)).
Phantom will keep tickets and PSKs session-owned, validate extension/cache
state before an attempt, and require concurrency and repeated-ticket tests
before resumption is enabled. Inconsistent state must return a typed error; it
must never panic from a request path.

## SSE and WebSocket

SSE timeouts recur in
[`tls-client`](https://github.com/bogdanfinn/tls-client/issues/177), while a
single SSE connection once blocked Obscura's accept loop
([issue 489](https://github.com/h4ckf0r0day/obscura/issues/489)). WebSocket is
still open in [HttpCloak](https://github.com/sardanioss/httpcloak/issues/58),
and `wreq` users have found endpoints sensitive to
[H1 casing and order](https://github.com/0x676e67/wreq/issues/984).

SSE is a parser and reconnect policy over the ordinary response stream; header
timeout ends once headers arrive, with a separate optional idle timeout.
WebSocket reuses the same route, TLS profile, and ordered request model. H1
Upgrade lands first; extended CONNECT follows retained wire evidence.

## Maintenance and performance

Unbounded native dependencies have caused QPACK and platform build failures in
[`tls-client`](https://github.com/bogdanfinn/tls-client/issues/204) and
[`wreq`](https://github.com/0x676e67/wreq/issues/672). Obscura has also exposed
native dependency and cross-platform build leakage
([issue 483](https://github.com/h4ckf0r0day/obscura/issues/483)).

Engine revisions remain exact pins. CI covers locked fresh builds, patch
replay, MSRV, debug and release, and the supported operating systems. Engine
updates must pass packet and slow-stream regressions, not just compile. Traces
measure DNS, route selection, proxy negotiation, TLS, ALPN, pool outcome, TTFB,
body progress, cancellation, and shutdown. Benchmarks compare cold/warm,
direct/proxied, concurrent, and slow-body workloads before the final allocation
and flamegraph pass.

Curlium has no public engine issue tracker, so its
[public architecture description](https://scrapfly.io/curlium) is treated as a
claim and reference, not validation. The review supports Phantom's existing
choice: own the Rust profiles, routing, sessions, and streaming API; reuse
mature protocol engines behind narrow adapters; do not fork an entire client or
hand-write TLS and QUIC.

### Additional active implementations

The active ecosystem also includes implementations that broaden the feature
comparison without changing that ownership decision:

| Project | Observed surface | Phantom lesson |
| --- | --- | --- |
| [`curl_cffi`](https://github.com/lexiforest/curl_cffi/tree/571560b) and its [`curl-impersonate` fork](https://github.com/lexiforest/curl-impersonate/tree/9d9b988) | Python CFFI over patched libcurl with browser and custom TLS/H2 profiles, H3 plus UDP proxying, synchronous and asynchronous sessions, and WebSocket APIs. | This is strong evidence for libcurl as a distribution and transfer engine. It is not the right Phantom core: the FFI/build boundary and backend-shaped option surface would constrain typed ordered QUIC/H3 policy and move patch ownership outside Rust. Its wheel and cross-platform test matrix remain useful CI references. |
| [`CycleTLS`](https://github.com/Danny-Dasilva/CycleTLS/tree/9671e04) | Go transport with a Node/TypeScript frontend, caller-supplied JA3/JA4 and QUIC shapes, H3, connection reuse, WebSocket, SSE, and proxy support. | A fingerprint string is a useful import format, not a coherent session identity. TLS, HTTP, QUIC, headers, routes, and mutable state still require cross-field validation and one resolved connection policy. |
| [`surf`](https://github.com/enetx/surf/tree/7da0502) | Go client built on uTLS and quic-go with Chrome/Firefox recipes, JA3/JA4, typed H2/H3 controls, QUIC shaping, proxies, and WebSocket support. | Its fluent configuration demonstrates demand for both presets and customization. Phantom should expose the same capabilities through validated recipe and route types rather than backend callbacks or an unrestricted option bag. |

The original `curl-impersonate` project remains an important historical design
reference, but the maintained `curl_cffi` fork is the more relevant source for
current H3, proxy, packaging, and browser-profile behavior. These projects are
references and differential subjects; none provides a complete substitute for
Phantom's typed Rust ownership boundaries.

## Passive observation

[Prism](https://github.com/WeAreMaven/prism) is a useful secondary observer.
Its source separates raw TCP, TLS, HTTP/2, and QUIC observations from derived
JA3, JA4, Peetprint, Akamai, JA4H, and JA4Q signals, and distinguishes
connection-level observations from per-request headers. Phantom keeps the same
conceptual boundary: retain exact ordered evidence first, then calculate
summary fingerprints for diagnosis and interoperability reports.

The summaries are intentionally not parity gates. Some sort cipher suites or
extensions; JA4Q retains transport-parameter identifiers but not values or
varint widths; decoded header maps cannot establish H1 spelling or
HPACK/QPACK/frame behavior. Prism's parser and integration checks are suitable
for passive service availability but are more permissive and lossy than a
fixture oracle. Phantom's retained decoders stay strict and report missing
capture separately from a match.

Prism also supplies useful test-harness lessons. Its QUIC path correlates by
connection ID, bounds reassembly, handles coalesced packets, and carries
capture deadlines and buffer ceilings. Fixes for truncated multi-buffer XDP
packets and a 1232-byte Chrome Initial show why every capture failure must
retain the phase, total length, bounded byte prefix, and typed reason. Its
fuzzing workflow and per-stage waterfall benchmarks map well to Phantom's
ClientHello, QUIC Initial, H2/H3, and QPACK boundaries.

Phantom should not fork or vendor Prism. A later optional Linux CI lane may run
an exact pinned Prism commit and consume structured output alongside Peet and
Pingly. Local raw packet/frame fixtures remain authoritative, and TCP/kernel or
latency fingerprints remain environment context unless Phantom explicitly owns
that network path.
