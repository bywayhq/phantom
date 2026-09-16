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

Phantom makes the route part of connection identity. HTTP, HTTPS, SOCKS5 local
DNS, SOCKS5 remote DNS, authentication, ordered CONNECT headers, IPv4/IPv6,
rotation, and local binding are explicit. Proxy failure never falls back to a
direct connection. H3 uses a separately proven UDP route—SOCKS5 UDP ASSOCIATE,
then CONNECT-UDP/MASQUE—not ordinary CONNECT.

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
