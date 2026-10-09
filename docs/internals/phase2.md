# Phase 2 implementation checklist

Use this checklist to review the API work before Phantom's first release.
All required changes are implemented. The final merge and CI proof remain
pending.

## Starting point

The starting commit is `0b78b83f` (2026-10-08). The workspace lint baseline
is merged in [PR 184](https://github.com/bywayhq/phantom/pull/184). Its full
integration gate and ten workflows on `main` passed. The enabled additions
are `missing_debug_implementations`, `rust_2018_idioms`,
`clippy::must_use_candidate`, `clippy::cast_lossless`, and `clippy::cargo`.

The [roadmap](../roadmap.md#phase-2-ergonomics) defines the full scope. This
checklist records its completion criteria; it does not replace the support
contract in [Coverage](../reference/coverage.md).

## Milestones

Checked items record implemented and reviewed changes, including the
candidate in [PR 187](https://github.com/bywayhq/phantom/pull/187) at
`b2cf66d0`. They do not yet establish completion on merged `main`.
See [Integration and completion](#integration-and-completion) for the
final proof.

### 1. Routes

The route change merged at `7b99fcaf` in
[PR 185](https://github.com/bywayhq/phantom/pull/185). The full Windows/Linux
gate passed all 23 steps and 2,862 tests on that commit. All 43 PR checks
passed, including Windows, macOS, and security scanning. Path/git downstream
consumers and ShellCheck passed before the final test-only redaction repair.
Fixtures, vendored sources, and the lockfile are unchanged. Push CI on
`main` passed all nine triggered workflows. The native BoringSSL push
workflow's path filter did not select this change; its PR check passed.

- [x] One route value for each transport path, accepted by protocol
  connection, send, and upgrade operations. Route-specific public methods
  are removed, with migration notes.
- [x] One owner constructs each connection leg. Pools and WebSocket code
  use that owner instead of repeating route dispatch.
- [x] DNS ownership, proxy authentication, forwarding versus tunneling,
  ECH, source binding, origin identity, and address-race behavior remain
  unchanged. Unsupported combinations still fail before dispatch.
- [x] Existing wire fixture replays are byte-identical. Route, protocol,
  and fingerprint never change as an implicit fallback.

### 2. Public API boundaries

The first API batch merged at `d2b8a6bd` in
[PR 186](https://github.com/bywayhq/phantom/pull/186). Its full Windows/Linux
gate passed all 24 steps and 2,906 tests. All 43 PR checks and eight triggered
push workflows passed, including Windows, macOS, and security scanning.
The eight feature rows of the public API inventory were regenerated.
Path/git downstream consumers passed with default and all features.
HTTP/1.1 backend errors now have an opaque payload; HTTP/3 backend conversion
is private. Source chains and replay observations remain available.
PR 187 finishes export cleanup, enum evolution, typed error categories,
conversions, common traits, and public examples. The public API inventories
and default/all-feature path and git consumers have been checked. Its final
gate, PR checks, merge, and push CI remain pending.

- [x] Unused internal exports become private. A public API inventory
  records the intended exports of each library crate.
- [x] Public enums have an explicit evolution policy. Extensible enums
  use `#[non_exhaustive]` where callers should keep a fallback arm.
- [x] Error APIs hide unintended vendored types. Intentional dependencies,
  including the QUIC provider interface, are listed explicitly.
- [x] Retained public APIs have consistent names, builders, conversions,
  meaningful settings types, and applicable common traits. Tests assert
  required `Send` and `Sync` bounds. Important returned values are
  `#[must_use]`. Examples and error documentation cover their use.

### 3. Profiles and settings

PR 186 groups recipes under five browser modules and adds explicit Windows
and Android constructors. Individual recipes remain available for custom
composition. Factories leave the default request template unset. You can
configure one on the profile, replace it on a request, or opt out for that
request. Credential stripping across redirects passed integration checks.
Checked TLS version ranges and ticket settings preserve recipe values and
keep TCP limits separate from QUIC ticket storage. PR 187 adds checked ECH
settings and trust-anchor ID orders. These types retain recipe values and
selection order. Public-field settings remain available for custom
composition, with validation and a documented breaking-change policy.

- [x] Settings constructors and their evolution policy are settled.
  Invalid combinations are prevented by types where practical; remaining
  invalid or unsupported values produce recoverable errors.
- [x] Browser modules have one naming convention. Composed constructors
  select compatible TCP, TLS, HTTP, QUIC, and client-hint recipes.
- [x] Browser version, platform, supported protocols, and template/header
  behavior are explicit. Selecting a named version never resolves a
  moving latest-version alias.
- [x] Profiles can supply a default request template with documented
  override rules. Deliberate custom composition remains available.
  Custom headers are not claimed to be automatically browser-validated.

### 4. Errors and responses

PR 186 adds recoverable status checks and bounded bytes, UTF-8, and optional
typed-JSON reads. Success and failure retain the response head and extensions.
Bodies and trailers follow the existing collection and cancellation rules.
These changes passed the full gate and CI. PR 187 adds typed recovery
categories, safe origin context, replay observations, and error formatting
that leaves causes in `source()`. Replay observations do not grant permission
to resend a method or body.

- [x] Public errors expose typed categories and useful `source()` chains.
  A cause is not repeated at every display layer.
- [x] Request failures expose replay safety and origin context without
  retaining a sensitive full URL for diagnostics.
- [x] Opt-in status-to-error conversion retains the response. Existing
  errors that have a response make it available to callers.
- [x] Bounded bytes, text, and typed-JSON helpers retain access to response
  metadata. Their body ownership, decoding, limits, and failure behavior
  are documented and tested. They never set request headers.

### 5. Request workflows

PR 187 adds explicit timeout overrides and one overall retry budget.
Ordered query pairs, validated authorization values, and bounded `Link`
parsing support request preparation. Prepared JSON, form, and multipart
bodies fill declared `Content-Type` and `Content-Length` slots. Windows
Chrome and Firefox fetch-upload templates cover HTTP/1.1 and HTTP/2.
SSE streams share polling state with `next_event()`. Environment proxies
remain opt-in, with explicit route and `NO_PROXY` precedence.

- [x] Client/request timeout inheritance is explicit. Phase timeouts and
  a total deadline have separate documented meanings.
- [x] An overall retry budget has defined interactions with each retry
  class and browser-required replay. Delay control cannot silently grant
  permission to retry. One-shot bodies are never implicitly replayed.
- [x] Query construction preserves order and duplicates. Authorization
  constructors validate values. `Link` parsing returns data only.
- [x] JSON, form, and multipart bodies fill declared template slots.
  Fetch-upload templates preserve the recorded HTTP/1.1 and HTTP/2 header
  order. Multipart encoding has separate tests for framing and escaping.
- [x] SSE implements `Stream`. Public APIs re-export the types callers
  need, including types previously reachable only through public fields.
- [x] Environment proxy selection is opt-in. Explicit routes, environment
  variables, and `NO_PROXY` have documented precedence and tested behavior.

### 6. Observability and downstream tests

PR 187 documents the tracing span and header-redaction contract. A
synchronous request hook fills only declared caller slots. It runs once
during preparation and retains redirect credential stripping.

The wire harness compares bounded HTTP/1.1 request heads with retained
expectations. Metadata identifies the browser build, platform, run, and
request kind. Package checks passed 95 tests and six doctests using
self-contained fixtures. The harness does not establish TLS, HTTP/2, or
HTTP/3 parity. Publication remains a separate release step.

- [x] Tracing has a stable span/field contract that omits credentials,
  cookies, bodies, and sensitive URLs.
- [x] A request hook can fill a declared template slot. It cannot add a
  header or change header order.
- [x] A downstream wire-assertion harness checks HTTP/1.1 request heads
  against retained expectations. Its package is prepared for publication,
  without publishing during this phase.
- [x] Consumer examples compile for profile setup, client reuse, proxy
  selection, request bodies, bounded responses, error inspection,
  timeouts, retries, streaming cancellation, and downstream assertions.

## Browser and TLS checks

Every API change keeps these existing boundaries:

- Origin trust, proxy trust, and origin-scoped client certificates remain
  distinct from fingerprint settings. Verification defaults and the
  restrictions on disabling verification stay unchanged.
- HTTP, WebSocket openings, direct/proxy routes, and reused connections
  preserve profile behavior and header case/order.
- Independent clients retain profile/trust isolation. Clones share only
  the state their documented contract shares.
- TLS, certificate, ALPN, and proxy failures remain diagnosable through
  typed APIs. Native build and dependency coexistence limits are stated
  without promising unsupported compatibility.
- Dropped futures and bodies retain their cancellation and cleanup rules.
  Streaming and collection remain bounded.

## Existing behavior to retain

The starting API already had per-request timeouts, total deadlines,
per-request retries, typed request errors, and bounded body collection.
Phase 2 extends these with explicit inheritance, a shared retry budget,
and response helpers.

Separate proxy roots and origin-scoped client certificates remain in place.
The route and settings changes preserve their selection and isolation.

## Research used for API decisions

Checked 2026-10-08. Documentation describes the upstream contract; issue
reports identify useful scenarios. A report is not an independently
reproduced defect, and a closed issue does not establish its current status.

| Source | Lesson for the API |
| --- | --- |
| [reqwest response ownership](https://github.com/seanmonstar/reqwest/issues/1542) and [ureq error bodies](https://github.com/algesten/ureq/issues/997) | Preserve response metadata and status-error bodies |
| [HTTPX timeouts](https://www.python-httpx.org/advanced/timeouts/) and [Go deadlines](https://pkg.go.dev/net/http#Client) | Distinguish phase limits from total deadlines |
| [Got retry control](https://github.com/sindresorhus/got/issues/2415) | Separate delay customization from retry permission |
| [Requests proxy precedence](https://requests.readthedocs.io/en/latest/user/advanced/#proxies) | Make route selection explicit |
| [curl_cffi profile headers](https://github.com/lexiforest/curl_cffi/issues/826) and [tls-client header defaults](https://github.com/bogdanfinn/tls-client/issues/213) | State which headers a profile supplies |
| [wreq WebSocket headers](https://github.com/0x676e67/wreq/issues/1296) | Preserve case/order across request paths |
| [rustls configuration](https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html) | Separate trust and identity from protocol settings |
| [rustls public dependencies](https://github.com/rustls/rustls/issues/3059) and [wreq builds](https://github.com/0x676e67/wreq#building) | Distinguish API stability from native linking limits |
| [native-tls identity report](https://github.com/rust-native-tls/rust-native-tls/issues/340) | Test supported identity formats across platforms |

## Integration and completion

The workspace lint baseline, route consolidation, and first API batch are
merged in PRs 184, 185, and 186. PR 187 contains the remaining implemented
items at candidate `b2cf66d0`. The earlier integration run passed all 24
gate steps and 3,085 tests. The candidate's final gate and CI are pending.

Completion proof pending: replace this paragraph after PR 187 merges.
Record the exact merged commit, its full gate result, all required PR
checks, and push CI on `main`. Until that proof is recorded, Phase 2 remains
awaiting final verification.

Every breaking API change has a migration note. Completion requires every
item above to be implemented, documented, reviewed, merged, and verified
on green `main`. A failing workflow on `main` blocks the next merge.

New browser coverage, backend changes, broader hardening, optimization,
and architecture audits are outside Phase 2. Publication and Phase 3 start
after this phase. Ask before any `cargo publish`.

## Next

- [Roadmap](../roadmap.md#phase-2-ergonomics): the complete phase scope.
- [Route matrix](../reference/route-matrix.md): supported combinations.
- [Contributing](../../CONTRIBUTING.md): required verification.
