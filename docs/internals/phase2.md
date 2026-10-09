# Phase 2 implementation checklist

Track the API changes needed before Phantom's first release. Each item needs
implementation, documentation, review, and evidence on merged `main`.

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

An unchecked item remains required. Commit links, review results, and exact
gate results belong beside an item when it is completed. A partial lane or
a passing focused test does not complete an item.

### 1. Routes

The route lane has a shared TCP connection-leg owner and borrowed route
values. HTTP/1.1, HTTP/2, and negotiated connectors use it for ordinary
connections and proxy request/upgrade paths. This is an unmerged checkpoint:
route-specific send/upgrade methods, ECH/slower setup, plaintext/forwarding, and datagram
routes still need consolidation. No route item is complete yet.

Checkpoint `27022128` passed 145 focused tests, including the connection
future-size budget, TCP settings/keepalive, TLS, ECH, route DNS ownership,
source binding, and HTTP/3 WebSockets. The full workspace compile passed at
`73164158`. Independent review approved both that refactor and the new
source-binding/certificate tests after the probe fix. Later API migration
commits require their own verification. Ordinary TCP connection methods are
removed. HTTP/1.1 route-specific request and TLS Upgrade methods are removed
in favor of route-taking operations; other operation families remain pending.

- [ ] One route value for each transport path, accepted by protocol
  connection, send, and upgrade operations. Route-specific public methods
  are removed, with migration notes.
- [ ] One owner constructs each connection leg. Pools and WebSocket code
  use that owner instead of repeating route dispatch.
- [ ] DNS ownership, proxy authentication, forwarding versus tunneling,
  ECH, source binding, origin identity, and address-race behavior remain
  unchanged. Unsupported combinations still fail before dispatch.
- [ ] Existing wire fixture replays are byte-identical. Route, protocol,
  and fingerprint never change as an implicit fallback.

### 2. Public API boundaries

- [ ] Unused internal exports become private. A public API inventory
  records the intended exports of each library crate.
- [ ] Public enums have an explicit evolution policy. Extensible enums
  use `#[non_exhaustive]` where callers should keep a fallback arm.
- [ ] Error APIs hide unintended vendored types. Intentional dependencies,
  including the QUIC provider interface, are listed explicitly.
- [ ] Retained public APIs have consistent names, builders, conversions,
  meaningful settings types, and applicable common traits. Tests assert
  required `Send` and `Sync` bounds. Important returned values are
  `#[must_use]`. Examples and error documentation cover their use.

### 3. Profiles and settings

- [ ] Settings constructors and their evolution policy are settled.
  Invalid combinations are prevented by types where practical; remaining
  invalid or unsupported values produce recoverable errors.
- [ ] Browser modules have one naming convention. Composed constructors
  select compatible TCP, TLS, HTTP, QUIC, and client-hint recipes.
- [ ] Browser version, platform, supported protocols, and template/header
  behavior are explicit. Selecting a named version never resolves a
  moving latest-version alias.
- [ ] Profiles can supply a default request template with documented
  override rules. Deliberate custom composition remains available.
  Custom headers are not claimed to be automatically browser-validated.

### 4. Errors and responses

- [ ] Public errors expose typed categories and useful `source()` chains.
  A cause is not repeated at every display layer.
- [ ] Request failures expose replay safety and origin context without
  retaining a sensitive full URL for diagnostics.
- [ ] Opt-in status-to-error conversion retains the response. Existing
  errors that have a response make it available to callers.
- [ ] Bounded bytes, text, and typed-JSON helpers retain access to response
  metadata. Their body ownership, decoding, limits, and failure behavior
  are documented and tested. They never set request headers.

### 5. Request workflows

- [ ] Client/request timeout inheritance is explicit. Phase timeouts and
  a total deadline have separate documented meanings.
- [ ] An overall retry budget has defined interactions with each retry
  class and browser-required replay. Delay control cannot silently grant
  permission to retry. One-shot bodies are never implicitly replayed.
- [ ] Query construction preserves order and duplicates. Authorization
  constructors validate values. `Link` parsing returns data only.
- [ ] JSON, form, and multipart bodies use browser evidence for
  `Content-Type` placement. Convenience APIs follow declared templates
  instead of inserting or reordering headers implicitly.
- [ ] SSE implements `Stream`. Public APIs re-export the types callers
  need, including types previously reachable only through public fields.
- [ ] Environment proxy selection is opt-in. Explicit routes, environment
  variables, and `NO_PROXY` have documented precedence and tested behavior.

### 6. Observability and downstream tests

- [ ] Tracing has a stable span/field contract that omits credentials,
  cookies, bodies, and sensitive URLs.
- [ ] A request hook can fill a declared template slot. It cannot add a
  header or change header order.
- [ ] A downstream wire-assertion harness checks actual requests against
  named recipes. Its package is prepared for publication, without
  publishing during this phase.
- [ ] Consumer examples compile for profile setup, client reuse, proxy
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

These features already exist at the starting commit. Their presence does
not complete the broader milestone that refines them.

| Feature | Current API | Remaining Phase 2 work |
| --- | --- | --- |
| Per-request timeouts | `RequestBuilder::timeouts` | Inheritance policy |
| Total deadline | `RequestTimeouts::total` | Preserve across API changes |
| Per-request retries | `RequestBuilder::retry_policy` | Overall budget |
| Typed request errors | `RequestError::kind` | Consistency across errors |
| Timeout detail | `RequestError::timeout_phase` | Preserve classification |
| Bounded collection | `ResponseBody::collect_with_limit` | Response helpers |
| Separate proxy roots | `ClientBuilder::add_proxy_root_certificate_der` | Preserve trust separation |
| Origin identities | `ClientBuilder::client_certificate_for` | Preserve selection and isolation |

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

Each milestone uses a `lane/<name>` worktree and an independent review.
The integration owner rebases, reviews every commit, and runs the full gate
from the integration checkout. All required PR checks must pass, including
Windows and macOS, before an exact-SHA fast-forward merge. A failing workflow
on `main` blocks the next merge. Integrated lanes are removed.

Every breaking API change has a migration note. Completion requires every
item above to be implemented, documented, reviewed, merged, and verified
on green `main`. Deferrals require an explicit scope decision.

New browser coverage, backend changes, broader hardening, optimization,
and architecture audits are outside Phase 2. Publication and Phase 3 start
after this phase; do not run `cargo publish` during it.

## Next

- [Roadmap](../roadmap.md#phase-2-ergonomics): the complete phase scope.
- [Route matrix](../reference/route-matrix.md): supported combinations.
- [Contributing](../../CONTRIBUTING.md): required verification.
