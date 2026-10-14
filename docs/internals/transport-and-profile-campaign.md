# Transport and profile campaign

Use this plan to repair the historical timing failures, grow the browser
corpus, and deliver the named client features. Track each result against its
acceptance criteria before closing the work.

The campaign is active. The plan was committed at `dbdee197` before source
changes began.

## Starting point

The source baseline is `f9454a9a`, checked on 2026-10-13. Local `main` and
`origin/main` match, the checkout is clean, and applicable main CI is green.
The architecture audit and its delivery PRs are complete. This campaign does
not reopen that audit or change its historical evidence.

The original audit worktree has an outdated, uncommitted delivery-plan
addition. Preserve it and the recovery branches. Their old commit IDs are
not a list of new changes to push. Preserve the local evidence archive too.

Playground's migration remains prepared at `399af77e` and unlanded by user
choice. Do not publish or land it, interrupt Foundry, or change dirty vendor
files. Use isolated consumer checks to inform priorities for Playground and
Solve. Local checks do not establish live service acceptance.

## Work order

| Wave | Work | Dependency |
| --- | --- | --- |
| 1 | T1 and T2: historical failures | Original logs and source |
| 2 | P1 through P5: profile corpus | Current recipe contracts |
| 3 | F1 through F8: client features | Resolved API and protocol contracts |
| 4 | B1 through B5: browser fidelity | Profile foundation and relevant features |
| 5 | E1 through E4: capture expansion | Capture hosts and tooling |
| 6 | D1: consumer checks and closeout | Integrated deliveries |

Research and independent source review may overlap across waves. Run browser
captures when the needed host is available. Choose the next implementation
by dependencies, downstream value, and uncertainty. Keep unrelated repairs in
separate PRs. A blocked capture must not stall independent engineering work.

Unchecked tasks remain open. When you start one, record its owner,
dependencies, current source, acceptance criteria, and next action here.
Update it after each verified delivery. Link detailed logs rather than
copying execution journals into this page.

## Current work

| Task | Owner lane | State and next check |
| --- | --- | --- |
| T1 | `h3-drain-diagnosis` | Readiness repair merged in PR #213 after the exact signed-head gate and platform CI. Main push CI passed; the historical trigger remains open. |
| T2 | `tls-done-diagnosis` | Framed-response repair and EOF controls merged in PR #212 after the full gate and platform CI. Main push CI passed; historical attribution remains open. |
| P1–P4 | `profile-catalog` | Ordered WebSocket components join the reviewed catalog layers at `efd6db4c`, with 372 profile tests and seven doctests passing. Immutable definitions, remaining layers, and integration wire checks remain. |
| P5 | `profile-history` | Edge 153 Windows profile passes four profile and six native replay controls. Catalog registration, corpus measurements, and integration remain. |
| F1 | `ticket-transfer` | Clearing, frozen stores, strict native decoding, and authenticated TCP publication pass focused checks. The reviewed lane is rebased on `6f6426f4`; scoped QUIC publication awaits native verification. Transfer encoding and full policy bindings remain. |
| F3 | `socks4-integration` | SOCKS4/4a merged in PR #215 after the exact-head full gate and macOS/Windows CI. Main push CI passed. |
| F4 | `digest-integration` | Digest merged in PR #218 after the full gate and platform CI. Enterprise contracts are recorded. PR #220 repaired the cookie and shared-port fixtures; main push CI passed. |
| F5 | `doh-wire` | The bounded wire codec is committed at `edecd611`, with 78 DNS tests passing. Caller-reported DNS lifetimes await compilation and review. DoH transport and alternate-host discovery remain. |
| F8 | `http3-debug-auth` | Origin opt-in merged in PR #219 after independent review, all 22 gate steps, 4,643 Rust tests, and 43 green PR checks at `6f6426f4`. |
| B2 | `proxy-h2-idle-integration` | The integration gate passed 21 steps but exposed a PING acknowledgment write during retirement. A native retirement guard is under causal verification. Integration and CI remain; Alt-Used and WINDOW_UPDATE stay separate. |

Neither controlled timing reproduction proves the exact historical host
delay. The unchanged historical TLS suite also passed all 1,041 tests with
four skips. Keep original attribution open while repairing the demonstrated
synchronization weaknesses. Detailed run logs are retained under each
lane's `target/transport-profile-campaign/` pending a reviewed evidence index.
The [TLS timing record](transport-profile-evidence/tls-retirement.md) binds
the T2 repair and retained evidence. Its historical attribution remains open.
The [HTTP/3 draining record](transport-profile-evidence/http3-draining.md)
binds T1's fixture repair. Its original scheduling trigger remains unresolved.
The [proxy authentication investigation](transport-profile-evidence/proxy-authentication.md)
records separate NTLM, Negotiate, and Kerberos contracts. No enterprise
authentication implementation or successful peer exchange is claimed.

The [connection fixture record](transport-profile-evidence/connection-fixtures.md)
binds the cookie closure and shared-port repairs that blocked integration.
Their controlled mechanisms do not establish the original host sequence.

## Historical timing failures

- [ ] T1: Diagnose the HTTP/3 draining failures at `89524379`. Identify both
  original tests and retain their complete failure logs. Reproduce their
  timer, stream, shutdown, and scheduler sequence under the original suite
  conditions and controlled contention. Distinguish a production defect
  from fixture ownership or host scheduling. Repair a demonstrated cause
  and verify the original assertions under isolated and suite execution.
- [ ] T2: Diagnose the TLS capture `/done` read timeout at `39488c23`.
  Reconcile the exact native dependency, worker, callback, socket, and timer
  sequence. Reproduce it before choosing a repair. Verify the original
  OpenSSL server controls and the capture suite on the affected platform.

Start with the [original evidence index](architecture-audit/evidence.md).
Both failures passed later in isolation. Those passes and the current green
gate do not diagnose either cause. Keep separate run logs and source/build
identities. Do not replace assertions, widen timeouts, add retries, or
rebaseline failures to obtain a pass. A justified timing contract change
needs a demonstrated cause and an independent review.

## Profile corpus

- [ ] P1: Add a catalog with stable identifiers and immutable versioned
  definitions. Describe browser/build, OS, architecture, and device where
  known. Store provenance and coverage per layer, including different builds
  within one composed profile. Distinguish captured, source-derived, reused,
  unverified, unavailable, and intentionally absent behavior.
- [ ] P2: Migrate the current recipes into reusable components with explicit
  overrides. Share a component only when its equivalence is established.
  Preserve ordered lists, GREASE policies, session behavior, and draws made
  per client or connection. Keep those draws separate from catalog records.
- [ ] P3: Add validated structured declarations and deterministic generation
  for repetitive recipes and fixture registration. Reject unknown values,
  invalid references, cycles, incompatible components, and excessive input.
  Keep typed Rust policies and transport validation. Retain captures as
  evidence linked to definitions, rather than treating them as executable
  profiles.
- [ ] P4: Provide explicit discovery and selection by catalog identity and
  supported layers. Distinguish metadata identity from wire compatibility.
  Do not silently select another version, platform, or generic default when
  a requested layer is absent. Preserve deliberate custom composition.
- [ ] P5: Prove corpus growth with current recipes and a second independently
  validated version for at least one browser. Use retained historical
  captures where suitable. Adding it must leave existing definitions and
  transport code unchanged. Measure generation/build cost, selection and
  construction cost, and memory at representative corpus sizes. Label
  synthetic scale records as synthetic, never as validated browser recipes.

Replay the current recipe contracts before and after migration. Account for
every existing public recipe and document replacements. Breaking cleanup is
allowed; compatibility shims are unnecessary. Keep the work inside
`phantom-profile` initially. A runtime loader, database, or new crate needs a
demonstrated requirement. Do not assert a runtime bottleneck without data.

## Client functionality

- [ ] F1: Add client-owned TLS and QUIC ticket clearing, export, and import.
  Define and verify origin, profile, server identity, and route/proxy
  authentication bindings. Preserve protocol-specific consumption semantics,
  including TLS 1.2 restoration. Verify expiry, bounds, malformed snapshots,
  and backend compatibility. Keep exported secrets out of logs and review
  artifacts. Use sanitized identifiers and synthetic ticket material in
  controls. Document snapshot sensitivity and portability.
- [ ] F2: Add import of externally described fingerprints through a defined,
  bounded format. Preserve supported order and policy information. Return
  explicit errors for unsupported settings. A JA3/JA4 hash or lossy TLS
  description cannot reconstruct a complete browser profile. Distinguish
  partial custom settings from a validated catalog recipe.
- [x] F3: Add SOCKS4 and SOCKS4a with explicit route capabilities, bounded
  negotiation, and owned cancellation. Verify local versus proxy name
  resolution. Reject unsupported HTTP/3 use before proxy I/O.
- [x] F4: Add Digest proxy authentication with challenge, nonce, stale,
  replay, and credential-isolation controls. Investigate enterprise proxy
  authentication using primary sources and peer APIs. Define the mechanism
  and platform contract before implementation. Record the result separately
  for NTLM and Negotiate/Kerberos; the word "enterprise" is not an API.
- [ ] F5: Add explicit browser-backed DNS-over-HTTPS and alternate-host
  Alt-Svc/ECH discovery policies. Cover resolver bootstrap, cancellation,
  bounds, HTTPS records, and target-host identity. Keep route and protocol
  choices explicit. Verify resumed ECH early-data acceptance and rejection
  only where source and replay-safety contracts support it.
- [ ] F6: Support multiple CONNECT-UDP tunnels on one outer connection.
  Verify bounded admission, authentication isolation, per-tunnel failure and
  cancellation, flow control, and shutdown. Resolve the exact protocol
  extensions meant by datagram APIs before adding them. Test a named peer
  implementation and reject unsupported extensions explicitly.
- [ ] F7: Add an RTT-derived racing policy where the target browser behavior
  supports it. Define which measurements feed it, their lifetime and
  bounds, and behavior before a sample exists. Verify timing decisions and
  cancellation with controlled peers. Keep existing fixed policies explicit.
- [x] F8: Extend the explicit, feature-gated verification-disabled debugging
  mode to HTTP/3. Verify its opt-in behavior and certificate/hostname failure
  controls. Preserve verification in normal configurations.

Implement the concrete additions. Enterprise mechanisms and datagram
extensions first need a supported contract and a feasibility result. Their
investigation cannot close the Digest or CONNECT-UDP delivery tasks. Use
primary protocol/browser sources and current peer implementations to resolve
uncertainty. Research must lead to a decision, bounded experiment, or repair.

## Browser fidelity

- [ ] B1: Extend Firefox address selection to proxies, WebSockets, exact H2,
  and ECH. Cover slower backup ownership, remembered families, failed-address
  suppression, cache lifetime, and connection reuse without changing routes.
- [ ] B2: Correct Firefox `Alt-Used` position and first-request omission,
  ordinary H2 stream `WINDOW_UPDATE` shape, and HTTPS-proxy H2 idle closure.
  Record and verify these as separate changes with their own wire controls.
  The proxy idle-timer repair passed its controlled baseline and focused
  runtime checks. Its [evidence](transport-profile-evidence/proxy-h2-idle.md)
  records the pending integration gate and platform delivery.
- [ ] B3: Add Chromium macOS idle-only keepalive and Android TCP recipes.
  Add verified source-backed Firefox macOS, Linux, and Android keepalive
  recipes. Source-backed support and observed socket behavior remain distinct.
- [ ] B4: Add Firefox Windows DNS record TTL through an audited FFI boundary
  and Chromium per-platform DNS configuration. Cover adapter/VPN/name-policy
  choices and address/HTTPS-query interaction without claiming uncaptured
  browser parity. Coordinate this work with F5.
- [ ] B5: Expand recipes to Safari and missing Firefox/Opera Android layers,
  including Edge Android WebSocket coverage. Define each exact build and
  platform before capture. Add only supported, verified layers to the
  catalog. Existing emulator evidence does not prove physical-device parity.

## Evidence expansion

- [ ] E1: Capture SSE over H2 and H3. Existing transport support does not
  establish browser evidence. Compare opening headers and lifecycle behavior
  for the selected browsers and builds, including macOS and Safari.
- [ ] E2: Capture decrypted tunnelled `wss://` openings. Keep proxy and origin
  handshakes distinct. Compare the supported tunnel types without inferring
  browser use of HTTP/3 WebSockets or MASQUE from Phantom's capabilities.
- [ ] E3: Capture headful Chromium-family macOS `User-Agent` values and
  compare the retained emulator recipes with a physical Android device.
- [ ] E4: Establish a bounded capture matrix for Intel Macs, Linux, and
  additional OS/build variants. Record the selected targets before running
  captures. Keep inaccessible targets explicit; do not generalize results
  to unobserved platforms or versions.

For B5 and E1 through E4, attempt supported capture paths using available
hosts. Missing hardware, browser access, or certificate trust can produce a
limited investigation result with the exact blocker and required resource.
It cannot produce a completed browser-support claim. Retain source-derived,
local-wire, browser-capture, and live-peer results as separate evidence.

## Boundaries

Base URLs and ordered header hooks are delivered. Keep blocking APIs,
automatic `Link` following, arbitrary wire middleware, silent route/protocol
fallback, generic non-H3 QUIC APIs, and replay of ambiguous opened H3 streams
outside this campaign. Do not publish crates or change repository settings.

Other roadmap gaps remain visible but do not silently expand this plan:
Opera trust-anchor distributions, additional validator templates, cookie
contexts, Firefox stale-DNS behavior, broader transaction restarts, and
browser MASQUE capture evidence.
Record a newly discovered defect and repair it when it blocks a named task.
Otherwise retain it as a separate follow-up. Avoid another whole-codebase
audit, speculative crate splits, and unrelated dependency updates.

## Delivery and completion

- [ ] D1: Verify the integrated features against isolated Playground and
  Solve consumer checks. Reconcile this plan, the roadmap, coverage, limits,
  examples, and migration notes. Preserve the unlanded migration and Foundry.

Use subagents for bounded source research, independent implementations, and
non-author reviews. Give each an owned file set, acceptance criteria, and
verification scope. The integration owner keeps central APIs and shared
manifests, combines results, and controls commits and delivery. Follow
[AGENTS.md](../../AGENTS.md) and the engineering standards used by the audit.

Commit coherent verified slices. Each PR needs an independent gate review,
the full gate on its rebased head, and every applicable PR check green,
including Windows and macOS. Integrate by fast-forward only, watch main CI,
and stop subsequent merges if main is red. Retain full logs and exact source,
build, workload, and capture identities. Archive before removing delivered
lanes. Preserve unrelated dirty work and recovery history.

Tests must establish the changed behavior and meaningful failure paths.
Avoid unrelated fixture rewrites, repeated source inventories, and repeated
gates without a new change, failure, or unresolved concern.

Run Cargo through the worktree lock helper. Never format vendored forks with
`cargo fmt --all`. Apply vendor changes through recorded patch series and run
their checks. Run the Linux gate for affected platform code. Confirm Windows
and macOS runtime checks independently of WSL compilation.

Use these outcomes per task: delivered and verified; investigated with a
supported decision; blocked with retained attempts; unresolved. Required
engineering tasks need verified delivery. Optional mechanisms and unavailable
capture targets may end in an explicit limited investigation. Do not mark
required blocked work complete. A rejection needs technical evidence, not a
priority label or lack of time. Repeated green runs do not close unknown
historical causes.

Before completion, read the final full-gate logs and applicable CI results.
Provide a task-by-task report of delivered features, measured corpus costs,
timing causes and remedies, limited investigations, and remaining resources.
Keep completed records linked rather than repeatedly creating new prompts.

## Next

- [Roadmap](../roadmap.md): other release, hardening, and profiling work.
- [Coverage](../reference/coverage.md): the current support contract.
- [Historical evidence](architecture-audit/evidence.md): original audit runs.
