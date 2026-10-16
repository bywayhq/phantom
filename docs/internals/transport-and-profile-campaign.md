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

PR #247 merged at `4dbe270b` after all 23 gate steps, 5,384 runtime tests
and 29 PR checks; both applicable main push workflows passed. PR #248 then
merged at `5c11188a` with all eight main push workflows passing. PR #249
fast-forwarded main to `8e22f319` on 2026-10-16 at 00:34:07 UTC after
independent review, all 23 Windows/Linux gate steps, 5,456 runtime passes
with two skips, and 43 successful current PR checks. All eight applicable
main push workflows passed. PR #250 then merged at `c934f82a` on
2026-10-16 at 03:09:45 UTC after independent review, all 23 Windows/Linux
gate steps, 5,585 runtime passes with three skips, and all 43 current PR
checks. Its nine applicable main push workflows include BoringSSL native;
all nine main push workflows passed. PR #251 fast-forwarded main to
`28e08108` on 2026-10-16 at 04:35:41 UTC after independent review, all 23
Windows/Linux gate steps, 5,680 runtime passes with three skips, and all 43
current PR checks. All eight applicable main push workflows passed. PR #252 then
fast-forwarded main to `41483d5a` on 2026-10-16 at 06:14:21 UTC after
independent review, all 23 Windows/Linux gate steps, 5,721 runtime passes
with three skips, and all 43 current PR checks. All eight applicable main
push workflows passed. PR #253 fast-forwarded main to `61685a6d` on
2026-10-16 at 08:29:36 UTC after independent review, all 23 Windows/Linux
gate steps and all 29 current PR checks, including both platform jobs.
Both applicable main push workflows passed.

| Task | Owner lane | State and next check |
| --- | --- | --- |
| T1 | `h3-drain-diagnosis` | Readiness repair merged in PR #213 with gate and platform CI. A rebuilt historical-source test passed once under current contention and the debugger, observing shutdown, GOAWAY and replacement in order. This does not attribute the original failure; its cause remains OPEN. |
| T2 | `tls-done-diagnosis` | Repair merged in PR #212. The 2026-10-16 single original test passed with the complete /done response, native EOF wait and same retirement timer observed. Its 12-ms dispatch delay does not explain the historical 17.579-second pause. The earlier address-in-use attempt remains retained; original cause OPEN. |
| P1–P4 | `profile-catalog` | Catalog composition merged in PR #223 at `8754e971` after independent review, all 22 gate steps, 4,708 Rust tests and 43 green PR checks. Provenance and coverage are recorded per component, with explicit reuse and absent layers. |
| P5 | `profile-catalog` | Edge 153 Windows and corpus measurements merged in PR #225 at `b0a40765` after independent review, all 22 gate steps, 4,828 Rust tests and 43 green PR checks. All eight applicable main push workflows passed. Synthetic growth measurements cover 11 through 1,035 records without changing existing definitions. |
| F1 | `ticket-transfer` | TCP snapshots merged in PR #231, QUIC primitives in PR #234, and mixed transactions in PR #235. All nine main push workflows passed for PR #235. Final client transfer merged in PR #236 at `b132f446` after independent review, all 23 gate steps, 5,270 Rust tests and 43 green PR checks. Focused Linux runtime and all eight applicable main push workflows passed. |
| F2 | `fingerprint-import` | Bounded JSON import merged in PR #226 at `8b13da48` after independent review, all 22 gate steps, 4,851 Rust tests and 41 green PR checks. All six applicable main push workflows passed. Import controls cover all 11 profiles and 22 templates. |
| F3 | `socks4-integration` | SOCKS4/4a merged in PR #215 after the exact-head full gate and macOS/Windows CI. Main push CI passed. |
| F4 | `digest-integration` | Digest merged in PR #218 after the full gate and platform CI. Enterprise contracts are recorded. PR #220 repaired the cookie and shared-port fixtures; main push CI passed. |
| F5 | `alt-svc-ech-delivery` | DoH merged in PR #224 at `c7201173`; all nine applicable main workflows passed. Alternate-host ECH discovery and opt-in native server early data merged in PR #227 at `b9fdc60a` after independent review, all 22 gate steps, 4,903 Rust tests and 43 green PR checks, including macOS and Windows. All eight applicable main push workflows passed. Browser captures remain separate. |
| F6 | `connect-udp-sharing` | Merged in PR #229 at `0f404ab2` after independent review, all 22 gate steps, 4,982 Rust tests and 43 green PR checks, including macOS and Windows. All eight applicable main push workflows passed. Both named peer implementations passed their explicit controls. |
| F7 | `rtt-racing` | Merged in PR #228 at `3973d41c` after independent review, all 22 gate steps, 4,943 Rust tests and 43 green PR checks, including macOS and Windows. All eight applicable main push workflows passed. No browser timing parity or performance benefit is claimed. |
| F8 | `http3-debug-auth` | Origin opt-in merged in PR #219 after independent review, all 22 gate steps, 4,643 Rust tests, and 43 green PR checks at `6f6426f4`. |
| B1 | `firefox-forward-proxy-retention` | Direct ECH, direct H1/H2 WebSocket and exact H2 retention are merged through PR #243. Plaintext CONNECT retention merged in PR #245 with green main CI. H1 proxy retention merged in PR #248 at `5c11188a` after independent review, all 23 gate steps, 5,435 runtime passes with two skips, and 43 current PR checks. All eight applicable main push workflows passed. Remaining named proxy paths and failed-address feedback are delivered through PRs #249–#252. |
| B1 CONNECT | `firefox-h2-connect` | Merged in PR #249 at `8e22f319` after the exact-head full gate, 5,456 runtime passes with two skips, and 43 current PR checks. The unchanged future-size limits passed. All eight applicable main push workflows passed. |
| B1 outer H2 | `firefox-h2-proxy-owner` | Merged in PR #250 at `c934f82a` after independent review, all 23 Windows/Linux gate steps, 5,585 runtime passes with three skips, and 43 current PR checks. All nine applicable main push workflows passed. Raw backup progress ends at verified outer H2 activation, before authentication or CONNECT. |
| B1 dedicated outer H2 | `firefox-dedicated-h2-owner` | Delivered in PR #252 after the exact-head gate and current platform checks. Configured physical backup ownership covers dedicated ordinary H2 and dedicated/shared CONNECT-UDP H2 setup. This is transport-policy consistency, not Firefox MASQUE evidence. |
| B1 feedback/SOCKS | `firefox-feedback-socks-delivery` | Merged in PR #251 at `28e08108` after the exact-head full gate, 104 selected controls, actual API generation and 43 current PR checks. All eight applicable main push workflows passed. Earlier compile, runtime and macOS fixture failures remain retained. A later correction removes the direct early-data capability guard from SOCKS retention. Its three valid-fixture baseline tests fail on the unfixed source and pass in the delivered PR #252 gate. |
| B1 proxy WebSocket | `firefox-proxy-ws-delivery` | Delivered in PR #252 at `41483d5a`. All 23 gate steps, 5,721 runtime tests and 43 current PR checks passed, followed by all eight main workflows. All 150 selected controls passed. Actual NET API inventory has 1,647 lines; profile and facade inventories are unchanged. Proxy ECH and proxy early data remain unsupported. |
| B2 | `firefox-h2-window-delivery` | Proxy idle closure and Alt-Used placement/mapping merged in PRs #222, #230 and #237; the alternative-port fixture repair merged in PR #239 with green main CI. Ordinary H2 stream-window behavior merged with the reviewed union in PR #250 after its exact-head gate and 43 current PR checks. All nine applicable main push workflows passed. |
| B3 | `platform-tcp-integration` | TCP/keepalive policies merged in PR #244 at `4d6c13cd` after independent review, all 23 gate steps, 5,363 Rust tests and 43 green PR checks, including macOS and Windows. All eight applicable main push workflows passed. The generated API inventory records five recipe functions and two policy fields. |
| B4 | `chromium-linux-dns-integration` | Windows DNS TTL and configuration support merged in PR #250. All nine applicable main push workflows passed. Linux paired wiring at `e2d516aa` passed independent source review, strict all-target/all-feature NET Clippy, 142 production DNS tests and 17 production native FFI/watch tests. The intermediate-symlink watch repair and owned-directory regression passed. Native Linux API generation passed; its 1,647 lines differ only in the platform constructor. Full integration and MSRV checks remain pending. macOS native source has a separate signed checkpoint and source review, with SDK/runtime and paired integration still pending. Native probes do not establish browser parity or induced adapter/VPN changes. |
| B5 | `edge-android-websocket-integration` | The emulator-backed Edge Android H1/H2 WebSocket layer and source-backed bounded Chromium restarts merged in PR #250 after its exact-head gate and current PR checks. All nine applicable main push workflows passed. No physical Android or browser H3 parity is claimed; missing Safari and Android layers remain open. |
| E1/E2 | `capture-delivery` | Original Windows matrix: 60 successes, 14 failures, one interruption; twelve corrected tunnel follow-ups succeeded separately. The branch retains 60 SSE and 12 tunnel files. Actual Phantom controls observed all eight SSE trials (six H3 cleanup failures) and thirteen WebSocket trials (twelve successful exchanges, one explicit policy error). Independent comparison and integration are recorded separately. |
| E1/E4 Safari | `safari-hosted-capture` | Hosted macOS tooling prepares independent headed WebDriver HTTP and loopback H2 `reconnect-204` attempts, with no capture retries. Independent source review and twenty focused Python controls passed. H2 requires the returned session-only certificate-bypass capability and actual negotiated H2 observations. The workflows have not run Safari. Raw ClientHello/SETTINGS and ordinary domain SNI remain outside this slice; no complete Safari recipe or browser parity is claimed. Physical Android is unavailable. |
| E3/E4 macOS | `safari-hosted-capture` | Dispatch-only tooling prepares one headed Chrome HTTP `reconnect-204` attempt on each of `macos-latest` arm64 and `macos-15-intel` x86_64. The installed browser build, OS, architecture, launch mode and raw `User-Agent` bytes are retained without an override. Source review passed; neither hosted job has run. Actual observations and cleanup outcomes remain required. Physical Android is unavailable. |

The B2/B4/B5 union and pooled outer-H2 extension are delivered in PR #250.
Its exact `c934f82a` head passed the complete Windows/Linux gate and all 43
current PR checks. All nine main push workflows passed. The manifest changes also triggered
BoringSSL native. Native adapter changes, physical Android and browser H3 parity
remain outside that delivery evidence.

PRs #251 and #252 are delivered. Their retained baseline and first combined
gate failures remain separate evidence: nine runtime failures, a test lint,
a deep compiler Send proof and a Windows process-collection race. Reviewed
repairs preserved the assertions and deadlines. The exact `41483d5a` gate
then passed all 23 steps and all 5,721 runtime tests, with three skips.
Its actual API outputs match the installed inventories. The 150 selected
controls each passed once. The independent B1 acceptance review closes the
named engineering paths while retaining the documented proxy limitations.

PR #253 delivers five Linux files from seven headless WSL runs and 72
Windows files. All 77 files retain exact raw bytes and independent reviews.
The exact `61685a6d` gate passed 5,721 Rust tests with three skips and
1,135 capture tests with four skips. The prior Windows socket resource
failure remains retained with its cause unresolved. The
[capture comparison record](transport-profile-evidence/capture-expansion.md)
binds these observations and their limits.

The isolated Playground/Solve run passed 823 selected tests against delivered
`41483d5a`: 657 types, 157 TLS egress and nine offline Solve controls, with
no skips. Primary consumer work and Foundry were preserved. The migration
remains unpublished and unlanded. This is local consumer compatibility, not
live service acceptance; final documentation reconciliation remains open.

The Windows DNS watch and configuration probes retain separate native
read-only evidence. Actual adapter or VPN changes and browser parity remain
unobserved. Earlier failed compiler and fixture attempts remain retained.

The cancelled-relay ownership repair merged in PR #246 at `6c155e05` after
all 23 gate steps, 5,384 Rust tests and 41 green PR checks. All four
applicable main push workflows passed. The fixture-only change does not
select the other conformance workflows.

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

The [catalog cost record](transport-profile-evidence/catalog-costs.md) records
offline corpus measurements and their limits. Synthetic clones add scale,
not browser coverage.

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

- [x] P1: Add a catalog with stable identifiers and immutable versioned
  definitions. Describe browser/build, OS, architecture, and device where
  known. Store provenance and coverage per layer, including different builds
  within one composed profile. Distinguish captured, source-derived, reused,
  unverified, unavailable, and intentionally absent behavior.
- [x] P2: Migrate the current recipes into reusable components with explicit
  overrides. Share a component only when its equivalence is established.
  Preserve ordered lists, GREASE policies, session behavior, and draws made
  per client or connection. Keep those draws separate from catalog records.
- [x] P3: Add validated structured declarations and deterministic generation
  for repetitive recipes and fixture registration. Reject unknown values,
  invalid references, cycles, incompatible components, and excessive input.
  Keep typed Rust policies and transport validation. Retain captures as
  evidence linked to definitions, rather than treating them as executable
  profiles.
- [x] P4: Provide explicit discovery and selection by catalog identity and
  supported layers. Distinguish metadata identity from wire compatibility.
  Do not silently select another version, platform, or generic default when
  a requested layer is absent. Preserve deliberate custom composition.
- [x] P5: Prove corpus growth with current recipes and a second independently
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

- [x] F1: Add client-owned TLS and QUIC ticket clearing, export, and import.
  Define and verify origin, profile, server identity, and route/proxy
  authentication bindings. Preserve protocol-specific consumption semantics,
  including TLS 1.2 restoration. Verify expiry, bounds, malformed snapshots,
  and backend compatibility. Keep exported secrets out of logs and review
  artifacts. Use sanitized identifiers and synthetic ticket material in
  controls. Document snapshot sensitivity and portability.
- [x] F2: Add import of externally described fingerprints through a defined,
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
- [x] F5: Add explicit browser-backed DNS-over-HTTPS and alternate-host
  Alt-Svc/ECH discovery policies. Cover resolver bootstrap, cancellation,
  bounds, HTTPS records, and target-host identity. Keep route and protocol
  choices explicit. Verify resumed ECH early-data acceptance and rejection
  only where source and replay-safety contracts support it.
- [x] F6: Support multiple CONNECT-UDP tunnels on one outer connection.
  Verify bounded admission, authentication isolation, per-tunnel failure and
  cancellation, flow control, and shutdown. Resolve the exact protocol
  extensions meant by datagram APIs before adding them. Test a named peer
  implementation and reject unsupported extensions explicitly.
- [x] F7: Add an RTT-derived racing policy where the target browser behavior
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

- [x] B1: Extend Firefox address selection to proxies, WebSockets, exact H2,
  and ECH. Cover slower backup ownership, remembered families, failed-address
  suppression, cache lifetime, and connection reuse without changing routes.
  Direct ECH and H1 WebSocket retention are merged with green main CI.
  Exact H2 merged in PR #242 after its full gate and all 43 PR checks.
  All eight applicable main push workflows passed.
  Direct H2 WebSocket retention merged in PR #243 after its full gate and
  all 43 PR checks. Its repaired setup future stays within the unchanged
  size budget. All eight applicable main push workflows passed.
  Plaintext CONNECT retention merged in PR #245 with green main CI.
  Pooled outer H2 retention merged in PR #250 after its exact-head gate and
  all 43 current PR checks; all nine applicable main push workflows passed.
  Proxied WSS H1 and inner H2 through outer H1, SOCKS WebSocket retention and
  dedicated outer-H2 setup merged in PR #252 after independent review, all
  23 gate steps and 43 current PR checks. All eight main workflows passed.
  Their API inventory is generated and installed.
  Failed-address feedback merged in PR #251.
  Three controls passed for SOCKS retention with direct early-data capability;
  proxy TLS uses ordinary handshakes. ECH through proxies remains unsupported.
- [x] B2: Correct Firefox `Alt-Used` placement and mapping-time omission,
  ordinary H2 stream `WINDOW_UPDATE` shape, and HTTPS-proxy H2 idle closure.
  Record and verify these as separate changes with their own wire controls.
  The optional H3 slot and Firefox navigation/fetch placement merged in
  PR #230. Mapping-time omission now has checked-handshake publication,
  per-mapping lifetime and immutable request-hop decisions. Its full gate and
  platform checks passed before PR #237 merged; the subsequent main fixture
  failure and repair are recorded above. Ordinary H2 opening-stream
  WINDOW_UPDATE merged in PR #250 after its exact-head gate and all 43
  current PR checks. All nine applicable main push workflows passed.
  The proxy idle-timer repair merged in PR #222 after its full gate and
  platform checks. Its [evidence](transport-profile-evidence/proxy-h2-idle.md)
  records the controlled baseline, retirement guard and verified delivery.
- [x] B3: Add Chromium macOS idle-only keepalive and Android TCP recipes.
  Add verified source-backed Firefox macOS, Linux, and Android keepalive
  recipes. Source-backed support and observed socket behavior remain distinct.
- [ ] B4: Add Firefox Windows DNS record TTL through an audited FFI boundary
  and Chromium per-platform DNS configuration. Cover adapter/VPN/name-policy
  choices and address/HTTPS-query interaction without claiming uncaptured
  browser parity. Windows TTL and configuration support merged in PR #250.
  Linux/macOS
  Chromium eligibility and search configuration remain required engineering.
  Actual adapter or VPN changes remain unobserved. Coordinate with F5.
- [ ] B5: Expand recipes to Safari and missing Firefox/Opera Android layers,
  including Edge Android WebSocket coverage. Define each exact build and
  platform before capture. Add only supported, verified layers to the
  catalog. The Edge Android H1/H2 WebSocket layer merged in PR #250.
  Existing emulator evidence does not prove physical-device parity.

## Evidence expansion

On 2026-10-15, the user confirmed that neither a local Mac nor a physical
Android device is available. Hosted macOS workflows prepare the selected
Safari HTTP/H2 and headed Chrome attempts. Those jobs have not run; a local
Mac is not required for these bounded hosted attempts. Physical Android
remains unavailable. Continue Windows and Linux work alongside them.

- [ ] E1: Compare the retained Windows H3 SSE captures and Firefox H2
  `retry-0` capture with Phantom. Resolve the three unsuccessful Chrome SSE
  rows and expand H2 and platform/build coverage, including macOS and Safari.
  Tracked `sse_reconnect --protocol h2|h3` modes are available; fresh
  integration checks of the composed capture tools remain pending.
- [x] E2: Compare the twelve retained Windows tunnelled `wss://` openings
  with Phantom, keeping proxy and origin handshakes distinct. Expand the
  selected builds and platforms without inferring browser H3 WebSocket or
  MASQUE use from Phantom's capabilities. The tracked `tunnelled_websocket`
  tool and manifest runner expose the proxy/origin modes for new captures
  with fresh paths; historical attempts and their outcomes remain unchanged.
  All twelve public-client comparisons passed their exchange controls. Two
  selected Firefox Linux HTTPS-proxy captures expanded H1/H2 coverage.
  Chromium 154/155 frame differences remain explicit; this closes the
  selected comparisons and captures without claiming whole-build parity.
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
