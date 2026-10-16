# Capture expansion evidence

Use this record to distinguish browser captures from the public-client
comparisons made on 2026-10-16. Original failures remain part of the result.

## Source and runtime

Browser peers used capture commit `543cf22f`. The public Rust clients used
library commit `41483d5a`. Their controllers verified 42 peer inputs and
139 native inputs before and after execution. Later capture-branch rebasing
is not represented as the source that produced these observations.

The Windows comparisons used Python 3.10.20, aioquic 1.3.0, h2 4.4.1,
hpack 4.2.0 and cryptography 50.0.2. Driver source, actual binaries, lock
resolution and runtime identities remain bound in the retained receipts.
The WebSocket driver's initial review found a proxy-CA placement error.
Only that experiment was corrected to use the separate proxy trust store,
rebuilt and reviewed before execution. Original source and binary remain.

## Browser capture sets

| Set | Files | Runs | Result |
| --- | ---: | ---: | --- |
| Windows SSE | 60 | 120 | 59 H3 files, one Firefox H2 file |
| Windows tunnelled WebSocket | 12 | 12 | Corrected follow-ups, two browsers and three proxy types |
| Firefox Ubuntu WSL | 5 | 7 | Snapshot, H2/H3 SSE and two HTTPS-proxy WebSocket cases |

The original Windows matrix attempted all 75 rows: 60 succeeded, 14 failed
and one was interrupted. Twelve successful tunnel follow-ups are separate
from the twelve original failed tunnel rows. Nine early SSE files retain
18 UDP cleanup diagnostics. Four successful SOCKS tunnel files retain nine
Windows reset callback log entries. These do not diagnose all earlier failures.

The Linux package is Firefox 157.0, build ID `20260924084938`. Its official
archive SHA256 is
`42f2c62a562316982ef5a796738c57602bf84a984f5c616e80bcff4627f78fff`.
All five selected jobs ran once without a harness retry on Ubuntu 24.04.4
WSL2 x86_64, headless with WSLg available and UID 0. Exact host metadata is
inside each fixture. The files do not establish native hardware or headful
behavior. No Mac or physical Android device was available.

## Public SSE observations

Four cases ran twice: Firefox H3 empty-ID reset, Firefox H2 retry zero,
Firefox H3 temporary redirect and Chromium H3 temporary redirect. Only the
seven unattempted cells ran after the first failure; no cell was retried.

All eight clients returned success and reported closed event sources.
Both H2 trials were clean. All six H3 trials retained owned Win1234 UDP
receive errors during peer cleanup. All recorded owner collections were
empty. The seven continuation proofs also verified retired listeners and
empty actual server collections. External containment cleanup completed.
That ownership evidence does not turn failed trials into successful runs.

| Comparison | Observation |
| --- | --- |
| Firefox H2 retry zero | All eight normalized SSE opening headers agree |
| Firefox H3 empty ID | Absent ID, `phantom-1`, absent ID |
| Firefox H3 headers | Browser `Alt-Used` absent from exact-origin Phantom |
| Firefox 307 paths | Original, target, original in both clients |
| Chromium 307 paths | Phantom original/target/original; browser original/target/target |
| Retry timing | Measured intervals differ; no tolerance or attribution |

The explicit templates and retry policies are experiment inputs. Selecting
a transport profile does not supply a browser EventSource lifecycle policy.
Chromium 154 and 155 EventSource and parser source are pairwise identical
at the inspected seams. Phantom documents original-URL reconnection; this
leaves a Chromium browser behavior gap. Firefox's temporary redirect policy
agrees with the observed original-URL reconnect.

H3 comparisons retain the different selection paths: Phantom selected exact
origin H3, while browsers used Alt-Svc. Diagnostic removal of `Alt-Used`
does not change the inequality verdict. The four Phantom redirect trials
reset the initial H3 redirect stream with code 268, absent at that point
in the browser records. The six failed trials do not establish the full
three-second post-terminal observation. Callback-time ownership and endpoint
provenance are insufficient to attribute the Win1234 cause.

## Public tunnelled WebSocket observations

Twelve exchange cells cover Firefox 157 and the Chromium 154 profile over
HTTP CONNECT, HTTPS CONNECT and SOCKS5, each with inner H1 and H2. Each
client sends the same five-message corpus, verifies every echo and closes
with code 1000. The peer declines offered compression. Caller user-agent,
Origin and language are explicit. All 60 payload hashes and echoes agree.

Ordered opening headers, normalized proxy openings and origin ALPN match
all twelve browser cases. H2 priority matches all six H2 cases; HTTPS proxy
ALPN and server name match all four applicable cases. Firefox frame lengths
match. The Chromium 154 profile sends the 1 MiB message as one frame, while
captured headless Chrome 155 uses 14–17. Caller UA does not change that
transport build. No whole-build equivalence follows from matching headers.

The thirteenth trial preserves Firefox's explicit profile-policy outcome
against an H1-only origin: H2 ALPN error, no fallback and no WebSocket bytes.
Explicit H1 succeeds separately. Each installed resolver observes only its
proxy host, and SOCKS5 sends the origin domain. This establishes the tested
route, not absence of every possible platform network request.

All thirteen trials and their external owner completed without primary or
cleanup failures. The comparison excludes outer H2, authentication, SOCKS4,
H3 WebSockets, full TLS fingerprints and other-platform parity.

## Retained receipts

Each path below is relative to a lane's `target/transport-profile-campaign/`,
except the public client adapter folders under `firefox-socks-eligibility/target/`.
Raw outputs, original attempts and exact input manifests stay with these
receipts. Archive them before removing delivered worktrees.

| Lane and receipt | SHA256 |
| --- | --- |
| `capture-delivery/E4-linux-snapshot-observed-v1/review.json` | `65ae00da1a0151855741630860ba621339debcd6193f82165dc06e8a3505c1c0` |
| `capture-delivery/E4-linux-remaining-observed-v1/review.json` | `4822e49fb0d29714c741c6139abc7cc2408a8e1e45c2497cafaa32161aea6758` |
| `capture-delivery/E4-linux-fixture-install-v1/result.json` | `8f44b1730c9b330f545866d72e33fd8e3c27195909cad0c4c1a277490c8c912b` |
| `capture-delivery/E1-public-actual-observations-v1/receipt.json` | `14fc61df8e58698457d4a6f2441ff5c9ab36e667d0d25c1e88ab5f34082558ad` |
| `h3-drain-diagnosis/E1-actual-runtime-independent-v1/review.json` | `0285011067e8f47de429d3519b266db1e69ea739d413748e1573b69ee37df087` |
| `h3-drain-diagnosis/E2-actual-runtime-independent-v1/review.json` | `53d3fa5117b6d99b9055ed80abfbc3e3d8da740ad429f0e89c7ce4930eab0899` |
| `macos-headful-capture/E2-acceptance-reconciliation-v1/receipt.json` | `08bbe18018b5ab7a032b7dabdbe816303232dc0100ae584b05f348f7e5fb80ae` |
| `firefox-socks-eligibility/E1-upstream-eventsource-policy-v1/receipt.json` | `fb75bc7baf9b7c44f4a93e3f73a59ad4b41f3c2c768632abf03931250ce9510f` |
| `h3-drain-diagnosis/capture-rebase-composition-independent-v1/review.json` | `aa55e0908edf2ecaa989a4019eca856ef2cb531d70501d7d4c8d629c89a93a40` |

The SSE interpretation author also wrote its continuation. A separate
reviewer approved the actual observations with all six failures retained.
Source and result reviews do not replace the final rebased-head gate.

## Next

- [Validation](../../explanation/validation.md#windows-h2-and-h3-sse-expansion):
  browser fields and lifecycle observations.
- [Campaign](../transport-and-profile-campaign.md): remaining required work.
- [Consumer checks](consumer-checks.md): isolated downstream results.
