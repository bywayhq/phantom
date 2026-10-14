# RTT-based alternative racing

This record describes F7's source contract and focused checks. The full
integration gate and platform CI remain.

## Browser source

The reading uses Chromium tag `154.0.8037.97`, downloaded on 2026-10-14.
Raw encoded responses, decoded files and hashes are retained in this lane's
`target/transport-profile-campaign/f7-design/primary-v1/` and `primary-v2/`
directories.

| Source | Observed rule |
| --- | --- |
| [`QuicSessionPool::GetTimeDelayForWaitingJob`](https://chromium.googlesource.com/chromium/src/+/refs/tags/154.0.8037.97/net/quic/quic_session_pool.cc#1581) | No delay when QUIC has not worked on the network, except the persisted-network startup case; no delay after recent QUIC breakage |
| Same function | 1.5 times stored smoothed RTT, in whole microseconds; 300 ms when that calculation is zero; optional feature-controlled additional delay |
| [`GetServerNetworkStatsSmoothedRtt`](https://chromium.googlesource.com/chromium/src/+/refs/tags/154.0.8037.97/net/quic/quic_session_pool.cc#2519) | Direct routes only; origin host and port, partitioned by network anonymization key |
| [`ProcessGoingAwaySession`](https://chromium.googlesource.com/chromium/src/+/refs/tags/154.0.8037.97/net/quic/quic_session_pool.cc#2665) | Store measured statistics after 1-RTT keys exist; do not record proxy measurements or a currently broken alternative |
| [`MaybeSetWaitTimeForMainJob`](https://chromium.googlesource.com/chromium/src/+/refs/tags/154.0.8037.97/net/http/http_stream_factory_job_controller.cc#744) | Normally skip delay for an available HTTP/2 session; cap the wait at three seconds |

[`features.cc`](https://chromium.googlesource.com/chromium/src/+/refs/tags/154.0.8037.97/net/base/features.cc#818)
enables the additional delay by default on Android, with 100 ms. Desktop
defaults disable it. Both default to bypassing available HTTP/2 connections.
The session key uses the request origin, independently of the dial target.
These are build defaults, not active field-trial settings or captured timing.

## Current Phantom ownership

`AltSvcRace::new` holds one fixed `Duration`. The race starts origin setup
immediately when discovery is pending or a pooled HTTP/2 session is ready.
Existing failure, deadline, admission and cancellation rules stay applicable.

`phantom-net` records completed-handshake QUIC connection RTT at handshake
completion and connection close. Its existing native ticket cache stores the
latest value by server name, with a count bound. That data feeds the
`initial_rtt_us` wire parameter. It has no sample timestamp or port key and
exists only when tickets are enabled. It is unsuitable as the racing store
without additional ownership and lifetime rules. This recorder does not
exclude verification-disabled connections.

## Approved implementation contract

Keep fixed racing explicit and unchanged. Add an opt-in policy based on
completed, verified direct HTTP/3 connections. Keep this policy's history in
the owning client, separate from portable ticket snapshots and profile
definitions. Do not let proxy measurements influence a direct request.

The caller chooses fixed timing or RTT timing, with explicit sample capacity,
maximum age and optional additional delay. History belongs to one client and
uses origin and dial-target host/port keys. Clones share it. Proxy, pending,
failed and verification-disabled connections cannot publish samples.

Before a fresh eligible direct success, the delay is zero. After success,
a missing or zero sample gives 300 ms plus the additional delay. A fresh
sample gives 1.5 times its whole-microsecond RTT plus that delay, capped at
three seconds. Reads never refresh age. Existing fixed delays are unchanged.

One timer uses the first eligible alternative's sample, preserving field
order. Pending discovery, ready HTTP/2 and all-alternative failure retain
their immediate-origin behavior. Broken alternatives invalidate their sample.

Normal connections publish once after verified completion. An early connection
publishes once after its first successful response confirms settled metadata.
This conservative publication point differs from Chromium's close-time update.
Clearing history changes its generation. Older connections cannot reseed it.
Clearing Alt-Svc also clears racing history; it does not close connections.

Phantom has no browser network-anonymization key or persisted network-success
state. A client-local policy must describe that difference plainly. Do not
call an origin-scoped success flag equivalent to Chromium's network state.

## Acceptance controls

Use a paused clock for sample age, arithmetic, fallback and cap decisions.
Use controlled direct peers to prove that a completed authenticated handshake
supplies the sample. A failed handshake or verification-disabled connection
must not contribute. Prove route, origin and destination isolation.

Verify origin-start timing, ready HTTP/2 bypass, pending discovery, all
alternative failures, total deadline and cancellation. Preserve single
request dispatch and release every admission. Record actual event readiness
instead of relying on sleeps as the proof of ownership.

No performance benefit or browser timing parity is claimed. These controls
check Phantom's client-local policy and do not establish browser parity.

## Focused results

On 2026-10-14, the Windows lane passed these checks with unchanged assertions:

| Controls | Passed |
| --- | ---: |
| History bounds, age, generation and isolation | 14 |
| Paused-clock delay decisions | 4 |
| Fixed and RTT policy validation | 4 |
| Native early completion | 12 |
| Native connection behavior | 20 |
| Actual RTT peers | 6 |
| Resumed HTTP responses | 2 |
| Resumed WebSocket responses | 2 |
| Fixture worker ownership and close codes | 9 |

Strict Clippy, Rust 1.88, strict rustdoc and 131 doctests passed. Five existing
doctests remain ignored. Full logs, source rosters and binary identities are
retained in `f7-focused-v3/` and `f7-focused-v5/` under the lane's
`target/transport-profile-campaign/`.

The first actual peer run failed. Its new IPv4-only fixtures left `localhost`
resolving to IPv6 first. Explicit IPv4 overrides preserve the hostname and
verification policy. A remaining cleanup failure reported a remote
`H3_NO_ERROR` after the seeded client closed. The fixture now accepts that
exact code while awaiting another request. Its new protocol-error control
still requires the nonzero remote error to reach the owner.

Original failures remain in `f7-focused-v3/` and `f7-focused-v4/`. No deadline,
retry or assertion changed. This repair does not diagnose T1's historical
draining trigger. Matching-target timing uses controlled models; actual peer
tests establish publication and bypass behavior, not browser timing parity.

## Next

- [Campaign](../transport-and-profile-campaign.md): fixed task scope.
- [Limits](../../reference/limits.md#delays-and-timers): current fixed delays.
