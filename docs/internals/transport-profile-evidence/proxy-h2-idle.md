# HTTP/2 proxy idle timer

The proxy pool now retires an expired HTTP/2 connection without another
tunnel opening. Existing tunnels and caller-owned connection handles keep
the retired connection alive until released. New tunnels use a replacement.

## Failure and repair

The original pool checked the idle limit only during acquisition. A loopback
HTTPS-proxy control waited for the idle connection to close without another
checkout. It failed on the original source after eight seconds. The same
control passed with the route timer and observed `GOAWAY(NO_ERROR)` and EOF.

The timer owns a weak route reference. A cancelled callback cannot replace
its successor. Retirement releases native connections outside the pool lock.
A failed timer setup or rearm returns `RuntimeUnavailable`; it cannot leave
a timed connection available indefinitely.

Only consumed response heads, DATA and trailers restart the idle clock.
PINGs and their ACKs do not. The unlimited policy installs no timer.

## Verification and limits

Eighteen pool controls and five client controls passed. They cover closure
without checkout, native GOAWAY bytes, unlimited reuse, acknowledged PINGs,
live CONNECT tunnels, read activity, timer cancellation and timer failures.
Strict Clippy and the default build also passed.

The integration owner's local archive is
`target/transport-profile-campaign/proxy-h2-idle-reviewed/`. It retains the
failed control, unchanged repaired control, full logs, source identities and
commit receipt. Integration gate and platform CI are still pending.

The integration gate at `ecadb639` passed 21 steps. Of 4,659 Rust tests,
4,658 passed. The acknowledged-PING control failed during retirement. An
isolated trace observed the second PING's acknowledgment write fail before
the peer could read GOAWAY. The original failure and a separate trace are
retained in `proxy-h2-idle-ecadb639-failed-gate/` and
`proxy-idle-diagnostic-ecad/` under the same archive parent.

A native guard at `2bd1f082` stops new idle probes after the final reference
is dropped while retaining the existing reset flush. With identical
manual-clock assertions, the old source emitted PING before the required
GOAWAY. The repaired source passed that control and the retained-sender
control. All 52 client tests and the native Rust 1.88 check passed.

The unchanged proxy test also passed with GOAWAY and EOF after acknowledged
PINGs. Required vendor checks passed: HTTP/2 ran 219 executions across 167
distinct passing tests; its existing ignored test remains. The dependent
HTTP implementation passed 64 tests. Source, logs and binaries are retained
in `idle-ping-2bd1f082-focused-final-v2/` under the same archive parent.

An additional standalone HTTP/2 Clippy check failed on 13 diagnostics at
unchanged parent source lines. The diagnostic mapping and full log are
retained without suppression. The workspace's strict Clippy check remains
required in the final integration gate, along with platform CI.

Firefox's idle policy follows source. A browser idle-closure capture is still
absent. These loopback controls establish Phantom's behavior. Buffered DATA
may arrive before the caller consumes it; consumption advances the clock.

## Next

Continue the [campaign](../transport-and-profile-campaign.md) after integration
verification and platform CI.
