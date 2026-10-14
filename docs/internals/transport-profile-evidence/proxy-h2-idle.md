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

A native guard is being checked against identical manual-clock controls on
old and repaired source. It stops new idle probes after the final reference
is dropped while retaining the existing reset flush. Its outcome and the
unchanged proxy control must be verified before integration.

Firefox's idle policy follows source. A browser idle-closure capture is still
absent. These loopback controls establish Phantom's behavior. Buffered DATA
may arrive before the caller consumes it; consumption advances the clock.

## Next

Continue the [campaign](../transport-and-profile-campaign.md) after integration
verification and platform CI.
