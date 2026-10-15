# Connection fixtures and shared listener ports

These repairs address failures that blocked campaign integration. Keep
their controlled reproductions separate from the original host conditions.

## Cookie connection closure

Main `4cae238a` failed its macOS cookie negotiation test. The first peer sent
an empty HTTP/1.1 response, then closed without declaring `Connection: close`.
The client could reuse that connection before its driver observed closure.
The test expected the second request on a new connection.

A controlled peer kept the first connection open until it observed the
cookie-bearing second request. Closing it then reproduced the same typed
`Http1` error and `ReusedConnectionClosed` observation as CI. Adding the close
header made the peer receive the second request on a new connection. Both
original cookie assertions passed. All 33 negotiated controls and strict
Clippy passed with the permanent header-only repair.

The control demonstrates this failure mechanism. The original macOS socket
and scheduler sequence was not recorded. Production pooling and retry
behavior are unchanged.

## Shared TCP and UDP listener ports

The H3 integration gate failed while reserving a snapshot listener port on
Windows. Its alternating ephemeral binds exhausted 64 attempts with error
10013. The host had contiguous UDP exclusions from 55961 through 56860.

A control models sequential ephemeral choices inside that exclusion span.
The original reservation exhausts its retries. The repair disperses candidates
from 20000 through 32767, following the Rust shared-port helper. It keeps
loopback binding, the retry bound, socket cleanup, and original error reporting.
The candidate stride visits each port before repeating.

Both reservation controls and all 47 snapshot controls passed. The original
failed allocation sequence was not retained, so the simulated exclusion is
mechanism evidence rather than an exact reconstruction of that run.

## Alternative destination port ownership

Main `f307150d` failed its macOS alternative-host ECH test before the client
request. Separate UDP and TCP binds to port zero both received port 49683.
The fixture asserted that those port numbers differed, although the operating
system allows independent protocols to share a number.

The destination now reserves both protocols through the existing bounded
shared-port allocator. It keeps the TCP listener until its QUIC peer finishes.
The advertisement therefore cannot take that destination port. All six
original scenarios, assertions and deadlines stay unchanged.

A socket control added to the original fixture failed because another TCP
listener could bind the destination port. The same control and all six
scenarios passed with the reservation. This verifies the missing ownership
constraint. The original CI log separately records the observed collision.

## TLS ticket cleanup phase ordering

The gate on `dc59841a` failed the ticket cleanup control's timeout assertion.
The control joined a cleanup deadline of 10 ms with a peer-release sleep of
30 ms. A delayed runtime wakeup can leave both ready. If the peer finishes
before cleanup is polled, Tokio returns its error before checking the timer.

A control forced that ordering and reproduced the missing-timeout assertion.
The repair keeps the blocking peer held while polling cleanup after the
original sleep. It releases the peer only after cleanup enters its second
join. Both original error assertions and all deadlines remain unchanged.
All 17 session-cache tests passed. Production cleanup behavior is unchanged.

This demonstrates a permitted ordering that explains the failed assertion.
The original gate did not record the scheduler sequence.

## Retained evidence

The integration owner's local archive is
`target/transport-profile-campaign/`. `negotiated-cookie-close-reviewed/`
contains original and controlled sources, complete logs, source and binary
hashes, and independent review. `snapshot-shared-port-reviewed/` contains the
original source, failure control, repaired controls, host exclusion lists,
and independent review.

`firefox-alt-used-mapping-f307150d-gate/main-ci-failed.log` preserves the
original macOS failure. `alternative-port-root-review-v1/` binds the original,
control and repaired source. `alternative-port-baseline-v1/` and
`alternative-port-focused-v2/` contain their complete execution logs. An
earlier fixed-source check reused the baseline binary because copying the
source preserved an older timestamp; its failed log remains in
`alternative-port-focused-v1/`. Writing the reviewed bytes with a current
timestamp forced compilation before the successful check.

The cookie packet also preserves a compiler allocation failure before any
test ran. An unchanged retry with one build job reached the behavioral
control. That compiler failure is not counted as a reproduced test failure.

Full integration gates and platform CI remain separate delivery requirements.

`firefox-ech-retention-rebased-dc59841a-gate/` retains the original gate
failure and its other 22 passing steps. `tls-cleanup-phase-controls-v1/`
contains baseline, forced-order and repaired source. The corresponding
`tls-cleanup-phase-red-v1/` and `tls-cleanup-phase-fixed-v1/` packets retain
commands, full output, source hashes and native-artifact guards.

## Next

Continue the [transport and profile campaign](../transport-and-profile-campaign.md)
after the repairs pass their integration gate and platform CI.
