# Connection fixtures and shared listener ports

These repairs address two failures that blocked campaign integration. Keep
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

## Retained evidence

The integration owner's local archive is
`target/transport-profile-campaign/`. `negotiated-cookie-close-reviewed/`
contains original and controlled sources, complete logs, source and binary
hashes, and independent review. `snapshot-shared-port-reviewed/` contains the
original source, failure control, repaired controls, host exclusion lists,
and independent review.

The cookie packet also preserves a compiler allocation failure before any
test ran. An unchanged retry with one build job reached the behavioral
control. That compiler failure is not counted as a reproduced test failure.

Full integration gates and platform CI remain separate delivery requirements.

## Next

Continue the [transport and profile campaign](../transport-and-profile-campaign.md)
after the repairs pass their integration gate and platform CI.
