# HTTP/3 draining readiness

Use this record to assess the draining fixture repair and its limits. The
controlled schedule reproduces both failures without diagnosing the original
host's scheduling delay.

## Original failure

At `89524379d76418df9734cbd186f0bd5029abc7d9`, two draining tests failed
while waiting for a replacement connection. The fixture signalled server
GOAWAY, then slept 300 milliseconds before making its next request.

The request can acquire the old connection before the client processes
GOAWAY. It then waits for stream capacity while the fixture waits for a new
connection. The sleep did not establish client readiness.

## Controlled results

The relevant production source, dependency lock, toolchain, and nextest
configuration match the historical revision. Later fixture changes add
diagnostic labels. The original failed-run binary was not available for new
hashing; original logs and source/build context remain retained.

| Control | Result |
| --- | --- |
| Unchanged focused baseline | 15 tests passed |
| Original assertions with GOAWAY delayed 750 milliseconds | Both original tests failed |
| Repaired assertions under the same delay | Both tests passed |
| Final focused fixtures | 17 tests passed |
| Full sessions at 16 concurrent tests | 400 tests passed |
| Focused Clippy and formatting | Passed |

The controlled failures match the historical error trees. Comparison removes
only diagnostic deadline wrappers and ephemeral loopback ports. Error kinds,
nesting, and replay observations remain. This proves a matching mechanism,
rather than exclusive historical attribution.

## Repair and review

The fixture waits for the existing client event emitted after GOAWAY
processing marks the connection closing. Two peer controls withhold server
GOAWAY and establish that replacement waits for actual client processing.

Request and connection counts, body and protocol assertions, and the original
10-second operation and five-second cleanup deadlines remain. The repair
adds no retries, production changes, or vendor changes. A request acquired
before GOAWAY is not claimed to have a production repair.

Independent review approved lane commit
`fed05d46dcd2f02739d7afcaf9fc371b28267949`. The integration checkout must
verify its exact delivered composition with the full gate and platform CI.

## Retained evidence

The integration archive is
`target/transport-profile-campaign/h3-drain-diagnosis/`. All 45 artifacts
were checked against byte counts and SHA256 hashes before copying. Retained
controls include the mutation patches, complete failure logs, comparison
script, source identities, and repaired binary identities.

- Packet: `h3-final-handoff.json`.
- Packet SHA256: `29c6f698d462989bc7b449ba3d740003e82f11a935ce93446f01c77bccc48789`.
- Manifest: `h3-final-evidence-manifest.json`.
- Manifest SHA256: `20875f8ea881e2c5aa1a9a6dafb4ba2e09c8c990652c756376a40aed9b498170`.

T1's readiness weakness has a verified fixture repair. The original runner
or OS scheduling trigger remains unresolved. Later green runs do not close it.

## Next

- [Campaign](../transport-and-profile-campaign.md): open tasks and delivery.
- [Original evidence](../architecture-audit/evidence.md): historical logs.
