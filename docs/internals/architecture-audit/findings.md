# Audit findings

Use this ledger to connect each finding to its cause, change, and evidence.
No finding is resolved by an assignment or a proposed fix.

## Findings

| ID | Contract | Evidence | State |
| --- | --- | --- | --- |
| A01 | Total deadline covers body reads | Raw and decoded ready-frame paths differ | Red/green tests; review approved |
| A02 | Invalid admission settings return a build error | Caller counts reach `Semaphore::new` above its maximum | Red/green tests; review approved |
| A03 | Disabled QUIC tickets prevent resumption | Changing the TLS profile retains an isolated cache | Red/green tests; review approved |
| A04 | Address cache bounds shared background work | Clear removes pending bookkeeping without ending work | Red/green tests; review approved |
| A05 | Proxy setup waiters receive their attempt's failure | A newer failure overwrites an older attempt's result | Fix prepared; tests pending |
| A06 | EventSource owns Last-Event-ID | Templates and automatic hints can supply an unmanaged ID | Fix in progress |
| A07 | WebSocket receive errors close the connection | Close-stream shutdown error retains the socket and pending control message | Needs regression |
| A08 | Debug output protects arbitrary header values | Three profile field enums derive Debug over literal values | Red/green tests; review approved |
| A09 | QUIC key-update documentation matches its interface | Comment still describes an infallible interface | Needs source reconciliation |
| A10 | GREASE parameter IDs fit their configured width | Full-range IDs overflow accepted narrow widths | Fix in progress |
| A11 | A failed boundary scan cannot report success | Manifest scan failure is lost through process substitution | Reproduced; fix pending |
| A12 | Malformed capture hex returns an error | Byte slicing can panic on non-ASCII text | Test harness fix pending |
| A13 | QUIC setup errors retain meaningful categories | Local provider failures map to an endpoint-stopping error | Contract investigation |
| A14 | Cargo lock holders retain exclusive ownership | Stale reclamation can move a new holder's directory | Isolated race reproduction pending |

## Initial source evidence

- A01: `crates/phantom/src/body.rs`, `poll_wire_frame` and
  `poll_decoded_frame`. Ready wire frames reset idle activity without
  checking total expiry. Decoded output checks expiry. Phase futures give
  a ready operation precedence; the body contract needs explicit review of
  that distinction before the remedy is chosen.
- A02: `crates/phantom/src/session.rs`, `validate_policies`, and
  `session/admission.rs`, `Admission::new`. Tokio 1.53.1's semaphore
  constructor panics above `Semaphore::MAX_PERMITS`. Check the effective
  profile bound as well as each caller override.
- A03: `crates/phantom-quic-btls/src/backend/client.rs`,
  `with_tls_profile` and `start_session`. Discarding the cache on disable
  also prevents a later early-data opt-in from using its old ticket.
- A04: `crates/phantom-net/src/address_cache.rs`, `clear`,
  `cached_or_pending`, and `Publisher`. Keep an outstanding-work reservation
  through clear and release it with the task, while excluding stale results.
- A05: `crates/phantom-net/src/proxy/http2_pool.rs`, `acquire`,
  `RouteState`, and `SetupReservation::fail`. Test two failures before an
  older waiter is polled; keep failure outcomes tied to their attempts.
- A06: `crates/phantom/src/sse/event_source/request.rs`, `SseRequest::send`,
  and `request/template.rs`, `expand_on_route`. Hook protection does not
  govern generated template defaults.
- A07: `crates/phantom/src/websocket/connection.rs`,
  `poll_pending_incoming`. Surrounding transport failure paths discard
  ownership; the stream-shutdown failure path does not.
- A08: `crates/phantom-profile/src/request_template.rs`, `websocket.rs`,
  and `proxy_connect.rs`. Redact arbitrary literal and conditional values
  rather than guessing sensitive header names.
- A09: `crates/phantom-quic-btls/src/key_schedule.rs`, `next_packet_keys`,
  compared with the implemented fallible backend key-update trait.
- A10: `crates/phantom-quic-btls/src/transport_parameters.rs` and `wire.rs`.
  Structural validation accepts narrow GREASE identifier widths, but the
  entropy draw uses the full reserved identifier range.
- A11: `scripts/ci/check-unsafe-boundaries.sh`. Injecting status 2 from the
  manifest `git grep` prints an error, then reports success and exits 0.
- A12: `crates/phantom-profile/src/request_template/capture.rs`,
  `decode_hex`. This is test infrastructure, not a runtime HTTP parser.
- A13: `crates/phantom-quic-btls/src/backend/client.rs`, `map_start_error`.
  Reconcile the pinned provider trait's error options before selecting a fix.
- A14: `scripts/dev/with-cargo-lock.sh`, `reclaim_stale_lock`. The dead
  owner check and later rename do not establish that the renamed directory
  still belongs to that owner. Reproduce the interleaving in an isolated
  repository before selecting the replacement ownership mechanism.

## Executed evidence

The starting implementations fail the A01, A02, A03, and A04 regression
tests. A01 returned ready buffered data after a one-second deadline had
elapsed by two seconds. A02 accepted an oversized bound. A03 retained
resumption after disabling tickets. A04 kept two live resolver futures
under a shared-work limit of one after clear and caller cancellation.

The composed first four fixes pass 1,704 unit tests: 584 in the HTTP
client, 949 in the transport crate, and 171 in the QUIC backend. Independent
review approved their changed paths and test controls. A08's three
redaction regressions fail on the starting implementation and pass after
the fix. The documentation checker reports zero errors and warnings.

All local verification so far applies to the audit lane. Integration main
remains at the starting revision. No audit change has been pushed or merged.

Local logs are retained under `target/architecture-audit` in the integration
checkout. These are focused test results, not a full gate or integration
claim. Every finding above still needs final composition and CI evidence.

These entries are source findings or candidates. Tests, independent review,
and integration evidence remain required; none is closed.

## Required evidence

Each entry records severity, affected contract, exact source locations,
cause, reproduction or inspection evidence, remedy, tests, independent
review, integration revision, and any verification limits.

Rejected candidates record the source or contract that disproves them.
Uncertain candidates remain open for investigation. A confirmed finding
cannot move to later work merely because it is difficult to fix.

## Next

- [Coverage](coverage.md): reviewed paths and gaps.
- [Audit plan](../architecture-audit.md): scope and completion criteria.
