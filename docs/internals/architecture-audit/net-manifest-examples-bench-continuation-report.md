# Net manifest, examples, benches and external tests

Baseline `df2ae9b7d87567907a2f273068220349dcd4750b`. Manual source review only, with exact Git blob and working-byte hashes in the paired JSON. Reviewed 18 files and 3,801 lines. No builds, Cargo, browser/conformance runs or benchmark measurements.

This additive pass covers the 18 actual unread files identified in `net-review-disposition-index.json`. It leaves that earlier inventory snapshot unchanged and preserves the separate 35 supported import gaps. Baseline coverage is not a fresh review of changed aggregate code.

- `crates/phantom-net/Cargo.toml` (1-112): Reviewed all package metadata, opt-in features, platform-specific BTLS/libc/windows-sys boundaries, production/dev dependency features, transport bench and TLS-Anvil feature requirement, and lint inheritance/authorized unsafe deny override. This source review does not certify current fork pins, compilation, optional feature combinations or target platforms.

- `crates/phantom-net/benches/transport.rs` (1-37): Reviewed Criterion registration and current-thread runtime construction. The suite registers H1 and H2 CPU transport paths, not H3 or real network/TLS performance. Child modules have concrete harness responsibilities.

- `crates/phantom-net/benches/transport/http1.rs` (1-226): Reviewed constructor, response-head, warm-reuse, content-length and chunked-body benchmarks end to end. Cold samples include connection/startup/send/collect work; warm samples reuse one duplex connection. The peer bounds request heads to 32 KiB. Fixed response fixtures determine expected payload, but H1 samples do not assert body contents/length. The warm peer is aborted without a join. These are measurement/ownership limits, not a newly proved production failure.

- `crates/phantom-net/benches/transport/http2.rs` (1-225): Reviewed response/frame builders, batch preparation, driver subscriber scope and complete_response lifecycle. Samples require status/body length, transport drop and supervised driver completion before black_box. The synthetic peer has fixed stream 1, startup write gating and a GOAWAY, rather than independent socket backpressure. Four 16 KiB body frames are constructed. No sample deadline is present.

- `crates/phantom-net/benches/transport/http2_replay.rs` (1-110): Reviewed write-count gating, bounded response copying/EOF, vectored writes and completion-on-drop ownership. The synthetic stream accepts all writes, uses saturating byte accounting and wakes the write poll context; it is used by the one connection driver, not claimed as a general cross-task stream. Receiver drop after a failed sample is allowed. No live network claim is made.

- `crates/phantom-net/benches/transport/http2_supervisor.rs` (1-234): Reviewed observer Dispatch lifetime, FIFO sample registration, exact driver span name/outcome recognition, span reference counting and final observer send. Driver finish is distinct from transport drop. Queue state is drained by completed samples; a rejected/missing outcome terminates the bench by panic. Completion waits have no deadline. This review does not independently test the custom observer itself.

- `crates/phantom-net/benches/transport/replay_stream.rs` (1-75): Reviewed prefix-offset read/EOF, request-start write gate, immediate flush/shutdown and vectored writes. The fixture stream makes a fixed response readable after the first write and accepts all bytes. It measures synthetic parsing/transport CPU work; it does not emulate partial writes, peer errors or network flow control.

- `crates/phantom-net/examples/capture_alps_accept_ch.rs` (1-172): Reviewed exact loopback bind guard, origin-specific bounded-length ALPS frame builder, generated TLS identity, ALPN callback, per-connection HTTP2 server, field/hint reporting, page/fetch/done transitions and 60-second main deadline. Connection tasks are detached and rely on runtime shutdown; /done sender rejection is explicitly justified. Header keys are reported after the server HeaderMap decoder, not independently captured raw HPACK. Arbitrarily many local connections can be admitted during the run.

- `crates/phantom-net/examples/capture_ech_client_hello.rs` (1-1078): Reviewed all argument validation, generated identity/SPKI, published versus reject ECH keys, loopback TCP/QUIC/DoH setup, eight-origin arrival slots, captured-state publication, TCP prefix replay/handshake/page serving, QUIC handshake data/errors/H3 serving, DNS-over-HTTPS HTTP framing/DNS/SVCB/base64 encoders and fixture output. Test keys are deliberately public testkit fixtures, and only public keys/config/captured hellos are emitted. Origin work is bounded by eight arrivals and operation/run/grace deadlines. DoH task count and query metadata are not bounded independently; per-connection TLS/read waits have no deadlines. Explicit detailed follow-up is recorded below. No example unit tests are present.

- `crates/phantom-net/examples/capture_http2_tls.rs` (1-286): Reviewed exact argument count, single-line/nonempty metadata checks, loopback listener/peer guards, one accepted connection, independent accept/handshake/frame deadlines, TLS1.3/ALPN/SNI constraints, 64 KiB/128 KiB/16-frame capture limits and fixture publication after success. Argument tests check valid and selected invalid metadata; they do not execute a browser or fixture capture.

- `crates/phantom-net/examples/capture_http2_tls/fixture.rs` (1-160): Reviewed first-frame SETTINGS and stream-zero WINDOW_UPDATE summary checks, exact ordered v2 output metadata and raw frame hex, ALPS absent/empty/nonempty distinction, checked output errors and lowercase hex encoding. Tests independently compare representative bytes and all three ALPS metadata states. This helper is not a public hostile-input parser.

- `crates/phantom-net/examples/capture_http3_request.rs` (1-178): Reviewed exact argument count/nonempty single-line hostname, loopback remote guard, additional root loading, Chrome154 transport recipe selection, explicit direct UDP route, status and exact ok body assertions, separate 30-second send/body deadlines and fixed 13-header request. Tests check argument rejection, IPv4/IPv6 loopback and first/last/lowercase header names, but not full header values. Chrome152 identity values are still hard-coded while the opening comment says Chrome154; this is recorded as a bounded wording/fixture-shape candidate, not a transport parity failure.

- `crates/phantom-net/examples/quic_version_interop.rs` (1-78): Reviewed explicit Firefox157 recipes, isolated session cache, fresh direct loopback connections, separate 10-second connect/send/body/ticket deadlines, retained prior connection handles and required ticket availability between requests. Status/body/resumed state are printed for the external peer report; they are not asserted here. The optional usize request count accepts zero. The documented default reproduction uses three requests, so zero does not invalidate the recorded interop observations or existing CI.

- `crates/phantom-net/examples/tls_anvil_client.rs` (1-114): Reviewed named argument parser, required host/port/server name, explicit danger-disabled TLS verification, H1-only ALPN and disabled ALPS, route construction and five-second connect deadline, followed by connection drop. The manifest requires the danger feature for this harness. Tests independently check parsed fields and missing/unknown options. This is an intentional one-handshake conformance adapter, not an example of authenticated production usage.

- `crates/phantom-net/tests/browser_http2_fixtures.rs` (1-157): Reviewed fixture-wire reconstruction, bounded independent frame parser, exact preface/count/every-frame comparison and parsed settings/window summary checks. The public client emits startup into a duplex peer, remains pending while the peer is held, then returns Protocol after peer drop with a join deadline. Malformed fixture controls change key order/duplicates/unknown/missing/frame numbering and line breaks. Capture failure before final join relies on runtime teardown, not a scoped abort-and-join guard.

- `crates/phantom-net/tests/browser_http2_fixtures/chrome.rs` (1-147): Reviewed all eight fixed browser/version/platform fixture paths, selected exact provenance assertions, full raw-startup checks and actual public-recipe startup comparisons. Chrome/Edge/Brave/Opera desktop and Android controls retain independent capture bytes. Tests assert recipe aliases where promised; they do not make a new live browser or HTTP3/TLS parity claim.

- `crates/phantom-net/tests/browser_http2_fixtures/fixture.rs` (1-206): Reviewed complete ordered fixture parser: positive capture timestamp, hostname/loopback, exact capture deadlines/limits/ALPN, ALPS state/length consistency, exact 24-byte preface, bounded nonzero frame count, numbered frame keys, lowercase even-length hex, required fields and trailing-data rejection. Individual payload byte lengths are enforced by the subsequent bounded frame parser rather than before hex allocation; the input is a trusted include_str fixture, not an externally exposed network parser.

- `crates/phantom-net/tests/error_categories.rs` (1-206): Reviewed public validators for missing Host and uppercase H2 field, category distinctions, invalid local ALPN configuration, peer ALPN/application-setting categories, exact Bytes body metadata/payload conversion, typed nested proxy and IO source preservation, single cause-message occurrence, invalid TLS validator source and compile-time Copy/Eq/Debug/Send/Sync category requirements. Some mapping cases construct enum variants directly; the suite also exercises actual validators/connectors. It is not a complete network-error execution matrix.

## Supported follow-ups

### crates/phantom-net/examples/capture_ech_client_hello.rs

source-supported capture resource/ownership defect; no runtime reproduction in this read-only pass.

Cause: The parent DoH listener task spawns a detached task for every accepted loopback connection. Child TLS handshakes and repeated request loops have no timeout or task-count reservation. Every valid DNS query appends a String to the shared log without a count or byte bound. MAX_CONNECTIONS bounds only origin tasks, and aborting the listener does not explicitly join its previously spawned children.

Observed source contract: A local peer can keep arbitrarily many accepted DoH handshakes/read futures pending or append arbitrarily many DNS query records during the capture run. The origin accept deadline bounds time but not retained work/metadata. Process/runtime shutdown eventually drops the tasks; this is not a persistent net library leak.

Regression: Use a controlled DoH listener with a small explicit concurrency/log allowance. Hold multiple TLS handshakes pending and prove later arrivals cannot increase active futures beyond the allowance; complete/drop a child and prove reuse. Send more valid DNS requests than the log allowance on a kept-alive TLS connection and assert deliberate overflow/failure instead of unlimited append. Abort the capture and assert all owned child futures are dropped/joined. Preserve successful accept/reject capture output and report a listener/child failure with operation context.

Remedy: Own DoH children in a bounded task set; bound capture query metadata and TLS/request waits; deliberate shutdown aborts and drains children. Preserve public test-capture semantics and avoid introducing a transport API knob.

### crates/phantom-net/examples/capture_http3_request.rs

bounded example documentation/fixture-shape inconsistency; no browser differential.

Cause: The example claims a Chrome154 request but retains Chromium/HeadlessChrome152 client hints and user agent values. Its header test checks count/boundary/lowercase names only.

Observed source contract: The actual helper emits a Chrome154 transport profile with explicitly supplied Chrome152 identity headers. No caller/fixture reference for this exact helper was found in the bounded docs/scripts/workflow search; manual uses remain possible.

Regression: Decide the intended recorded browser request before changing data. If this is an old capture helper, qualify its opening comment or remove the unused harness after checking consumers. If it should represent Chrome154, use the corresponding recorded request identity and compare the full ordered field list to that independent fixture.

Remedy: Clarify the helper contract or update it from a matching retained fixture; do not invent browser header values or alter the general transport behavior.

## Rejected or bounded candidates

- The QUIC interop helper accepts a zero request count, but it is a manual adapter that prints observations. Validation documents a concrete three-request reproduction. No zero-count automated success gate was found, so this is an input/diagnostic gap rather than evidence that existing interoperability observations are false. Its status/body output is intentionally available to an independent server report.

- The ECH example directly opens QUIC on the already allocated TCP address. It does not bind UDP to port zero at that call site; the caller defaults to loopback port 443. Automatic ephemeral shared-port allocation could need retry under Windows, but this source read does not reproduce such a failure and does not claim the already tracked direct-port-zero defect here.

- ECH capture deliberately retains public test keys/config and raw captured hellos. No private generated key serialization or newly demonstrated credential exposure was found. DoH input support is a selected browser harness: its custom parser does not establish general DNS/HTTP conformance, and no general-purpose parser contract was inferred.

- Several fixture/bench peers rely on runtime teardown after early failure or abort without a join. Normal-path assertions and deadlines were reviewed; these are explicit ownership/evidence limits, not automatically assigned production defects. Benchmark names do not independently establish isolated parser timing or real network throughput.

## Coverage boundary

No unread paths remain in this 18-file subset. That result does not import or freshly re-review the earlier 35 gaps, dispose the supported follow-ups, cover vendored/registry implementation or establish complete audit/runtime/platform validation. Only the integration owner may update the central inventory and perform execution.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
