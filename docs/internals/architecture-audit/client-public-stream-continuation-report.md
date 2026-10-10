# Client public stream continuation

This is a source-only review of `0ad0d5609a8a65291e5ab1082a310e67b418fa84`. The integration checkout still had working HEAD `df2ae9b7d87567907a2f273068220349dcd4750b`, so source reads used the exact committed snapshot through `git show`. No Cargo command, runtime test, process launch, tracked source edit, or integration operation was performed. SHA-256 values below cover raw committed blob bytes, with no newline normalization. The companion JSON retains the Git object IDs and read ranges.

## Disposition

One source-supported candidate needs the integration owner's runtime reproduction. No additional actionable defect was identified in the fully read Link, SOCKS5 or SSE files. This disposition covers the listed functions and contracts; it does not establish whole-facade coverage.

`crates/phantom/src/route/connect_udp.rs:300: major:` `ConnectUdpProxy::expand` serializes target port zero. `Http3TransportTarget::for_origin` retains an explicit URL port zero, and the shared `connect_udp_path` helper expands it for every CONNECT-UDP proxy leg. Current outer checks validate request/path shape, without enforcing the UDP target-port range. [RFC 9298 section 3](https://www.rfc-editor.org/rfc/rfc9298.html#section-3) requires 1 through 65535. Reject zero with a typed pre-I/O target error; verify a quiet proxy observes no connection, and retain 1/65535 positive controls. This candidate is not runtime-reproduced by this reviewer. Direct HTTP port-zero policy is a separate decision.

## Boundary traces

- Link input flows through the aggregate byte budget before per-field parsing. The parser returns owned targets, ordered parameters and relations only after every field succeeds. It neither resolves nor follows targets. Errors expose category, field index and byte offset; formatting of owned values is redacted. Generic URI references intentionally permit userinfo and arbitrary decimal port strings as data, rather than silently treating them as dial endpoints.
- CONNECT-UDP configuration owns parsed template parts, ordered headers, credentials, proxy endpoint and explicit leg choice. Target host characters are percent-encoded and the path is parsed before connector I/O. A selected HTTP/1, HTTP/2 or HTTP/3 proxy leg remains explicit. Target port zero is the missing semantic gate described above. SOCKS5 configuration separately retains DNS ownership and owned RFC 1929 credentials; identity includes DNS and credentials while Debug hides their values.
- The SSE decoder enforces line and event-block byte limits before growing their corresponding owned state. CR/LF fragmentation and leading BOM state precede UTF-8 conversion. Blank-line dispatch commits ID changes, including reset; NUL IDs and nonnumeric/overflowing retry fields are ignored, and EOF discards unfinished blocks.
- `SseStream` owns the response body and validates status, content type and identity-only content encoding. It decodes buffered events first. Ready DATA resets idle timing before the pending-read timeout path, preserving the existing ready-data precedence. Terminal failure or EOF drops the body. Dropping a pending next-event future clears its outcome state, rather than creating a background read task.
- `SseEventSource` owns its reconnect timer and future. Committed ID/retry state is copied from the stream before processing its outcome. Reconnect eligibility follows existing RequestError categories and a finite builder budget; deterministic input/policy failures stop. Closing or dropping the source drops the owned stream and reconnect future. Pending next-event cancellation keeps source state for a later poll.
- `SseRequest::validate_headers` checks active template defaults against actual trustworthy/forwarded conditions for selected protocols and configured H3-to-H2 fallback, where supported. Managed automatic hints are checked against actual emission gating. Each send resolves the committed Last-Event-ID in its declared caller position and marks it managed before entering generic request processing. Input errors are raised before its send; this source trace does not itself measure network silence.

## Test contracts read

Link tests compare independently written targets, order and values, reject malformed later fields without partial output, check inclusive budgets and separators (including an endless empty-value iterator), exercise every quoted-pair byte, and assert redacted errors with exact offsets. CONNECT-UDP tests compare exact host/IP/query expansions and explicit leg/credential identity; they currently omit target port zero. SOCKS5 inline tests check canonical endpoints, local versus remote DNS, owned credential limits and redaction.

SSE unit tests cover byte-wise fragmentation, ID commit/reset, unfinished EOF, byte limits and typed source preservation. Request-helper tests cover placeholder order/omission, default-producing trust/forward conditions, selected versus irrelevant protocols, configured fallback, non-emitting hints, base URLs, environment routes, and managed-hint retry exclusion. These assertions are meaningful source contracts, but none was executed in this pass.

## Read coverage

The first eleven files below were completely read at this snapshot. Supporting caller files retain their actual partial ranges.

| File | Read ranges | SHA-256 of committed bytes |
| --- | --- | --- |
| `crates/phantom/src/link.rs` | full: 1-604 | `db40f61c7f1892433a9266eb7a8786a51c4ee9be0b80f10408f20de23e595546` |
| `crates/phantom/src/link/tests.rs` | full: 1-448 | `9ff0bf9334b4176d9c5476d3532612b2170f83aef76ba48443f7914855b56d81` |
| `crates/phantom/src/route/connect_udp.rs` | full: 1-539 | `f08be144a1e65384775ea8f11176e67b810fcc11fc97b7b2259edf8a3b4c0be1` |
| `crates/phantom/src/route/connect_udp/tests.rs` | full: 1-280 | `596f2ce514dd9cb4515bd5982e953a5adc52b0e0f01b71e68a5eaeb7db503712` |
| `crates/phantom/src/route/socks5.rs` | full: 1-418 | `deb5c598cdea47ebbddb0dfb1eb510ab1a311ead3b2b758103ab1cce61c562ad` |
| `crates/phantom/src/sse.rs` | full: 1-622 | `5efbae3b675c3f52555a0adc2d2f3c2cea819a86ce9c4bbe29ef7449c36ba5d1` |
| `crates/phantom/src/sse/decoder.rs` | full: 1-169 | `da896ddbbe33d41cbcdeb1354614f780d860e9800f7cbbe2877d05d21f8e5e40` |
| `crates/phantom/src/sse/tests.rs` | full: 1-151 | `96883015ac94edbd1352434757a95e614fc3852b6c6960705fcd346a5e28eb6f` |
| `crates/phantom/src/sse/event_source.rs` | full: 1-501 | `7b2365d9a9950af054b92230135596a543e89493c84a1e8d5730f7a62d2eabb9` |
| `crates/phantom/src/sse/event_source/request.rs` | full: 1-600 | `a0e7024d7687b9391a1963366a703f8199ab67e0b4b08d0d797148064315bb6f` |
| `crates/phantom/src/sse/event_source/request/tests.rs` | full: 1-552 | `83cd8c952f993cbcfc63bea31f5ed00c2f9e6baea5db7c15354a9e05302ce201` |
| `crates/phantom/src/authority.rs` | partial: 1-260 | `179a512328f46b6195181cb2a8d168f1c92a4a667dd65af0e0666b7100e3de63` |
| `crates/phantom/src/session/http3_pool.rs` | partial: 38-78, 121-206, 706-896, 1236-1440 | `c04a84017369af6665152cdb7e5a69d5142d180681d30d99b887425592531cab` |
| `crates/phantom-net/src/http3/connector.rs` | partial: 1271-1368 | `9bf21a3a7eb6abd8f3a1179f1a5fc1d345c8b32a4abaea16685ae70a55bcff93` |
| `crates/phantom-net/src/request.rs` | partial: 559-648 | `88034c1a13e742ad2fd4445a8ad9bc02f2e0eec6053360ae4bafeba745725fda` |
| `crates/phantom/src/websocket/http3.rs` | partial: 1-160 | `8cb8b38255bc7f12fcffca5bda78e29e08ac8490cd8441452f646032be79b4d6` |
| `crates/phantom/src/request.rs` | partial: 295-374, 1508-1627 | `18269f15e31bd11bdc17bbe38606a3c63451f0119ba46de6b6060cd05fa3c011` |
| `crates/phantom/src/request/template.rs` | partial: 320-485 | `14b2bde462cefef3620b1df4ecb00db409f0731c04cb2cedacaa40ab3d690634` |

## Prior coverage and remaining work

Existing lifecycle, remaining-file and docs-contract records were inspected first. They left the current public-flow group open. Earlier SSE request coverage at `1e44399e` was partial (1-160 and 300-588); this pass reread its whole 600-line blob at `0ad0d560`, including the former gap. Earlier reads of other client/pool files remain credited to their original snapshots. They are not counted as new complete reads here.

- Full current request.rs/client.rs attempt, retry and redirect implementation was not reread in this pass; listed request.rs ranges are supporting partial reads only.
- Live public SSE integration tests under crates/phantom/tests/streams/sse and the complete live CONNECT-UDP/proxy harness were not read here. The local unit tests reviewed here do not substitute for those contracts.
- Full lower-layer CONNECT-UDP transport, stream/tunnel lease cancellation and all WebSocket operations remain outside this bounded pass; selected caller ranges are explicitly partial.
- No runtime scheduling, idle timer race, reconnect cancellation, ready-stream fairness, network acceptance or actual proxy I/O claim follows from this source pass.
- Configured parser/event limits bound their owned parsing state; this pass does not prove a whole transport-chunk retention bound or universal allocator bound.

The integration owner still owns candidate reproduction, any repair, focused positive/negative controls, and the exact composed gate. This pass introduces no vendor change and does not replace the repository gate or its runtime evidence.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
