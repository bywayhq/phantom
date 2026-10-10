# TLS early data and retry continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Four complete files, 1,168 lines, leave 27 paths not completed in this agent's additive inventory. Exact Git blob and working-byte hashes are separate in the JSON. No tests were executed and no new production defect was confirmed.

## Early data on TCP

`tls/tests/early_data.rs` lines 1–227: an isolated session cache learns an early-data-capable ticket by reading peer application bytes after the ticket. A delayed resumed peer accepts exact early bytes or rejects them and reads their replay after handshake on the same resumed connection. ALPN changes after rejection produce InvalidData and fail the early-data answer waiter. A plain handshake resumes but offers no early data. Individual connect, read and answer/join phases have TEST_TIMEOUT; writes and server helpers lack a single whole-test deadline. A failed ALPN test awaits the server deadline but ignores its inner result, so it proves client error rather than a particular peer termination error. Peer tasks are joined on success; early failures retain runtime teardown as owner. Cancellation, replay size ceilings and exactly-once reads after partial writes are not established by these small five-byte cases.

A concrete stale comment at line 139 says both proxy routes and WebSocket openings use the plain handshake. Current direct Firefox WebSocket openings deliberately offer early data, as the composed controls below verify. The comment should describe the relevant proxy/non-early route instead. This is a local explanatory contradiction, not evidence that the production handshake is wrong.

## WebSocket early-data composition

`tls/tests/websocket_early_data.rs` lines 1–469: two actual TLS connections share or replace ticket keys. Certificate selection records exact early_data offers [false, true]. Accepted HTTP/1 opens with the full Upgrade GET as early bytes. Rejected HTTP/1 reads one post-handshake head and explicitly rejects extra trailing bytes. Accepted H2 early bytes contain the preface and only SETTINGS/WINDOW_UPDATE frame types, while the later decoded request is extended CONNECT with protocol websocket. Rejected H2 restarts protocol initialization on the same resumed TLS connection. New ticket keys and an untrusted certificate or changed ALPN produce the exact typed handshake/unsupported-protocol result, with no application bytes processed on the failed peer.

Each opening and final server join is timed. The server task itself has no unconditional abort guard on early client failure. Its Upgrade head loop has no byte bound but consumes this implementation's trusted request; no public inbound-parser claim is made. The H2 frame-type helper intentionally permits a final partial payload and does not establish complete frame validity or the exact setting values. The separate successful H2 decoder shows a usable initialization, rather than proving byte-identical whole framing. Ignored disconnect reads are deliberate close observations and reject nonempty trailing bytes where required.

## Authenticated HelloRetryRequest

`tls/tests/hello_retry.rs` lines 1–269: the server selects P-384 to require an authenticated HRR. The client negotiates TLS 1.3; server explicitly reports HRR use. A bounded 128 KiB capture reconstructs exactly two ClientHellos, comparing session ID, cipher list and extension identifier order after permitted identifier omissions, with initial hybrid/X25519 shares and the requested P-384 final share. The test name says only permitted delta, but assertions at lines 67–72 do not compare random, compression or stable extension bodies. That broader claim remains unproven by this test alone. Capture retention has no overflow flag and stops extracting at two hellos; it is a selected-shape observer, not a complete malformed TLS transcript validator. Parsers check vector bounds and key-share list length, while general handshake type/declared-length/trailing-byte validation belongs to other code.

## Independent NSS sizing model

`tls/test_support/nss_ech_grease.rs` lines 1–203: a test-only NSS-derived model counts inner fields, compressed outer extension references, copied SNI/version/PSK sections, omission rules, hostname padding to 32 bytes and the 16-byte tag. Controlled helpers extract actual sent ECH payload, a single PSK identity length, and optionally replace the server-dependent PSK size for comparison with a recorded capture. Reader slices are bounds checked. It parses generated or frozen known ClientHellos, and does not validate arbitrary input's handshake type, declared handshake length or trailing vectors. Arithmetic uses trusted small fixture/model arguments; this is not a public hostile-input boundary. No fresh browser result or ECH handshake support claim is inferred from this independent length oracle.

Prior supported findings, deferrals and unrelated assertion gaps retain their status.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
