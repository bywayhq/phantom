# DNS, proxy and keepalive test continuation

Baseline `df2ae9b7d87567907a2f273068220349dcd4750b`, also observed as root HEAD.
Five complete files, 1,698 lines. Exact Git blob IDs, SHA256 of blob bytes,
working-file byte hashes, and complete reviewed ranges are recorded in
`net-dns-proxy-lifecycle-continuation-coverage.json`. These distinguish Git LF
bytes from supported Windows CRLF working files. The remaining inventory now
contains 46 paths; this is the inventory for this agent, not the whole team.

No new supported production defect in this bounded pass. No tests, sockets,
Cargo commands or browser captures were executed.

## DNS address lookup tests

`dns/address_lookup/tests.rs:1-421` checks outgoing A/AAAA question types,
question flags/counts, IPv6-first results and minimum record TTL with a real
loopback DNS peer. Fifty cold lookups on a multithread runtime check query
order. A held AAAA reply verifies that A is released when AAAA is sent, before
AAAA is answered. Test deadlines cover the one-second observation window,
but the subsequent resolver-task join has no test-wide deadline or explicit
abort guard. The three-second delayed reply does not test lookup cancellation.
The earlier delayed DNS task finding belongs to the testkit owner and is not
silently treated as resolved by reading this caller.

Other assertions distinguish negative SOA TTL from its MINIMUM field, local
host names from network queries, system fallback for single-label/local names,
IPv4-only system answers when IPv6 is unavailable, and hosts-file bypass.
Sixteen consecutive DNS fallbacks stop further DNS queries; resolver copies
with different UDP settings share that counter. The fallback tests use the
internal constant for iteration count, so they verify disabling and sharing,
not an independently fixed numerical protocol limit.

Record-TTL cache integration observes one DNS query for a warm lookup, a second
after a 1.1-second wait, and rebuilding the requested port. Minimum-record-TTL
policy survives a zero-TTL answer across two requested ports. UDP socket
observations verify the actual applied port-randomization option per family,
including default and unconfigured controls. This is applied-option evidence,
not a statistical guarantee about host port allocation. The optional IPv6
probe retry test explicitly accepts failure and tries unconfigured options;
its real fallback bind uses the testkit reserved-port helper.

No malformed DNS parser or custom stalled-resolver resource claim follows
from these successful lookup tests. Their production owner was read earlier.

## Proxy credential cache tests

`proxy/tests/credential_cache.rs:1-246` observes real CONNECT bytes and exact
credential placement. A successful challenge remembers credentials for later
first CONNECTs; a challenge to remembered credentials forgets and retries once.
A second 407 or malformed challenge leaves no record. A proxy that never
challenges is not remembered. The scripted peer keeps prior sockets open, so
later accepts demonstrate genuinely new connections despite the close header.
These helpers have no enclosing deadline and failed assertions can leave a
spawned peer until the test runtime shuts down. That is a test robustness gap,
not evidence of a library task leak.

Pure controls isolate scheme, case-normalized host, port and full credentials.
The full-cache test touches the first inserted pair, adds another, and checks
that the second pair is evicted while the total stays capped. It verifies LRU
behavior at the configured bound, not measured memory consumption. Exact Debug
contains only the entry count despite canary host/user/password values. Test
credentials are deliberately fixed dummy values, not user secrets.

## CONNECT negotiation and challenge lifecycle

`proxy/tests.rs:1-298` observes request field order/case, fragmented informational
heads, a final 204 tunnel and coalesced protocol bytes in both directions.
TouchCountingStream proves invalid authority fields, missing/duplicate authority
placeholders and target userinfo fail without polling stream I/O. Typed status
rejections omit response header markers; header Debug retains the field name
but excludes its value. An unsolicited 101 is terminal. Independent malformed
head and nine-informational-response inputs check exact 32,768-byte and eight
response bounds. Positive exact-limit controls are elsewhere; this file does
not establish every parser boundary. Cancellation tracing polls once and drops
negotiation; it asserts the cancelled outcome, not a complete peer EOF oracle.
The read helper bounds request bytes but has no read deadline.

`proxy/tests/challenged_connection.rs:1-482` distinguishes replay on the same
connection from a new accept using exact anonymous/authenticated wire heads.
HTTP/1.1 Content-Length and chunked challenge bodies permit reuse; HTTP/1.0
requires explicit keepalive. Close directives, ambiguous/missing framing,
malformed chunks, coalesced unsolicited next-response bytes and oversized body
force a new connection. Exact body bound has a successful reuse control, and
bound plus one uses a new connection. A peer closing after the first replay
receives the authenticated retry on a second socket, with no third accept in a
200-millisecond window. That quiet window is not a proof of no future dial;
the previously read production retry branch supplies the actual finite rule.

TLS replay uses one accepted TLS stream and loses the listener in accept_tls,
so the authenticated replay arriving there independently proves reuse. An
outer deadline covers that case. Plaintext helpers instead apply per-phase
setup/join deadlines; their tunnel-prefix read has no outer deadline. On early
failure the spawned peers rely on runtime teardown. No stronger cleanup proof
is inferred from those guards.

Unit drains test every split point of a chunked body, EOF, malformed line/size,
terminal chunks, trailers and whitespace before extensions. Supplied data is
fixed literal bytes, not parser-generated expected values. The drain's accepted
terminal position is checked even while the duplex peer stays open. The cache
integration verifies that same-connection replay also records credentials for a
later first CONNECT. No new protocol fallback or credential exposure found.

## TCP keepalive schedule tests

`tcp/keepalive_schedule/tests.rs:1-251` independently states whole-second setup
intervals, minimum intervals and exact schedule delays of 72, 82 and 63 seconds.
The largest supported probe count/interval receives an arithmetic control.
Real loopback sockets confirm initial short-lived options before request data,
HTTP/2 permanently disabling keepalive, immediate upgrade to long-lived options,
and returning a reused idle connection to short-lived options. Linux/macOS
also read actual keepalive idle time; Windows tests do not assert that getter.

Four-second schedules test switching only with a request outstanding and
restarting the switch after a later request. wait_for_phase has a 30-second
bound. Pair setup and the whole tests do not have one absolute deadline. These
checks observe applied options and elapsed scheduling, not emitted kernel
keepalive packets or measured browser behavior. No change to the separately
recorded macOS idle-only limitation is claimed.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
