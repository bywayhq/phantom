# Shared CONNECT-UDP connections

Use this contract when changing outer proxy connection ownership. One
CONNECT-UDP stream still carries one inner QUIC connection. Route clones can
share an authenticated outer HTTP/2 or HTTP/3 connection.

## Protocol contract

| Proxy leg | Required peer capabilities | UDP carriage |
| --- | --- | --- |
| HTTP/3 | Extended CONNECT, H3_DATAGRAM, QUIC DATAGRAM | HTTP Datagrams |
| HTTP/2 | Extended CONNECT | DATAGRAM capsules on DATA |
| HTTP/1.1 | Upgrade accepted with 101 | DATAGRAM capsules on the upgraded stream |

[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) defines HTTP
Datagrams and capsules. [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html)
defines CONNECT-UDP. HTTP/3 datagrams contain a Quarter Stream ID followed
by Context ID zero. HTTP/2 uses capsules, without an HTTP/2 DATAGRAM frame.
HTTP/1.1 keeps dedicated connections.

Missing capabilities produce explicit errors. The selected leg never changes
and HTTP/3 never falls back to capsules. Unknown capsule types are skipped.
Unknown datagram contexts are dropped. Malformed framing or an oversized
Context ID zero payload ends its tunnel, leaving other streams independent.

Dedicated HTTP/3 connections keep their first-stream bounds: a 1252-byte path
MTU and a 1205-byte maximum-datagram-frame requirement. Shared HTTP/3 sessions
reserve the longest Quarter Stream ID: 1259 and 1212 bytes respectively.
Actual per-stream peer send capacity is checked when opening the tunnel.

## Ownership and admission

`ConnectUdpProxyPool` owns bounded H2/H3 session slots. A scope includes the
proxy authority, exact credentials and ordered fields, connector settings,
initiating dial policy and Tokio runtime. The facade owns one pool per immutable route
scope. Native callers explicitly choose the paths that share their pool.
No inner origin tickets enter an outer cache.

Outer proxy handshakes own their ticket retry. An outer TLS failure cannot
trigger the inner-origin ticket retry after that proxy attempt fails.

One setup owner publishes a connection after an accepted response. A stream
reset may retain a healthy outer as anonymous. Sending credentials does not
prove that the peer accepted them. With Basic credentials, an initial
anonymous 2xx remains anonymous. A validated 407 permits one authenticated
retry on a fresh outer. Only an accepted authenticated retry marks that outer
as authenticated. Later streams carry the same configured credentials.

A tunnel lease retains its key and admission permit through stream cleanup.
Live keys are never evicted to admit another key. The pool keeps at most 32
keys, 100 active opens/tunnels and 100 queued opens by default. These are
Phantom resource limits. Explicit nonzero limits cannot exceed Tokio's
semaphore bound. Queue or key overflow reports `Capacity`.

Setup failure wakes its waiters with the same error category. Cancellation
releases the reservation and permits. Peer stream-capacity waits reuse the
retained H2 connection; GOAWAY, closure, expired idle limits and ALPN changes
prevent reuse. Locks protect short state transitions and never span awaits.

Route clones compare equal and share their immutable scope. Independent
routes and mutations to fields, credentials, transport or limits create a
fresh scope. This also prevents the inner origin pool from reusing a
connection opened under another scope.

The pool materializes isolated outer connector caches once per scope. The
base connector supplies configuration only. HTTP/1.1 retains the previous
per-origin dedicated outer cache. Clearing a native shared pool retires its
retained connections while active leases finish independently.

## Ticket lifecycle integration

F1 integration must register each actual isolated outer cache before first
use, including retired generations still held by active tunnels or handshakes.
Reading current `SessionState` slots alone misses those generations and races
cache creation. Shared descriptors bind the proxy host and port, leg, route
credentials and outer profile. Inner-origin descriptors would conflict.

Client ticket clearing and transfer registration need this ownership seam.
The pool adds no transfer authority or export API. Retiring live handles is
separate from clearing tickets held by active connector clones. Current main
has no client ticket clearing or transfer API. This is a prerequisite for F1
composition, which remains separate from sharing delivery.

## Controls and evidence

Focused native checks and both named peers pass. The complete integration
gate, platform CI and delivery remain pending. These controls do not establish
browser use of this sharing policy.

Native controls cover concurrent origins, fresh Basic challenge retry,
independent routes on one client, tunnel resets, admission overflow and
cancellation. Duplex H2 controls hold the peer stream limit and deliver
GOAWAY. Dedicated and shared profile-bound controls include encoded stream
ID width boundaries.

Three additional native controls pass. Clearing the pool during a held
CONNECT response keeps active tunnels usable and prevents late publication.
Canceling a queued open releases its admission slot while an accepted sibling
continues. A peer advertising one bidirectional stream keeps the second open
pending until the first tunnel closes. These test admission and stream credit.

Both authenticated-retry reset controls pass. A reset before the authenticated
2xx leaves the healthy outer anonymous. The next open must receive a new
challenge before credentials can be accepted and shared with a sibling.
The failed target receives no origin connection or application request.

A pooled H3 GOAWAY control keeps accepted HTTP Datagrams usable and opens a
fresh outer after observing retirement. Two reliable-capsule pressure controls
fill the real receive queue, count overflow and then reject truncated or
oversized Context ID zero input while a sibling remains usable. These controls
exercise native proxy streams, rather than an inner HTTP application.

A native H2 control exhausts a real 32-byte stream window while leaving ample
connection credit. The actual capsule writer blocks, a sibling completes two
markers, and returning peer credit lets the blocked capsule finish. Its peer
uses a duplex H2 connection without TLS. This is a flow-control result.

The final focused run passes 17 native sharing controls, ten peer-ownership
controls, and both named peers. Strict all-target lint and Rust 1.88 checks
passed before the integration repairs below; the full rerun remains required.

A real local QUIC peer rejects incompatible ALPN on direct and pooled proxy
connections. The original classifier incorrectly accepted the proxy failure
for an inner-ticket retry. Narrowing it to origin handshake errors makes the
same control pass. This checks error classification without seeding tickets
or measuring total connection attempts.

The independent adapters use aioquic 1.3.0, python-h2 4.4.1 and hpack 4.2.0.
Their Python unit controls exercise integer widths, fragmented capsules,
unknown contexts, malformed input and loopback-only targets. These parser
results are separate from the successful HTTP requests through both adapters.
The retained runs identify the actual interpreter, pinned packages and owned
child processes. Both peers shared one authenticated outer across two origins.
The aioquic fixture checks each datagram against the peer's current packet
capacity before queueing it; an oversized head cannot stall its siblings.

The first rebased integration gate at `eb7ab1c9` failed two nextest controls
and the pinned nightly recursion check. Its full logs remain under
`target/transport-profile-campaign/connect-udp-eb7ab1c9-gate/`, including
copies of every step log. Those failures have not been rebaselined.

The new pooled setup enlarged the HTTP/3 send future to 13,528 bytes.
Boxing that setup branch reduces it to 11,360 bytes under the unchanged
12,288-byte limit. Private pool ownership and explicit `Send` bounds on the
two SOCKS setup helpers keep downstream compiler proofs bounded. The final
pinned nightly check passes without warnings. The private owner change also
passes its identity and auto-trait control.

The existing ticket-isolation fixture required a fresh outer connection but
kept a healthy shared outer open. It now closes and drains that connection
before reopening the proxy with the same server ticket store. The original
ticket counts, two-connection assertion and deadlines remain unchanged.
That control and five existing SOCKS upgrade controls pass. These focused
results do not replace the pending exact-head integration gate.

The rerun at `f181d1f7` passed all 4,982 Rust tests and the pinned nightly
check. Workspace and feature-matrix Clippy rejected the two explicit future
signatures as a style issue. Item-local allowances retain their required
`Send` proof boundary. All other gate steps passed. The complete logs remain
under `target/transport-profile-campaign/connect-udp-f181d1f7-gate/`.
The next signed-head gate must pass before delivery.

The explicit Rust interoperability tests require `PHANTOM_CONNECT_UDP_PYTHON`
to name an interpreter with those pinned packages. The process is owned
directly, with readiness and result files retained under the lane's target
folder. The two ignored test names identify aioquic and python-h2. They must
be run explicitly before claiming interoperability.

For the old-source comparison, retain the original production files and run
the same two-origin assertions with the new concurrent native peers. The
expected original result is two outer connections. The repaired assertion
requires one, with distinct stream IDs and successful independent bodies.
This is a proposed reproduction, not a measured result.

## Next

- [Campaign](../transport-and-profile-campaign.md): full gate, platform CI
  and delivery requirements.
- [Connections and client state](../../guides/connections-and-state.md):
  public connection ownership.
