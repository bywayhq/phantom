# Upgrade and ALPS test continuation

Baseline df2ae9b7. Four complete previously unfinished files, 680 lines,
exact hashes/ranges in net-upgrade-alps-continuation-coverage.json. My remaining
inventory is 57 files. This is not a whole-team gap count.

No new supported production finding in these files.

HTTP1 upgrade tests use duplex peers and literal bytes to check forward absolute
URI/header order, host mismatch before I/O, ordered response metadata and
coalesced upgraded protocol bytes. 401 remains normal streaming HTTP; unsolicited
101 is typed UnexpectedUpgrade. Pending upgrade cancellation aborts its task,
observes peer EOF within one second. Entire cases use bounded_peer_test. The
ignored aborted JoinError is expected cancellation, not a production ignored
failure. The cancellation control tests pending response, not all post-upgrade
stream owner/drop paths; these remain existing driver review/test contracts.

HTTP2 ALPS tests independently encode fixed frame types and setting IDs. They
distinguish absent/empty/no SETTINGS payload, check all supported settings,
final-wins duplicates and cross-frame monotonic transition constraints. Unknown
extension frames/flags and reserved stream bit are explicitly accepted. ACCEPT_CH
first duplicate wins across frames, malformed trailing entry preserves complete
prior entries. Exact typed malformed total/header/payload/frame size/stream/ACK/
length and known-value controls are meaningful. Total >65535 is tested; a full
positive exact-total boundary isn't asserted here. Builders encode fixed integer
widths, not by calling the production parser. No memory/runtime claims.

HTTP3 ALPS tests independently encode QUIC varint frame sequences and verify
ignored unknown frames, exact supported-origin lookup, first duplicate wins,
ignored origin accounting, absent/empty values. Nonminimal varint widths are
accepted on actual parse; separate truncated frame and entry field controls
assert typed errors. Public support versus canonical origin policy was read in
prior owner source; this pass doesn't claim every malformed/fuzz input covered.

The TLS PING-close test uses actual loopback TLS and raw HTTP2 frames: unanswered
PING results in typed timeout, GOAWAY debug suffix and no TCP bytes after the
GOAWAY TLS record (therefore no close_notify). Reset/aborted are accepted transport
close outcomes. bounded_tls_test scopes lifetime. It awaits the server on its
success path; outer deadline doesn't explicitly abort the server task on failure
in this test (runtime teardown remains task owner). This isn't an independent
execution or fresh browser capture; shortened timers exercise recipe behavior.

No edits/builds/pushes. Source retrieved through git show of exact baseline to
avoid concurrent root integration drift.

## Next

- [Coverage](coverage.md): review boundaries and remaining work.
- [Findings](findings.md): confirmed defects and verification.
