# TLS control tests continuation

Exact baseline df2ae9b7. Six complete files, 881 lines, raw hashes and complete
ranges in net-tls-controls-continuation-coverage.json. My remaining inventory
is 51 paths. This is not a whole-team unfinished count.

No new supported production finding.

TLS test parent: trust-anchor length prefix literal bytes, TLS 1.2 absence of key
share, actionable unsupported backend setting, configuration failure before I/O
with typed validator source, exact redacted ALPS Debug contract, trusted-chain
ALPN/version/cipher/SNI success, no-ALPN absence, wrong-name failure/cache empty,
untrusted-root failure. Shutdown captures raw bytes after TLS handshake and
checks exactly one alert-shaped encrypted record for Firefox, none for Chromium.
Alert body isn't decrypted by this test, so shape is evidence of shutdown record
policy rather than a direct alert-content oracle. Test server/capture tasks are
awaited with per-phase deadlines on success. Earlier exits drop JoinHandles and
rely on test runtime teardown; no explicit abort guard here. Capture helpers
using `tokio::join!` keep peer/handshake inline under one timeout; older spawned
single-capture helper only times client phases and awaits task later. No new
library ownership defect inferred from private test helper styles.

Capabilities tests compare independently stated numeric cipher/group/key-share/
signature/version IDs, exact extension order, compression vector bytes, omitted
delegated credential/record size/session ticket settings. This verifies outgoing
ClientHello declarations; it does not establish successful TLS 1.0/3DES/FFDHE or
certificate-compression negotiation. Exact record size limit 16,385 encoded as 0x4001 and
omission tested; all config-range boundaries belong to profile validation tests
outside this small pass.

ECH tests compare exact 239-byte payload's total of 281 bytes, backend-default allowed
body sizes, configured AES256GCM suite octets and disabled omission. TLS 1.2+ECH
rejection preserves original configuration validator; QUIC settings connector
acceptance is construction only, not HTTPS record fetch or accepted ECH. These
are GREASE wire controls; no encrypted accepted handshake support claim.

Tracing tests distinguish connector success/failure, failed handshake static
kind, one-poll cancellation outcome with no error kind, negotiated TLS 1.3/cipher
metadata. The subscriber assertions do not capture all arbitrary log fields or
prove universal redaction; opaque ALPS Debug marker test is separate. One-poll
pending handshake shows cancellation reporting, not exhaustive TLS flush/drop
or runtime shutdown semantics.

ClientHello fixture loader reads checked field names, strict lowercase even hex,
concatenates retained local records, and runs independent testkit capture with
32 KiB handshake, 40 KiB wire and four-record limits. Byte-slice helpers check overflow/truncation,
then locate declared extension and read five ECH suite octets. It intentionally
is a focused inspector, not a complete handshake validator; outer capture owns
that role. Trusted retained fixture counts are not input from library users.
No DoS claim from test-only local fixture concatenation. A malformed zero-wire
fixture would not be a valid capture but is outside current caller corpus.

No source edits/builds/OS/browser execution. Read exact git show baseline to
avoid concurrent integration drift. Prior production source reads are not
reclaimed in this inventory.

## Next

- [Coverage](coverage.md): review boundaries and remaining work.
- [Findings](findings.md): confirmed defects and verification.
