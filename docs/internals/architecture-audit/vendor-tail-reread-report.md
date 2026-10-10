# Vendor boundary tail reread

These are fresh bounded source reads at the identities in the paired record.
The two historical ranges beyond EOF remain excluded. This pass does not
silently shorten those records or promote either file to a complete review.

H3 client connection lines 620–794 cover shared state, graceful shutdown,
late TLS application settings, remembered control settings and the close
driver. Invalid application settings reach the connection error path.
The driver polls QPACK before control frames, validates server GOAWAY as a
request stream ID, rejects unexpected control frames and rejects a peer
bidirectional stream. Deeper decoder and state-machine contracts remain
separate review records.

The retained native ECH slices cover server configuration parsing and key
copy, grease payload and AEAD configuration, and key collection ownership.
Unsupported server parameters fail before the key copy. Grease setters reject
invalid length or AEAD inputs before assigning configuration. The key
collection setter takes a reference and swaps under the context lock.
The acceptance getter treats the client early-data state separately.

No additional supported defect was found in these slices. The native source
is a retained build artifact; its presence does not prove current compiler
selection. Full ECH parsing, handshake states, cryptographic implementations,
platform verification and runtime execution remain outside these reads.

## Next

- [Coverage](coverage.md): remaining source and verification work.
