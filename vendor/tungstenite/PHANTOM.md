# Phantom patch

Upstream: `tungstenite` 0.30.0 from crates.io.

The ordered patch series adds RFC 7692 `permessage-deflate` support derived
from upstream pull request 561, keeps frame and message payloads out of logs
and errors, makes client masking entropy failure an ordinary result, and
reports forbidden peer Close codes instead of rewriting them. A small
integration patch exposes ordered negotiation for Phantom's custom handshake,
rejects terminal raw-DEFLATE streams, and keeps an 8-bit negotiated window
within its wire bound. The final default-preserving patch adds an opt-in
per-message data fragment count, rejects overflow before decompression or
reassembly, and makes that receive failure terminal. The `deflate` feature
enables only its codec and HTTP value types; the separate `handshake` feature
still owns tungstenite's built-in handshake implementation.

`scripts/ci/check-vendor.sh tungstenite` downloads the checksummed upstream
crate, replays every entry in `patches/series`, and compares the result with
this directory.
