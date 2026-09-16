# Phantom patch

Upstream: `tungstenite` 0.30.0 from crates.io.

The local patch keeps frame and message payloads out of dependency logs and
UTF-8 errors, makes client masking entropy failure an ordinary `Error::Random`
result, and reports forbidden peer Close codes instead of rewriting them.

`scripts/ci/check-vendor.sh tungstenite` downloads the checksummed upstream
crate, replays `patches/redacted-fallible-masking.patch`, and compares the
result with this directory.
