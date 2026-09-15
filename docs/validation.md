# Validation model

Successful connectivity is not proof of browser-compatible behavior.

Wire-sensitive changes will be checked at three levels:

1. Deterministic local protocol assertions
2. Normalized packet, frame, or qlog differentials against a pinned fixture
3. Supplemental live checks against services such as Peet and Pingly

Normalization may remove values that are intentionally nondeterministic, such as random bytes, connection identifiers, packet numbers, timestamps, and cryptographic key material. It must not erase ordering, presence, negotiated values, or other behavior the profile claims to control.

The TLS testkit preserves complete TLS record bytes and the exact reassembled
ClientHello handshake. Its strict decoder exposes ordered semantic fields,
requested trust-anchor IDs, and extension payload lengths. The Chrome 152
differential compares a fresh Phantom ClientHello directly with the retained
browser capture. It normalizes GREASE codepoint values and the measured random
ECH GREASE payload length while retaining record count, vector positions,
extension membership, and every other extension payload length.

Compatibility claims must cite the exact browser capture and differential fixture that supports them. A successful response or summary fingerprint alone is not evidence of parity.

## Reproducing the Chrome TCP ClientHello fixture

The retained Chrome fixture is
`fixtures/tls/chrome/152.0.7977.83/macos-15.5/client-hello.txt`.
It is a reference measurement, not a browser-compatibility claim. The fixture
contains the complete TLS record in lowercase hexadecimal, the semantic decoder
output, and the browser, operating system, hostname, listener, and flag metadata.

The recorded environment was Google Chrome `152.0.7977.83` on macOS `15.5`
(`24F74`). Confirm those values before comparing a new capture:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version
sw_vers
```

In the repository, start the bounded one-connection listener in one terminal:

```sh
cargo run -p phantom-testkit --example capture_client_hello -- 127.0.0.1:9443
```

The example accepts only a loopback listener and loopback peer, waits at most 30
seconds for the connection, gives the ClientHello 10 seconds to complete, and
limits the capture to 128 KiB and 16 TLS records. It prints one exact record hex
line followed by an ordered semantic summary. Byte strings such as ALPN protocol
identifiers and SNI are lowercase hexadecimal, so every value remains
unambiguous even when it is not UTF-8 or contains delimiters.

In a second terminal, create an isolated profile and start Chrome with the
recorded flags:

```sh
capture_profile_dir="$(mktemp -d /tmp/phantom-chrome-capture.XXXXXX)"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new \
  --user-data-dir="$capture_profile_dir" \
  --no-first-run \
  --no-default-browser-check \
  --disable-background-networking \
  --disable-component-update \
  --disable-default-apps \
  --disable-quic \
  --no-proxy-server \
  --host-resolver-rules="MAP server.phantom.test 127.0.0.1, EXCLUDE localhost" \
  --ignore-certificate-errors \
  --dump-dom \
  https://server.phantom.test:9443/
```

`--disable-quic` makes this specifically a TCP TLS capture; it does not provide
H3 evidence. The host resolver mapping keeps the controlled hostname on
loopback. The listener intentionally closes after the ClientHello, so Chrome is
expected to show a connection error and may retry until stopped. Stop Chrome
after the fixture prints, then remove only the temporary profile directory named
by `capture_profile_dir`.

When retaining a new fixture, copy the example output without editing random or
cryptographic bytes and record the full metadata above. The fixture regression
strictly parses every key and requires every metadata, record, and semantic
field. It regenerates the stored semantic summary from the raw record, including
the controlled SNI hostname.

For ordered vectors, the regression replaces each selected GREASE codepoint with
one sentinel without deleting it. This preserves the number and position of
cipher suites, supported versions, groups, signature algorithms, and key shares.
The raw fixture also preserves the exact extension order; this single capture
does not establish Chrome's extension-permutation behavior, so the direct
differential compares exact extension membership and stable payload lengths
without claiming that one permutation is canonical. The built-in recipe used by
that differential is `phantom_profile::chromium::v152_macos_tls()`.
