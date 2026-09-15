# Validation model

Successful connectivity is not proof of browser-compatible behavior.

Wire-sensitive changes will be checked at three levels:

1. Deterministic local protocol assertions
2. Normalized packet, frame, or qlog differentials against a pinned fixture
3. Supplemental live checks against services such as Peet and Pingly

Normalization may remove values that are intentionally nondeterministic, such as random bytes, connection identifiers, packet numbers, timestamps, and cryptographic key material. It must not erase ordering, presence, negotiated values, or other behavior the profile claims to control.

The TLS testkit preserves complete TLS record bytes and the exact reassembled ClientHello handshake. Its strict decoder exposes the ordered semantic fields asserted by the current TLS transport tests. Broader normalization will be added only when a retained browser fixture requires it, so each normalized field has an immediate differential assertion.

Compatibility claims must cite the exact browser capture and differential fixture that supports them. A successful response or summary fingerprint alone is not evidence of parity.

## Reproducing the Chrome TCP ClientHello fixture

The retained Chrome fixture is
`crates/phantom-testkit/tests/fixtures/chrome-152.0.7977.83-macos-15.5-client-hello.txt`.
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
line followed by an ordered semantic summary.

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
test treats only the selected GREASE codepoints as variable in its ordered value
assertions. It checks ALPN, supported versions, cipher, group, signature, and
key-share ordering. The raw fixture preserves the exact extension order; this
single capture does not establish Chrome's extension-permutation behavior, so
the regression asserts required extension presence rather than a compatibility
model that the evidence does not yet support.
