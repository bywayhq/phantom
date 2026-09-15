# Validation model

Successful connectivity does not establish browser wire behavior.

Wire-sensitive changes are checked at three levels:

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

Claims about browser wire behavior must cite the exact capture and differential
fixture that supports them. A successful response or summary fingerprint alone
does not establish the same wire behavior.

## Reproducing the Chrome TCP ClientHello fixture

The retained Chrome fixture is
`fixtures/tls/chrome/152.0.7977.83/macos-15.5/client-hello.txt`.
It is one reference measurement. The fixture contains the complete TLS record
in lowercase hexadecimal, the semantic decoder output, and the browser,
operating system, hostname, listener, and flag metadata.

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

## Reproducing the Chrome HTTP/2 startup fixture

The retained local fixture is
`fixtures/http2/chrome/152.0.7977.83/macos-15.5/client-startup.txt`.
It records one Chrome connection through the initial SETTINGS and connection
WINDOW_UPDATE. It is raw local evidence and is not derived from the retained
Pingly output. That output is stored separately and is never used as the oracle
for this regression.

Confirm Chrome and macOS versions as described above. In one terminal, run the
bounded TLS listener with explicit fixture metadata:

```sh
cargo run -p phantom-net --example capture_http2_tls -- \
  127.0.0.1:9444 \
  "Google Chrome 152.0.7977.83" \
  "macOS 15.5 (24F74)"
```

The example accepts one loopback peer, creates an ephemeral certificate for
`server.phantom.test`, selects only `h2`, and advertises ALPS using its new TLS
extension codepoint with an empty server payload. It gives accept, handshake,
and HTTP/2 frame capture separate absolute deadlines. Frame payload, total byte,
and frame-count limits are included in the output. Private-key material is never
printed.

In a second terminal, start Chrome with an isolated temporary profile:

```sh
capture_profile_dir="$(mktemp -d /tmp/phantom-chrome-h2.XXXXXX)"
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
  https://server.phantom.test:9444/
```

Chrome is expected to report a reset after the bounded listener exits. The
retained capture completed on the first connection without a retry. Its peer
ALPS state was `empty`: Chrome negotiated new-codepoint ALPS and supplied a
zero-length value, which the fixture distinguishes from absent ALPS. Stop any
remaining Chrome process before removing only the temporary directory printed
in `capture_profile_dir`.

The fixture output is ordered `key=value` text. Binary values are lowercase
hexadecimal. Its regression reconstructs the exact connection preface and frame
bytes, reparses them through `phantom-testkit`, and verifies the ordered SETTINGS
and connection WINDOW_UPDATE summary. A second bounded regression sends a fresh
request through Phantom's public HTTP/2 transaction using
`v152_macos_http2()` and requires its exact startup bytes to match the retained
Chrome frames.

## Current HTTP/2 protocol coverage

Deterministic local tests also cover behavior beyond the retained startup
fixture: declared pseudo-header and ordinary-header order, request validation
before I/O, response flow control, streaming DATA and trailers, incomplete-body
`CANCEL`, reset flushing, and bounded connection-driver shutdown.

The exact-`h2` TLS path distinguishes absent ALPS from a negotiated empty value.
A negotiated value is parsed as bounded HTTP/2 frames: known non-SETTINGS core
frames, ACK SETTINGS, invalid known values, and truncated or oversized input
are rejected before the HTTP/2 preface. `ENABLE_PUSH` accepts only zero;
unknown setting identifiers and extension-frame types are ignored. Duplicate
known settings apply in order. Only a complete SETTINGS frame seeds peer state;
negotiated-empty ALPS does not. Seeded settings affect the first request without
producing a SETTINGS ACK, because no peer SETTINGS frame was received on the
HTTP/2 wire.

The raw fixture and direct differential establish only the captured Chrome 152
macOS startup behavior. The retained Pingly result and live Peet or Pingly
checks are supplemental observations, not substitutes for local bytes. No H3,
Firefox, or Safari wire fixture exists yet.
