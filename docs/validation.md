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

## Browser ClientHello fixture workflow

### Retained Chrome capture

The retained Chrome fixture is
`fixtures/tls/chrome/152.0.7977.83/macos-15.5/client-hello.txt`.
It is one reference measurement. The fixture contains the complete TLS record
in lowercase hexadecimal, the semantic decoder output, and the browser,
operating system, hostname, listener, and browser-neutral launch metadata. The
version 2 schema stores fields in a fixed order and records the launch as
`launch_mode` plus a single-line `launch_arguments` value, so the same schema
can describe command-line and application-driven captures. The
`launch_arguments` field remains present but may be empty when the browser was
launched without arguments, as with a normal Safari application launch.

The recorded environment was Google Chrome `152.0.7977.83` on macOS `15.5`
(`24F74`). Confirm those values before comparing a new capture:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --version
sw_vers
```

In the repository, start the bounded one-connection listener in one terminal:

```sh
launch_arguments='--headless=new --user-data-dir=<temporary-directory> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom'
cargo run -p phantom-testkit --example capture_client_hello -- \
  127.0.0.1:9443 \
  "Google Chrome" \
  "152.0.7977.83" \
  "macOS 15.5 (24F74)" \
  "command-line" \
  "$launch_arguments"
```

The example accepts only a loopback listener and loopback peer, waits at most 30
seconds for the connection, gives the ClientHello 10 seconds to complete, and
limits the capture to 128 KiB and 16 TLS records. It prints one exact record hex
line within a complete ordered fixture, followed by the semantic summary. Byte
strings such as ALPN protocol identifiers and SNI are lowercase hexadecimal, so
every value remains unambiguous even when it is not UTF-8 or contains
delimiters.

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

When retaining a new fixture, copy the complete example output without editing
random or cryptographic bytes. Record exact launch arguments or an empty value
when there were none, using a clear placeholder only for an ephemeral profile
path. The fixture regression strictly
parses every key in order and requires every metadata, record, and semantic
field. It regenerates the stored semantic summary from the raw record, including
the controlled SNI hostname.

Run the browser-fixture regression directly with:

```sh
cargo test -p phantom-testkit --test browser_client_hello_fixtures
```

For ordered vectors, the regression replaces each selected GREASE codepoint with
one sentinel without deleting it. This preserves the number and position of
cipher suites, supported versions, groups, signature algorithms, and key shares.
The raw fixture also preserves the exact extension order; this single capture
does not establish Chrome's extension-permutation behavior, so the direct
differential compares exact extension membership and stable payload lengths
without claiming that one permutation is canonical. The built-in recipe used by
that differential is `phantom_profile::chromium::v152_macos_tls()`.

### Retained Firefox capture

The retained Firefox fixture is
`fixtures/tls/firefox/154.0/macos-15.5/client-hello.txt`. It records Mozilla
Firefox `154.0` (bundle build `15426.8.12`) on macOS `15.5` (`24F74`). Firefox
was started directly with a new temporary profile and
`--headless --no-remote --profile <temporary-profile>`, then navigated to
`https://localhost:9446/`. No browser profile or executable is retained.

The source capture used the version 1 output schema. Its complete text SHA-256
was `07a482027d9687d81700876b39b305fe7cea4615a9e82eac490fb06e4d7285c1`.
Only the metadata was converted to version 2; the TLS record and all semantic
lines are unchanged. The record SHA-256 before and after conversion is
`c9f0144a04876b66915974cdd845a4111a1613541847edf5d9b648ed48c91194`.

Two independent captures had source text SHA-256 values
`ff5466a27d2bcff78756ebea35fc87cf100347d5dcdb84bdb3d1f72d414a14e0`
and `80a527792b8f40cff97c10473e6b05462306c476013981ec8d4657bc105bcfb6`.
All three produced normalized SHA-256
`f825dadb908340cd0e03defa05115e40edaa7c24018b7e985357411cd6475433`
after zeroing the client-random, session-id, key-share, and ECH payload bytes in
place while retaining every payload length and the exact extension order.
Firefox supplied no GREASE codepoints in these observations, so the regression
does not invent a GREASE normalization for this fixture.

Confirm the installed versions, then capture on the loopback listener:

```sh
"/Applications/Firefox.app/Contents/MacOS/firefox" --version
defaults read /Applications/Firefox.app/Contents/Info CFBundleVersion
sw_vers

launch_arguments='--headless --no-remote --profile <temporary-profile>'
cargo run -p phantom-testkit --example capture_client_hello -- \
  127.0.0.1:9446 \
  "Mozilla Firefox" \
  "154.0" \
  "macOS 15.5 (24F74)" \
  "command-line" \
  "$launch_arguments"
```

In another terminal, create a fresh profile and navigate exactly once:

```sh
capture_profile_dir="$(mktemp -d /tmp/phantom-firefox-capture.XXXXXX)"
"/Applications/Firefox.app/Contents/MacOS/firefox" \
  --headless \
  --no-remote \
  --profile "$capture_profile_dir" \
  https://localhost:9446/
```

The listener closes after the ClientHello, so a connection error is expected.
Stop Firefox before removing only the temporary directory named by
`capture_profile_dir`.

### Retained Safari capture

The retained Safari fixture is
`fixtures/tls/safari/18.5/macos-15.5/client-hello.txt`. It records Safari
`18.5` (bundle build `20621.2.5.11.8`) on macOS `15.5` (`24F74`). Safari was
already running as the normal application; the URL `https://localhost:9445/`
was entered through the user interface. Accordingly, `launch_mode=application`
and the required `launch_arguments` value is empty.

The primary version 1 source text SHA-256 was
`b8b18c93662ed508d5246ba0041049719a840151a79f503cef6cba207f9e8d6e`.
Only its schema metadata was converted. The TLS record SHA-256 before and after
conversion is
`0cdd41e3a4445365399c9ce0ed8b2bdd926f926405ac56070c48236e9756ba75`.
Two independent source captures had text SHA-256 values
`0d74de7da2d0209731e70dd4650bcfacd486607965a42f474a85c8045d8a3c46`
and `b5358e3c535ef946fdec9b7a079f557ef499a3779bcd2273b40c39ef3cf99988`.
All three produced normalized SHA-256
`f4f43360e43d6e8069d883b4089e422565b5e1bd146ea185b3cee94939f77d29`
after zeroing the client-random, session-id, key-share, and ECH payload bytes in
place, then replacing each GREASE codepoint in cipher suites, extension IDs,
supported groups, supported versions, and key-share group IDs with `0x0a0a`.
Payload lengths and order were preserved throughout.

Confirm Safari and macOS versions, then start the listener:

```sh
defaults read /Applications/Safari.app/Contents/Info CFBundleShortVersionString
defaults read /Applications/Safari.app/Contents/Info CFBundleVersion
sw_vers

cargo run -p phantom-testkit --example capture_client_hello -- \
  127.0.0.1:9445 \
  "Safari" \
  "18.5" \
  "macOS 15.5 (24F74)" \
  "application" \
  ""
```

Navigate to `https://localhost:9445/` in Safari's user interface. Do not launch
Safari with automation flags for this observation. The listener closes after
the ClientHello, and the fixture makes no claim about Safari HTTP/2 startup:
remote automation was disabled in the measured environment.

## Browser HTTP/2 fixture workflow

### Retained Chrome capture

The retained local fixture is
`fixtures/http2/chrome/152.0.7977.83/macos-15.5/client-startup.txt`.
It records one Chrome connection through the initial SETTINGS and connection
WINDOW_UPDATE. It is raw local evidence and is not derived from the retained
Pingly output. That output is stored separately and is never used as the oracle
for this regression.

Confirm Chrome and macOS versions as described above. Record the normalized
single-line launch arguments, then run the bounded TLS listener with explicit
browser-neutral fixture metadata:

```sh
launch_arguments='--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom'
cargo run -p phantom-net --example capture_http2_tls -- \
  127.0.0.1:9444 \
  "Google Chrome" \
  "152.0.7977.83" \
  "macOS 15.5 (24F74)" \
  "command-line" \
  "$launch_arguments"
```

The example accepts one loopback peer, creates an ephemeral certificate for
`server.phantom.test`, selects only `h2`, and advertises ALPS using its new TLS
extension codepoint with an empty server payload. It gives accept, handshake,
and HTTP/2 frame capture separate absolute deadlines. Frame payload, total byte,
and frame-count limits are included in the output. Private-key material is never
printed.

The command is browser-vendor-neutral, but its completion shape is deliberately
narrow: it requires initial SETTINGS and then a connection WINDOW_UPDATE. It
times out if that connection WINDOW_UPDATE is absent. This exactly matches the
measured startup shape retained here; it is not a general HTTP/2 frame capture
mode. A future browser observation with a different startup shape should add an
explicitly designed capture mode and schema rather than weakening or fabricating
this evidence.

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

The version 2 fixture output is ordered `key=value` text. Browser identity,
version, operating system, launch mode, and launch arguments are separate
fields; `launch_arguments` may be empty but must remain a single line. Binary
values are lowercase hexadecimal. Its browser-fixture regression
reconstructs the exact connection preface and frame bytes, reparses them through
`phantom-testkit`, and verifies the ordered SETTINGS and connection
WINDOW_UPDATE summary. A second bounded regression sends a fresh request
through Phantom's public HTTP/2 transaction using `v152_macos_http2()` and
requires its exact startup bytes to match the retained Chrome frames.

Run both retained HTTP/2 fixture checks directly with:

```sh
cargo test -p phantom-net --test browser_http2_fixtures
```

### Retained Firefox capture

The Firefox local oracle is
`fixtures/http2/firefox/154.0/macos-15.5/client-startup.txt`. It records the
exact connection preface, initial SETTINGS frame, and connection WINDOW_UPDATE
from Mozilla Firefox `154.0` on macOS `15.5` (`24F74`). The connection selected
`h2`; ALPS was absent. The ordered settings were
`1:65536,2:0,4:131072,5:16384`, followed by connection window increment
`12517377`.

The original version 1 capture text SHA-256 was
`78b13d84775538b293190f43e0ae647fea4c21ac25b08b38011117fad578118e`.
Only schema metadata was converted to version 2. The concatenated preface and
frame bytes have SHA-256
`288bd22099e228f3845afd4682ecaf1277d71761909597c2d45a0e28a73ab234`
both before and after conversion.

The capture used official arm64 geckodriver `0.37.1`, whose downloaded archive
had SHA-256
`d02b3f7003f999caf90974a2ef5da0286c05d01cee19112c86846d759fdba4f5`.
WebDriver created an isolated profile. Caller-supplied launch arguments were
only `--headless`; generated driver arguments are deliberately not presented as
caller arguments. The W3C capabilities set `acceptInsecureCerts=true`,
`network.dns.localDomains=server.phantom.test`, and `browser.startup.page=0`.
The bounded listener command was:

```sh
cargo run -p phantom-net --example capture_http2_tls -- \
  127.0.0.1:9448 \
  "Mozilla Firefox" \
  "154.0" \
  "macOS 15.5 (24F74)" \
  "WebDriver" \
  "--headless"
```

With the listener waiting, create one bounded WebDriver session whose request
includes these capture-relevant capabilities, then navigate it once to
`https://server.phantom.test:9448/`. Driver-generated defaults and temporary
profile paths are omitted from this illustrative request:

```json
{
  "capabilities": {
    "alwaysMatch": {
      "acceptInsecureCerts": true,
      "browserName": "firefox",
      "moz:firefoxOptions": {
        "args": ["--headless"],
        "binary": "/Applications/Firefox.app/Contents/MacOS/firefox",
        "prefs": {
          "browser.startup.page": 0,
          "network.dns.localDomains": "server.phantom.test"
        }
      }
    }
  }
}
```

The fixture regression reparses and verifies only these raw startup bytes and
their ordered semantic summary. There is intentionally no Firefox Phantom
recipe differential yet.

Two concise live-service summaries sit beside the raw fixture:
`pingly-api-all.txt` retains source JSON SHA-256
`6ea07fda8d1f22f986b12985236bd646cffca1858f54c1c43143fc0e7b3e5abb`,
and `peet-api-all.txt` retains source JSON SHA-256
`15dd2be6c48f7807c4834878cf1a9302469ed1fd4866fe1efd1d6e64164405fa`.
Both live services reported initial SETTINGS and connection WINDOW_UPDATE
components matching the local fixture. The local bounded capture ends there; it
does not establish the full Akamai fingerprint, pseudo-header order, or stream
priority. The reported pseudo-header order `method,path,authority,scheme`,
dependency `0`, weight `42`, nonexclusive priority, JA3, and JA4 are live-only
supplemental evidence, not regression oracles. Service behavior and reports may
change independently of the browser.

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

The raw Chrome fixture and direct differential establish the captured Chrome
152 macOS startup behavior. The raw Firefox fixture establishes only Firefox
154's captured startup shape; it has no Phantom recipe differential. Retained
Pingly and Peet results are supplemental observations, not substitutes for
local bytes. No H3 or Safari HTTP/2 wire fixture exists yet.
