# Validation

Check the evidence behind each claim in [Coverage](../reference/coverage.md),
and what that evidence leaves unproven.

> For specialists checking a claim and evaluators deciding how far to trust
> one.

## Trust at a glance

Phantom's claims rest on four kinds of evidence:

- A **browser capture** records a named browser build's traffic against a
  loopback listener. Captures are retained under `fixtures/`, and most are
  replayed by tests.
- **Browser source** is the browser's code at a release tag. It is the
  evidence where a capture cannot see a behavior.
- A **loopback test** drives Phantom's public client against a scripted local
  peer. It proves Phantom's own contract, not browser parity.
- A **hostile-peer regression** sends malformed or abusive traffic. It proves
  that Phantom stays safe and bounded, not that it matches a browser.

| Area | Strongest evidence | Main limits |
| --- | --- | --- |
| [Chrome 154 recipes](#chrome-154-recipes) | Windows captures of every Chrome layer, replayed by recipe tests | One Windows build; macOS only for client hints and request fields; no Linux; no Chrome for Testing build exists at this version |
| [Edge 153 and Firefox 156 recipes](#edge-153-and-firefox-156-recipes) | Windows browser captures, replayed by recipe tests | One Windows build per browser; macOS only for client hints and request fields |
| [Edge 154 recipes](#edge-154-recipes) | Fingerprint snapshots against Edge 153, and Windows and macOS captures of every scenario whose request fields carry the brand list | One run of the client hints, QUIC resumption, and H3 startup on Windows; ECH and the raw H2 startup rest on Edge 153 |
| [Brave 154 and Opera 135 recipes](#brave-154-and-opera-135-recipes) | Windows browser captures, replayed by recipe tests | One Windows build per browser; no TCP, SSE, or Alt-Svc evidence; Opera's H2 and H3 startups launched through DevTools |
| [macOS recipes](#macos-recipes) | macOS 15.5 arm64 captures of Chrome 154, Edge 154, Opera 135, and Firefox 156 client hints and request fields, replayed by recipe tests | One Apple silicon host; headless only; single-sample parity runs for the other layers |
| [Opera for Android 102 recipes](#opera-for-android-102-recipes) | Android 17 emulator captures of the TLS ClientHello and client hints; Android 15 emulator captures of HTTP/1.1 requests to loopback | Opera takes no switches: no H2, QUIC, H3, or templates |
| [Firefox for Android 156 recipe](#firefox-for-android-156-recipe) | Android 15 emulator captures of the TLS ClientHello | No certificate trust on Android, so no other layer |
| [Chrome for Android 154 recipes](#chrome-for-android-154-recipes) | Android 17 emulator captures, reporting a Pixel 7, of TLS, H2, QUIC, H3, QUIC resumption, client hints, WebSocket openings, plaintext trust, and templates, replayed by recipe tests; one Chrome 153 cellular startup on an Android 15 emulator | An emulator, not a phone; no TCP layer; one process per transport layer |
| [Brave for Android 153 recipes](#brave-for-android-153-recipes) | Android 17 and Android 15 emulator captures of the same layers, replayed by recipe tests | As for Chrome for Android |
| [Edge for Android 153 recipes](#edge-for-android-153-recipes) | arm64 Android 17 emulator captures, reporting a Pixel 7, of TLS, H2, QUIC, H3, client hints, and templates, replayed by recipe tests | As for Chrome for Android; no WebSocket opening recipe, and no resumption or proxy capture |
| [TCP socket options and address racing](#tcp-socket-option-evidence) | Browser source at one tag per browser, plus socket read-back tests | No capture confirms the options; field trials cannot be ruled out |
| [Address cache](#address-cache-evidence) | Browser source at one tag per browser, plus unit and loopback tests | No capture counts a browser's DNS queries; record TTLs and Firefox's grace period not modeled |
| [HTTP/1.1 connection bound](#http11-connection-bound-evidence) | Browser source at one tag per browser, plus loopback tests | No capture counts a browser's connections; no Edge source |
| [Plaintext origin trust](#plaintext-origin-trust-evidence) | Chrome 154, Edge 154, and Firefox 156 proxy route captures, browser source, and loopback tests of Phantom | HTTP/1.1 and HTTP/2 page loads and default-mode `fetch()` only; WebSocket openings not adjusted |
| [SSE reconnect](#sse-browser-reconnect-evidence) | Chrome 154 and Firefox 156 captures, replayed against Phantom | Plaintext HTTP/1.1 on Windows only |
| [Cookie crumbs](#cookie-crumb-evidence) | Chrome 154, Edge 154, and Firefox 156 captures over H1, H2, and H3, replayed against Phantom | Five cookies on one origin; Firefox H3 not reproduced |
| [WebSocket openings](#websocket-browser-evidence) | Chrome 154, Edge 154, Brave 154, Opera 135, and Firefox 156 captures | No subprotocols, H3, proxies, macOS, or Safari |
| [WebSocket handshake timers](#websocket-handshake-timer-evidence) | Browser source at one tag per browser, plus loopback tests | No capture shows a timer firing; no Edge source |
| [HPACK encoder](#hpack-encoder-evidence) | Every H2 HEADERS block in the cookie and WebSocket captures of five browsers, replayed byte for byte, and browser source | One origin, small fields; Chromium's size and field rules rest on source |
| [HTTP/2 stream numbering](#http2-stream-numbering-evidence) | The stream of every request in the H2 cookie, WebSocket, and TLS proxy captures of eight browsers on Windows, macOS, and Android, and browser source for the stream limit and its cap | No capture shows the stream limit or the cap |
| [HTTP/2 preface PING](#http2-preface-ping-evidence) | Chromium source and a retained loopback capture of Chrome 154 reusing an idle connection, replayed against Phantom | One Windows build; the PING after a DATA frame and the 10-second boundary rest on source |
| [Alt-Svc racing](#alt-svc-racing-evidence) | Chrome 154 captures and Chromium source, plus loopback tests of Phantom | Caller-supplied origin delay; several listed differences from Chromium |
| [Alt-Svc upgrade](#alt-svc-http3-upgrade-evidence) | Loopback tests | No browser `Alt-Used` ordering; no proxy routes |
| [QUIC resumption and 0-RTT](#quic-resumption-and-0-rtt-evidence) | Chrome 154, Edge 154, Brave 154, Opera 135, and Firefox 156 captures, with the Chromium-family ones replayed against Phantom's resumed H3 connections | Loopback and headless only; `initial_rtt_us` compared by encoding, not value; no Firefox H3 recipe |
| [TLS resumption over TCP](#tls-resumption-over-tcp-evidence) | Chrome 154, Edge 154, Brave 154, Opera 135, and Firefox 156 captures, replayed against Phantom's resumed TCP ClientHellos | Loopback and headless only; Firefox's TCP early data not reproduced; no network partitions in Phantom |
| [Request trailers](#ordered-request-trailer-evidence), [forward proxies](#forward-proxy-evidence), [H3 over SOCKS5](#h3-socks5-udp-evidence) | Loopback tests | No browser-capture fidelity |
| [Proxy routes in browsers](#proxy-route-browser-evidence) | Chrome 154, Edge 154, Brave 154, Opera 135, and Firefox 156 captures, replayed against Phantom | Plaintext origins only; no `https://` or `wss://` origins or SOCKS |
| [Proxy authentication](#proxy-authentication-evidence) | Chrome 154, Edge 154, and Firefox 156 captures and browser source, plus loopback tests of Phantom | One realm; no `407` to a CONNECT captured; forwarded field position and H2 indexing differ |
| [Connection and status retries](#connection-retry-evidence) | Loopback tests | Not browser retry policy; some paths have no recovery test |
| [Content decoding](#content-decoding-evidence) | Unit and loopback tests; browser source for documented divergences | No browser-parity claim |
| [Response-body limits](#response-body-limit-evidence) | Unit tests and an H1 loopback test | No H2 or H3 test exceeds a limit |
| [H2 receive bounds](#adversarial-coverage) | Hostile-peer regressions | Not browser evidence |

Every desktop capture comes from one Windows 11 build, except those behind
the [macOS recipes](#macos-recipes), which come from one macOS 15.5 Mac. The
Android captures come from Android 17 and Android 15 emulators on the Windows
host, except Edge for Android's, which come from an arm64 Android 17 emulator
on a Mac. No
third-party observer backs any current recipe. [Recorded coverage losses](#recorded-coverage-losses)
lists the checks Phantom used to run and no longer does.

## Contents

- [Evidence rules](#evidence-rules): what counts as proof, and what a
  comparison may normalize.
- [Browser recipes](#browser-recipes): the captures and browser source behind
  the named browser profiles.
- [Feature evidence](#feature-evidence): the tests behind individual client
  features, and the browser captures where they exist.
- [Robustness evidence](#robustness-evidence): hostile peers, fuzzing, and
  sanitizers.
- [Other checks](#other-checks): external suites, diagnostics, benchmarks,
  and contributor gates.

Each evidence section states, in order, what is claimed, the evidence, how to
reproduce it, and its limits. Read the limits before relying on a claim.

## Evidence rules

### Evidence ladder

A claim about wire-sensitive behavior needs every level that applies to it:

1. A deterministic local assertion for parsing, validation, and lifecycle.
2. A normalized [differential](../reference/glossary.md#differential) against
   a pinned capture, at the level of bytes, frames, packets, or qlog events.
3. A hostile-peer regression for relevant unusual or malformed input.
4. Supplemental evidence from interoperability tests or a live observer.

A working connection and a matching summary fingerprint do not show that
behavior is browser-compatible.

### Fixtures and normalization

A [fixture](../reference/glossary.md#fixture) records the client, version,
platform, launch conditions, and raw evidence needed to reproduce a claim.
Strict decoders keep the ordered semantic fields that differentials compare.

Normalization may remove values that must vary: random bytes, cryptographic
key material, timestamps, connection IDs, packet numbers, and measured GREASE
values. It must not erase order, presence, lengths, negotiated values, or any
other behavior a profile controls.

Built-in recipes are compared through the same public path that users
exercise. A profile component is not complete when it merely parses or
connects.

## Browser recipes

A [recipe](../reference/glossary.md#recipe) is the wire data for one browser
build at one protocol layer, such as `chromium::v154_tls`. The sections below
record the captures and source reading behind each recipe and the tests that
replay them.

### Capture normalization

Every desktop recipe in this tree comes from Windows 11 (build 26200, x64)
captures of the browser build installed on the capture host. The Android
recipes come from captures on Android emulators, described in each Android
section. Phantom carries one version
per browser, so a recipe name always points at a build that can be recaptured
and reverified. Retired captures, including the Chrome 152 and Firefox 154 macOS and Windows
sets that once established cross-platform transport parity, are no longer in
the tree, and no current claim rests on them.

Capture comparisons normalize only per-connection randomness:

- TLS and QUIC GREASE values normalize to one sentinel. Extension order is
  compared as a multiset, because Chrome permutes it per connection.
- Client random, session ID, key-share bytes, ECH GREASE config ID and
  payload bytes, and the QUIC initial source connection ID reduce to lengths
  or are ignored. Chrome chooses its ECH GREASE payload length per connection,
  so that length is excluded from record-length comparison.
- Chrome's GREASE `version_information` entry changes position between
  connections; the chosen version stays first. The H3 reserved setting, its
  value width, and the GREASE QUIC transport parameter's id and length also
  vary per connection.
- Firefox chooses its ECH GREASE AEAD per connection, between AES-128-GCM
  (`0x0001`) and ChaCha20-Poly1305 (`0x0003`). A multi-connection capture saw
  both values in each of three processes (359 and 337 of 696 connections),
  which is consistent with NSS taking the choice from the low bit of fresh
  per-handshake random bytes. The comparison therefore treats the AEAD as
  per-connection randomness. `firefox::v156_tls` lists both AEADs in
  `ech_grease_aeads`, and the patched BoringSSL backend draws one uniformly
  per connection from fresh random bytes, keeping it across a
  HelloRetryRequest. `firefox_156_recipe_draws_either_ech_grease_aead_per_connection`
  replays both retained captures, then requires 200 loopback connections from
  one connector to contain only these two values, with each count in 60..=140.
  A fair draw fails that bound with probability below 1e-7. Only the
  distribution is reproduced; NSS and BoringSSL draw from different random
  sources.
- Every retained Chrome and Edge ClientHello, over TCP and QUIC, uses
  HKDF-SHA256 with AES-128-GCM for ECH GREASE. The Chrome TLS recipe tests
  compare that cipher suite exactly, and
  `chromium_recipes_emit_aes_128_gcm_ech_grease_on_every_connection` checks it
  on 64 connections from one connector for each of Chrome 154 and Edge 153.
  Chromium-family recipes leave `ech_grease_aeads` empty and rely on the
  backend default, which selects AES-128-GCM because the recipes set
  `aes_hardware`.
- `user-agent`, `sec-ch-ua`, `sec-ch-ua-mobile`, and `sec-ch-ua-platform` are
  persona data and differ by browser and build by design. Only their positions
  in the request field order are compared.

Limits:

- One Windows build, and one build per browser. The
  [macOS recipes](#macos-recipes) compare client hints, request fields, and
  single parity runs with macOS; no other layer is claimed to be platform
  independent, and no Linux capture exists.
- Desktop launches are headless, except the headful client-hint and SSE runs
  each section names. Android has no headless mode; its fixtures record
  `android-typed` or `android-intent`.

### Chrome 154 recipes

What is claimed: the `chromium::v154_*` recipes, a complete Chromium set
(listed in [Coverage](../reference/coverage.md#browser-profiles)), reproduce
Google Chrome 154.0.8037.58 on Windows 11.

Evidence: Chrome 154.0.8037.58, the stable build installed on the Windows 11
capture host (build 26200, x64), was captured in every area that holds a
Chrome fixture. Each run used a fresh temporary profile and a loopback
listener bound to port 0. Each capture repeats the launch flags recorded in
the Chrome 153 fixture for the same layer, which the Chrome 154 fixtures now
carry in their own `launch_arguments` lines. Chrome ran without
`--disable-field-trial-config`, as the branded Chrome 153 captures did: every
QUIC capture carries `max_idle_timeout` 30000 ms and the `ORIG` connection
option, not the testing configuration's 300000 ms and `ORIGNOIP`.

| Layer | Samples | Result against Chrome 153 |
| --- | --- | --- |
| TLS ClientHello | 61 fresh processes | Equal on legacy version, cipher suites, extension membership, supported groups, EC point formats, signature algorithms, ALPN, supported versions, key-share groups, and every compared extension payload. The 28 trust-anchor IDs are unchanged, but every process now sends them in one ascending order |
| HTTP/2 startup | 3 processes | Byte-identical preface, SETTINGS pairs and their order, connection WINDOW_UPDATE, and empty ALPS payload |
| QUIC ClientHello, QUIC and H3 startup | 3 processes | Equal on every non-GREASE transport parameter, the five H3 SETTINGS with their id and value widths, the QPACK stream prefixes, and the seventeen request fields in order; trust-anchor IDs sorted as above |
| Client hints | 3 headless runs and 1 headful | The same eleven hint names, order, and `default` or `accept-ch` delivery, and the same two navigation field orders; only persona values changed, and the headful run matched the headless runs exactly |
| WebSocket openings | 3 runs of each of 9 scenarios | Equal on every compared field; see [Comparison with Chrome 153](#comparison-with-chrome-153) |
| EventSource reconnects | 10 runs of each of 17 scenarios, and 5 headless with 5 headful `retry-750` runs | Equal on shape and fields, with every attempt median within 6 ms; see [Comparison with Chrome 153](#comparison-with-chrome-153) |
| Alt-Svc racing | 10 runs per scenario, 2 for `broken-backoff` | Equal on every recorded job decision, bound job, and brokenness lifetime; see [Alt-Svc racing evidence](#alt-svc-racing-evidence) |

The persona values that changed are the Chromium brand list and the build
number. Chrome 153 sent `"Google Chrome";v="153", "Not_A Brand";v="8",
"Chromium";v="153"`; Chrome 154 sends `"Chromium";v="154", "Google
Chrome";v="154", "Not A(Brand";v="99"`. The greased brand's name, version, and
position in the list all differ. `sec-ch-ua-full-version`,
`sec-ch-ua-full-version-list`, and the `user-agent` build number follow the new
version. Every other hint value, and every hint name and position, is
unchanged.

#### Chrome 154 trust-anchor ID order

Chrome 153 serialized its trust-anchor ID list by iterating an
`absl::flat_hash_set`, so the order was fixed within a browser process and
differed between processes: 35 distinct orders across 60 processes, in a
capture that is no longer retained. Chromium commit `942bda4298c1`
(2026-08-28) sorts the list before encoding. Chrome 154 shows that change.

Sixty fresh headless processes, one TCP ClientHello each, produced one order.
The retained `client-hello.txt` from a further process and all three QUIC
ClientHellos carry the same order. It is the 28 Chrome 153 IDs in ascending
byte order, from `82df130201` to `d679090f`.
`fixtures/tls/chrome/154.0.8037.58/windows-11-26200/trust-anchor-orders.txt`
retains the order, its count, and the per-process sequence.
`chromium::v154_tls` lists the 28 identifiers in that ascending order, which
is how a `TlsSettings` expresses trust-anchor order: the wire order is the
vector order, and the type has no sorting mode.
`chrome_154_tls_trust_anchor_ids_are_sorted_and_shared_by_every_process`
requires the fixture to hold one order, the recipe to equal it, and the recipe
list to be sorted;
`chrome_154_trust_anchor_extension_matches_the_retained_client_hello` finds
the same encoded extension in the retained ClientHello; and
`chrome_154_tls_recipe_emits_the_sorted_trust_anchor_order` checks the order
the TLS connector actually emits.

Each process contributed one connection. These captures therefore show that
the order no longer varies between processes; they do not on their own show
that it is fixed within a process. Earlier multi-connection captures of
Chrome 152 and 153, 48 connections from each of 13 fresh processes per build,
showed one order per process and never a per-connection reshuffle; those
captures were not retained as fixtures and their builds are no longer in the
tree.

#### What still varies per connection

The per-connection randomness described in
[Capture normalization](#capture-normalization) applies. Across the 61 TCP
ClientHellos:

- the extension order differed on all 61, always with the same 19-entry
  multiset and a GREASE extension both first and last;
- ECH GREASE used HKDF-SHA256 with AES-128-GCM on all 61, with a 32-byte
  `enc` and a payload of 144, 176, 208, or 240 bytes (19, 14, 16, and 12
  samples); and
- the GREASE cipher suite, group, signature algorithm, and version values
  differed per connection.

In the QUIC captures the transport-parameter order, the GREASE
transport-parameter id and length, the GREASE H3 setting id and value, and the
position of the reserved version inside `version_information` differ per
connection. The QUIC ClientHello carries no GREASE cipher suite, group, or
extension. `chromium::v154_quic` keeps one captured parameter order as its
permutation template;
`deterministic_entropy_reproduces_captured_parameters` re-encodes the retained
capture's transport parameters byte for byte from that recipe with fixed
entropy.

#### QUIC session resumption

`chromium::v154_http3_tls`, and `edge::v154_http3_tls` through it, enable
`session_tickets`, so a later QUIC connection to an origin resumes the TLS
session. The recipes rest on Chromium source. At tag `154.0.8037.58`:

- `QuicSessionPool::CreateCryptoConfigHandle` gives each crypto configuration
  its own `quic::QuicClientSessionCache` (`net/quic/quic_session_pool.cc`
  lines 2799-2800).
- `TlsClientConnection::CreateSslCtx` turns on BoringSSL client session
  caching with `SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL` and a
  new-session callback (`quiche/quic/core/crypto/tls_client_connection.cc`
  lines 38-40, at quiche revision `80bf9559`, the one Chromium's `DEPS` pins
  at that tag).

A TLS 1.3-only ClientHello never carries the TLS 1.2 `session_ticket`
extension, so the first ClientHello of a connection is unchanged.

`resumed_chrome_154_client_hello_keeps_the_captured_shape`, in
`crates/phantom-net/src/http3/tests/resumption.rs`, resumes a loopback
connection with the Chrome 154 recipe against a server whose tickets do not
permit early data. It compares the resumed ClientHello with the retained
Chrome 154 startup captures, which are all fresh connections, and requires
every field to match except the added `pre_shared_key` extension.
`early_data_client_hello_adds_only_early_data_and_pre_shared_key`, in
`crates/phantom-net/src/http3/tests/early_data.rs`, does the same for a
ticket that permits early data, which also adds `early_data`. The comparison
with resumed browser connections is under
[QUIC resumption and 0-RTT evidence](#quic-resumption-and-0-rtt-evidence).

Chromium enables client early (0-RTT) data by default. The quiche
`QuicCryptoClientConfig` constructor passes `!quic_disable_client_tls_zero_rtt`
to `CreateSslCtx` (`quiche/quic/core/crypto/quic_crypto_client_config.cc`
lines 84-85), and that flag defaults to false
(`quiche/common/quiche_protocol_flags_list.h` line 209).
`HttpNetworkTransaction` lets a request of default idempotency use early data
when `HttpUtil::IsMethodSafe` accepts its method
(`net/http/http_network_transaction.cc` lines 435-439). `chromium::v154_quic`
sets `early_data`, so the Chrome 154 and Edge 153 recipes offer early data on
every resumed connection, and Phantom applies the same method rule to the
requests it sends early, requiring no body and no trailers as well.

#### Comparison with Chrome 153

Chrome 154 was compared against the Chrome 153 Windows fixtures while those
were still in the tree. They have since been removed with the Chrome 153
recipes, so the comparison is recorded here and cannot be reproduced from the
repository. Where a Chrome 153 observation itself rested on a normalization,
the Chrome 154 comparison inherits it.

- WebSocket openings: the same nine scenarios, three runs each. The CONNECT
  pseudo-field order and HPACK representations, the exclusive parent-0
  weight-147 CONNECT priority, the `permessage-deflate;
  client_max_window_bits` offer, the `http/1.1`-only ALPN offer on a fresh
  origin and when the peer omits `SETTINGS_ENABLE_CONNECT_PROTOCOL`, the
  `RST_STREAM(CANCEL)` after a `403` and after an unoffered extension, the
  retry after `RST_STREAM(REFUSED_STREAM)`, RSV1 and fragmentation behavior,
  and the HTTP/1.1 opening field order all equalled Chrome 153. One difference
  is visible: every Chrome 154 `refused-stream` run opened its WebSocket on
  the page's H2 session and so carries a refusal to compare, where one Chrome
  153 run had opened over HTTP/1.1 instead. The count of idle speculative
  connections and the number of frames the uncompressed 1 MiB message is
  split into vary between runs of both versions.
- EventSource reconnects: the same tool, seventeen scenarios, and ten
  fresh-profile runs each. Every scenario matched Chrome 153 on request shape,
  reconnect field order, `Last-Event-ID` spelling, position, and raw bytes,
  connection reuse, and the absence of any request after a terminal response,
  with each attempt median within six milliseconds of the Chrome 153 median.
  Chrome 154's own five-run headless and headful `retry-750` comparison,
  retained under `launch-mode/`, gave medians within four milliseconds of
  each other.
- Alt-Svc racing: see [Alt-Svc racing evidence](#alt-svc-racing-evidence).

#### Capture commands and launches

How to reproduce: every fixture records its own launch arguments, with the
profile path replaced by a placeholder. Chromium launches repeat the flags the
Chrome 153 fixture for the same layer used, with the page URL on the loopback
port the listener bound. Each command below runs once per fresh browser
process unless it takes `--repeat`.

| Capture | Command |
| --- | --- |
| TLS ClientHellos and trust-anchor orders | `cargo run -p phantom-testkit --example capture_client_hello 127.0.0.1:0 "Google Chrome" 154.0.8037.58 "Windows 11 Home 10.0.26200 x64" command-line "<launch arguments>"` |
| HTTP/2 startup | `cargo run -p phantom-net --example capture_http2_tls 127.0.0.1:0 ...` |
| QUIC ClientHello and H3 startup | `scripts/capture/chrome_http3.py --listen 127.0.0.1:<port> --client-hello ...` |
| Client hints | `scripts/capture/client_hints.py --browser chrome --repeat 3` |
| WebSocket openings | `scripts/capture/http2_websocket.py --browser chrome --scenario all --repeat 3` |
| EventSource reconnects | `scripts/capture/sse_reconnect.py --browser chrome --scenario all --repeat 10` |
| Alt-Svc racing | `scripts/capture/alt_svc_race.py --browser chrome --repeat 10`, and `--scenario broken-backoff --repeat 2` |

<details>
<summary>Launch flags and listener ports</summary>

The TLS and HTTP/2 launches use `--headless=new`,
`--user-data-dir=<temporary-profile>`, `--no-first-run`,
`--no-default-browser-check`, `--disable-background-networking`,
`--disable-component-update`, `--disable-default-apps`, `--disable-quic`,
`--no-proxy-server`,
`--host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost`,
`--ignore-certificate-errors`, and `--dump-dom`, followed by
`https://server.phantom.test:<port>/`.

The HTTP/3 launch replaces `--disable-quic` and `--ignore-certificate-errors`
with `--enable-quic`, `--origin-to-force-quic-on=server.phantom.test:<port>`,
a port-qualified `--host-resolver-rules`, and
`--ignore-certificate-errors-spki-list=<certificate-spki>`. The client-hint,
WebSocket, SSE, and Alt-Svc tools launch through `browser_launch.py`, whose
longer flag list each of those fixtures records.

`chrome_http3.py` takes a fixed listen address, so its port came from a
loopback UDP socket bound to port 0 and then released; every other listener
bound port 0 itself. Fixture `listen_address` lines therefore hold the chosen
ephemeral port, and `trust-anchor-orders.txt`, which aggregates 60 separate
listeners, records `127.0.0.1:0`.

</details>

Retained fixtures, each under `fixtures/<area>/chrome/154.0.8037.58/windows-11-26200/`:

| Area | Files |
| --- | --- |
| `tls` | `client-hello.txt`, `trust-anchor-orders.txt`, `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| `http2` | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-{1,2}.txt` |
| `client-hints` | `navigation.txt` |
| `websocket` | Nine scenarios |
| `sse` | Seventeen scenarios and `launch-mode/` |
| `alt-svc` | Seven scenarios |

Limits:

- One Windows build, and one branded Chrome build. The macOS captures of
  this build cover client hints, request fields, and single parity runs
  ([macOS recipes](#macos-recipes)); no Linux capture exists. No Chrome for
  Testing build of it is published, so build flavor is not isolated at 154
  and there is no
  `*-chrome-for-testing` fixture. The Chrome for Testing 154 list ends at
  154.0.8037.57, a different build that would need its own version directory.
- `chromium::v154_tcp` rests on Chromium source at tag `154.0.8037.58`, not
  on a capture; see
  [TCP socket option evidence](#tcp-socket-option-evidence).
- `client-startup.txt` under `http3` is the only CRLF file under `fixtures/`,
  because `chrome_http3.py` printed it through Windows text-mode standard
  output. Its bytes and pinned SHA-256 are stable in the repository.
  `chrome_http3.py --output` writes LF on every platform, so a rerun that uses
  it would not reproduce that hash; see
  [Capture tools](../../scripts/capture/README.md#http3-startup).
- The comparison with Chrome 153 is recorded, not reproducible; see
  [Comparison with Chrome 153](#comparison-with-chrome-153).
- Launches are headless, except one headful client-hint run and five headful
  `retry-750` SSE runs.

### Edge 153 and Firefox 156 recipes

What is claimed: Edge 153.0.4234.48 matched the Chromium recipes as below,
which the [Edge 154 recipes](#edge-154-recipes) build on, and the
`firefox::v156_*` recipes reproduce Firefox 156.0, both on Windows 11.

Evidence: both are the builds installed on the Windows 11 capture host. Every
capture used a fresh profile, a loopback listener, and the launch flags of the
Chromium or Firefox fixture for the same layer. Edge ran without
`--disable-field-trial-config`.

| Browser and layer | Samples | Result against the Chromium recipes |
| --- | --- | --- |
| Edge 153.0.4234.48 TLS | 20 processes | The Chromium ClientHello without the trust-anchor IDs extension |
| Edge 153 QUIC ClientHello | 3 processes | The Chromium QUIC ClientHello without the trust-anchor IDs extension |
| Edge 153 H2 startup and request HEADERS | 1 raw startup, 3 H2 session runs | Equal to `chromium::v154_http2` |
| Edge 153 QUIC, H3 SETTINGS and request | 3 processes | Equal to `chromium::v154_quic`, `chromium::v154_http3`, and `chromium::v154_http3_request`; request fields equal except persona values |
| Edge 153 client hints | 3 runs (plus 1 headful) | The Chromium names, order, and delivery; Edge brand list and version values |
| Firefox 156.0 TLS | 12 processes | Its own fixed extension order and a 240-byte ECH GREASE payload |
| Firefox 156 H2 startup and request HEADERS | 3 retained H2 session runs, 6 connections | `m,p,a,s` pseudo-headers; non-exclusive parent 0 weight 42 |

The recipes follow from those results. `edge::v154_tls` and
`edge::v154_http3_tls` remove the trust-anchor IDs from the Chromium recipes.
The Chrome 153 and Chrome 154 ClientHellos differ only in that extension, so
the Edge captures replay against the surviving Chromium recipes unchanged.
Edge has no H2, QUIC, or H3 recipe of its own, because those layers equal the
Chromium recipes on every compared field. The Edge client hints carry
Edge's brand list and build values. The
complete Firefox set is `firefox::v156_tls`, `v156_http2`, `v156_websocket`,
`v156_tcp`, `v156_cookie_placement`, and the Firefox request templates.
Firefox sends no user-agent client hints, and no Firefox QUIC startup
capture backs a recipe. The only Firefox H3 captures are the
[QUIC resumption captures](#quic-resumption-and-0-rtt-evidence).

Edge's full version list reports `"Chromium";v="153.0.8010.53"`, a newer
Chromium build than the branded Chrome 153 that was captured at the time.
Headful and headless runs produced identical client hints for both browsers.

Firefox 156 kept its fixed extension order and chose AES-128-GCM on 7 and
ChaCha20-Poly1305 on 5 of 12 connections, each with a 240-byte payload. One
sample of each is retained.

The H2 request evidence reuses the navigation in the retained WebSocket session
fixtures (`fixtures/websocket/*/accept.txt`, recorded through
`http2_session.py`). Those fixtures already hold each navigation's SETTINGS,
WINDOW_UPDATE, HEADERS priority, and HPACK field order. No raw Firefox 156 H2
startup fixture was taken: the raw startup tool needs WebDriver certificate
trust for Firefox, and geckodriver is not installed on the host. The extended
CONNECT pseudo-header order and priority in those fixtures differ from the
navigation's and are carried by the WebSocket recipes and `v156_http2`.

The `edge_154_*` and `firefox_156_*` tests in `phantom-profile` and
`phantom-net` replay the Edge 154 and Firefox fixtures. TLS and QUIC
ClientHellos go through the public TLS and H3 connector paths, and H2 startup
frames through the public H2 path. H3, QUIC, H2 request, and client-hint fields are compared against the
recipe data.

How to reproduce: the TLS ClientHello (`capture_client_hello`), Edge H2
startup (`capture_http2_tls`), QUIC (`chrome_http3.py --client-hello`), and
client-hint (`client_hints.py`) tools are the ones in the
[Chrome capture commands](#capture-commands-and-launches), run once per fresh
browser process. Chromium TLS and H2 launches use the arguments recorded in
the retained Chrome fixtures, with `https://server.phantom.test:<port>/`.
Firefox TLS uses `--headless --no-remote --profile <temporary-profile>` with
`https://localhost:9446/`. Per-process samples beyond the retained ones are
not kept; the table gives their counts.

Retained fixtures, each under `fixtures/<area>/<browser>/<version>/windows-11-26200/`:

| Browser | Area | Files |
| --- | --- | --- |
| Edge 153.0.4234.48 | `tls` | `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt` |
| Edge 153.0.4234.48 | `http2` | `client-startup.txt` |
| Edge 153.0.4234.48 | `http3` | `resumption-streams-accept.txt`, `resumption-streams-reject.txt` |
| Edge 154.0.4258.37 | `tls` | `client-hello.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Edge 154.0.4258.37 | `http3` | `client-startup.txt`, `quic-client-hello-1.txt`, `quic-client-hello-2.txt`, `resumption-accept.txt`, `resumption-accept-delayed.txt`, `resumption-reject.txt` |
| Edge 154.0.4258.37 | `client-hints` | `navigation.txt` |
| Edge 154.0.4258.37 | `cookies` | `crumbs-h1.txt`, `crumbs-h2.txt`, `crumbs-h3.txt` |
| Edge 154.0.4258.37 | `websocket` | Nine scenarios; see [WebSocket browser evidence](#websocket-browser-evidence) |
| Edge 154.0.4258.37 | `proxy` | Twenty scenarios; see [Proxy route browser evidence](#proxy-route-browser-evidence) |
| Firefox 156.0 | `tls` | `client-hello.txt` (AES-128-GCM ECH GREASE), `client-hello-chacha20-ech.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Firefox 156.0 | `websocket` | Nine scenarios |
| Firefox 156.0 | `sse` | Seventeen scenarios |

Limits:

- One Windows build per browser. On macOS only Edge's client hints, both
  browsers' request fields, and single parity runs are captured; see
  [macOS recipes](#macos-recipes). No Linux capture exists.
- Headless launches only, except the headful client-hint check.
- Firefox 156 has no raw H2 startup fixture, so its SETTINGS and connection
  window rest on the H2 session captures rather than on raw startup bytes.

### Edge 154 recipes

What is claimed: the `edge::v154_*` recipes, with the Chromium recipes they
reuse, reproduce Edge 154.0.4258.37 on Windows 11. Edge 154 differs from
Edge 153.0.4234.48 only in its client hints.

Evidence: Edge updated itself on the Windows 11 capture host. Three
[fingerprint snapshots](#fingerprint-snapshot-evidence) of Edge 154 matched
the retained Edge 153 TCP and QUIC ClientHellos, H2 startup, first H2
navigation, and H3 SETTINGS, and differed only in the client hints:

| Hint | Edge 153.0.4234.48 | Edge 154.0.4258.37 |
| --- | --- | --- |
| `sec-ch-ua` | `"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"` | `"Chromium";v="154", "Microsoft Edge";v="154", "Not A(Brand";v="99"` |
| `sec-ch-ua-full-version` | `"153.0.4234.48"` | `"154.0.4258.37"` |
| `sec-ch-ua-full-version-list` | `"Microsoft Edge";v="153.0.4234.48", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53"` | `"Chromium";v="154.0.8037.58", "Microsoft Edge";v="154.0.4258.37", "Not A(Brand";v="99.0.0.0"` |

Every other hint and every field order equal Edge 153's. The recipes and
templates of Edge 153 therefore carry over, and only
`edge::v154_windows_client_hints` has new values.

Because the brand list appears in the request fields of the WebSocket, proxy
route, and H3 startup captures that the template and replay tests read, those
captures were taken again for Edge 154: one `run_matrix.py` manifest ran
`client_hints`, all nine `http2_websocket` scenarios, all twenty
`proxy_route` scenarios, `tls_resumption` `sequential`, `quic_resumption`
`accept`, `accept-delayed`, and `reject`, each once, and `startup_capture` at
the `http3` layer twice. All 35 jobs passed on the first attempt in 128
seconds of wall clock; the three snapshots took 7 seconds. The WebSocket,
proxy route, and all nine `tls_resumption` scenarios were then run again
with `repeat` 3, because the replay and capture tests count three runs per
scenario as for the other browsers; those 38 jobs took 313 seconds. The
three `cookie_crumbs` scenarios followed, three runs each, in 16 seconds.
`snapshot.py --split` wrote the TCP `client-hello.txt`. Against the Edge 153
files, the new ones differ in the brand values, timings, ports, and
connection counts, not in field order, frame shapes, HPACK or QPACK
representations, or settings. The TCP resumption summaries differ only in
how many connections a run opened; early data, ticket reuse, and the
position of `pre_shared_key` are unchanged.

No Edge 154 capture repeats the ECH, raw H2 startup, or
`resumption-streams-*` scenarios: ECH needs an administrator policy, and
the other two carry no brand value. Those Edge 153 fixtures stay, and the
tests that replay them name Edge 153.

The Mac's Edge was updated from 153.0.4234.48 to 154.0.4258.37 with the
signed app from Microsoft's official stable pkg, moved into `/Applications`
in place of the old bundle without an administrator password; the pkg
installer itself needs one. Three snapshots there matched the retained
macOS Edge 153 H2 navigation, QUIC ClientHello, and H3 SETTINGS, and
differed in the same client-hint values as on Windows. The macOS captures
of [macOS recipes](#macos-recipes) were then taken again for Edge 154 in 23
seconds: client hints and the `accept` and `h1-accept` WebSocket scenarios
three times each with `--accept-lang=en-US`, and one TLS `sequential` and
one H3 startup run. `edge::v154_macos_client_hints` differs from the Windows
hints only in the platform data.

Limits:

- On Windows, one run of the client hints and of each QUIC resumption
  scenario, and two H3 startups, where Edge 153 had three or five.
- The ECH behavior of `edge::v154_tls` and `edge::v154_http3_tls` rests on
  Edge 153 captures and on Edge 154 sending the same ClientHello without an
  HTTPS record.

### Brave 154 and Opera 135 recipes

What is claimed: the `brave::v154_*` recipes, with the Chromium recipes they
reuse, reproduce Brave 154.1.96.59, and the `opera::v135_*` recipes, with the
Chromium recipes they reuse, reproduce Opera 135.0.5973.92, both on Windows
11. Brave 154 is built on Chromium 154. Opera 135 reports Chromium
151.0.7922.176 in its client hints; Phantom carries no Chromium 151 recipe,
so every Opera capture is compared with the Chrome 154 recipes.

Evidence: both are the builds installed on the Windows 11 capture host,
read from the file versions of `brave.exe` and of Opera's versioned
`opera.exe`. Brave had updated from 153.1.95.104, which the roadmap named,
before these captures. Every capture used a fresh profile, a loopback
listener, and the launch flags of the retained Chrome 154 fixture for the
same layer, with `--browser brave` or `--browser opera` in the Python tools.

| Browser and layer | Samples | Result against the Chromium recipes |
| --- | --- | --- |
| Brave TLS | 20 processes | The Chrome 154 ClientHello without the trust-anchor IDs extension |
| Opera TLS | 19 of 20 processes | The Chrome 154 ClientHello without trust-anchor IDs and without a GREASE value in `signature_algorithms` |
| Brave and Opera QUIC ClientHello | 3 processes each | The Chrome 154 QUIC ClientHello without trust-anchor IDs |
| Brave and Opera H2 startup | 3 raw startups each | Byte-identical to the Chrome 154 SETTINGS and WINDOW_UPDATE frames |
| Brave and Opera H2 request HEADERS, pseudo-header order, priority, HPACK | 3 H2 session runs each | Equal to `chromium::v154_http2` |
| Brave and Opera QUIC transport parameters, H3 SETTINGS, H3 pseudo-header order | 3 processes each | Equal to `chromium::v154_quic`, `chromium::v154_http3`, and `chromium::v154_http3_request` |
| Brave client hints | 3 runs (plus 1 headful) | The Chromium names, order, and delivery without `sec-ch-ua-full-version` and `sec-ch-ua-form-factors`; every version reduced to `154.0.0.0` or `99.0.0.0` |
| Opera client hints | 3 runs (plus 1 headful) | The Chromium names, order, and delivery; Opera brand list and version values |
| Brave request fields | 9 WebSocket scenarios, 20 proxy scenarios, H3 startup | Chromium order, plus `Sec-GPC: 1` after `Accept`; `Accept` without signed exchanges; `Accept-Language` q value drawn per session |
| Opera request fields | Same | Equal to the Chromium templates except `User-Agent` and brand values |
| WebSocket openings and connection choice | 9 scenarios, 3 runs each | Equal to `chromium::v154_websocket` |
| Proxy CONNECT fields | 20 proxy scenarios, 3 runs each | Equal to `chromium::v154_proxy_connect` |
| Brave ECH from an HTTPS record | 1 `accept` and 1 `reject` run | Chrome 154's outer extension fields; one retry with the server's configuration after a rejection |
| Brave ECH over QUIC | 3 `accept` and 3 `reject` runs | Chrome 154's outer QUIC fields without trust-anchor IDs; no QUIC connection after a rejection |

The recipes follow from those results. `brave::v154_tls` and
`brave::v154_http3_tls` remove the trust-anchor IDs from the Chromium
recipes, and both keep `ech_from_https_records`.
`opera::v135_tls` also clears `grease_signature_algorithms`;
`opera::v135_http3_tls` removes only the IDs, since the Chromium QUIC offer
has no signature algorithm GREASE. Neither browser has an H2, QUIC, H3,
WebSocket, or proxy CONNECT recipe of its own, because those layers equal
the Chromium recipes on every compared field. The client-hint recipes and
request templates carry the brand lists and the differences in the table.

Brave's `Accept-Language` is the one request value that no literal can
match. The sample is the 87 runs of the Brave WebSocket and proxy route
fixtures (9 and 20 scenarios, three runs each). Brave sent `en-US,en;q=`
followed by `0.5`, `0.6`, `0.7`, `0.8`, or `0.9`: one value on every request
of a run, varying between runs, with all five values present. Brave's templates therefore make
`Accept-Language` a required caller slot, as the Edge, Brave, and Opera
templates do for `User-Agent`: every retained capture of these browsers ran
headless and sent `HeadlessChrome`, and the one headful client-hint run
per browser was not retained. `Sec-GPC: 1` appears on every Brave page
request and `fetch()`, to loopback and named plaintext origins alike, and on
no WebSocket opening.

Opera needed a different launch for two layers. At startup it opens a
preconnect to the page's origin, then logs `Cert verifier changed` and
abandons every open connection. The raw H2 and QUIC capture tools serve only
their first connection, so with the page URL on the command line they saw
the abandoned preconnect and no request. (A diagnostic Opera NetLog run
showed the preconnect session and the
`QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY` event. It was not
retained and backs no claim; it only explained the failed captures.) The
retained Opera H2 and H3 startups were therefore taken by
`startup_capture.py --navigate devtools`, which starts Opera on
`about:blank` with `--remote-debugging-port=0` and calls `Page.navigate` over
DevTools five seconds later; their `launch_mode` is `devtools-navigate`.

The DevTools launch does not change what the page's connection sends. One
Brave H3 run taken the same way is retained under
`fixtures/http3/brave/154.1.96.59/windows-11-26200/launch-mode/`
(`client-startup-devtools.txt` and `quic-client-hello-devtools.txt`, 1
process). `brave_154_devtools_launch_sends_the_command_line_h3_startup`
compares its H3 SETTINGS and request fields, apart from `:authority`, with
Brave's command-line startup, and the Brave QUIC tests replay its transport
parameters and ClientHello against the same recipes as the command-line
runs. The TLS capture tool records only the
first ClientHello, which for Opera may be the startup preconnect's; one of
the 20 Opera processes closed its connection before a ClientHello completed.
In two Opera `refused-stream` WebSocket runs, Opera had closed the page's H2
session before opening the socket, so it opened an HTTP/1.1 Upgrade
connection, which the Chromium policy also chooses without a session, and no
stream was refused.

In the resumption captures every later Brave and Opera connection resumed
and offered early data, and the resumed ClientHellos match Phantom's for each
recipe. Brave's second navigation in `accept` arrived in 0-RTT in all 5 runs
where Chrome's and Opera's arrived in 1-RTT; Phantom does not model the
preconnect timing that decides this (see
[QUIC resumption and 0-RTT evidence](#quic-resumption-and-0-rtt-evidence)).

Opera sent no DNS-over-HTTPS query with the `chrome_ech.py` preferences, as
Edge 153 did not, so no capture shows whether Opera uses an HTTPS record's
`ech`. `opera::v135_tls` leaves `ech_from_https_records` unset and keeps ECH
GREASE, which every Opera ClientHello carried.

Tests: the `brave_154_*` and `opera_135_*` tests in `phantom-profile` and
`phantom-net`, and the Brave and Opera cases of the Chromium tests, replay
these fixtures. TLS and QUIC ClientHellos go through the public TLS and H3
connector paths, H2 startup frames through the public H2 path, and Brave's
ECH outer ClientHello through the ECH connector. Request templates are sent
by the `phantom` client in the `requests` test binary's
`request_templates.rs` and `plaintext_templates.rs` and the `proxies`
binary's `proxy_field_order.rs` and `proxy_h2.rs`, all under
`crates/phantom/tests/`, and compared with the captured requests.
`brave_154_accept_language_is_one_drawn_value_per_session` checks the
`Accept-Language` observations above on all 87 runs.

How to reproduce: the Python tools take `--browser brave` or
`--browser opera` with the executable paths in
[Capture tools](../../scripts/capture/README.md#browser-launcher). The TLS,
H2, and QUIC startups come from
[`startup_capture.py`](../../scripts/capture/README.md#connection-startup-launches),
once per fresh process:

| Fixture | Command arguments after `--browser <name> --browser-path <path> --client-version <version> --operating-system "Windows 11 Home 10.0.26200 x64"` |
| --- | --- |
| Brave and Opera `tls` | `--layer tls --repeat 20` |
| Brave `http2` | `--layer http2 --repeat 3` |
| Brave `http3` | `--layer http3 --repeat 3` |
| Brave `http3`, `launch-mode/` files | `--layer http3 --navigate devtools` |
| Opera `http2` | `--layer http2 --navigate devtools --repeat 3` |
| Opera `http3` | `--layer http3 --navigate devtools --repeat 3` |

`startup_capture.py` was committed after these captures. They came from a
scratch script that ran the same listeners with the same launch arguments;
`test_startup_capture.py` checks that the tool records exactly the
`launch_arguments` and `launch_mode` of every retained Brave and Opera
startup fixture, and one run of each Opera DevTools layer and of Brave TLS,
repeated with the committed tool, matched the retained fixtures on every
compared field. The other layers use `client_hints.py --repeat 3`,
`http2_websocket.py --scenario all --repeat 3`,
`proxy_route.py --scenario all --repeat 3`, `quic_resumption.py` as in its
section, and `chrome_ech.py --scenario accept` and `reject`, without and
with `--quic`.

Retained fixtures, each under `fixtures/<area>/<browser>/<version>/windows-11-26200/`:

| Browser | Area | Files |
| --- | --- | --- |
| Brave 154.1.96.59 | `tls` | `client-hello.txt`, `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Opera 135.0.5973.92 | `tls` | `client-hello.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Both | `http2` | `client-startup.txt` |
| Both | `http3` | `client-startup.txt`, `quic-client-hello-{1,2}.txt`, `resumption-accept.txt`, `resumption-accept-delayed.txt`, `resumption-reject.txt` |
| Brave 154.1.96.59 | `http3` | `launch-mode/client-startup-devtools.txt`, `launch-mode/quic-client-hello-devtools.txt` |
| Both | `client-hints` | `navigation.txt` |
| Both | `websocket` | Nine scenarios |
| Both | `proxy` | Twenty scenarios |

Limits:

- One Windows build per browser. Opera's macOS captures cover client hints,
  request fields, and single runs of the other layers
  ([macOS recipes](#macos-recipes)); Brave has none, and no Linux capture
  exists.
- Every retained capture ran headless. One headful client-hint run per
  browser matched the headless runs, but it was not retained.
- No TCP, HTTP/1.1 connection, address cache, or cookie placement recipe.
  Socket options and connection counts are not visible in these captures.
  Brave's source is public and could back them after a source reading at
  its release tag; Opera's network source is not public.
- No SSE or Alt-Svc racing capture exists for either browser.
- The Opera comparison is with Chrome 154, not with a Chromium 151 build.
- Opera's H2 and H3 startups were launched through DevTools; its TLS
  ClientHello may be the startup preconnect's.

### macOS recipes

What is claimed: `chromium::v154_macos_client_hints`,
`edge::v154_macos_client_hints`, `opera::v135_macos_client_hints`, the
Chrome templates `chromium::v154_macos_navigation_template` and
`chromium::v154_macos_fetch_no_store_template`, and the Firefox templates
`firefox::v156_macos_navigation_template` and
`firefox::v156_macos_fetch_no_store_template` reproduce what those browsers
send on macOS 15.5 on Apple silicon. On macOS, Opera 135 sends the fields
of its Windows request templates with the macOS client hints, and Edge 154
does too with its language list set to `en-US`; for another locale, override
`Accept-Language`. So neither has a separate macOS template. Every other
layer of these browsers is the Windows recipe, and the replay tests compare
it with the single macOS runs listed below.

Evidence: the capture host is a MacBook Air (M4) on macOS 15.5 (24F74). It
ran Chrome 154.0.8037.58 as installed, Edge 154.0.4258.37 from Microsoft's
stable pkg (see [Edge 154 recipes](#edge-154-recipes)), Opera
135.0.5973.92 from Opera's release archive installed over the older
135.0.5973.66, and Firefox 156.0 from Mozilla's release archive. Each
archive's checksum and Developer ID signature were checked. Every run was
headless, on a fresh profile in a throwaway directory, against a listener
on 127.0.0.1. Chromium launches on macOS add `--use-mock-keychain`
([Browser launcher](../../scripts/capture/README.md#browser-launcher)).

| Browser and layer | Samples | Result |
| --- | --- | --- |
| Chrome, Edge, Opera client hints | 3 runs each | Windows names, order, delivery, and brand values; `sec-ch-ua-platform` `"macOS"`, `sec-ch-ua-platform-version` `"15.5.0"`, `sec-ch-ua-arch` `"arm"`; `sec-ch-ua-bitness` `"64"` and `sec-ch-ua-wow64` `?0` as on Windows |
| Chrome, Edge, Opera page loads and no-store `fetch()` over H1 and H2 | 3 runs each | The Windows template fields and values. `User-Agent` is a caller slot in every macOS Chromium-family template, and the headless value names `Macintosh; Intel Mac OS X 10_15_7` |
| Chrome, Opera H3 page request | 1 startup each | The Windows template's H3 fields |
| Firefox page loads and no-store `fetch()` over H1 and H2 | 3 runs | The Windows template, with `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:156.0) Gecko/20100101 Firefox/156.0` |
| Chrome, Edge, Opera, Firefox resumed TCP ClientHello | 1 `tls_resumption.py --scenario sequential` run each | The shape of the TLS recipe's resumed ClientHello, as for the Windows captures (`phantom-net` `tls::tests::resumption`) |
| Chrome, Edge, Opera, Firefox H2 session | 3 page loads each | The H2 recipe's SETTINGS, WINDOW_UPDATE, priority, pseudo-header order, and static-name choice |
| Chrome, Edge, Opera QUIC ClientHello and H3 startup | 1 startup each | `chromium::v154_quic` and the Chromium H3 control stream; Chrome's and Opera's H3 request fields equal their Windows startups apart from persona fields |

On macOS the page's final `fetch()` sometimes opened a new H2 connection,
where on Windows it reused the page's connection. The H2 session replay
therefore takes the connection whose first request is the document.

Edge on macOS takes `Accept-Language` from the system's language list and
ignores `--lang`. On the capture host that list gave
`en-CA,en-US;q=0.9,en;q=0.8`. The Edge client-hint and WebSocket captures
therefore ran with `--accept-lang=en-US`, passed through `--browser-switch`,
and sent the Windows value `en-US,en;q=0.9`. The Edge H3 startup ran with
the shared startup launch arguments and sent the system value, so only its
field names are compared.

Capture commands, from the repository root on the Mac, with `TMPDIR` set to
a scratch directory:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.client_hints \
  --browser edge \
  --browser-path "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
  --client-version 154.0.4258.37 \
  --operating-system "macOS 15.5 (24F74) arm64" \
  --browser-switch=--accept-lang=en-US --repeat 3 \
  --output fixtures/client-hints/edge/154.0.4258.37/macos-15.5-arm64/navigation.txt
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.http2_websocket \
  --browser edge \
  --browser-path "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
  --client-version 154.0.4258.37 \
  --operating-system "macOS 15.5 (24F74) arm64" \
  --browser-switch=--accept-lang=en-US \
  --scenario accept h1-accept --repeat 3 \
  --output-dir fixtures/websocket/edge/154.0.4258.37/macos-15.5-arm64
```

Chrome and Opera ran the same commands with
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` and
`/Applications/Opera.app/Contents/MacOS/Opera` and no switch, and Firefox
with `Firefox-156.0.app/Contents/MacOS/firefox`. The single runs used
`tls_resumption.py --scenario sequential --repeat 1` for all four browsers
and `startup_capture.py --layer http3 --repeat 1` for the Chromium browsers,
with `--navigate devtools` for Opera.

Retained fixtures, under `<area>/<browser>/<version>/macos-15.5-arm64/`:

| Browser | Area | Files |
| --- | --- | --- |
| Chrome 154.0.8037.58, Edge 153.0.4234.48, Opera 135.0.5973.92 | `client-hints` | `navigation.txt` |
| Chrome, Edge, Opera | `websocket` | `accept.txt`, `h1-accept.txt` |
| Chrome, Edge, Opera | `tls` | `resumption-sequential.txt` |
| Chrome, Edge, Opera | `http3` | `client-startup.txt`, `quic-client-hello-1.txt` |
| Firefox 156.0 | `client-hints` | `navigation.txt`, with no hints |
| Firefox 156.0 | `websocket` | `accept.txt`, `h1-accept.txt` |
| Firefox 156.0 | `tls` | `resumption-sequential.txt` |

Limits:

- One macOS build on one Apple silicon Mac. Intel Macs and other macOS
  versions are not captured; `sec-ch-ua-arch` and
  `sec-ch-ua-platform-version` carry this host's values.
- Every capture ran headless, so no Chromium-family `User-Agent` literal is
  claimed for macOS.
- The TCP, QUIC, H3, and resumption runs are single samples. SSE, Alt-Svc,
  proxy, cookie, and ECH behavior is not captured on macOS.
- Keepalive timing on macOS rests on Chromium source, as
  [TCP socket option evidence](#tcp-socket-option-evidence) records; no
  capture measured it.

### Chrome for Android 154 recipes

What is claimed: the `chrome_android::v154_*` recipes reproduce Google Chrome
154.0.8037.57 for Android, as captured on the Android 17 emulator described
below.

Evidence: Chrome 154.0.8037.57 is the build the Google Play Store served to
the `phantom-pixel7` emulator on 2026-09-26. The emulator runs the Android 17
(API 37) Google Play x86_64 system image, build `CE2A.260420.019`, on the
Windows 11 capture host. It is rooted with Magisk v30.7, and a Magisk module
sets the build properties of a Pixel 7: model `Pixel 7`, fingerprint
`google/panther/panther:17/CP3A.260905.009/16091614:user/release-keys`, and
security patch 2026-09-05. Wi-Fi is its only network, with mobile data off.

That identity is one a Pixel 7 reports. Google's factory image list
(<https://developers.google.com/android/images>, section `"panther" for
Pixel 7`, read on 2026-09-26) ends with these entries:

```text
16.0.0 (CP1A.260405.005, Apr 2026)
16.0.0 (CP1A.260405.005.B1, Apr 2026, Telia)
17.0.0 (CP2A.260605.012, Jun 2026)
17.0.0 (CP2A.260705.006, Jul 2026)
17.0.0 (CP3A.260905.009, Sep 2026)   panther-cp3a.260905.009-factory-2eb27508.zip
```

Pixel binary transparency
(<https://developers.google.com/android/binary_transparency/image_info.txt>)
logs Android 17 images under the system fingerprint
`google/generic_system_google/generic:17/CP3A.260905.009/16091614:user/release-keys`,
whose build ID and incremental the module's `panther` fingerprint carries.

[Android browsers](../../scripts/capture/README.md#android-browsers)
describes how each run clears Chrome's app data, passes switches through the
command-line file, and opens the page.

Two entry methods were used, and each fixture records its own:
`android-typed` types the URL into the address bar, as a person does, and
`android-intent` opens it with a `VIEW` intent. A page opened by intent has no
user activation and comes from another app, so Chrome omits `Sec-Fetch-User`
and sends `Sec-Fetch-Site: cross-site`; the request templates therefore rest
on typed captures only. The TLS, HTTP/2 startup, QUIC, QUIC resumption,
WebSocket opening, and plaintext-trust layers do not depend on how the page
was opened: every request their recipe tests compare comes from the page's
own script, and no WebSocket opening carries a `Sec-Fetch-*` field. The
intent captures record the page load too, but no test compares it.

| Layer | Samples | Result against the desktop Chrome 154 recipes |
| --- | --- | --- |
| TLS ClientHello | 1 intent process | Equal to `chromium::v154_tls` on every compared field, the 28 trust-anchor IDs in sorted order included |
| HTTP/2 startup | 1 intent process | Byte-identical to the Chrome 154 startup: SETTINGS, their order, the connection WINDOW_UPDATE, and the empty ALPS payload |
| QUIC ClientHello, QUIC and H3 startup | 1 intent process | The ClientHello equals `chromium::v154_http3_tls`, sorted trust-anchor IDs included; the transport parameters equal `chromium::v154_quic`; the H3 SETTINGS and QPACK stream prefixes equal `chromium::v154_http3`. The request fields equal Chrome 154's apart from persona values, the missing `Sec-Fetch-User`, and `Sec-Fetch-Site: cross-site` |
| Client hints | 3 typed runs | The same eleven names, order, and `default` or `accept-ch` delivery as `chromium::v154_windows_client_hints`; Android persona values |
| WebSocket `accept` and `h1-accept` | 3 typed runs each | Every page load and no-store `fetch()` equals the Android templates on HTTP/1.1 and HTTP/2 |
| WebSocket openings, the other 7 scenarios | 3 intent runs each | With `accept` and `h1-accept`, equal to `chromium::v154_websocket` and `chromium::v154_http2` on every compared field, with the same connection choices and counts as desktop Chrome: 15 openings on the page's H2 session, 6 HTTP/1.1 Upgrades, and 3 refused streams retried once |
| QUIC resumption | 3 intent runs each of `accept` and `reject` | Every later connection resumed, offered early data, and added `early_data` and a final `pre_shared_key`, and unsafe methods stayed in 1-RTT, as on Windows. Unlike the Windows runs, the `/navigate` GET travelled in 0-RTT in all three `accept` runs |
| Plaintext trust | 3 intent runs each of `direct-loopback` and `direct-hostname` | Every `ws://` opening equals the Chromium WebSocket template for its origin's trust: `Accept-Encoding: gzip, deflate, br, zstd` to `127.0.0.1`, and `gzip, deflate` to `origin.phantom.test` |

Chrome 154 contains Chromium commit `942bda4298c1`, which sorts the
trust-anchor list. The unsorted, per-transport orders that Chrome 153 for
Android sent therefore no longer apply to any recipe.

Persona values: `User-Agent` is Chrome's reduced Android string,
`Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/154.0.0.0 Mobile Safari/537.36`, on every request. `sec-ch-ua` is
`"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`,
`sec-ch-ua-mobile` is `?1`, and `sec-ch-ua-platform` is `"Android"`. After
`Accept-CH`, Chrome adds platform version `"17.0.0"`, model `"Pixel 7"`, an
empty architecture and bitness, and form factor `"Mobile"`.
`v154_android_client_hints()` sends the captured model, and
`v154_android_client_hints_for_model` sends another; only the Pixel 7 value
is captured.

`v154_tls` and `v154_http3_tls` are the Chromium recipes with
`ech_from_https_records` off. The H2, QUIC, H3, H3 request, and WebSocket
functions return the Chromium recipes. The templates change only
`User-Agent` in the Chromium templates. The H3 startups were opened by
intent, so the H3 lists in the templates are the Chromium ones.
`chrome_android_154_h3_capture_matches_the_chromium_recipe` compares the
Android H3 request with the Chrome 154 Windows one, apart from persona
values and the two intent fields.

Replay tests: the `chrome_android_154_*` tests replay the TLS, QUIC, H2, H3,
and client-hint captures through the recipes, and the `phantom-net` TLS,
HTTP/2, and HTTP/3 connector tests replay them on the wire.
`android_17_navigation_matches_every_captured_page_request` compares every
captured page load with its template, and the facade tests
`chrome_android_navigation_sends_the_captured_page_request` and
`chrome_android_fetch_sends_the_captured_report_request` send the templates
over HTTP/1.1 and HTTP/2 and compare the result with the captures.

These three layers replaced Chrome 153.0.8010.52 captures from an Android 15
(API 35) emulator, taken by typed entry. Against them, Chrome 154 changed
nothing the recipes model. The WebSocket openings had the same outcome, close
code, extensions, and connection count in every run, except that one Chrome
153 `reject-403` run opened no spare H2 connection; which of the two H2
connections carried the page varied between runs in both builds. In QUIC
resumption, Chrome 153 split some requests across 0-RTT and 1-RTT packets
and sent more of the concurrent safe requests in 0-RTT; no Chrome 154 request
was split. The plaintext `ws://` openings and default-mode `fetch()` requests
had the same fields; the page loads differ only by the intent's missing
`Sec-Fetch-User` and `Sec-Fetch-Site: cross-site`.

#### Network type and `initial_rtt_us`

This finding comes from Chrome 153 and Brave 153 for Android on the Android
15 emulator. That emulator offered a Wi-Fi network and a cellular (HSPA)
one, and Android picks the default. With Wi-Fi as the default, no fresh QUIC
connection of Chrome or Brave for Android sent `initial_rtt_us` (`0x3127`),
as on Windows: Brave's Wi-Fi startup retained from that emulator,
`http3/brave-android/153.1.95.104/android-35-emulator/client-startup.txt`,
and 6 fresh connections taken with mobile data switched off (`svc data disable`) to check this. With the
cellular network as the default, which the emulator chose after a restart,
every fresh connection sent it, set to 400000 microseconds: 13 of 13 Chrome
and 12 of 12 Brave startups. Two Chrome startups before the restart sent it
too, with no record of the default network at the time.

The recipes model Wi-Fi: `chromium::v154_quic` sends `initial_rtt_us` only
on a resumed connection. `network/client-startup-cellular.txt` under
`http3/chrome-android/153.0.8010.52/android-35-emulator/` retains one
cellular Chrome startup, and
`chrome_android_153_cellular_startup_adds_only_initial_rtt` checks that it
holds the recipe's fresh-connection parameters plus that one. Every Android 17 capture ran
with Wi-Fi only and mobile data off.

#### Chrome for Android capture commands

How to reproduce: start the emulator and pass the Android browser names as
the [capture README](../../scripts/capture/README.md#android-browsers)
describes. Every fixture records its launch arguments, which are the switches
written to Chrome's command-line file followed by the page URL.

| Capture | Command |
| --- | --- |
| TLS ClientHello | `capture_client_hello` on a free loopback port, then the browser opened by intent through the Android launcher with `--disable-quic`, `--host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost`, and `--ignore-certificate-errors` |
| HTTP/2 startup | `capture_http2_tls` with the same launch |
| QUIC ClientHello and H3 startup | `chrome_http3.py --client-hello --output`, with the browser opened by intent through the launcher with `--enable-quic`, `--origin-to-force-quic-on`, a port-qualified `--host-resolver-rules`, and the certificate's `--ignore-certificate-errors-spki-list` |
| Client hints | `client_hints.py --browser chrome-android --repeat 3` |
| WebSocket page and `fetch()` requests | `http2_websocket.py --browser chrome-android --scenario accept h1-accept --repeat 3` |
| WebSocket openings | `http2_websocket.py --browser chrome-android --android-entry intent --scenario accept-deflate extension-mismatch fresh-origin h1-accept-deflate no-connect-protocol refused-stream reject-403 --repeat 3` |
| QUIC resumption | `quic_resumption.py --browser chrome-android --android-entry intent --scenario accept reject --repeat 3` |
| Plaintext trust | `proxy_route.py --browser chrome-android --android-entry intent --scenario direct-loopback direct-hostname --repeat 3` |

`android_run.py --entry intent` performs the same intent launch for a
listener. The launcher rewrites `127.0.0.1` in `--host-resolver-rules` to
`10.0.2.2`, the emulator's route to host loopback, and adds `adb reverse`
for a URL on the device's own `127.0.0.1`. The Android 17 captures of Chrome,
Brave, and Opera took about 29 minutes of wall-clock time on the Windows
host; the typed entries took most of it. The intent captures of QUIC
resumption, plaintext trust, and the seven WebSocket scenarios took about 3
minutes. That time covers 39 runs: 6 QUIC resumption and 6 plaintext-trust
runs, and 3 runs of each of the 7 WebSocket scenarios. Adding the 6 typed runs
of `accept` and `h1-accept`, 45 Chrome 154 runs back these three layers.

Retained fixtures under
`fixtures/<area>/chrome-android/154.0.8037.57/android-17-pixel7-emulator/`:

| Area | Files |
| --- | --- |
| `tls` | `client-hello.txt` |
| `http2` | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-1.txt`, `resumption-accept.txt`, `resumption-reject.txt` |
| `client-hints` | `navigation.txt` |
| `websocket` | Nine scenarios |
| `proxy` | `direct-loopback.txt`, `direct-hostname.txt` |

The Chrome 153 cellular startup stays under
`fixtures/http3/chrome-android/153.0.8010.52/android-35-emulator/network/`.

Limits:

- An emulator, not a phone. The Magisk module changes what the device
  reports, not its hardware: the CPU is x86_64 with AES instructions, where
  phones run ARM cores, and the device ran on a busy Windows host. No
  capture from a real device checks any of these recipes.
- The emulator's network ends the guest's TCP connections and opens new ones
  from the host, so no TCP option, SYN, or keepalive is visible, and there is
  no `chrome_android` TCP, HTTP/1.1 connection, or address-cache recipe.
- No capture shows Chrome for Android using an HTTPS record's `ech`, because
  the device cannot be given a DNS-over-HTTPS resolver as the desktop capture
  was, so `ech_from_https_records` is off.
- No proxy, SSE, or Alt-Svc racing capture exists for Android, so there is no
  `chrome_android` proxy CONNECT or cookie-placement recipe. No Android
  capture carries a cookie either: the H2 and H3 recipes split `cookie` into
  crumbs as the desktop cookie captures show, which no Android capture
  checks.
- One Play-served build, sampled by one process per transport layer.
- The cellular `initial_rtt_us` finding rests on one Chrome 153 startup from
  the Android 15 emulator; Chrome 154 was captured on Wi-Fi only.

### Brave for Android 153 recipes

What is claimed: the `brave_android::v153_*` recipes reproduce Brave 1.95.104
for Android, built on Chromium 153, as captured on the Android 17 emulator of
the [Chrome for Android section](#chrome-for-android-154-recipes) and, for
some layers, on the Android 15 emulator used before it. Fixtures name the
build `153.1.95.104`, the desktop form, because Android reports only
`1.95.104`.

Evidence: Brave 1.95.104 is the build the Play Store served to the Android
15 emulator on 2026-09-25 and to the Android 17 emulator on 2026-09-26.
Brave for Android reads Chrome's command-line file, so the Chrome launches,
switches, and tools apply unchanged; a cleared Brave profile shows no
first-run screen.

| Layer | Emulator | Samples | Result |
| --- | --- | --- | --- |
| TLS ClientHello | Android 17 | 1 intent process | Equal to the desktop Brave 154 ClientHello (`brave::v154_tls`): no trust-anchor IDs, and every other compared field, ECH GREASE included |
| HTTP/2 startup | Android 15 | 3 intent processes | Byte-identical to the Chrome 154 and Brave 154 startups |
| QUIC ClientHello, QUIC and H3 startup | Android 17 | 1 intent process | Equal to `brave::v154_http3_tls`, `chromium::v154_quic`, `chromium::v154_http3`, and `chromium::v154_http3_request` |
| H3 startup | Android 15 | 1 typed process | The typed H3 page request that `brave_android_navigation_sends_the_captured_page_request` reproduces |
| QUIC resumption | Android 15 | 3 typed runs each of `accept` and `reject` | `reject` equals desktop Brave's summary. In `accept`, every later connection resumed and offered early data; a few concurrent requests went in 1-RTT, where desktop Brave sent them in 0-RTT |
| Client hints | Android 17 | 3 typed runs | The desktop Brave names, order, and delivery (no `sec-ch-ua-full-version` or `sec-ch-ua-form-factors`); Android values, platform version `"17.0.0"`, an empty model, and versions reduced to `.0.0.0` |
| WebSocket `accept` and `h1-accept` | Android 17 | 3 typed runs each | Every page load and no-store `fetch()` equals the Brave for Android templates |
| Request fields | Android 15 | 9 WebSocket scenarios and 2 direct proxy-route scenarios, 3 typed runs each | The desktop Brave differences from Chrome: `Accept` without signed exchanges, `Sec-GPC: 1` after `Accept`, and an `Accept-Language` `q` value drawn per session (all five values from `0.5` to `0.9` appear, one per run) |
| WebSocket openings | Android 15 | 9 scenarios, 3 runs each | Equal to `chromium::v154_websocket` with the same connection choices and counts as Chrome |

Between the two emulators, the only client-hint value that changed was the
platform version, from `"15.0.0"` to `"17.0.0"`; the model stayed empty.

`brave_android::v153_tls` is `brave::v154_tls` with
`ech_from_https_records` off, for the reason given for Chrome for Android,
and `v153_http3_tls` is `brave::v154_http3_tls` with the same change. The H2, QUIC, H3, and WebSocket
functions return the Chromium recipes. The templates apply desktop Brave's
changes to the Chromium templates with Chrome's reduced Android
`User-Agent`, which Brave sent on every request; `Accept-Language` stays a
caller slot.

How to reproduce: the commands of the
[Chrome for Android capture commands](#chrome-for-android-capture-commands)
with `--browser brave-android`.

Retained fixtures under `fixtures/<area>/brave-android/153.1.95.104/`:

| Area | `android-17-pixel7-emulator/` | `android-35-emulator/` |
| --- | --- | --- |
| `tls` | `client-hello.txt` | None |
| `http2` | None | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-1.txt` | `client-startup.txt`, `resumption-accept.txt`, `resumption-reject.txt` |
| `client-hints` | `navigation.txt` | None |
| `websocket` | `accept.txt`, `h1-accept.txt` | Nine scenarios |
| `proxy` | None | `direct-loopback.txt`, `direct-hostname.txt` |

Limits: those of Chrome for Android, and one Brave build, which Play served
while its desktop build was 154.

### Edge for Android 153 recipes

What is claimed: the `edge_android::v153_*` recipes reproduce Microsoft Edge
153.0.4234.49 for Android, as captured on an arm64 Android 17 emulator that
reports a Pixel 7.

Evidence: Play serves Edge for Android only as an arm64 build, which cannot
start on the x86_64 emulator. Edge was therefore captured on 2026-09-26 on
`phantom-pixel7-arm`, an emulator on an Apple silicon Mac that runs the same
Android 17 build as an arm64-v8a image, with the same Magisk module, Wi-Fi
only and mobile data off. Edge for Android reads Chrome's command-line file,
so the Chrome launches, switches, and tools apply unchanged.

The Edge TLS ClientHello and H2 startup listeners, the Rust examples, ran on
the Windows host. The emulator reached them at `10.0.2.2`, the Mac's
loopback, through an `ssh -R` forward of the Mac's loopback port to the
Windows host. The forward passes the TCP stream bytes unchanged, so the
ClientHello and H2 frames are the browser's. The QUIC, H3, client-hint, and
WebSocket tools ran on the Mac. The Edge captures took about 15 minutes of
wall-clock time there.

| Layer | Samples | Result |
| --- | --- | --- |
| TLS ClientHello | 3 intent processes | Each equals `edge::v154_tls`, the desktop Edge ClientHello that Edge 153 and 154 send alike: the Chromium ClientHello without trust-anchor IDs |
| HTTP/2 startup | 1 intent process | Byte-identical to the Chrome 154 startup |
| QUIC ClientHello, QUIC and H3 startup | 1 intent process | Equal to `edge::v154_http3_tls`, `chromium::v154_quic`, `chromium::v154_http3`, and `chromium::v154_http3_request`. The request fields are as for Chrome for Android opened by intent: no `Sec-Fetch-User`, and `Sec-Fetch-Site: cross-site` |
| Client hints | 3 typed runs | The Chromium names, order, and delivery; desktop Edge 153's brand list, `"Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153"`, full version `"153.0.4234.49"`, and a full version list with Chromium `153.0.8010.53`; `?1`, `"Android"`, platform version `"17.0.0"`, model `"Pixel 7"`, an empty architecture and bitness, and form factor `"Mobile"` |
| WebSocket `accept` and `h1-accept` | 3 typed runs each | Every page load and no-store `fetch()` equals the Edge for Android templates |

`User-Agent` is `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36 EdgA/153.0.0.0` on
every request. The captures ran with a visible browser, so the templates
carry this literal value, where the headless desktop Edge templates leave
`User-Agent` to the caller.

`v153_tls` and `v153_http3_tls` are desktop Edge's recipes with
`ech_from_https_records` off. `v153_http2`, `v153_quic`, `v153_http3`, and
`v153_http3_request` return the Chromium recipes.
`v153_android_client_hints()` sends the captured model, and
`v153_android_client_hints_for_model` sends another. The templates change
only `User-Agent` in the Chromium templates; their H3 lists are the Chromium
ones, as for Chrome for Android.

Replay tests: `edge_android_153_tls_recipe_matches_every_android_capture`,
`edge_android_153_quic_client_hello_recipe_matches_android_capture`,
`edge_android_153_http2_recipe_matches_android_capture`,
`edge_android_153_http2_session_capture_matches_the_chromium_recipe`,
`edge_android_153_quic_capture_matches_the_chromium_recipe`,
`edge_android_153_h3_capture_matches_the_chromium_recipe`,
`edge_android_153_client_hints_match_navigation_capture`, and
`edge_android_153_templates_change_only_the_user_agent`. The facade tests
`edge_android_navigation_sends_the_captured_page_request` and
`edge_android_fetch_sends_the_captured_report_request` send the templates
over HTTP/1.1 and HTTP/2 and compare the result with the captures.

How to reproduce: the commands of the
[Chrome for Android capture commands](#chrome-for-android-capture-commands)
with `--browser edge-android`, on an arm64 emulator.

Retained fixtures under
`fixtures/<area>/edge-android/153.0.4234.49/android-17-pixel7-emulator/`:

| Area | Files |
| --- | --- |
| `tls` | `client-hello.txt`, `client-hello-2.txt`, `client-hello-3.txt` |
| `http2` | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-1.txt` |
| `client-hints` | `navigation.txt` |
| `websocket` | `accept.txt`, `h1-accept.txt` |

Limits: those of Chrome for Android, on an arm64 emulator rather than an
x86_64 one, and:

- No TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, WebSocket, or
  cookie-placement recipe. The `accept` and `h1-accept` captures back only
  the page and `fetch()` templates.
- No QUIC resumption, plaintext trust, or proxy capture.

### Opera for Android 102 recipes

What is claimed: `opera_android::v102_tls` and
`opera_android::v102_android_client_hints` reproduce Opera 102.1.5206.90382
for Android, built on Chromium 152.0.7977.82, on the Android 17 emulator of
the [Chrome for Android section](#chrome-for-android-154-recipes).

Evidence: Opera 102.1.5206.90382 is the build Play served to the Android 15
emulator on 2026-09-25 and to the Android 17 emulator on 2026-09-26. Opera
for Android reads no command-line file: with a resolver rule in
`chrome-command-line` and Opera as the debug app, it still could not resolve
the rule's name, and no other command-line file name appears in its code. No
capture can therefore map a test name, trust a test certificate, force QUIC,
or set a proxy, and Opera reaches only the device's own loopback through
`adb reverse`. A cleared Opera profile also opens first-run screens: the
terms notice, a default-browser offer, a notifications offer, a
data-collection consent, and a wallpaper choice. The capture declined each
offer and unchecked every data-collection box
([Android browsers](../../scripts/capture/README.md#android-browsers)).

| Layer | Emulator | Samples | Result |
| --- | --- | --- | --- |
| TLS ClientHello to `https://localhost` | Android 17 | 1 process on a cleared profile, after the launcher stepped through the first-run screens | Equal to `opera_android::v102_tls` |
| TLS ClientHello to `https://localhost` | Android 15 | 14 fresh processes: 2 on cleared profiles, 12 restarted on one onboarded profile | All agree. Equal to Chrome 154's ClientHello without trust-anchor IDs, signature-algorithm GREASE included, where desktop Opera 135 drops that GREASE |
| Client hints | Android 17 | 3 typed runs on cleared profiles | The Chromium names, order, and delivery; a four-brand list (`OperaMobile` 102, `Opera` 137, `Chromium` 152, and a greased brand last), platform version `"17"`, model `"Pixel 7"`, and an empty `sec-ch-ua-form-factors` |
| HTTP/1.1 page load, `fetch()`, and `ws://` opening to `127.0.0.1` | Android 15 | 3 typed runs of `direct-loopback` | The field names Chrome 154 for Android sends: the page load equals the typed `h1-accept` page load in the WebSocket captures, and the `fetch()` and `ws://` opening equal the `direct-loopback` capture; `User-Agent` ends in `OPR/102.0.0.0` |

On the Android 15 emulator the 12 restarted processes kept one profile,
because the first-run screens did not complete reliably from a script on
every cleared profile. A ClientHello comes from the process, and the 2
cleared-profile samples equal the 12.

`v102_android_client_hints()` sends the captured model, and
`v102_android_client_hints_for_model` sends another. There are no Opera for
Android request templates. Only HTTP/1.1 requests were captured, and a
template needs an HTTP/2 list, which no capture backs.
`opera_android_102_navigation_field_order_equals_chrome_for_android` records
that the captured HTTP/1.1 order is Chrome's.

Retained fixtures, each under
`fixtures/<area>/opera-android/102.1.5206.90382/<emulator>/`:

| Area | Emulator | Files |
| --- | --- | --- |
| `tls` | `android-17-pixel7-emulator` | `client-hello.txt` (a cleared-profile sample, `hostname=localhost`) |
| `client-hints` | `android-17-pixel7-emulator` | `navigation.txt` |
| `proxy` | `android-35-emulator` | `direct-loopback.txt` |

Limits: those of Chrome for Android, and no HTTP/2, QUIC, HTTP/3, WebSocket
over HTTP/2, plaintext named-origin, proxy, or ECH capture. The ClientHello
was sent to `localhost`, so its server name differs from a capture to
another name.

### Firefox for Android 156 recipe

What is claimed: `firefox_android::v156_tls` reproduces the TCP ClientHello
of Firefox 156.0.1 for Android on the Android 15 (API 35) emulator used
before the [Chrome for Android](#chrome-for-android-154-recipes) Android 17
emulator. Firefox for Android was not recaptured on Android 17.

Evidence: Firefox 156.0.1 is the build Play served to the Android 15
emulator on 2026-09-25. That emulator was a Pixel 7 device profile on the
Android 15 Google Play x86_64 system image, build `AE3A.240806.036`, on the
Windows 11 capture host. Release Firefox for Android reads
`/data/local/tmp/org.mozilla.firefox-geckoview-config.yaml` when it is the
device's debug app: a probe with `network.dns.localDomains` naming a test
host reached a listener on the device's loopback. A capture can therefore
set preferences, but it cannot put a `cert_override.txt` into the app's
private profile, so no page over TLS loads with a test certificate. A page
opened by intent loads while Firefox's first-run screens are showing, so the
ClientHello capture needed no first-run handling.

Twelve fresh-profile processes, each opened by intent at
`https://server.phantom.test:<port>/` with `network.dns.localDomains` and
`network.dns.disableIPv6` set and `adb reverse` for the port, sent the
desktop Firefox 156 ClientHello: the same fixed extension order and every
compared field, and a 240-byte ECH GREASE payload. The ECH GREASE AEAD
varied per connection, as on Windows: 5 AES-128-GCM and 7
ChaCha20-Poly1305. `firefox_android::v156_tls` returns `firefox::v156_tls`,
and `firefox_android_156_tls_recipe_matches_android_captures` replays one
retained sample of each AEAD through the TLS connector.

Retained fixtures, under
`fixtures/tls/firefox-android/156.0.1/android-35-emulator/`:
`client-hello.txt` (AES-128-GCM) and `client-hello-chacha20-ech.txt`.

Limits: those of Chrome for Android, on the Android 15 emulator, and no
HTTP/2, WebSocket, request-field, or proxy capture, because none can load a
TLS page. Firefox for Android sends no user-agent client hints; a plaintext
probe request carried none. No client-hint capture ran on Android 17: the
launcher's typed entry opens `about:blank` by `VIEW` intent, which Firefox
does not resolve.

### TCP socket option evidence

What is claimed: `chromium::v154_tcp` and `firefox::v156_tcp` set the socket
options, and `chromium::v154_tcp` races addresses, as those browsers do at the
profiled release tags.

Evidence: a capture cannot show socket options, so the TCP recipes rest on
browser source. The socket-option and Happy Eyeballs default citations are to
Chromium tag `154.0.8037.58` and Firefox tag `FIREFOX_156_0_RELEASE`. The line
numbers for the rest of the racing algorithm, which `TcpAddressRacing` and
`phantom-net`'s `address_racing` module document, were read at Chromium tag
`153.0.8010.48` and have not been re-read at 154; the defaults those recipes
encode were.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_tcp` | `TCPClientSocket` calls `SetDefaultOptionsForClient` when it opens each socket, before connecting (`net/socket/tcp_client_socket.cc:173`, `:558`). That sets `TCP_NODELAY` and a 45-second keepalive idle time and interval: `SIO_KEEPALIVE_VALS` on Windows (`net/socket/tcp_socket_win.cc:50`, `:55-72`, `:815-818`), `TCP_KEEPIDLE` and `TCP_KEEPINTVL` on Linux (`net/socket/tcp_socket_posix.cc:88-100`, `:493-517`). |
| `firefox::v156_tcp` | `nsSocketTransport::InitiateSocket` sets `PR_SockOpt_NoDelay` on every socket before connecting (`netwerk/base/nsSocketTransport2.cpp:1449-1454`). |
| `chromium::v154_tcp` address racing | Happy Eyeballs v2 is enabled and v3 disabled by default, so every TCP connection uses a `TcpConnectJob` (`net/base/features.cc:114-124`, `net/socket/transport_connect_job.cc:118-123`). It prefers IPv6 first (`net/socket/tcp_connect_job.h:211`), the other family after a failure (`net/socket/tcp_connect_job_connector.cc:298-303`), and starts a second, IPv4-preferring attempt `kIPv6FallbackTime = 300` ms after the first (`net/socket/tcp_connect_job.h:85`, `net/socket/tcp_connect_job.cc:443-466`, `:573-610`). No address is tried twice (`:703-746`); the first connection wins and a total failure returns the most recent error (`:406-431`, `:946-958`). The delay-changing trials `kAdjustIPv6FallbackTime` and `kIPv6FallbackBasedOnRTT` are disabled by default (`net/base/features.cc:128`, `:136`). |

Differences from the browsers:

- Chromium ignores a failure to set either option
  (`net/socket/tcp_socket_win.cc:70-71`). Phantom fails that connection
  attempt instead, so no connection proceeds with options the profile did not
  ask for.
- Chromium on macOS sets only the keepalive idle time
  (`net/socket/tcp_socket_posix.cc:101-105`), and Android and iOS builds
  enable no keepalive. `chromium::v154_tcp` describes Windows and Linux; a
  macOS profile sets `TcpKeepalive::interval` to `None`.
- Firefox's keepalive is not modeled. It changes per HTTP connection: a
  10-second idle time for about the first 60 seconds of an HTTP/1 connection,
  then 600 seconds, with an RTT-derived probe interval, and none after HTTP/2
  negotiation (`netwerk/protocol/http/nsHttpConnection.cpp:405-406`,
  `:2124-2239`; `modules/libpref/init/all.js:1270-1278`).
  `firefox::v156_tcp` leaves `SO_KEEPALIVE` at the operating-system default.
- Edge's network-stack source is not public, and no capture shows socket
  options, so there is no Edge TCP recipe.
- Chromium races as DNS answers arrive and sorts addresses itself. Phantom
  races the system resolver's complete answer, keeping its order within each
  family. Chromium's QUIC job uses only the first resolved address
  (`net/quic/quic_session_pool_direct_job.cc:219-221`), so racing is not
  applied to HTTP/3, and Phantom's H3 connector keeps trying later addresses
  after a connection failure.
- Firefox's address selection is not modeled. Release builds keep its Happy
  Eyeballs implementation behind a nightly-only pref
  (`modules/libpref/init/StaticPrefList.yaml:17057-17060`). The release path
  opens an IPv4-only backup connection after 250 ms
  (`modules/libpref/init/all.js:1213`, `:1245`;
  `netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`) and orders the
  primary connection's addresses using per-host family preferences and DNS
  failure history (`DnsAndConnectSocket.cpp:170-178`,
  `netwerk/base/nsSocketTransport2.cpp:1742-1745`, `:1785-1787`).

Tests in `phantom-net` read the options back from connected sockets with
`socket2` getters:

| Test | What it proves |
| --- | --- |
| `tcp::address_racing::tests` | With scripted attempt outcomes and a test-controlled fallback delay: IPv6 preference, alternation, the IPv4 fallback attempt and role swap, the two-attempt bound, cancellation of the loser, and the returned error |
| `tcp::tests::racing_reaches_ipv4_when_nothing_listens_on_ipv6` | Real sockets raced to `[::1]` and `127.0.0.1` at the same port, with a listener only on IPv4, connect over IPv4 |
| `tcp::tests::host_check_*` | The build-time host check for every combination of platform capabilities. The facade rejects a Windows keepalive without an interval as `BuildErrorKind::InvalidProfile` |
| `tcp::tests::connected_socket_carries_requested_options` | `TCP_NODELAY` and `SO_KEEPALIVE`, and on Linux and macOS the idle time and interval. Windows exposes no getter for the `SIO_KEEPALIVE_VALS` values |
| `tcp::tests::paths` | Options on every socket opened by the direct, forward proxy, HTTP CONNECT (with and without Basic), HTTPS proxy, SOCKS5 (remote and local DNS), HTTP/1.1-or-HTTP/2, and SOCKS5 UDP control paths |
| `profile_tcp_settings_reach_every_tcp_connector` (facade) | A profile's settings reach each TCP connector the client builds, including the WebSocket HTTP/1.1 connector |

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- No capture confirms the options, including keepalive probe timing on an
  idle connection.
- The source was read at one tag per browser, so build-time or field-trial
  changes to these options would not be seen. Branded Chrome receives
  server-side field-trial configuration, so the source cannot rule out a
  trial that enables Happy Eyeballs v3 or a different fallback delay for some
  users.

### HTTP/1.1 connection bound evidence

What is claimed: `chromium::v154_http1` and `firefox::v156_http1` allow 6
HTTP/1.1 connections to one origin and route, as those browsers do at the
profiled release tags, and the client opens connections up to the profile's
bound. Negotiated requests that select HTTP/1.1 use the same bound, and
their TLS handshakes follow the browsers' rule for a server whose protocol
is not yet known.

Evidence: a capture of one page load cannot show a limit that the page never
reached, so the recipes rest on browser source at Chromium tag
`154.0.8037.58` and Firefox tag `FIREFOX_156_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_http1` | The normal socket pool allows six sockets per group, `g_max_sockets_per_group` (`net/socket/client_socket_pool_manager.cc:46-58`). A group is one scheme, host, and port within the pool of one proxy chain (`net/socket/client_socket_pool.h:130-153`, `net/socket/client_socket_pool_manager_impl.h:48`), which Phantom keys as one origin and route. Idle, connecting, and in-use sockets all occupy a slot (`net/socket/transport_client_socket_pool.h:356-363`), and a request takes the most recently used idle socket before it opens another (`net/socket/transport_client_socket_pool.cc:530-560`). |
| `firefox::v156_http1` | `network.http.max-persistent-connections-per-server` is 6 (`modules/libpref/init/all.js:1158-1161`). Firefox applies it to direct and CONNECT-tunneled connections and counts active connections together with those still connecting (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1150-1157`, `:1342-1378`; `netwerk/protocol/http/ConnectionEntry.cpp:284-292`). |

Differences from the browsers:

- Chromium also caps sockets at 256 per pool and 128 per proxy chain
  (`net/socket/client_socket_pool_manager.cc:37-44`, `:60-66`), and allows
  255 per group for WebSocket connections. Phantom does not model these caps.
- Firefox counts idle connections separately and reuses them before it opens
  another; Phantom counts them toward the bound. Firefox uses
  `network.http.max-persistent-connections-per-proxy`, 32, for plaintext
  requests forwarded through an HTTP proxy (`modules/libpref/init/all.js:1167-1170`),
  where the recipe keeps 6, and lets urgent-start requests exceed the limit
  by 3 (`modules/libpref/init/all.js:1163-1165`).
- Edge's network-stack source is not public, so there is no Edge recipe.

Negotiated requests: both browsers count a connection whose ALPN selected
HTTP/1.1 against the same per-group limit, and differ from each other only
while a handshake to a server known to speak HTTP/2 is in flight.

| Browser | Source behavior |
| --- | --- |
| Chromium 154 | Every HTTPS job registers with `SpdySessionPool::RequestSession` (`net/http/http_stream_factory_job.cc:749-775`). The first job for a session key is the blocking request (`net/spdy/spdy_session_pool.cc:269-303`). A later job is held only when `HttpServerProperties` says the server supports HTTP/2 (`net/http/http_stream_factory_job.cc:1417-1429`), until the blocking request finishes (`net/spdy/spdy_session_pool.cc:536-545`) or `kHTTP2ThrottleMs`, 300 ms, passes (`net/http/http_stream_factory_job.h:62`). Support is recorded when a connection negotiates HTTP/2 (`net/http/http_stream_factory_job.cc:1304-1306`). Without it, each job asks the socket pool for its own socket at once, up to the group limit. A job whose socket negotiated HTTP/2 after another session to the key appeared closes its socket and uses that session (`:1245-1280`), and a new session closes the group's idle sockets (`:1283-1287`). `HttpStreamPool`, which applies the same rule with the same 300 ms delay (`net/http/http_stream_pool_attempt_manager.cc:1597-1615`, `net/http/http_stream_pool_attempt_manager.h:100`), runs only with `kHappyEyeballsV3`, off by default (`net/base/features.cc:124`). |
| Firefox 156 | `nsHttpConnectionMgr::MakeNewConnection` opens no connection while `ConnectionEntry::RestrictConnections` holds (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1399-1409`). That requires `mUsingSpdy` and an attempt still negotiating, or an active connection whose ALPN result is pending or that can take another stream (`netwerk/protocol/http/ConnectionEntry.cpp:225-282`). `mUsingSpdy` starts false (`:38`) and is set only when a connection reports HTTP/2 (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1007-1024`), so a new entry opens connections in parallel up to the limit. |

Both browsers keep the fact once learned. Every writer of Chromium's flag
sets it to true (`net/http/http_stream_factory_job.cc:1304-1306`,
`net/http/http_stream_pool_attempt_manager.cc:823-825`), and so does every
writer of Firefox's (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1023`,
`:3920`). Chromium keys it by scheme, host, and port, plus the network
anonymization key when partitioning is on, but not by proxy
(`net/http/http_server_properties.cc:75-86`,
`net/http/http_stream_factory_job.cc:386-391`), and keeps the 500 most
recently used servers (`net/http/http_server_properties.h:97`,
`net/http/http_server_properties.cc:124-125`). Firefox keeps it on the
`ConnectionEntry`, whose key includes the proxy of a CONNECT tunnel or
SOCKS route (`netwerk/protocol/http/nsHttpConnectionInfo.cpp:212-232`).

Phantom follows both: a pool key that has never selected HTTP/2 starts
handshakes in parallel up to the bound, requests past the bound wait for a
handshake to finish, and a key that has selected HTTP/2 holds each new
handshake until the one in flight finishes. The client remembers the keys
that selected HTTP/2, 500 at most, keyed by origin and route. Differences:

- Chromium stops holding after 300 ms; Phantom, like Firefox, holds until
  the handshake in flight finishes or fails.
- Chromium shares HTTP/2 support across proxies and saves it to disk.
  Phantom keys it by origin and route, as Firefox does and as Phantom keys
  its other learned state, so a new route or a new client starts as a
  first contact.
- Chromium closes a waiting job's socket, handshake finished or not, when a
  session to the key becomes available
  (`net/http/http_stream_factory_job.cc:1337-1342`). Phantom lets every
  handshake it started finish, then closes a second HTTP/2 connection.

Loopback tests in `crates/phantom/tests/sessions/session_http1_parallel.rs`:

| Test | What it proves |
| --- | --- |
| `concurrent_requests_open_connections_up_to_the_bound_then_wait` | `max_concurrent_http1_requests_per_origin` replaces the recipe's bound; requests open connections up to it, and a further request waits for a free connection |
| `idle_connection_is_reused_before_another_opens` | A freed connection is reused before a new one opens |
| `bound_is_counted_per_route_to_one_origin` | Each route to one origin has its own bound |
| `named_recipe_opens_six_connections_to_one_origin` | Both recipes open six connections and hold a seventh request |
| `profile_without_http1_policy_keeps_one_connection_per_origin` | A profile without `Http1Settings` keeps one connection |
| `requests_cancelled_during_connection_setup_leave_the_full_bound` | Requests dropped while their connection is being set up do not use up the bound |
| `custom_profile_carries_its_own_http1_bound` | A custom `Http1Settings` bound reaches the client |

Loopback tests in `crates/phantom/tests/sessions/negotiated_parallel.rs`:

| Test | What it proves |
| --- | --- |
| `first_contact_with_an_http1_origin_opens_parallel_handshakes_up_to_the_bound` | Five concurrent requests open three connections whose handshakes run at once, and all succeed over HTTP/1.1 |
| `fewer_requests_than_the_bound_open_one_connection_each` | Two concurrent requests open two connections under a bound of six |
| `named_recipe_opens_six_negotiated_http1_connections` | Both recipes open six negotiated connections and hold a seventh request |
| `idle_negotiated_http1_connection_is_reused_before_another_opens` | A freed connection is reused before a new one opens |
| `negotiated_http1_request_beyond_the_bound_waits_for_a_free_connection` | A request past the bound waits and then runs on the connection freed first |
| `first_contact_with_an_h2_origin_converges_on_one_connection` | Parallel first handshakes that all select HTTP/2 leave one connection carrying every request |
| `concurrent_requests_to_a_known_h2_origin_wait_for_the_handshake_in_flight` | Once HTTP/2 was selected, concurrent requests open one connection |
| `negotiated_http1_through_an_http_proxy_opens_one_tunnel_per_connection` | Each HTTP/1.1 connection through an HTTP proxy has its own CONNECT tunnel |
| `burst_past_the_http1_limits_to_a_new_h2_origin_succeeds_on_one_connection` | Twenty first-contact requests, past the H1 active and waiting bounds, all succeed over one HTTP/2 connection; the other handshake's connection closes |
| `burst_to_a_new_http1_origin_meets_the_http1_limits` | Once a handshake selects HTTP/1.1, the H1 bound runs, the H1 waiting bound queues, and the rest fail with `Capacity` for HTTP/1.1 |
| `short_pool_admission_timeout_spares_requests_waiting_for_a_handshake` | Waiting for another request's handshake counts under the connect limit, not pool admission |
| `setup_retry_delay_releases_the_connection_slot` | With a bound of one, a request in its setup retry delay leaves the slot to another request |
| `reused_connection_replay_opens_a_fresh_connection_past_idle_ones` | A reused-connection replay opens a new connection rather than taking another idle one |
| `requests_cancelled_during_handshakes_release_their_slots` | Requests dropped mid-handshake free their slots |

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- No capture confirms the limit or the reuse order.
- The source was read at one tag per browser, so field-trial changes would
  not be seen.

### Address cache evidence

What is claimed: `chromium::v154_dns_cache` and `firefox::v156_dns_cache`
keep as many names, and an answer and a failure for as long, as those
browsers do for an answer without a record TTL at the profiled release tags.
With a cache, the client makes one lookup per name it resolves itself per
cache `ttl`, shares one lookup between concurrent connections, keeps every
resolved address as returned except its port, and never resolves a
proxy-resolved target. The shared lookup runs on the starting runtime's
blocking pool, which bounds the resolutions in flight, and a connection on
one Tokio runtime never waits on another runtime that has stopped being
driven.

Evidence: a capture of one page load cannot show how long a browser reuses
an answer, so the recipes rest on browser source at Chromium tag
`154.0.8037.58` and Firefox tag `FIREFOX_156_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_dns_cache` | Each `URLRequestContext`, one per browser profile, creates its resolver with caching on (`net/url_request/url_request_context_builder.cc:363-382`), and its `ResolveContext` holds a `HostCache` of `kDefaultCacheSize = 1000` entries in builds with the built-in DNS client (`net/dns/resolve_context.cc:109-121`), which is every Blink build (`net/dns/BUILD.gn:9`). An answer from the system resolver is kept for `kCacheEntryTTLSeconds = 60` and a failure for `kNegativeCacheEntryTTLSeconds = 0` (`net/dns/host_resolver_manager_job.cc:54-58`, `:799-815`); a failure without a positive TTL is not cached (`net/dns/host_resolver_manager.cc:1284-1291`). A full cache evicts the entry that expires soonest, stale entries first (`net/dns/host_cache.cc:886-916`, `:1289-1319`). A request joins the job already running for its key (`net/dns/host_resolver_manager.cc:993-1010`). |
| `firefox::v156_dns_cache` | `network.dnsCacheEntries` is 1600 outside nightly builds and `network.dnsCacheExpiration`, the lifetime of an answer without an OS TTL, is 60 seconds (`modules/libpref/init/StaticPrefList.yaml:15551-15565`; `netwerk/dns/nsHostResolver.cpp:1310-1317`). A failed lookup is kept for `NEGATIVE_RECORD_LIFETIME`, 60 seconds (`netwerk/dns/nsHostResolver.cpp:65-67`, `:1303-1308`). A request for a name being resolved is appended to that record's callbacks (`netwerk/dns/nsHostResolver.cpp:646-652`). |

Both browsers keep one cache per browser profile. Chromium keys an entry by
host, query type, flags, source, secure mode, target network, and network
anonymization key (`net/dns/host_cache.h:70-111`), but the key is empty
unless `kPartitionConnectionsByNetworkIsolationKey` is on, and it is off by
default (`net/dns/host_resolver_manager_request_impl.cc:51-56`,
`net/base/network_anonymization_key.cc:261-266`,
`net/base/features.cc:213-217`). Firefox keys a record by host, type, flags,
address family, private browsing, and origin-attributes suffix
(`netwerk/dns/nsHostRecord.h:77-93`). Phantom keys an entry by the
lowercased host name alone, one cache per client, with a new empty cache for
each session built from it, as it does for cookies and Alt-Svc.

Differences from the browsers:

- Chromium's built-in DNS client, on by default on Windows, macOS, Linux,
  ChromeOS, and Android (`net/base/features.cc:42-48`), keeps an answer for
  its record TTL, at least 60 seconds
  (`net/dns/host_resolver_manager_job.cc:61`, `:965-966`), and a negative
  answer for its SOA TTL (`:907-908`). Firefox asks Windows for the record
  TTL (`network.dns.get-ttl`,
  `modules/libpref/init/StaticPrefList.yaml:15567-15575`). Phantom resolves
  through the operating system, which reports no TTL, so it follows the
  browsers' rule for an answer without one.
- Firefox serves an expired answer for up to
  `network.dnsCacheExpirationGracePeriod`, 600 seconds, while it resolves
  the name again (`modules/libpref/init/StaticPrefList.yaml:15584-15589`,
  `netwerk/dns/nsHostResolver.cpp:1265-1283`). Phantom resolves an expired
  name before it connects.
- Both browsers flush the cache when the network changes
  (`net/dns/host_resolver_manager.cc:1803-1816`, `:1912-1925`;
  `netwerk/dns/nsDNSService2.cpp:1369-1386`,
  `netwerk/dns/nsHostResolver.cpp:218-255`). Phantom does not watch the
  network; `Client::clear_dns_cache` is the caller's equivalent.
- Firefox evicts from an LRU queue; Phantom, like Chromium, evicts the entry
  that expires soonest.
- Edge's network-stack source is not public, so there is no Edge recipe.

Unit tests in `crates/phantom-net/src/address_cache/tests.rs`:

| Test | What it proves |
| --- | --- |
| `repeated_lookups_within_the_ttl_resolve_once` | A second lookup, on another port, uses the stored answer |
| `answers_keep_the_resolver_order` | Stored addresses come back in the resolver's order |
| `names_differing_only_in_case_share_an_entry` | Names are compared without regard to ASCII case |
| `an_expired_answer_is_resolved_again` | A lookup after the TTL resolves again |
| `concurrent_lookups_share_one_resolution` | Eight concurrent lookups make one resolution and get the same answer |
| `a_resolution_fills_the_cache_after_its_lookups_are_dropped` | A resolution whose lookup was cancelled still stores its answer |
| `a_lookup_does_not_depend_on_another_runtime_being_driven` | A lookup on one runtime joins a resolution another runtime started and completes while that runtime is never driven again |
| `a_resolution_a_shut_down_runtime_drops_is_released_and_restarted` | A resolution spawned on a runtime that has shut down is dropped; its waiter gets an error, and the next lookup of the name resolves it again |
| `resolutions_in_flight_are_bounded_by_the_blocking_pool` | Twelve distinct names on a runtime with two blocking threads never run more than two resolutions at once, and all twelve are answered |
| `a_scoped_ipv6_address_keeps_its_scope_and_flow_label` | A cached link-local IPv6 address keeps its scope ID and flow label; only the port changes |
| `a_ttl_beyond_the_clock_range_never_expires` | `Duration::MAX` keeps the answer instead of expiring it at once |
| `the_cache_keeps_at_most_max_entries_names` | The bound holds, and the name that expires soonest is evicted |
| `failures_are_not_kept_without_a_negative_ttl`, `failures_are_kept_for_the_negative_ttl`, `an_empty_answer_is_returned_and_kept_as_a_failure` | Failures and empty answers follow `negative_ttl`; failures keep the resolver's error kind, and an empty answer reaches each connection path as it would without a cache |
| `a_zero_ttl_resolves_every_sequential_lookup`, `ip_literals_are_used_without_a_lookup`, `clear_forgets_answers_and_drops_resolutions_in_flight`, `clones_share_one_cache` | Edge cases of the lifetime, IP literals, clearing, and sharing |
| `routes::*` | Each connector path resolves only the names the client resolves itself: the origin on direct TCP and QUIC, the proxy host on forward, CONNECT, HTTPS proxy, SOCKS5, and CONNECT-UDP over TCP routes, and the target as well only on local-DNS SOCKS5 over TCP and UDP |

Loopback tests in `crates/phantom/src/client/dns_cache_tests.rs` drive the
client against a plaintext origin that closes each connection:
`repeated_requests_to_one_host_resolve_it_once`,
`concurrent_requests_to_one_host_share_one_lookup`,
`clones_share_the_cache_and_sessions_start_empty`, and
`clear_dns_cache_resolves_the_host_again`.
`profile_dns_cache_reaches_every_connector` and
`builder_settings_replace_or_disable_the_profiles` check the wiring.

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- No capture counts a browser's DNS queries, so the lifetimes rest on
  source alone.
- The source was read at one tag per browser, so field-trial changes would
  not be seen.

### Plaintext origin trust evidence

What is claimed: for a URL that is not
[potentially trustworthy](../reference/glossary.md#potentially-trustworthy),
such as `http://origin.phantom.test/`, the built-in request templates send
the fields Chrome 154, Edge 154, and Firefox 156 send there, in the same
order: no `Sec-Fetch-*` fields and `Accept-Encoding: gzip, deflate`. Phantom
sends automatic client hints to an `http://` loopback or `localhost` origin
and learns `Accept-CH` from it, and sends none to a named `http://` origin.
The built-in WebSocket recipes do the same for a `ws://` opening: to
`ws://origin.phantom.test` they send `Accept-Encoding: gzip, deflate`, and
Firefox's sends no `Sec-Fetch-*` field.

Evidence: the proxy route captures under
[`fixtures/proxy/`](../../fixtures/proxy/), described in
[Proxy route browser evidence](#proxy-route-browser-evidence), load the same
page from `http://127.0.0.1` and from `http://origin.phantom.test`, directly
and through a plaintext and a TLS proxy, three runs per scenario. The fields
depend on the origin, not on the route:

| Origin | `Accept-Encoding` | `Sec-Fetch-*` | Client hints |
| --- | --- | --- | --- |
| `127.0.0.1` | `gzip, deflate, br, zstd` | Sent by all three | Chrome and Edge send the defaults |
| `origin.phantom.test` | `gzip, deflate` | Not sent | Not sent |

The table holds for the page request and the `fetch()` on all 27 runs of each
origin, and for the `ws://` Upgrade too, except that Chrome and Edge send no
`Sec-Fetch-*` field on it to either origin. Every other field keeps its
order. The H2 requests through the TLS
proxy show the same differences, in the H2 lists' order. The other plaintext
captures under `fixtures/` use a `127.0.0.1` origin, so their
`Accept-Encoding`, client hints, and fetch metadata are what a browser sends
to loopback, not to a named plaintext origin.

Browser source at the captured tags gives the rule behind the captures:

| Behavior | Chromium `154.0.8037.58` | Firefox `FIREFOX_156_0_RELEASE` |
| --- | --- | --- |
| Trust test | `net::IsOriginPotentiallyTrustworthy`, `net/base/is_potentially_trustworthy.cc` lines 294-346 | `nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin`, `dom/security/nsMixedContentBlocker.cpp` lines 294-362 |
| `br` and `zstd` | `HttpRequestHeaders::SetAcceptEncodingIfMissing`, `net/http/http_request_headers.cc` lines 261-275: cryptographic scheme or `net::IsLocalhost` | `isSecureOrTrustworthyURL`, `netwerk/protocol/http/HttpBaseChannel.cpp` lines 325-329, selects `network.http.accept-encoding.secure` |
| `Sec-Fetch-*` | `SetFetchMetadataHeaders`, `services/network/sec_header_helpers.cc` lines 288-292 | `SecFetch::AddSecFetchHeader`, `dom/security/SecFetch.cpp` lines 383-387 |
| Client hints | `IsValidURLForClientHints`, `content/browser/client_hints/client_hints.cc` lines 501-503, for sending and for `Accept-CH` | Not sent |

Phantom's test is `is_potentially_trustworthy` in
`crates/phantom/src/request/secure_context.rs`, the same one the cookie jar
uses for `Secure` cookies. A WebSocket URL applies its host rules, with
`wss://` counted as `https://`. The templates carry the per-browser data as
`RequestField::ByTrust` entries, and the WebSocket recipes as
`WebSocketField::ByTrust` entries, so the transport has no browser branch.

Tests:

- `templates_send_the_captured_plaintext_named_origin_fields` in
  `phantom-profile` compares each template's HTTP/1.1 and HTTP/2 lists, for
  both kinds of URL, with the captured field names and codings.
- `crates/phantom/tests/requests/plaintext_templates.rs` sends each built-in template
  to `http://127.0.0.1` directly and to `http://origin.phantom.test` through a
  loopback forward proxy, and compares every received field and value with
  the captured request. It also checks that `Accept-CH` is learned from the
  loopback origin only, and that after a redirect from loopback to the named
  origin the second hop advertises `gzip, deflate` and a `br` response fails
  to decode while `gzip` decodes.
- `direct_plaintext_loopback_sends_and_learns_client_hints` in
  `direct_http.rs` covers a profile without a template.
- `websocket_recipes_follow_origin_trust_in_the_proxy_route_captures` in
  `phantom-profile` reads every `ws://` Upgrade in `fixtures/proxy/`, 18 per
  browser, and compares it with the recipe's HTTP/1.1 template for that
  origin's trust, value for value.
- `crates/phantom/tests/streams/websocket_trust.rs` opens each built-in WebSocket
  recipe, through `Client::websocket` and through
  `Client::websocket_with_profile_policy`, to `ws://127.0.0.1` directly and
  to `ws://origin.phantom.test` through a loopback CONNECT proxy. It supplies
  only `User-Agent`, `Origin`, and `Accept-Language` and compares every
  received field and value, apart from the fresh key and the loopback `Host`,
  with the `direct-loopback` and `http-proxy-hostname` captures. It also
  checks that a caller `Accept-Encoding` replaces the recipe's value in place.

How to reproduce: `scripts/capture/proxy_route.py --browser <browser>
--scenario all --repeat 3`, then
`cargo test -p phantom-http --all-features --test requests
plaintext_templates::` and
`cargo test -p phantom-http --all-features --test streams websocket_trust::`
and
`cargo test -p phantom-profile plaintext_named_origin` and
`cargo test -p phantom-profile origin_trust`.

Limits:

- The request template tests hold the captured field lists as data; they do
  not read the fixtures. The WebSocket tests read them.
- The direct captures' `fetch()` used the default cache mode. The
  `*-auth-nostore-*` proxy captures show a no-store `fetch()` to a named and
  a loopback origin, with `Pragma` and `Cache-Control` where the no-store
  templates place them.
- Through an HTTP/1.1 proxy, Chromium sends `Proxy-Connection: keep-alive`
  where a direct request has `Connection: keep-alive`. The Chrome and Edge
  templates carry both as `RequestField::ByForwarding` entries; see
  [Proxy route browser evidence](#proxy-route-browser-evidence).
- Every captured WebSocket page is same-origin with its socket, except the
  `fresh-origin` scenario in `fixtures/websocket/`, whose Firefox socket
  sends `Sec-Fetch-Site: cross-site`. The recipe's `same-origin` default fits
  the first case; a caller sets the field for the second.
- H2 extended CONNECT carries only `wss://`, which is always potentially
  trustworthy, so its trust-dependent fields have one captured value.

### Fingerprint snapshot evidence

Claim: a [fingerprint snapshot](../../scripts/capture/README.md#quick-fingerprint-snapshot)
of a desktop browser records the same TLS, HTTP/2 startup, QUIC, HTTP/3
SETTINGS, and client-hint values as the per-layer capture tools, so a
snapshot that `snapshot_compare.py` finds equal shows those layers unchanged.

Evidence: on 2026-09-26 the Windows 11 capture host ran `snapshot.py
--repeat 3` headless for each installed desktop browser, then
`snapshot_compare.py` on every run against the retained fixtures.

| Browser | Seconds per run | Differences from the retained fixtures |
| --- | --- | --- |
| Chrome 154.0.8037.58 | 1.9, 2.4, 1.9 | None |
| Edge 154.0.4258.37 | 1.8, 1.9, 2.0 | Client hints only: the brand list and versions of Edge 154 against the retained Edge 153 |
| Brave 154.1.96.59 | 1.8, 1.8, 1.8 | None |
| Opera 135.0.5973.92 | 2.3, 2.4, 1.9 | None |
| Firefox 156.0.1 | 2.8, 2.8, 2.6 | TCP ClientHello `server_name` only (the retained capture used `localhost`); no retained HTTP/2 startup, QUIC ClientHello, HTTP/3 startup, or client-hint fixture to compare |

Every run used HTTP/3 and parsed without an error line. The seconds include
the browser's launch and teardown. The first HTTP/2 navigation's field
order, flags, and priority equal the WebSocket `accept.txt` navigation for
all five browsers.

The runs also showed what varies per connection, which the comparison
normalizes: Chromium's TLS extension and QUIC transport parameter order, and
the length of Chromium's GREASE ECH payload, which took 144, 176, 208, and
240 bytes. Brave's `accept-language` quality value changed between runs
(0.5, 0.5, and 0.7, against 0.9 retained); the comparison does not read it.

One `run_matrix.py` manifest with a `snapshot` capture for all five
browsers, `repeat` 1, ran the five jobs at once in 4.7 seconds of wall
clock, with the same comparison results.

Reproduce with the commands in the capture README, once per browser.

Limits:

- The Python TLS server does not negotiate ALPS, so a snapshot cannot show
  the peer ALPS settings that `capture_http2_tls` records.
- The first HTTP/3 request is a script navigation after `Accept-CH`, so its
  fields are not compared with the retained command-line navigation.
- Snapshots were taken on Windows only; the macOS capture host has not run
  the tool.

#### Android snapshots

Claim: a snapshot of Chrome, Brave, or Edge for Android records the same
TLS, HTTP/2 startup, QUIC, HTTP/3 SETTINGS, and client-hint values as the
per-layer Android captures, in seconds and with no typed address-bar entry.
For Opera and Firefox for Android it records the TCP ClientHello only.

Evidence: on 2026-09-26 `snapshot.py` ran against the Android 17 emulators
that report a Pixel 7, the x86_64 one on the Windows capture host and, for
Edge, the arm64 one on the Mac. `snapshot_compare.py` compared each run with
the fixtures recorded on the same emulators.

| Browser | Seconds per run | Differences from the retained fixtures |
| --- | --- | --- |
| Chrome 154.0.8037.57 | 6.3, 5.8, 6.6 | First navigation lacks `sec-fetch-user` |
| Brave 1.95.104 | 8.1, 8.1, 7.4 | As Chrome; no HTTP/2 startup fixture from this emulator to compare |
| Edge 153.0.4234.49, arm64 | 2.6, 2.5, 2.6 | As Chrome |
| Opera 102.1.5206.90382 | 48.4, 71.2 | None in the TCP ClientHello; no other layer recorded |
| Firefox 156.0.1 | about 10 each, with `--run-timeout 5` | None in the TCP ClientHello against the Android 15 capture, except that one run offered ECH GREASE with ChaCha20-Poly1305, which the retained `client-hello-chacha20-ech.txt` shows as a variant; no other layer recorded |

The Chromium runs used HTTP/3, and their client hints equal the retained
`navigation.txt`. `sec-fetch-user` is missing because a page opened by an
intent carries no user activation. The seconds include clearing the app's
data and the cold start. Opera's first-run screens took 42 to 65 seconds of
each run before its one connection.

Limits:

- Edge for Android is an arm64 build. On the x86_64 emulator it loaded `/`
  and the `Critical-CH` retry and then stopped, or connected not at all.
- Opera and Firefox for Android accept no certificate override from the
  launcher, so their HTTP/2, HTTP/3, request, and client-hint layers still
  need the per-layer tools.

### Recorded coverage losses

Carrying one version per browser retires evidence along with the recipes it
described. These are the checks Phantom used to run and no longer does. Each
is a real reduction, not a restatement.

| Lost check | What it did | Where the claim rests now |
| --- | --- | --- |
| Third-party HTTP/2 observations | The Chrome 152 Pingly and Firefox 154 Peet and Pingly fixtures, with `assert_akamai_summary`, compared a recipe's SETTINGS, window increment, and pseudo-header order against an independent observer's summary of the same browser | No current recipe has a second opinion from outside this repository |
| Raw Firefox HTTP/2 startup bytes | The Firefox 154 `client-startup.txt` replay compared startup frames byte for byte | `firefox::v156_http2`'s SETTINGS and connection window rest on the HTTP/2 session captures of the WebSocket fixture set. No Firefox 156 equivalent exists: the raw startup tool needs WebDriver certificate trust, and geckodriver is not installed on the capture host |
| Cross-platform transport parity | The Chrome 152 and Firefox 154 macOS and Windows capture pairs showed that those transport layers did not depend on the host platform | No current recipe has a second platform, so platform independence is not claimed for any of them |
| Chrome for Testing field-trial comparison | The retained `client-hello-field-trial-config.txt` kept the testing configuration's differences visible; it went with the Chrome 152 fixtures | No Chrome for Testing build of 154.0.8037.58 is published, so build flavor is not isolated at the current version |
| Within-process trust-anchor stability | Chrome 152 and 153 multi-connection captures, 48 connections from each of 13 processes, showed one trust-anchor order per browser process; they were never retained as fixtures | The Chrome 154 captures take one connection per process, so they show only that the order no longer differs between processes |

## Feature evidence

These sections cover individual client features. Most rest on loopback tests
of Phantom's own contract. Where a section also has browser captures, it says
so and states what they cover.

### SSE browser reconnect evidence

What is claimed: Phantom's event source matches Chrome 154 and Firefox 156 on
`Last-Event-ID` handling, retry persistence, termination, reconnect delays,
and reconnect field order, over plaintext HTTP/1.1.

Evidence: `fixtures/sse/` retains HTTP/1.1 EventSource captures from headless
Chrome 154.0.8037.58 and Firefox 156.0 (build ID 20260909172920) on Windows 11
(10.0.26200), recorded against a plaintext loopback server. Each of the
seventeen scenarios ran ten times on a fresh profile. Fixtures keep the raw
request lines and header lines in arrival order, connection reuse, and the
delay from each server stimulus to the next request. Each file records the
capture page and the exact launch arguments.

The Firefox captures were first recorded under the label 155.0.1, which was
passed to the capture tool by hand. Every Firefox request in them sends
`Firefox/156.0` in its user-agent, and the machine's update history shows
Firefox 156.0 (build ID 20260909172920) installed before the first Firefox
capture. They were therefore moved to `firefox/156.0/` and their
`client_version` was corrected. Nothing else in them changed; they were not
re-captured.

Observed on both browsers:

- `Last-Event-ID` is spelled that way, carries the committed id as raw UTF-8
  bytes, is omitted when the committed id is empty, and sits among the
  browser's ordinary fields rather than last. Chrome places it after
  `sec-ch-ua-mobile`; Firefox places it after `Accept-Encoding`.
- A valid `retry` value persists across later connections, and a non-digit
  value is ignored.
- The delay spread across ten runs stayed within about 50 ms and did not grow
  between attempts: neither browser showed jitter or backoff.
- `204`, `404`, `500`, and a `text/plain` response each ended the
  EventSource, with no request during the observation window.
- A stream with only response headers stayed open for 90 seconds; neither
  browser has an idle timeout.
- A cookie set by the stream response was sent on the reconnect.

Where they differ:

| Behavior | Chrome 154 | Firefox 156 |
| --- | --- | --- |
| Delay without `retry` | 3 s | 5 s |
| `retry: 0` and `retry: 100` | honored (about 1 ms and 110 ms) | raised to 500 ms (observed about 510 ms) |
| Request after a reset before any response | one HTTP-stack resend on a new connection when the failed request reused a connection, then the retry delay | HTTP-stack transaction restarts on new connections |
| Reconnect target after a followed `307` | redirected URL | original URL |
| `Cookie` position on the reconnect | last of 16 fields | after `Referer`, before `Sec-Fetch-Dest` |

The immediate requests after a reset are HTTP-stack resends, not EventSource
reconnects:

- Three `reset-before-head` runs of Chrome 153.0.8010.48, whose captures the
  Chrome 154 set reproduced field for field, with
  `--log-net-log --net-log-capture-mode=Everything` each showed one URL
  request that was sent on a reused keep-alive socket, failed with
  `ERR_CONNECTION_CLOSED`, logged `HTTP_TRANSACTION_RESTART_AFTER_ERROR`, and
  was resent on a new connection, where it failed with `ERR_EMPTY_RESPONSE`.
  Each later request was a new URL request about 3 s later, so Chrome's
  EventSource waited the retry delay after every failure.
- One run of the same Firefox 156.0 build with
  `MOZ_LOG=nsHttp:5,EventSource:5` showed one channel whose transaction
  restarted three times after `NS_BASE_STREAM_CLOSED` on fresh connections.
  The `204` answered that same channel, so the EventSource never scheduled a
  reconnect.

The logs were kept outside the repository; the fixture timings of these runs
matched the retained captures. Phantom's event source already waits the retry
delay after each failure, like Chrome's. By default its HTTP/1 layer does not
resend a request after a reused connection closes before a response;
`RetryPolicy::with_reused_connection_replay` opts into Chrome's single
resend. That request-layer policy is outside the SSE controller.

A five-run comparison of headless and headful Chrome on `retry-750`, retained
under `launch-mode/`, gave medians within 1 ms of each other, so headless
timers are not throttled.

Other background traffic continued during the captures. Firefox 156 still
contacted Remote Settings, and Chrome contacted Google update and messaging
services, because release builds ignore those services' test-only switches.
That traffic used separate remote connections and never reached the loopback
listener.

`crates/phantom/tests/streams/sse_browser_reconnect.rs` reads the retained fixtures
and replays the same server stimuli against Phantom with a paused clock. It
asserts that Phantom matches both browsers on `Last-Event-ID` spelling and raw
value, and omission of an empty id; retry persistence, and ignoring a
non-digit retry; and termination on `204`, `404`, `500`, and `text/plain`.

With Firefox options (`initial_retry` 5 s, `min_retry` 500 ms) and Chrome
defaults, each browser's median delay per attempt must lie between Phantom's
exact delay and 30 ms above it. This covers `retry-0`, `retry-100`,
`retry-750`, and the default delay. A template built from each browser's
captured reconnect fields, with `SseHeader::last_event_id` at the captured
position, reproduces the browser's field lines except the `Host` port.

How to reproduce: `scripts/capture/sse_reconnect.py`;
[Capture tools](../../scripts/capture/README.md) has the commands. The
Chrome 153 comparison is under
[Comparison with Chrome 153](#comparison-with-chrome-153).

Limits:

- The captures cover plaintext HTTP/1.1 only. H2, H3, macOS, and Safari
  behavior is not inferred from them.

### Cookie crumb evidence

What is claimed: over HTTP/2, the Chromium and Firefox recipes split the
`cookie` field into one field per cookie at the field's position and encode
each crumb as Chrome 154, Edge 154, and Firefox 156 do, except for Firefox's
name index noted below. Over HTTP/3, the Chromium request recipe splits it and
its QPACK encoder stream and field sections equal Chrome's and Edge's.

Evidence: `fixtures/cookies/` retains three runs per protocol from headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 156.0 on Windows 11
(10.0.26200), each on a fresh profile. A run loads `/start`, whose response
sets five probe cookies, then navigates to `/page`, which fetches `/fetch` and
`/done`, so three requests on one connection carry the cookies. The probes
include crumbs of 19 and 20 bytes. Every run of a browser and protocol agrees.

| Behavior | Chrome 154 and Edge 154 | Firefox 156 |
| --- | --- | --- |
| HTTP/1.1 | One `Cookie` line, joined with `"; "`, last | One `Cookie` line after `Referer` and `Connection`, before `Upgrade-Insecure-Requests` or `Sec-Fetch-Dest` |
| HTTP/2 split | One `cookie` field per cookie, in jar order, before `priority` | One field per cookie, after `Referer`, before `upgrade-insecure-requests` or `sec-fetch-dest` |
| HTTP/2 first request with cookies | Every crumb a literal with incremental indexing naming static entry 32, Huffman-coded | Crumbs under 20 bytes never-indexed literals naming entry 32; the 20-byte and 53-byte crumbs incrementally indexed |
| HTTP/2 later requests | Every crumb an index into the dynamic table | Short crumbs never-indexed again, named by the oldest dynamic `cookie` entry; long crumbs indexed |
| HTTP/3 | One field per cookie before `priority`; each inserted with a static name reference to entry 5 and sent as an indexed field line | One joined `cookie` field after `referer` and `alt-used`, a literal with a static name reference, never inserted |

The HTTP/2 rules match browser source: quiche
`HpackEncoder::CookieToCrumbs` followed by its default indexing policy, and
Firefox's `Http2Compressor::EncodeHeaderBlock`, which never indexes a crumb
shorter than 20 bytes. `vendor/http2/PHANTOM.md` cites both.

`crates/phantom/tests/requests/cookie_crumbs.rs` replays run 0 of each HTTP/2 capture
through a client with a cookie jar and the browser's HTTP/2 and cookie
placement recipes: the loopback origin sets the probes on `/start`, and the
client sends the captured fields of each later request without `cookie`. For
each browser, the ordinary field order and every crumb's value,
representation, index, and Huffman flag equal the capture. In each Firefox
run, 7 of the 15 crumbs name the oldest dynamic `cookie` entry, as Firefox
names a literal with the highest-numbered entry that has its name.
[HPACK encoder evidence](#hpack-encoder-evidence) compares every block of
all three runs byte for byte.

`crates/phantom-net/src/http3/tests/cookie_crumbs.rs` encodes the four
captured requests of each Chromium HTTP/3 capture with a caller `cookie`
field and compares the encoder stream and each field section with the
capture byte for byte. `extended_connect_sends_one_cookie_field_per_jar_cookie`
in `crates/phantom/tests/streams/websocket_profile.rs` checks that the jar's field is
split on an HTTP/2 WebSocket opening too; no capture shows a browser's
WebSocket opening with cookies.

How to reproduce: `scripts/capture/cookie_crumbs.py --browser <browser>
--scenario all --repeat 3`, as shown in the
[capture tool README](../../scripts/capture/README.md#cookie-crumbs).

Limits:

- One origin, five cookies with `Path=/`, and navigations and `fetch()`
  only. No capture covers cookies on a WebSocket opening, a redirect, or a
  proxy route.
- Firefox 156 does not split `cookie` over HTTP/3, and Phantom has no Firefox
  HTTP/3 recipe.
- The HTTP/3 capture server advertised aioquic's QPACK limits (4,096 bytes,
  16 blocked streams), not Chrome's own.
- Indexing crumbs exposes cookie values to the compression side channel
  that RFC 7541 section 7.1.3 describes;
  [Design](design.md#cookie-crumbs-and-compression) explains the trade and
  the opt-out.

### WebSocket browser evidence

What is claimed: Phantom's profile WebSocket connection policy and recipes
open a WebSocket the way Chrome 154, Edge 154, and Firefox 156 do, apart from
the [differences](../reference/websocket.md#differences-from-the-captures)
the WebSocket reference lists.
The Brave 154 and Opera 135 openings match `chromium::v154_websocket` too;
[Brave 154 and Opera 135 recipes](#brave-154-and-opera-135-recipes) records
them.

Evidence: `fixtures/websocket/` retains WebSocket openings from headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 156.0 on Windows 11
(10.0.26200). Each of nine scenarios ran three times on a fresh profile
against loopback listeners: TLS for `server.phantom.test` (ALPN `h2` and
`http/1.1`, a throwaway certificate) and plaintext HTTP/1.1. The page sends a
fixed corpus and closes with 1000 after the echoes return. The corpus is empty
text, 1 B text, 100 B compressible text, 64 KiB of seeded random binary, and
1 MiB of patterned binary.

The fixtures keep the ClientHello ALPN offer per connection; every H2 frame in
both directions, with ordered details; each client HPACK block in hex, with
every representation and decoded field in order; H1 opening lines in hex; and,
per message, the opcode, RSV1, frame payload lengths, and whether the decoded
payload matches the corpus. Masks and payload bytes are not retained. Chromium trusts the certificate
through `--ignore-certificate-errors-spki-list`; Firefox trusts it through a
`cert_override.txt` written only into its disposable profile. Both are
recorded with the launch arguments.

| Behavior | Chrome 154 and Edge 154 | Firefox 156 |
| --- | --- | --- |
| WebSocket on the page's H2 session with the setting | Extended CONNECT | Extended CONNECT; also opens a second H2 connection and closes it with `GOAWAY(NO_ERROR)` |
| First connection to the origin is the WebSocket | New TLS connection offering only `http/1.1`; HTTP/1.1 Upgrade | New TLS connection offering `h2,http/1.1`; extended CONNECT |
| Peer omits `SETTINGS_ENABLE_CONNECT_PROTOCOL` | New connection offering only `http/1.1`; HTTP/1.1 Upgrade | Same |
| CONNECT pseudo-field order | `:method`, `:authority`, `:scheme`, `:path`, `:protocol` | `:method`, `:path`, `:authority`, `:scheme`, `:protocol` |
| CONNECT HEADERS priority | Exclusive, parent 0, weight 147 | Non-exclusive, parent 0, weight 22 |
| Extension offer | `permessage-deflate; client_max_window_bits` | `permessage-deflate` |
| `403` with a body | `RST_STREAM(CANCEL)`; no retry or fallback | No stream reset within 1.5 s; `GOAWAY(NO_ERROR)` on the page session |
| `RST_STREAM(REFUSED_STREAM)` | Same fields retried on the next stream about 1 ms later | No retry; close code 1006 |
| Unoffered extension selected | `RST_STREAM(CANCEL)`; close code 1006 | No stream reset within 1.5 s; close code 1006 |
| RSV1 after deflate is accepted | Every message, including the empty one | Every message except the empty one |
| Fragmentation | One frame per message up to 64 KiB; the uncompressed 1 MiB message split into 9 to 20 frames at boundaries that varied between runs; compressed messages unfragmented | One frame per message |

Further observations:

- Chromium sends no `sec-websocket-key`, fetch metadata, or client hints on
  H2 CONNECT. Its HPACK encoder sends `:method`, `:path`, and `:protocol`
  without indexing, names a repeated static entry with the lower index, and
  Huffman-codes a literal string only when that shortens it. Across the 27
  retained WebSocket captures, all 774 Chrome and Edge coding decisions follow
  that rule, and Firefox codes all 831 of its strings. The rules differ on
  the 105 Chrome and Edge ties, such as `CONNECT`, `13`, `*/*`, `?0`, `?1`,
  and `1`, which code to their own raw length.
- Firefox H2 CONNECT adds fetch metadata (and `sec-fetch-storage-access` from
  a cross-site page) and follows it with a stream `WINDOW_UPDATE`.
- Both browsers compress a 64 KiB random message even though the output
  grows to 65,558 bytes.
- The HTTP/1.1 opening-field order differs by family and is retained
  verbatim. Chromium sends `Connection: Upgrade` second; Firefox sends it
  tenth, with `Upgrade` last.
- Chromium opens idle speculative connections that never send a request; they
  remain in the fixtures.
- In one Chrome `refused-stream` run, the page session closed before the
  socket opened, so that run used the `http/1.1`-only path instead of a
  refused stream.
- Firefox 156.0 is the build the machine had updated to.

`crates/phantom/tests/streams/websocket_profile.rs` drives
`Client::websocket_with_profile_policy` against a loopback origin and
compares what the origin observes with these captures. It compares every
emitted CONNECT pseudo-field with the capture's HPACK `repr`, static
`index`, `name_huffman`, and `value_huffman`. A dynamic-table index itself is
not compared there, because its value depends on earlier blocks on the
connection; [HPACK encoder evidence](#hpack-encoder-evidence) replays whole
connections and compares every block byte for byte.
`hpack_shapes_of_extended_connect_separate_the_client_families` checks that
each recipe emits its own family's `:method` shape and not the other's. The
test of a reopened CONNECT after `REFUSED_STREAM` does not compare HPACK
representations, because the first attempt's dynamic-table entries shrink the
second block; Chrome's capture shrinks the same way. The WebSocket
reference lists where Phantom's recipes still differ from the captured
browsers; see
[Differences from the captures](../reference/websocket.md#differences-from-the-captures).

Direct H2 WebSocket regressions use an authenticated loopback peer that
advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. They assert that Phantom waits
for the initial peer SETTINGS before dispatch; emits CONNECT with `:protocol =
websocket` and the configured five-field pseudo-header order; omits the H1
Upgrade and key fields; preserves ordered ordinary fields; and exchanges
framed messages over simultaneous request and response DATA. Negative cases cover an absent peer setting without CONNECT dispatch or H1
fallback, streaming non-2xx rejection responses, direct-`wss://` route
validation, and a stream-scoped reset. These are standards-level
deterministic fixtures, not named-browser evidence.

How to reproduce: `scripts/capture/http2_websocket.py --browser <browser>
--scenario all --repeat 3`. The Chrome 153 comparison is under
[Comparison with Chrome 153](#comparison-with-chrome-153).

Limits:

- The captures do not cover subprotocols, H3, proxies, or Safari. The macOS
  `accept` and `h1-accept` captures back request fields only; see
  [macOS recipes](#macos-recipes).
- WebSocket proxy routes are covered only by loopback tests; see
  [Forward-proxy evidence](#forward-proxy-evidence).

### WebSocket handshake timer evidence

What is claimed: `chromium::v154_websocket` limits one WebSocket opening to
240 seconds and `firefox::v156_websocket` to 20 seconds, as those browsers'
own handshake timers do. `WebSocketRequestBuilder::handshake_timeout` applies
that limit to the whole opening and fails with
`WebSocketErrorKind::Timeout`. `WebSocketRetryPolicy` retries only a
connection-setup failure that sent nothing to the origin.

Evidence: a capture cannot show a timer that never fired, so the recipes
rest on browser source at Chromium tag `154.0.8037.58` and Firefox tag
`FIREFOX_156_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_websocket` | `kHandshakeTimeoutIntervalInSeconds` is 240, set equal to the TCP connect timeout so that a page cannot tell which step timed out (`net/websockets/websocket_stream.cc:60-64`). `WebSocketStreamRequestImpl::Start` starts the one-shot timer before the opening request starts (`:248-255`), `PerformUpgrade` stops it once the handshake stream is upgraded (`:258-262`), and `OnTimeout` cancels the request with `ERR_TIMED_OUT` (`:338-340`). A failure is reported to the page (`:303-332`); nothing opens the WebSocket again. |
| `firefox::v156_websocket` | `mOpenTimeout` starts at 20,000 ms (`netwerk/protocol/websocket/WebSocketChannel.cpp:1200`) and is read from `network.websocket.timeout.open`, clamped to 1 to 1,800 seconds (`:3511-3514`), whose default is 20 (`modules/libpref/init/all.js:1325`). `BeginOpenInternal` starts the timer after it opens the HTTP channel (`WebSocketChannel.cpp:1403-1420`), `CallStartWebsocketData` cancels it when the handshake completes (`:2974-2982`), and when it fires the connection is aborted with `NS_ERROR_NET_TIMEOUT_EXTERNAL` (`:3342-3351`). |

Differences from the browsers:

- Firefox resolves the host for its per-host admission queue
  (`WebSocketChannel.cpp:2924`, `:2938`) before `BeginOpen`, so that lookup
  is outside its timer. Phantom's deadline starts when `connect` is first
  polled and includes every lookup.
- Firefox delays a new WebSocket to a host whose last attempt failed, by 200
  to 400 ms at first and by up to 60 seconds after repeated failures
  (`WebSocketChannel.cpp:103-117`). Phantom has no such delay across
  connects; a `WebSocketRetryPolicy` delay is the caller's fixed value.
- Edge's network-stack source is not public. The Edge, Brave, and Opera
  WebSocket openings match `chromium::v154_websocket`
  ([WebSocket browser evidence](#websocket-browser-evidence)); their timer is
  assumed to be Chromium's.

Loopback tests in `crates/phantom/tests/streams/websocket_handshake.rs`:

| Test | What it proves |
| --- | --- |
| `handshake_timeout_fires_while_the_name_lookup_is_pending` | A lookup that never answers times out |
| `handshake_timeout_fires_while_the_tls_handshake_is_unanswered` | A TLS handshake that never answers times out |
| `handshake_timeout_fires_while_the_upgrade_response_is_pending` | An H1 opening with no response times out |
| `handshake_timeout_fires_while_an_http_proxy_holds_the_connect` | An unanswered proxy CONNECT times out for H1 and H2 |
| `handshake_timeout_fires_while_a_socks5_proxy_holds_the_greeting` | An unanswered SOCKS5 greeting times out |
| `handshake_timeout_fires_while_an_extended_connect_is_unanswered` | An H2 extended CONNECT with no response times out |
| `handshake_timeout_on_a_pooled_http2_session_cancels_the_stream_and_frees_it` | A profile-policy stream on a pooled H2 session times out, is reset with `RST_STREAM(CANCEL)`, and releases its admission; a request and a WebSocket on the same session then succeed |
| `recipe_handshake_timeout_applies_unless_the_caller_removes_it` | The recipe's timer applies by default, and `handshake_timeout(None)` removes it |
| `no_handshake_timeout_applies_without_a_recipe` | A profile without a WebSocket recipe has no limit |
| `an_unusable_handshake_timeout_fails_before_any_io` | A zero timeout and one beyond the clock fail with `InvalidRequest` without connecting |
| `a_recipe_timeout_beyond_the_clock_fails_the_build` | A recipe timeout beyond the clock fails `build` with `InvalidProfile` |
| `retry_opens_a_new_connection_after_a_failed_lookup` | A failed lookup is retried and the second opening succeeds |
| `retry_covers_a_failed_proxy_lookup_and_an_http2_origin` | A failed proxy lookup is retried for an H2 opening through an HTTP proxy |
| `an_exhausted_retry_budget_returns_the_last_setup_failure` | The budget bounds the attempts, and no policy means one attempt |
| `no_retry_follows_an_invalid_101_or_a_rejection` | A `101` with a wrong accept value and a `503` open one connection |
| `no_retry_follows_an_invalid_extended_connect_answer` | A `200` with an unoffered subprotocol opens one connection |
| `no_retry_follows_a_tls_failure_or_a_handshake_timeout` | A TLS failure and a handshake timeout open one connection |

Each timeout test checks the error kind, the `WebSocketHandshake` phase, the
protocol, and that the error came at the limit. Unit tests of the retry loop
in `crates/phantom/src/websocket/retry.rs` check the delay with a paused
clock.

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- No capture shows either timer firing.
- A handshake timeout is not split by phase: it reports
  `TimeoutPhase::WebSocketHandshake` for any step, as both browsers report one
  timeout.
- No retry test covers a refused TCP connect or a SOCKS5 proxy failure; they
  share the classification of the request pools
  ([Connection-retry evidence](#connection-retry-evidence)).

### HPACK encoder evidence

What is claimed: over HTTP/2, `chromium::v154_http2` and `firefox::v156_http2`
encode request fields as Chrome 154 and Firefox 156 do, down to the byte of
every HEADERS block: which fields enter the dynamic table, which entry names a
literal, which strings are Huffman-coded, and when a dynamic-table size update
starts a block. Edge 154, Brave 154, and Opera 135 use the Chromium recipe
and match it too.

Evidence: every client HEADERS block of every HTTP/2 connection in the
retained cookie and WebSocket captures. Those captures keep each block in hex,
and the WebSocket captures also keep every frame, the server's SETTINGS
included (see
[Cookie crumb evidence](#cookie-crumb-evidence) and
[WebSocket browser evidence](#websocket-browser-evidence)).

| Browser | Connections | HEADERS blocks | Equal to Phantom's |
| --- | --- | --- | --- |
| Chrome 154 | 22 | 66 | All |
| Edge 154 | 21 | 66 | All |
| Brave 154 | 18 | 54 | All |
| Opera 135 | 20 | 50 | All |
| Firefox 156 | 27 | 66 | All |

The rules come from browser source, which the Firefox blocks confirm:

| Rule | Chromium (quiche `HpackEncoder`) | Firefox (`Http2Compressor`) |
| --- | --- | --- |
| Fields kept out of the dynamic table | Pseudo-headers but `:authority` | `:path`; `authorization` and cookie crumbs under 20 bytes as never-indexed literals |
| Field matching a table entry but kept out | Sent as that index, so `:path: /` is index 4 | Sent as a literal naming that entry |
| Entry that names a literal | Static when one has the name, else the newest dynamic | The highest-numbered with the name: the oldest dynamic, else the higher static |
| Largest indexed field | Any size; one larger than the table empties it | Half the table; nothing below a 128-byte table |
| Huffman coding | Only when it shortens the string | Every string, an empty one as `0x80` |
| Size update after `SETTINGS_HEADER_TABLE_SIZE` | Only when the size changes | After every setting, so 4,096 is answered with 4,096 |

Chromium 154's `DEPS` pins quiche `80bf9559d3a4`; Firefox is mozilla-central
`4d5216592535`. `vendor/http2/PHANTOM.md` cites the lines.

`crates/phantom-net/src/http2/tests/hpack_replay.rs` opens an
`Http2Connection` with the family's recipe against a raw peer that sends the
server's SETTINGS, sends each captured request with its pseudo-header
values and ordinary fields (a run of cookie crumbs rejoined into one `cookie`
field), and compares every block the client sends with the capture byte for
byte. Firefox encodes its first request before applying the server's
SETTINGS on 3 connections, where its SETTINGS acknowledgement follows that
request; the replay applies the SETTINGS at the same point.
`chromium_recipe_does_not_reproduce_a_firefox_session` checks that the
comparison separates the families. With the recipes' earlier HPACK
settings, 24 of the 27 Firefox connections differed; every Chromium-family
connection already matched.

How to reproduce: capture with `scripts/capture/cookie_crumbs.py` and
`scripts/capture/http2_websocket.py`, as in the two sections above, then run
`cargo test -p phantom-net --lib http2::tests::hpack_replay`.

Limits:

- The captured requests are navigations, `fetch()` calls, and WebSocket
  openings on one origin, with at most 19 ordinary fields and a table of
  4,096 bytes. The largest captured table entry is 175 bytes, far below
  either size limit, and no Chromium-family request carries `authorization`
  or `content-length`, so the Chromium rules that differ from the vendored
  encoder's defaults rest on source alone. Encoder unit tests in the vendored
  `http2` crate cover them.
- The cookie captures do not record the server's frames. Their replay sends
  the default SETTINGS of the capture server's library, python-h2 4.4.1, as
  the proxy route captures record them from a server built the same way.
  Only the 4,096-byte table size reaches the encoder, and Firefox's first
  block in each cookie run announces exactly that size.
- A field you mark sensitive is always a never-indexed literal, even when a
  table entry matches it, although Chromium has no such form. A `cookie`
  field sent as crumbs is the exception: the crumb rule decides. Phantom
  marks the cookie jar's field (split into crumbs under both recipes) and
  `proxy-authorization`
  ([Proxy authentication evidence](#proxy-authentication-evidence)).
- When a browser applies the server's SETTINGS depends on timing; Phantom
  applies them as soon as they arrive, so a Firefox profile announces the
  table size in whichever block follows their arrival.

### HTTP/2 stream numbering evidence

What is claimed: on every HTTP/2 connection, `chromium::v154_http2` sends
the first request on stream 1 and `firefox::v156_http2` on stream 3, and each
later request takes the next odd stream, as Chrome 154 and Firefox 156 do.
Until the peer states `SETTINGS_MAX_CONCURRENT_STREAMS`, both recipes open at
most 100 streams at once, and SETTINGS that omit the setting leave that limit
in place. A stated value above 256 is lowered to 256 by the Chromium recipe
and applied unchanged by the Firefox recipe. This holds for direct
connections, the pooled HTTP/2 connections to a TLS proxy, and WebSocket
openings over HTTP/2.

Evidence: the stream of every client HEADERS frame on every HTTP/2
connection in the retained cookie, WebSocket, and `https-proxy-*` captures,
on Windows 11 and, for the WebSocket captures, macOS 15.5 and Android
emulators.

| Browser | Platform | Connections | Requests | First stream | Later streams |
| --- | --- | --- | --- | --- | --- |
| Chrome 154 | Windows | 134 | 334 | 1 | +2 each |
| Chrome 154 | macOS | 5 | 8 | 1 | +2 each |
| Edge 154 | Windows | 156 | 459 | 1 | +2 each |
| Edge 154 | macOS | 3 | 9 | 1 | +2 each |
| Brave 154 | Windows | 45 | 183 | 1 | +2 each |
| Opera 135 | Windows | 101 | 331 | 1 | +2 each |
| Opera 135 | macOS | 3 | 9 | 1 | +2 each |
| Chrome for Android 154 | Android 17 emulator | 18 | 54 | 1 | +2 each |
| Brave for Android 153 | Android 15 and 17 emulators | 21 | 63 | 1 | +2 each |
| Edge for Android 153 | Android 17 emulator | 3 | 9 | 1 | +2 each |
| Firefox 156 | Windows | 99 | 246 | 3 | +2 each |
| Firefox 156 | macOS | 3 | 9 | 3 | +2 each |

Firefox source gives the reason. `Http2Session` starts its next stream at 3
and keeps stream 1 for a connection upgraded from HTTP/1.1. It would first
spend streams 3 to 13 on RFC 7540 priority groups, but only while
`network.http.http2.enabled.deps` is set, and that preference is off by
default. Chromium starts at `kFirstStreamId`, 1.

No capture shows the stream limit, because every capture server states 100.
It comes from source:

| | Chromium (`SpdySession`) | Firefox (`Http2Session`) |
| --- | --- | --- |
| Limit before the peer states one | `kInitialMaxConcurrentStreams`, 100 | `network.http.http2.default-concurrent`, 100 |
| A request past the limit | Waits in `pending_create_stream_queues_` | Waits in the queue `QueueStream` fills |
| SETTINGS without the setting | Keep the limit | Keep the limit |
| A stated value | Replaces it, lowered to at most 256 | Replaces it, with no cap |

The sources are Chromium tag `154.0.8037.58` (`net/spdy/spdy_session.h:84`,
`:93`; `net/spdy/spdy_session.cc:383`, `:837`, `:1696-1712`,
`:2355-2358`) and mozilla-central `4d5216592535`
(`netwerk/protocol/http/Http2Session.cpp:172`, `:236`, `:708-716`, `:873-880`,
`:1139-1141`, `:1179-1199`, `:1880-1883`;
`modules/libpref/init/StaticPrefList.yaml:16554-16557`, `:16638-16641`). At
tag `FIREFOX_156_0_RELEASE` the stated value is assigned as it is at
`Http2Session.cpp:1877-1878`.

`crates/phantom-net/src/http2/tests/hpack_replay.rs` checks the stream of
each replayed request against the capture along with its HPACK block, for
the Windows cookie and WebSocket sessions of five browsers. Each recipe's
session capture test, on Windows and macOS, compares the first stream of the
captured navigation with the recipe's.
`crates/phantom-net/src/http2/tests/stream_limit.rs` runs each recipe
against a loopback peer that holds its SETTINGS back: 100 requests arrive
before the peer sends anything, numbered from the recipe's first stream, the
101st waits through SETTINGS without a limit, and it opens once the peer
states 101. A profile without an assumed limit sends all 101 at once. The
same file sends 257 requests to a peer that states 1,000: 256 open under the
Chromium recipe and the last waits through a PING round trip, while all 257
open under the Firefox recipe. The
proxy pool tests check that tunnels to three origins are streams 1, 3, and 5
of one proxy connection under the Chromium recipe and 3, 5, and 7 under the
Firefox recipe. The vendored `http2` crate's own tests cover the limit that
SETTINGS without the setting, wire or seeded through ALPS, leave in place,
and the upstream behavior that lifts it.

How to reproduce: capture with `scripts/capture/cookie_crumbs.py`,
`scripts/capture/http2_websocket.py`, and `scripts/capture/proxy_route.py`,
as in the sections that describe them, then run
`cargo test -p phantom-net --lib http2::tests::hpack_replay` and
`cargo test -p phantom-net --lib http2::tests::stream_limit`.

Limits:

- Every capture server states a limit of 100 in its first SETTINGS, so no
  capture shows what a browser does before or without that setting.
- No capture shows the cap on a stated limit, which rests on source and the
  loopback test.
- The proxy captures show only page requests. Firefox's own background
  requests, which the browser sends on some of the same proxy connections,
  take stream numbers that Phantom's requests take instead.

### HTTP/2 preface PING evidence

What is claimed: on an HTTP/2 connection that has read nothing from the peer
for more than 10 seconds, `chromium::v154_http2` sends a PING right after the
next request HEADERS, or after the next DATA frame with a non-empty payload,
as Chrome 154 does. The first PING on a connection carries the 64-bit
big-endian value 1 and each later one the next value. No other is sent while
one awaits its ACK, and the ACK, like any frame read, restarts the idle time.
Every Chromium-family recipe shares `chromium::v154_http2`, so each sends the
PING. `firefox::v156_http2` sends none.

Evidence: Chromium source at tag `154.0.8037.58` and loopback captures of
Chrome 154.0.8037.58 on Windows 11, one of them retained. `SpdySession::MaybeSendPrefacePing`
(`net/spdy/spdy_session.cc:2446-2456`) queues a PING when ping-based
connection checking is on (`net/http/http_network_session.h:88`, on by
default), none of its own is in flight or awaiting its status check, and the
last socket read (`:2060`) is more than
`kSpdyDefaultConnectionAtRiskOfLossSeconds`, 10, ago
(`net/spdy/spdy_session.h:111`). It runs from `CreateHeaders` (`:1088`) and
from `CreateDataFrame` for a non-empty payload (`:1205-1207`). Both run
inside `DoWrite` (`:2143-2186`), which picks a stream's write before its
producer builds the frame (`net/spdy/spdy_stream.cc:68-84`), so the PING,
queued at the highest priority (`:2479-2499`), is the next write after the
frame. Its payload is `next_ping_id_`, from 1, serialized as 64 bits by
quiche's `SpdyFramer::SerializePing` at the pinned revision `80bf9559d3a4`.
Firefox 156 sends a PING of its own only from its read-timeout tick and on a
network change (`netwerk/protocol/http/Http2Session.cpp:436-503`,
`:4190-4212` at tag `FIREFOX_156_0_RELEASE`).

`scripts/capture/http2_preface_ping.py` serves one page over TLS and HTTP/2
on loopback to headless Chrome, with `--disable-quic`. The page fetches `/a`,
waits 11.5 seconds, fetches `/b`, waits 9 seconds, fetches `/c`, waits 11.5
seconds more, and sends a 100-byte `POST /p` before `/done`. The retained
fixture,
[`preface-ping.txt`](../../fixtures/http2/chrome/154.0.8037.58/windows-11-26200/preface-ping.txt),
keeps every client frame of the page's connection. Those after the first
request:

| Time (s) | Frame | Stream | Payload |
| --- | --- | --- | --- |
| 0.456 | HEADERS `/a` | 3 | |
| 11.982 | HEADERS `/b` | 5 | |
| 11.982 | PING | 0 | `0000000000000001` |
| 11.985 | WINDOW_UPDATE | 0 | |
| 20.999 | HEADERS `/c` | 7 | |
| 20.999 | WINDOW_UPDATE | 0 | |
| 32.516 | HEADERS `/p` | 9 | |
| 32.516 | PING | 0 | `0000000000000002` |
| 32.516 | DATA | 9 | 100 bytes |
| 32.517 | WINDOW_UPDATE | 0 | |
| 32.517 | HEADERS `/done` | 11 | |

`/c` came 9 seconds after the ACK of PING 1 and carried no PING. Two earlier
runs of the same timeline, not retained, showed the same frames. The
retained run took 37 seconds of wall clock.

`crates/phantom-net/src/http2/tests/preface_ping.rs` checks the fixture's
order and payloads, then drives the Chromium recipe through the same
timeline with its idle time scaled to 1 second against a loopback peer and
compares the request frames and PINGs with the fixture's. Other tests there
check no PING after the first request, PING 1 right after the HEADERS of a
request sent 1.5 seconds later, none right after its ACK, PING 2 after the
next idle period, and none with the setting off. The vendored `http2`
crate's tests add the PING after a 4,096-byte DATA frame, none after an
empty END_STREAM DATA frame, and none while PING 1 is unanswered.

How to reproduce:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  python -m scripts.capture.http2_preface_ping --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --output-dir fixtures/http2/chrome/154.0.8037.58/windows-11-26200
cargo test -p phantom-net --lib http2::tests::preface_ping
```

Limits:

- One Windows build and one retained run.
- The capture shows no PING after a DATA frame alone; a `POST` after an idle
  period gets its PING from the HEADERS. That case and the exact 10-second
  boundary rest on source.
- Chrome closes a session whose PING goes unanswered for 10 seconds
  (`ERR_HTTP2_PING_FAILED`). Phantom keeps the connection and sends no
  further preface PING on it.
- Phantom restarts the idle time when a whole frame is read; Chrome restarts
  it on every socket read, including part of a frame.

### Alt-Svc racing evidence

What is claimed: Phantom's opt-in `AltSvcPolicy::race` follows Chrome's
decisions when it races an Alt-Svc alternative against the origin, except for
the listed differences.

Evidence: Chrome 154.0.8037.58 on Windows 11 26200 was captured with
`scripts/capture/alt_svc_race.py`. The loopback origin served H2 over TCP and
H3 over UDP on the same port, advertised as `h3=":<port>"; ma=86400`. Fixtures
are in
[`fixtures/alt-svc/chrome/154.0.8037.58/windows-11-26200/`](../../fixtures/alt-svc/chrome/154.0.8037.58/windows-11-26200/).
The timings and NetLog observations in the table were first recorded from
Chrome 153.0.8010.48, and the Chrome 154 captures reproduced them on every
recorded job decision, bound job, and brokenness lifetime.

Capture conditions:

- Ten headless runs per scenario (two for `broken-backoff`), each on a fresh
  profile.
- Every other host name was unresolvable, so browser background traffic
  neither left the machine nor recorded QUIC success.
- The certificate's SPKI is allowed with `--ignore-certificate-errors-spki-list`.
  Chromium's QUIC proof verifier rejects unknown roots for hosts not named by
  `--origin-to-force-quic-on`
  (`net/quic/crypto/proof_verifier_chromium.cc` line 430), so the capture
  names the same host on a decoy port that is never requested.
- Every race in the NetLogs is an `alternative` job created from
  `ALT_SVC_FOUND`, never a forced-QUIC main job.
- Chrome keeps `HappyEyeballsV3` disabled (`net/base/features.cc`
  line 124), so these are `HttpStreamFactory::JobController` decisions.

| Scenario | Observed | Phantom | Conclusion |
| --- | --- | --- | --- |
| First new connection after learning (`race-after-learning`) | Chrome 153: QUIC job starts first; main TCP job logs `should_wait:true`, then `HTTP_STREAM_JOB_DELAYED delay:0` and resumes 1-2 ms later; first TCP connect 0-1 ms after the first QUIC packet (server: 1.4-1.6 ms after the first datagram, one 11.9 ms outlier). QUIC bound 10/10; the main job was cancelled 10/10, yet its connection was still established and stayed idle without a request. Chrome 154: main job waits 0 ms; alternative bound 10/10. | Alternative setup starts first; origin setup starts after the caller's delay | The main job is blocked while an alternative job exists [1], and the wait is 0 while QUIC has never worked on the network [2] |
| After QUIC worked (`race-after-quic-worked`, second race) | Chrome 153: `HTTP_STREAM_JOB_DELAYED` 3-8 ms (median 7.5); QUIC connected within the wait, the main job never started, QUIC bound 10/10. Chrome 154: main job waits 4-10 ms (median 8). | The caller supplies the delay | The wait is 1.5 x smoothed RTT, or 300 ms without RTT stats, plus a non-Android 0 ms additional delay [3], capped at 3 s [4]; the RTT-dependent value is only what loopback produced |
| UDP blackhole (`udp-blackhole`) | Chrome 153: TCP starts 0-1 ms after QUIC (fresh profile) and wins 10/10; the orphaned QUIC job fails with `-356` after the 4 s handshake idle timeout; the next request logs `is_broken:true` and creates only a main job; polled expiry 299-300 s after the failure. Chrome 154: TCP wins 10/10; orphaned QUIC job fails with `-356`; broken 299-300 s. | The origin wins; the alternative stops at the 4 s limit and is marked broken | The orphaned alternative runs to completion to report brokenness [5] and is marked broken only when the main job succeeded [6]; the 4 s is `max_idle_time_before_crypto_handshake` [7] |
| QUIC certificate failure (`quic-bad-certificate`) | Chrome 153: QUIC fails in about 1 ms; TCP wins 10/10; broken for 299-300 s; the next request does not use QUIC. Chrome 154: TCP wins 10/10; broken 299-300 s. | Origin setup starts at once; the alternative is marked broken when the origin succeeds | Same reporting path as the blackhole [5] [6] |
| QUIC ALPN failure (`quic-bad-alpn`) | Chrome 153: same as the certificate failure, broken 10/10 for 299-300 s. Chrome 154: TCP wins 10/10; broken 299-300 s. | As for a certificate failure | Same reporting path as the blackhole [5] [6] |
| Existing H2 session (`existing-h2-session`) | Chrome 153: the request after learning uses the existing H2 session at once (wait 0) 10/10 while the alternative job keeps running and connects QUIC; the next two same-page requests use that QUIC session 10/10. Chrome 154: binds the H2 session at once while the alternative keeps connecting. | A reusable pooled H2 connection skips the origin delay | Zero wait with an available SPDY session unless `delay_main_job_with_available_spdy_session`, which defaults to false [8] |
| Broken expiry and backoff (`broken-backoff`) | Chrome 153: about 290 s after the first failure the alternative is still broken; about 305 s after it QUIC is tried again, fails, and is broken for 599 s, both runs. Chrome 154: broken 299-300 s after the first failure and 599-600 s after the second. | `AltSvcBrokenBackoff::CHROMIUM_153`: 300 s, doubling, capped at two days | `ComputeBrokenAlternativeServiceExpirationDelay`: 300 s initial, `initial << broken_count`, capped at 2 days [9] |

Source citations, at tag `153.0.8010.48` unless noted:

1. `http_stream_factory_job_controller.cc` line 1084.
2. `quic_session_pool.cc` line 1590.
3. `quic_session_pool.cc` lines 1606-1616.
4. `http_stream_factory_job_controller.cc` line 143.
5. `http_stream_factory_job_controller.cc` lines 1160-1167.
6. `http_stream_factory_job_controller.cc` lines 1257-1302.
7. `kInitialIdleTimeoutSecs` is 5 s (`net/quic/quic_context.h` line 172;
   quiche 2c4a1246 `quic_constants.h` line 159), less the one second quiche
   removes from a client idle timeout (`quic_connection.cc` lines 4983-4984).
8. `http_stream_factory_job_controller.cc` line 744; the default is in
   `net/quic/quic_context.h` line 238.
9. `net/http/broken_alternative_services.cc` lines 22, 58, and 62;
   `net/base/features.cc` lines 1027 and 1037;
   `exponential_backoff_on_initial_delay_` defaults to true in
   `broken_alternative_services.h` line 236.

The Chrome 154 captures used the same scenarios and repeat counts. Two
observations varied between runs of the same build: in one
`race-after-learning` run the NetLog recorded the main job as having opened a
new connection instead of being cancelled, while the alternative was still the
bound job; and in two `quic-bad-certificate` runs the first race after learning
was the `/hold` image rather than `/r/r1`, so the tool aggregated those runs
separately.

Phantom's policy, as [Coverage](../reference/coverage.md#http3) states it,
follows these rows: alternative setup first, origin setup after the caller's
delay or at once when the alternative fails or a reusable pooled H2
connection exists (`existing-h2-session`), one dispatch on the winner, and a
4-second limit on each alternative attempt. Beyond that summary:

- Reaching the 4-second limit marks the alternative broken, matching the
  blackhole rows. Nothing is marked when both candidates fail, and a broken
  alternative is not raced.
- A raced setup offers early data when the client does. Chromium's QUIC
  attempt requires handshake confirmation only when QUIC to the request
  origin's own host and port was recently broken, meaning broken or failed
  and not confirmed since (`net/quic/quic_session_attempt.cc` lines 83-84
  and 227-228; `net/quic/quic_session_pool.cc` lines 2553-2560, whose
  session key `QuicSessionRequest::Request` builds from the request URL at
  lines 442-443;
  `net/http/broken_alternative_services.cc` lines 198-206). Otherwise
  `QuicChromiumClientSession::CryptoConnect` activates the session once 0-RTT
  encryption is established (`net/quic/quic_chromium_client_session.cc`
  lines 1602-1606), so the job can complete, and its request be sent, before
  the handshake. Chromium also requires confirmation until QUIC has worked
  on the current network (`net/quic/quic_session_pool.cc` lines 2388-2392);
  a Phantom client resumes only after a connection that worked.
  `a_raced_alternative_sends_a_replay_safe_request_as_early_data`, in
  `crates/phantom/tests/http3/http3_early_data.rs`, races a resumed alternative
  whose server datagrams are held, and the `GET` reaches it; the store test
  `early_data_waits_until_quic_to_the_origin_connects_again` covers the
  recently broken rule.
- When a session that carried a request closes before its handshake
  completes, Chromium's requests on it fail with `ERR_QUIC_HANDSHAKE_FAILED`
  (`net/quic/quic_http_stream.cc` lines 692-697 and 715-723), QUIC to the
  session's server is marked recently broken
  (`net/quic/quic_session_pool.cc` lines 2714-2731), and
  `HttpNetworkTransaction::HandleIOError` restarts the transaction
  (`RetryReason::kQuicHandshakeFailed`,
  `net/http/http_network_transaction.cc` lines 2077-2078 and 2222-2233),
  which races again without early data. Phantom confirms a raced
  alternative that won on early data only after its handshake completes. If
  the handshake fails, it marks QUIC to the origin recently broken and races
  a request with no body or an owned body again, once. A raced alternative
  that resumed with early data but lost to the origin and then fails its
  handshake marks nothing: Chromium's `ProcessGoingAwaySession` returns early
  for a session that carried no request (`net/quic/quic_session_pool.cc`
  lines 2714-2716).
  `a_raced_alternative_whose_early_handshake_fails_falls_back_to_the_origin`,
  in `crates/phantom/tests/http3/http3_early_data.rs`, shows the retried race
  offering no early data, its alternative failing again, the origin carrying
  the request, and the next request going to the origin with no further QUIC
  attempt.
- `AltSvcBrokenBackoff::CHROMIUM_153` holds a 300 s initial period that
  doubles up to two days. A failure inside an active broken period counts
  toward the next period without extending the current one
  (`broken_alternative_services.cc` lines 137-154).

| Tests | What they cover |
| --- | --- |
| Unit tests with a paused clock: race coordinator | Origin start at the configured delay, immediate start after an alternative failure, cancellation of both candidates, and connect and total deadlines (the coordinator's permit tests use stand-in semaphores) |
| Unit tests with a paused clock: store | Brokenness per origin and alternative, expiry, doubling with a cap, a repeated failure inside one broken period, and clearing on success or `clear` |
| Unit tests with a paused clock: H3 connect turns | One location waits only for its own turn |
| Loopback, `crates/phantom/tests/http3/alt_svc_race.rs`, real client pools | The default sequential terminal failure; one dispatch per request, with background pooling of the losing alternative; a one-shot streaming body sent only by the winner; route preservation |
| Same file: blackholed alternative | Under a short connect timeout it loses after the origin delay. With default timeouts it stops at the 4 s limit, is marked broken, and is not raced again, while a second race queued behind it never opens a QUIC connection |
| Same file: other candidates | Exact H3 to the origin does not wait for a background alternative setup; an available H2 connection skips a 5 s origin delay |
| Same file: admission | With one H3 admission per origin, the alternative's permit is released after a win, after cancellation, and at the 4 s limit of a background setup, while a race still waiting for admission gives its place back |

How to reproduce: `scripts/capture/alt_svc_race.py --browser chrome --repeat
10`, and `--scenario broken-backoff --repeat 2`.

Limits, as differences from Chromium:

- The origin delay is supplied by the caller, because Chromium's depends on
  QUIC history and measured RTT.
- Chromium restarts its 4 s idle timer on every received packet and allows a
  responsive handshake up to 10 s. Phantom limits the whole attempt,
  including name resolution and proxy setup, to 4 s.
- Phantom cancels a losing origin setup instead of keeping its connection
  idle.
- Phantom does not persist brokenness and does not reset it on a network
  change. It races one alternative: a stored Alt-Svc alternative replaces an
  HTTPS-record one, where Chromium runs both jobs unless they name the same
  location.
- A background alternative keeps its H3 admission permit for the origin and
  route until it ends.

### Alt-Svc HTTP/3 upgrade evidence

What is claimed: with the Alt-Svc store enabled, a negotiated request learns
an `h3` alternative and later requests use it, keeping the origin's identity,
with no fallback when the alternative fails.

Evidence: an authenticated loopback H2 origin and H3 alternative share one
test identity while listening on distinct transport locations. Public
negotiated requests prove default-off and explicit bounded activation;
learning from the ordered response fields; an H2 first response followed by
H3; retention of the original authority, SNI, and certificate identity; and
selected-protocol metadata.

The managed H3 attempt carries one automatically generated `Alt-Used` value
with the canonical alternative host and explicit port. Regressions prove that
exact H3 requests and the tested negotiated H2 origin request do not receive
the field. A request-field regression proves that a caller-supplied
`Alt-Used` is rejected before any network I/O. `Alt-Used` is also reserved in
trailers, as part of the pre-I/O validation contract rather than as protocol
coverage claimed here. This evidence verifies the field's value and scope, not
a browser-specific position among ordinary request fields.

Parser regressions cover ordered duplicate fields, canonical host forms,
default and explicit `ma`, `Age` subtraction and expiry, replacement, `clear`,
unsupported alternatives, retention of malformed fields, bounded LRU
eviction, and explicit removal.

Failure regressions close the authenticated alternative before request
dispatch. They prove a typed H3 error, no same-request H1/H2 fallback,
eviction, and recovery through the origin on a later request. A `421` stays
visible as an H3 response, evicts the advertisement, and cannot cause the
alternative connection generation to be reused for the origin's transport
location. Manual clearing is covered through the public client.

H2 ALTSVC frame evidence has two layers:

- Vendored `phantom-http2` regressions write raw frames to a real client
  connection. They prove stream-0 and request-stream delivery in arrival
  order; the rules that ignore a stream-0 frame without an origin and a
  request-stream frame with one; truncated or oversized frames without a
  connection error; the 16-frame drop-oldest bound; and server indifference.
- Facade tests use a raw loopback H2 origin, because the vendored server
  cannot emit ALTSVC. They prove that stream-0 and request-stream frames
  upgrade the next negotiated request, while frames for another origin,
  frames on exact H2 requests, and frames with Alt-Svc disabled do not. A
  frame followed by a `clear` field on the same response proves that updates
  apply in arrival order.

Persistence tests use only the public client API. A learned `ma=3600`
alternative exports its canonical origin, location, and remaining lifetime.
Importing that export into a fresh client upgrades its first negotiated
request without contacting the origin, while an independent client without an
import learns nothing. Constructed snapshots prove removal of expired
entries; non-increasing expiry across repeated export/import round trips;
clamping of far-future expiry; retention of the newest entries at capacity,
with held entries winning; all-or-nothing typed rejection of noncanonical
origins and alternatives; the disabled-store error; and `Debug` output that
contains no host.

A loopback fixture serves exact H3 on the origin's own UDP port and Alt-Svc
H3 on a second port. Alternating requests between the two locations prove one
QUIC connection per location in the same pool entry, with no replacement on
every switch.

The route rules follow Chromium's source at tag `153.0.8010.48`. Chromium
creates the alternative job even when proxied, then fails it with
`ERR_NO_SUPPORTED_PROXIES` unless every hop of the proxy chain speaks QUIC
(`net/http/http_stream_factory_job.cc` lines 858-868), and resumes its main
TCP job. Phantom has no such fallback, so on an HTTP proxy route it never
learns the alternative: negotiated requests run in a CONNECT tunnel and stay
on H1 or H2, where Chromium ends up after its failed QUIC job. Chromium has
no SOCKS5 UDP ASSOCIATE (`net/socket/socks5_client_socket.cc` defines only
`kTunnelCommand`), so its SOCKS5 routes never carry QUIC; Phantom's carry the
Alt-Svc upgrade, as they carry exact H3.

Limits:

- Not covered: browser `Alt-Used` ordering, upgrades on proxy routes,
  snapshots on proxy routes, and racing among multiple alternatives. Racing
  between one alternative and the origin has its own
  [evidence](#alt-svc-racing-evidence).

### HTTPS DNS record evidence

What is claimed: with discovery enabled, an HTTPS DNS record that lists `h3`
for the origin's own host and port sends a later negotiated request over H3
to the origin, without an `Alt-Used` field and without delaying any request
whose profile leaves `ech_from_https_records` unset.

Evidence: `crates/phantom/tests/http3/https_records.rs` runs a loopback DNS server
from `phantom-testkit` beside a loopback H2 origin and H3 endpoint on the
same port. It proves that a sequential client sends the first request to the
origin and a later one over H3 without `Alt-Used`; that a lookup delayed by
4.5 seconds delays neither a sequential nor a racing request, and its answer
still reaches the cache; that a failed lookup leaves requests on the origin;
that a `421` over H3 marks the location broken; that proxy routes send no
query; and that discovery without an Alt-Svc store fails to build. Unit tests
in `crates/phantom/src/session/alt_svc/https_records/tests.rs` cover the
record selection rules, one shared lookup for concurrent requests, expiry,
the capacity bound, remembered failures, and IP-literal origins. Unit tests in
`crates/phantom-net/src/dns/tests.rs` cover the RFC 9460 RDATA parser,
including malformed records, the shape of each query, and the owner check
below. The `https_record` fuzz target feeds arbitrary DNS responses and RDATA
through the same extraction and parser.

A response whose HTTPS answers are not all owned by the end of the query
name's CNAME chain fails the lookup, as Chromium's `ValidateNamesAndAliases`
(`net/dns/dns_response_result_extractor.cc` lines 152-195) fails it. hickory
returns the whole answer section once any record in it answers the question,
so without this check a record for another name could decide whether `h3`
is advertised. A test with a raw loopback responder shows hickory passing
such a record through.

The selection rules follow Chromium's source at 154.0.8037.58:
`ExtractHttpsResults` (`net/dns/dns_response_result_extractor.cc` lines
479-628) decides which records count, and
`QuicSessionPool::SelectQuicVersion` (`net/quic/quic_session_pool.cc` lines
1656-1691) requires one that lists `h3`. The query name is the host for port
443 and `_<port>._https.<host>` otherwise, as in
`dns_util::GetNameForHttpsQuery`.

Each query carries one question with only the recursion-desired flag and no
EDNS(0) record, the shape of Chrome's queries over plain DNS
(`net/dns/dns_query.cc` lines 127-175). A test checks this shape; no capture
does.

Limits, as differences from Chrome:

- Chrome sends the HTTPS query beside its A and AAAA queries from its own
  DNS client (`HostResolverDnsTask::PushTransactionsNeeded`,
  `net/dns/host_resolver_dns_task.cc` line 393) and waits at most 50 ms more
  for it once the address answers arrive (`MaybeStartTimeoutTimer`, line
  1122, with the limits in `net/base/features.cc` lines 88-97). Phantom
  resolves addresses through the operating system, so its HTTPS queries come
  from a second DNS client. No request waits for them, except the TLS
  handshake of a profile that sets `ech_from_https_records`; see
  [Real ECH evidence](#real-ech-evidence).
- An unanswered query is resent after 333 ms and again 333 ms later, on the
  resolver library's schedule rather than Chrome's.
- A record's `ech` value is used only by the profiles and connections
  [Real ECH evidence](#real-ech-evidence) names; every other TLS connection
  offers ECH GREASE only.

### Real ECH evidence

What is claimed: with the Chrome 154, Edge 154, or Brave 154 recipe and
HTTPS record discovery, a direct negotiated connection to an origin whose
HTTPS record carries `ech` encrypts its ClientHello with that
configuration, as Chrome 154.0.8037.58, Edge 153.0.4234.48, and Brave
154.1.96.59 do: the outer server name is the configuration's public name,
the `encrypted_client_hello` extension has the kind, cipher suite, config ID,
encapsulated key length, and payload length the browser sent, and the outer
ClientHello carries the extension set the browser's did. After a rejection it
connects once more to the same address with the server's retry
configurations, or with ECH GREASE and the true name when the server sent
none. The ClientHello waits for the lookup as Chrome's does, for at most 50 ms
after the addresses arrive.

The direct connections of exact-protocol HTTP/1.1 and HTTP/2 requests and of
`wss://` WebSocket openings follow the same rules through the same connection
code. For a `wss://` opening this rests on Chromium's source, not on a
capture: no retained capture shows Chrome's `wss://` ClientHello, whose ALPN
offers only `http/1.1`. A WebSocket over exact HTTP/2 extended CONNECT has no
Chrome counterpart.

Evidence: `fixtures/tls/chrome/154.0.8037.58/windows-11-26200/` retains
`ech-accept.txt` and `ech-reject.txt`, headless Chrome 154.0.8037.58 on
Windows 11 (10.0.26200), recorded by
[`chrome_ech.py`](../../scripts/capture/README.md#encrypted-client-hello)
against a loopback origin that decrypts ECH and a loopback DNS-over-HTTPS
server. Chrome resolved `server.phantom.test` with one `HTTPS` and one `A`
query over DNS over HTTPS and sent no AAAA query.

- `accept`: both connections (the navigation and a preconnect) had outer
  server name `public.phantom.test`, an outer extension with HKDF-SHA256,
  AES-128-GCM, config ID 1, a 32-byte encapsulated key, and a 144-byte
  payload, and the origin decrypted `server.phantom.test` inside.
- `reject`: the origin held a different key. Each of two connections was
  rejected, completed with the public name, and was followed by a connection
  offering the retry configuration (config ID 2), which the origin accepted.
- The outer extension set equals the set of Chrome's ECH GREASE ClientHello in
  `client-hello.txt`.

Brave 154.1.96.59 behaves the same way. Its retained `ech-accept.txt` and
`ech-reject.txt`, under `fixtures/tls/brave/154.1.96.59/windows-11-26200/`,
show the same outer server name and extension fields, the Chrome extension
set without trust-anchor IDs, and, after a rejection, one connection with
retry configuration 2 that the origin accepted.
`outer_client_hello_has_the_shape_brave_154_sent` replays the accept capture
with `brave::v154_tls`, as described below.

`fixtures/tls/edge/153.0.4234.48/windows-11-26200/` retains `ech-accept.txt`
and `ech-reject.txt` from headless Edge 153.0.4234.48 on the same host and
origin. Edge ignores the `Local State` preferences, so its lookups were sent
to the capture server by the `DnsOverHttpsMode=secure` and
`DnsOverHttpsTemplates` machine policies under
`HKLM\SOFTWARE\Policies\Microsoft\Edge`, set for the capture and removed
after it; `chrome_ech.py --dns-from-policy` checked them with `reg query`
before each launch. Three runs of each scenario agreed, and the first of each
is retained.

- Edge sent an `A`, an `HTTPS`, and a second `A` query for
  `server.phantom.test`, where Chrome sent one `A` query. Neither sent an
  AAAA query.
- `accept` and `reject` match Chrome's field for field: the outer server
  name, the outer extension's cipher suite, config ID, encapsulated key
  length, and payload length, ECH accepted with the published key, and a
  rejection of each of two connections followed by a connection with the
  retry configuration, which the origin accepted.
- The outer extension set was the same in all six runs and equals Chrome's.

`crates/phantom-net/src/http1_or_2/tests/ech.rs` replays each browser's
`ech-accept.txt`: Phantom's outer ClientHello, sent with that browser's
recipe to a loopback origin holding the same key, has the same outer server
name, the same extension fields, and the same extension set, GREASE values
folded and order ignored because both permute it. It replays Edge's
`ech-reject.txt` too: with the Edge 154 recipe, the rejected connection and
its retry have the outer name, extension fields, acceptance, and name seen
by the origin that Edge's first rejected connection and its retry had. The
same file proves, against a loopback BoringSSL origin that decrypts ECH,
that the origin receives the inner name; that a rejection is retried once with the retry configurations,
and with GREASE and the true name when there are none, but not when the
server's certificate does not cover the public name; that a second
rejection fails with `EchFailure::Rejected`; that a list which does not parse
fails with `EchFailure::InvalidConfigList` before any TLS byte; and that a
lookup still running after the bounded wait is abandoned.
`crates/phantom/tests/http3/https_record_ech.rs` proves the same through the client
facade with a loopback DNS server, that a profile without the field keeps
GREASE, and that a request through an HTTP proxy sends no HTTPS query and no
ECH.

`crates/phantom/tests/http3/https_record_ech_exact.rs` covers exact HTTP/1.1 and
HTTP/2 requests and WebSocket openings over an HTTP/1.1 Upgrade and over
HTTP/2 extended CONNECT, through the facade:

- Once the record is cached, each connection has its ECH accepted, with the
  origin's name inside.
- A rejection is retried once, with the server's retry configuration.
- Through an HTTP proxy, the client sends no HTTPS query and no ECH.
- With the field unset, the client sends no HTTPS query and every connection
  sends GREASE.
- An exact HTTP/1.1 request, which offers `h2` too, takes a first record that
  supports only `h2`; a WebSocket opening, which offers only `http/1.1`,
  skips it.

`crates/phantom-net/src/dns/ech_config/tests.rs` checks, on truncated,
corrupted, unknown-version, invalid-name, mandatory-extension, and
malformed-extension samples, that the `ECHConfigList` parser accepts exactly
the lists BoringSSL's `SSL_set1_ech_config_list` accepts, and the `ech_config_list` fuzz target
drives it.

Chrome source at tag `154.0.8037.58`, with BoringSSL at Phantom's pinned
submodule commit `f1f2556a`, states the rules the recipe follows:

- ECH is on by default: `kEncryptedClientHelloEnabled` defaults to true
  (`chrome/browser/ssl/ssl_config_service_manager.cc` line 194), which gives
  `EchMode::kOpportunistic` (`net/socket/ssl_client_socket.cc` lines 248-257,
  `net/base/ech_mode.h` lines 32-47): use a configuration when one is
  available, send GREASE otherwise.
- Only direct connections use it: `SSLConnectJob::DoSSLConnect` takes the list
  from the resolved endpoint for a direct connection only
  (`net/socket/ssl_connect_job.cc` lines 406-420), and a proxied request sends
  no HTTPS query, as [HTTPS DNS record evidence](#https-dns-record-evidence)
  records.
- A `wss://` connection takes the same path. `InitSocketHandleForWebSocketRequest`
  passes it to the socket pools with the `https` scheme
  (`net/socket/client_socket_pool_manager.cc` lines 240-271), and
  `ClientSocketPool::CreateConnectJob` builds its connect job as for any
  request, except that ALPN offers only `http/1.1`
  (`net/socket/client_socket_pool.cc` lines 244-256). That offer becomes the
  job's supported protocols (`net/socket/connect_job_params_factory.cc` lines
  71-73 and 323-326), which pick the record below, and `SSLConnectJob` applies
  the record's `ech`.
- The record that counts is the first usable endpoint, in priority order,
  whose protocols include `h2` or `http/1.1`
  (`net/dns/dns_task_results_manager.cc` lines 295-339,
  `TcpConnectJob::IsEndpointResultUsable` and `FindServiceEndpoint`,
  `net/socket/tcp_connect_job.cc` lines 809-854). A first record without
  `ech` means no ECH, even when a later record has it.
- The TCP connect does not wait for the HTTPS answer; the TLS handshake does,
  in `kWaitForCryptoReady` (`net/socket/tcp_connect_job_connector.cc` lines
  250-255), until the HTTPS transaction has finished
  (`net/dns/dns_task_results_manager.cc` lines 128-133 and 266-268). That
  transaction ends with its answer or with a timer that starts once the
  address answers are in and runs for 20% of the DNS time, at least 5 ms and
  at most 50 ms (`HostResolverDnsTask::MaybeStartTimeoutTimer`,
  `net/dns/host_resolver_dns_task.cc` lines 1122-1195, limits in
  `net/base/features.cc` lines 88-110).
- `SSLClientSocketImpl::ConfigureEch` enables GREASE and passes the whole list
  to `SSL_set1_ech_config_list` (`net/socket/ssl_client_socket_impl.cc` lines
  1821-1851); BoringSSL uses the first configuration it supports
  (`ssl/encrypted_client_hello.cc` lines 425-509 and 654-706). A list that
  does not parse fails the connection with `ERR_INVALID_ECH_CONFIG_LIST`
  (`net/base/net_error_list.h` lines 448-449).
- After a rejection, whose certificate BoringSSL checks against the public
  name (`net/socket/ssl_client_socket_impl.cc` lines 1119-1128),
  `SSLConnectJob::DoSSLConnectComplete` retries once on a new connection to
  the same address with the retry configurations
  (`net/socket/ssl_connect_job.cc` lines 251-285 and 506-525); empty retry
  configurations mean GREASE and the true name. A second rejection is
  returned to the caller.

Phantom implements this as `TlsSettings::ech_from_https_records`, set in
`chromium::v154_tls` and kept by `edge::v154_tls`. Edge's network stack
source is not public, so for Edge these rules rest on the captures, which
show the same outer fields and retry, and not on its source. The wait is computed from Phantom's own address
resolution time, since its addresses come from the operating system. It
applies only when the field is set, which replaces, for that profile, the
rule that HTTPS record discovery never delays a request.

- When the client's address cache supplies the addresses, the handshake does
  not wait: the record is used only if its lookup has already finished. A
  Chromium cache hit finalizes the request at once with the HTTPS state
  stored beside the addresses, so its handshake does not wait either
  (`ServiceEndpointRequestImpl::DoResolveLocally`,
  `net/dns/host_resolver_manager_service_endpoint_request_impl.cc` lines
  366-369 and 433-445, and `EndpointsCryptoReady`, lines 161-167).
- Each parallel HTTP/1.1 connection of the negotiated pool, and each
  additional HTTP/2 connection it opens for an origin, offers the record's
  `ech` and waits on its own: every negotiated direct connection is opened by
  the same pool path. All of them join the origin's one shared lookup,
  so the waits overlap rather than add up, and once the lookup is cached no
  connection waits.
  `crates/phantom/tests/http3/https_record_ech.rs` proves three parallel
  connections each have ECH accepted, and
  `crates/phantom-net/src/http1_or_2/tests/ech.rs` proves the no-wait rule on
  a cached address and the wait after a slow resolution.
- Exact-protocol HTTP/1.1 and HTTP/2 requests and `wss://` openings follow
  the same rules on the connections they open, through the same connection
  code. Chrome has no exact-protocol request, so Phantom treats each as the
  direct TLS connection it is and picks the record for that connection's own
  ALPN offer: the exact connectors offer the profile's list, `h2` and
  `http/1.1` in the Chrome recipe, and an opening under Chrome's WebSocket
  policy offers only `http/1.1`. A WebSocket over exact HTTP/2 extended
  CONNECT opens a connection of its own, which Chrome never does, since it
  runs a WebSocket over HTTP/2 only on a session it already has; that
  connection offers the record's `ech` too.

Firefox 156, at tag `FIREFOX_156_0_RELEASE`, does not follow these rules, and
its recipe keeps GREASE:

- It builds the ClientHelloOuter with NSS, not BoringSSL.
- A transaction waits for the HTTPS record only when DNS over HTTPS is active
  (`nsHttpChannel.cpp` lines 8273-8288, `nsHttpConnectionMgr.cpp` lines
  1669-1674); otherwise a record that arrives after the transaction is
  activated is not used (`nsHttpTransaction.cpp` lines 3621-3625).
- Its retry handling differs: `SSL_ERROR_ECH_RETRY_WITH_ECH`,
  `SSL_ERROR_ECH_RETRY_WITHOUT_ECH`, and, for `SSL_ERROR_ECH_FAILED`, the next
  record (`nsHttpTransaction.cpp` lines 1299-1352).

Reproduce: build `cargo build -p phantom-net --example
capture_ech_client_hello`, then run
[`chrome_ech.py`](../../scripts/capture/README.md#encrypted-client-hello)
with `--scenario accept` and `--scenario reject`. For Chrome the tool writes
the `dns_over_https.mode` and `dns_over_https.templates` preferences into
the disposable profile's `Local State` file; it changes nothing outside that
directory. For Edge, pass `--doh-port 65355 --dns-from-policy` after an
administrator has set the two machine policies to `secure` and
`https://127.0.0.1:65355/dns-query`; the capture README has the commands to
set and remove them. The DNS-over-HTTPS server's certificate is self-signed.
`--ignore-certificate-errors` covers it without a trust-store change: the
network context turns the switch into its HTTP session's
`ignore_certificate_errors`
(`components/network_session_configurator/browser/network_session_configurator.cc`
lines 835-837, called from `services/network/network_context.cc` line 3212
at Chromium 153.0.8010.53), and DNS-over-HTTPS requests go through that
context (`net/dns/dns_transaction.cc`). An Edge window started without the
switch, while the policy is set, fails those handshakes.

Limits:

- This section covers connections over TCP. QUIC connections follow
  [Real ECH over QUIC evidence](#real-ech-over-quic-evidence), which differs
  after a rejection: Chrome does not repeat a QUIC connection.
- Chrome's wait timer starts when its own DNS client has both address
  answers; Phantom starts it when the operating system's resolver returns.
  Each Phantom connection times its own wait from its own resolution.
- Phantom keeps addresses and HTTPS records in two caches with their own
  lifetimes, where Chromium keeps one entry for both. An address cache hit
  while the record's lookup is running therefore sends GREASE.
- A record with several `ech` configurations is passed whole to BoringSSL,
  which picks one; no capture shows Chrome with more than one.
- The capture used a single record with `alpn=h2` and a target of `.`.

### Real ECH over QUIC evidence

What is claimed: with the Chrome 154, Edge 154, or Brave 154 HTTP/3 recipe
and HTTPS record discovery, a direct QUIC connection to the origin's own host
and port, whose first record that lists `h3` carries `ech`, encrypts its
ClientHello with that configuration, as Chrome 154.0.8037.58, Edge
153.0.4234.48, and Brave 154.1.96.59 do. The outer server name is the
configuration's public name, the `encrypted_client_hello` extension has the
cipher suite, config ID, encapsulated key length, and payload length the
browser sent, and the outer ClientHello carries the extension set the
browser's did. When the server rejects the configuration, the connection
closes with the TLS `ech_required` alert, QUIC error `0x179`, and is not
repeated over QUIC, with the retry configurations or without them. This
covers an HTTP/3 alternative found through the origin's HTTPS records and an
exact HTTP/3 request on the direct route. The connection starts once the
lookup ends, at most 50 ms after the addresses arrive.

Evidence: `ech-quic-accept.txt` and `ech-quic-reject.txt` under
`fixtures/tls/chrome/154.0.8037.58/windows-11-26200/`,
`fixtures/tls/edge/153.0.4234.48/windows-11-26200/`, and
`fixtures/tls/brave/154.1.96.59/windows-11-26200/`, from headless browsers
on Windows 11 (10.0.26200), recorded by
[`chrome_ech.py --quic`](../../scripts/capture/README.md#encrypted-client-hello).
The loopback origin serves HTTP/3 from a BoringSSL QUIC server that decrypts
ECH, the `phantom-quic-btls` `server` feature, and HTTP/1.1 over TCP on the
same port. Its DNS-over-HTTPS server answers with one record that lists `h3`
and `h2` and carries `ech`. Three runs of each scenario per browser agreed,
and the first of each is retained.

- `accept`: each browser opened a QUIC connection with outer server name
  `public.phantom.test`, HKDF-SHA256, AES-128-GCM, config ID 1, a 32-byte
  encapsulated key, and a 144-byte payload. The origin decrypted
  `server.phantom.test` inside and served the page over HTTP/3. In two of
  Chrome's three runs a second QUIC connection resumed the first one's
  session, with the same outer fields and a 368-byte payload.
- `reject`: the origin held another key. Every QUIC connection, three per
  Chrome run, two per Edge run, and one per Brave run, offered config ID 1,
  and the browser closed it with `0x179` after the origin completed its
  handshake as the public name. None offered the retry configuration. The
  page came over TCP instead: one connection rejected with config ID 1 and
  one retry with config ID 2, which the origin accepted, as in
  [Real ECH evidence](#real-ech-evidence).
- Each browser's outer extension set was the same in all its QUIC
  connections: 14 Chrome connections, 9 Edge connections, and 6 Brave
  connections. Chrome's set equals the set of its ECH GREASE QUIC
  ClientHello in
  `fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt`;
  Edge's and Brave's lack trust-anchor IDs, as their recipes do.
- Chrome and Brave sent one `HTTPS` and one `A` query; Edge sent an `A`, an
  `HTTPS`, and a second `A` query. In these runs Edge read its
  DNS-over-HTTPS server from the `Local State` preferences. Its policy key
  under `HKLM\SOFTWARE\Policies\Microsoft\Edge` existed and held no values.
- A diagnostic Chrome `reject` run with `--log-net-log`, not retained, shows
  each QUIC session closing with `TLS handshake failure
  (ENCRYPTION_FORWARD_SECURE) 121: ECH required`, and the navigation's TCP
  job failing with `ERR_ECH_NOT_NEGOTIATED` (-183) before its retry.

`crates/phantom-net/src/http3/tests/ech.rs` replays each browser's
`ech-quic-accept.txt`: Phantom's outer QUIC ClientHello, sent with that
browser's HTTP/3 TLS recipe to a loopback BoringSSL QUIC origin holding the
same key, has the same outer server name, `ech_outer` fields, 144-byte
payload included, and extension set, order ignored because both permute it.
It replays Chrome's `ech-quic-reject.txt`: with the Chrome 154 recipe the
connection has the rejected connection's outer fields, closes with `0x179`,
and fails with `EchFailure::Rejected`, and no second QUIC connection
arrives. The same file proves that a list which does not parse fails with
`EchFailure::InvalidConfigList` before any packet, and that a lookup which
ends within the bounded wait is used while one past it leaves GREASE.
`crates/phantom-quic-btls/src/backend/server/tests.rs` proves the TLS layer:
the origin receives the inner name, a rejection reports the server's retry
configurations or none, and a rejection by a certificate without the public
name fails verification instead. `crates/phantom/tests/http3/https_record_ech_http3.rs`
proves through the client facade that an exact HTTP/3 request and the
HTTP/3 alternative of an HTTPS record have their ECH accepted once the
record is cached, that a rejection fails the request without a second QUIC
connection, and that a profile without the field sends no HTTPS query and
keeps GREASE. It also proves that a connection which presented a session
ticket, after a resumed connection had its ECH accepted, is not repeated
with a full handshake when the origin's rotated keys reject it, and that a
racing client serves a rejected alternative's request from the origin over
TCP and opens no QUIC connection for the next request, while a sequential
client fails that request with `RequestErrorKind::Tls` and serves the next
one over TCP without another QUIC connection.

Chrome source at tag `154.0.8037.58`, with quiche at the revision its `DEPS`
pins, `80bf9559`, states the rules the recipe follows:

- `QuicChromiumClientSession::GetSSLConfig` enables GREASE and passes the
  endpoint's whole list (`net/quic/quic_chromium_client_session.cc` lines
  1760-1790), which `TlsClientHandshaker` gives to
  `SSL_set1_ech_config_list` (`quiche/quic/core/tls_client_handshaker.cc`
  lines 163-181).
- `QuicSessionPool::DirectJob` resolves the host, HTTPS record included,
  before it starts a session (`DoResolveHost` and `DoResolveHostComplete`,
  `net/quic/quic_session_pool_direct_job.cc` lines 135-189), then takes the
  first endpoint that `SelectQuicVersion` accepts, which for an HTTPS record
  is one listing `h3` (`DoAttemptSession`, lines 191-231, and
  `net/quic/quic_session_pool.cc` lines 1656-1691).
- Nothing in the QUIC path handles `SSL_R_ECH_REJECTED`. The failed
  `DNS_ALPN_H3` job leaves the request to the main job over TCP, and
  `JobController::MaybeReportBrokenAlternativeService` marks the DNS
  alternative broken when the main job succeeds
  (`net/http/http_stream_factory_job_controller.cc` lines 1262-1309).
- Later connections keep offering the cached record's configuration.
  `DoCreateJobs` creates no `DNS_ALPN_H3` job while the DNS alternative is
  broken (`net/http/http_stream_factory_job_controller.cc` lines 926-935),
  for 5 minutes after the first failure, doubling after each later one
  (`net/http/broken_alternative_services.cc` lines 22-60). The retry
  configurations are used only for the one TCP retry that received them
  (`net/socket/ssl_connect_job.cc` lines 251-285, 407-408, and 506-525),
  and nothing under `net/dns` or `net/quic` drops or replaces the cached
  HTTPS record after `ERR_ECH_NOT_NEGOTIATED` or a QUIC ECH rejection. Each
  new TCP connection therefore offers the stale configuration, is rejected,
  and retries, until the record expires.

Phantom implements this through the same `TlsSettings::ech_from_https_records`
field, set in `chromium::v154_http3_tls` and kept by `edge::v154_http3_tls`
and `brave::v154_http3_tls`; `opera::v135_http3_tls` clears it. The
connector checks the list, waits for the lookup as a TCP connection does,
and offers ECH through `QuicClientConfig::with_ech`. A rejection is an
HTTP/3 setup failure like any other: a sequential client fails the request
and marks the alternative broken, and a racing client sends it to the origin
and marks the alternative broken, with Chromium's backoff by default. A
connection that presented a session ticket is not repeated with a full
handshake after an ECH rejection. Like Chrome, Phantom keeps the cached
record and drops the retry configurations.

Limits:

- An Alt-Svc alternative at another host or port sends ECH GREASE. Chrome
  would look up that host's HTTPS records; Phantom looks up only the
  origin's.
- After a rejection, Chrome's QUIC client checks the certificate against the
  origin's true name (`TlsClientHandshaker::VerifyCertChain`, lines
  578-599), and BoringSSL's default verifier, which Phantom uses, checks it
  against the public name. The captures cannot tell them apart, since the
  origin's certificate covered both names. A server whose certificate covers
  only one of them fails the handshake in one client and reports a rejection
  in the other.
- The captures used one record, with `alpn=h3,h2` and a target of `.`, and
  loopback port 443.
- Under the default `AltSvcPolicy::sequential()`, an HTTPS-record
  alternative's setup failure ends the request, where Chrome falls back to
  TCP. A negotiated request to an origin that rejects the record's
  configuration fails with `RequestErrorKind::Tls`, where it used to
  succeed with GREASE. Later requests use TCP while the alternative is
  broken, and the first request after each broken period fails again, until
  the record expires, for at most its TTL, capped at one day.
  `AltSvcPolicy::race` falls back to TCP as Chrome does.
- An exact HTTP/3 request has no Chrome counterpart and no fallback: after
  a rejection it fails with `RequestErrorKind::Tls`, and every later exact
  request to the origin offers the same stale configuration and fails until
  the record expires. Marking the alternative broken does not stop an exact
  request.
- Setting `ech_from_https_records = false` on the value
  `chromium::v154_http3_tls` returns sends GREASE on HTTP/3 and avoids both
  failures.

### QUIC resumption and 0-RTT evidence

What is claimed: with the Chrome 154 or Edge 154 recipe, a resumed Phantom
H3 connection offers the ClientHello extensions and QUIC transport parameters
these captures show for that browser. The Brave 154 and Opera 135 recipes
are compared with their own resumption captures the same way; see
[Brave 154 and Opera 135 recipes](#brave-154-and-opera-135-recipes). Phantom sends `GET`, `HEAD`, and
`OPTIONS` requests issued before the handshake completes in 0-RTT packets,
as the browsers did, and never sends `POST`, `PUT`, or `DELETE` early. Like
Chromium, it starts a resumed connection from the server SETTINGS remembered
with the ticket, so the recipes' dynamic QPACK policy can encode a request
before the server's SETTINGS arrive. The Firefox 156 captures record browser
behavior only; Firefox has no H3 recipe.

Evidence: `fixtures/http3/<browser>/<version>/windows-11-26200/` retains
`resumption-accept.txt` (5 runs), `resumption-accept-delayed.txt` (3 runs),
and `resumption-reject.txt` (3 runs) for headless Chrome 154.0.8037.58 and
Firefox 156.0, and one run of each for Edge 154.0.4258.37, on Windows 11
(10.0.26200). Versions
are the file versions of the installed binaries. Each run used a fresh
profile against an aioquic 1.3.0 server that sends one NewSessionTicket per
connection with `max_early_data_size` 0xffffffff, and forced five new
connections: the first navigation, six concurrent `fetch` calls (`GET`,
`HEAD`, `OPTIONS`, `POST`, `PUT`, `DELETE`), a lone `POST`, a lone `GET`, and
a second navigation. `accept-delayed` holds each connection's datagrams for
50 ms before the server handles them; `reject` resumes the ticket but ignores
the `early_data` offer. Chromium ran with `--disable-field-trial-config`.

Observed on all three browsers:

- Every resumed connection used the ticket from the connection immediately
  before it, and offered `pre_shared_key` with one 64-byte identity and a
  48-byte binder, `psk_key_exchange_modes` `psk_dhe_ke` (1), and
  `early_data`. `psk_key_exchange_modes` is also in every fresh ClientHello.
- Against the same run's fresh ClientHello, a resumed one adds exactly
  `early_data` (0x2a) and `pre_shared_key` (0x29). `pre_shared_key` is always
  last; `early_data` takes a random position, because extension order is
  permuted on every connection. Cipher suites, key-share groups (X25519MLKEM768
  and X25519 for Chromium; X25519MLKEM768, X25519, and P-256 for Firefox), and
  every other extension body are unchanged, apart from key-share values and
  ECH GREASE, which are random per connection, and the transport parameters
  in the table below.
- On a connection that resumed with early data, `GET`, `HEAD`, and `OPTIONS`
  requests issued before the handshake completed arrived in 0-RTT packets.
  `POST`, `PUT`, and `DELETE` never did: each arrived in 1-RTT, including a
  `POST` that was the only request on its connection. A 0-RTT `fetch` `GET`
  carries the same fields in the same order as a 1-RTT one.
- When the server ignored `early_data`, the browsers still sent 0-RTT
  packets, then every request arrived in 1-RTT, and later connections still
  offered `early_data`.

Where they differ:

| Behavior | Chrome 154 and Edge 154 | Firefox 156 |
| --- | --- | --- |
| Transport parameters added on resumption | `initial_rtt_us` (0x3127), carrying the previous connections' RTT: 952-6414 µs on loopback, 41449-59157 µs with the 50 ms delay | None |
| `version_information` | Unchanged apart from the reserved version's position, which varies per connection | Chosen version becomes QUIC v2 (0x6b3343cf), and the resumed connection starts in v2 packets; fresh connections start in v1 and are upgraded by aioquic |
| Later connections that resumed (`accept`, `reject`) | Chrome 39 of 39; Edge 8 of 8 | 22 of 32 |
| Resumption in `accept-delayed` | Chrome 12 of 12; Edge 4 of 4 | 0 of 12 |
| Second navigation in 0-RTT (`accept`) | Chrome 0 of 5; Edge 0 of 1 | 2 of 5 |
| Second navigation in 0-RTT (`accept-delayed`) | Chrome 3 of 3; Edge 1 of 1 | none resumed |

The Chromium navigation arrived in 1-RTT because of a preconnect. A
diagnostic Chrome run with `--log-net-log`, not retained, showed a preconnect
job (`is_preconnect: true`) open the QUIC session about 5 ms before the
navigation request, reach `QUIC_SESSION_ZERO_RTT_STATE
AttemptedAndSucceeded`, and complete the loopback handshake before the request
bound to it. With 50 ms of added delay the navigation was issued during the
handshake and arrived in 0-RTT on every Chrome and Edge run.

The same log explains the extra connection at startup in 4 of 5 Chrome
`accept` runs, and in 4 of 5 Edge 153 runs; the one Edge 154 run had none.
A first preconnect opened a fresh session
(`QUIC_SESSION_ZERO_RTT_STATE NotAttempted`). The pool then logged
`QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY`, and a second
preconnect opened a session that resumed the first session's ticket and
carried the first navigation. The first session stayed open and idle.

Firefox did not resume after every connection. One run with
`MOZ_LOG=nsHttp:5,SSLTokensCache:5` in the `accept-delayed` scenario showed no
`ResumptionToken` event and no token stored for the origin, so each later
connection started without a PSK. Why the token was not released was not
investigated. Firefox needs
`network.http.http3.disable_when_third_party_roots_found=false` to keep an H3
connection whose certificate is trusted through `cert_override.txt`.

Each Chrome and Edge connection that sent a request in 0-RTT also sent 0-RTT
data on client stream 10, and no other resumed connection did. Stream 10 is
Chromium's QPACK encoder stream (see the source below), so Chromium inserted
into the dynamic table in 0-RTT, using the table capacity the aioquic server
advertised on the ticket's connection.

The `resumption-streams-accept.txt` and `resumption-streams-reject.txt`
fixtures repeat the `accept` and `reject` scenarios, three runs each per
browser, and also record each client unidirectional stream's type and the
packet-number space, length, and arrival time of the STREAM frame that carried
its first byte. In all 69 Chrome and Edge connections, fresh or resumed:

- client stream 2 is the control stream (type 0x00), and its first byte
  arrives before any other unidirectional byte. On all 29 resumed
  connections whose early data was accepted it arrived in 0-RTT packets;
- client stream 10 is the QPACK encoder stream (type 0x02). It is written on
  exactly the connections that carried a request, 0.1 to 2.6 ms before the
  first request's HEADERS reached the server, and its first STREAM frame
  holds 367 to 476 bytes: the type, the table capacity, and the request's
  inserts. A connection that carried no request, such as an idle preconnect,
  wrote only stream 2;
- client stream 6 is the QPACK decoder stream (type 0x03). It was written on
  33 connections, always after stream 10 and in 1-RTT packets, with a first
  STREAM frame of 2 or 5 bytes: the type and its first feedback;
- when the server rejected early data, streams 2 and 10 and every request
  were written again in 1-RTT packets on the same connection, with the same
  stream numbers, when the handshake completed.

Chromium's source shows what it remembers. Chrome 154.0.8037.58's `DEPS`
pins quiche `80bf9559d3a4c08dde4b85abc46d190a88ffef64`; paths below are under
`quiche/quic/core/` at that revision:

- `http/quic_spdy_client_session_base.cc`, lines 82-89: after the client
  applies the server's control-stream SETTINGS, it serializes the frame and
  passes it to the crypto stream as the ticket's application state.
  `tls_client_handshaker.cc`, lines 731-737 and 778-794, holds up to two
  tickets that arrive before that state and stores them once it is known.
- `tls_client_handshaker.cc`, lines 216-245, and
  `http/quic_spdy_session.cc`, lines 1069-1088: when a connection enters early
  data, the client applies the remembered SETTINGS before the server's
  arrive. A ticket without decodable state closes the connection.
- `http/quic_spdy_session.cc`, lines 1224-1289, with
  `qpack/qpack_header_table.h`, lines 215-224, and `qpack/qpack_encoder.cc`,
  lines 433-439: the server's SETTINGS must repeat a remembered nonzero QPACK
  table capacity exactly, and must not lower the field-section or
  blocked-stream limits. `http/quic_spdy_client_session_base.cc`, lines
  49-80, also rejects omitting a remembered non-default limit when the early
  data was accepted. The close is `QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH`,
  sent as `H3_SETTINGS_ERROR` (`quic_error_codes.cc`, lines 708-711).
- `tls_client_handshaker.cc`, lines 711-720, and `quic_session.cc`, lines
  2038-2049: when the server rejects early data, the client marks its 0-RTT
  packets for retransmission on the same connection. The remembered
  SETTINGS stay in force: `http/quic_spdy_session.cc`, lines 1224-1289,
  closes a connection whose server SETTINGS then lower a remembered limit
  with `QUIC_HTTP_ZERO_RTT_REJECTION_SETTINGS_MISMATCH`, sent as the
  transport error `INTERNAL_ERROR` (`quic_error_codes.cc`, lines 710-711),
  and `http/quic_spdy_client_session_base.cc`, lines 49-80, skips the
  omitted-setting checks after a rejection.
- `http/quic_spdy_session.cc`, lines 1629-1676: the client opens its control
  stream, then its QPACK decoder stream, then its encoder stream, so they are
  client streams 2, 6, and 10. `qpack/qpack_send_stream.cc`, lines 32-51,
  writes a QPACK stream's type byte only with its first instruction.

Replay against Phantom:

- `chromium_resumption_captures_match_the_quic_recipe`, in
  `crates/phantom-profile/src/chromium/quic_tests.rs`, reads every Chrome and
  Edge connection in the six fixtures. Each resumed one offered early data and
  carried the `chromium::v154_quic` parameter set plus `initial_rtt_us`; no
  fresh one carried `initial_rtt_us`. Where the fixture keeps raw ClientHello
  bytes (the first run of each scenario), `initial_rtt_us` has a two-byte id,
  a one-byte length, and a minimal-length varint value equal to the recorded
  `initial_rtt_us` field. The recipe lists the parameter with those widths.
- `resumed_chromium_client_hellos_match_the_resumption_captures`, in
  `crates/phantom-net/src/http3/tests/resumption.rs`, learns a ticket that
  permits early data from a loopback server with each recipe, then builds the
  resumed ClientHello and compares it with every resumed ClientHello the
  browser's fixtures keep. The extension sets are equal, with `early_data`
  present and `pre_shared_key` last in both. Cipher suites, supported
  versions, groups, key-share groups, signature algorithms, ALPN, trust
  anchors, and the `early_data`, `psk_key_exchange_modes`, and ALPS bodies are
  equal. The transport parameters have the same ids and id and length widths;
  their values are equal apart from GREASE, the reserved version's position,
  and `initial_rtt_us`, whose value must be a positive minimal-length varint.
- `a_resumed_connection_adds_only_initial_rtt_as_a_minimal_varint`, in
  `crates/phantom-quic-btls/src/transport_parameters/tests.rs`, encodes the
  captured values 2509 µs and 54894 µs as `0x49cd` and `0x8000d66e`, varies
  the parameter's position with the permutation, and omits it when there is
  nothing to send.
- `resumed_connection_sends_get_early_and_holds_post`, in
  `crates/phantom/tests/http3/http3_early_data.rs`, uses the Chrome 154 recipes,
  with their dynamic QPACK policy and no early-data setting from the caller.
  A relay holds every server datagram, so no handshake can complete and the
  server's SETTINGS never reach the client: a resumed connection's `GET`
  reaches the server through it, so it left in 0-RTT packets, encoded with
  the remembered SETTINGS. A resumed connection's `POST` does not arrive
  until the relay opens. The `POST`'s connection still offered early data.
- `concurrent_requests_share_one_resumed_connection`, in the same file,
  sends `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, and `DELETE` at once to a
  resumed origin with the Chrome 154 recipes, and the server sees one new
  connection, as Chrome 154 put its six concurrent fetches on one resumed
  connection. `rejected_early_data_is_sent_again_on_the_same_connection`
  shows a `GET` sent early and rejected reaching the server on the same
  connection, with no second connection. Other tests there show a rejected
  connection sending a waiting `POST` once with its whole body, a failed
  handshake failing the request without a second connection, and the
  connect timeout bounding the wait for the early-data answer.
- `dynamic_qpack_sends_a_replay_safe_request_early_from_remembered_settings`,
  in `crates/phantom-net/src/http3/tests/early_data.rs`, shows the recipe's
  `GET` opening its stream before the handshake on a connection that started
  from remembered SETTINGS.
  `a_server_that_reduces_a_remembered_setting_is_closed_with_settings_error`
  resumes against a server that lowers the field-section limit it advertised
  on the ticket's connection, and the server sees the connection closed with
  `H3_SETTINGS_ERROR` (0x109).
  `rejected_early_data_restarts_http3_on_the_same_connection` resumes
  against a server that rejects early data: the `GET` sent early fails as
  unprocessed, the connection stays reusable, and a `GET` and a `POST` sent
  on it after the handshake reach the server on the same connection.
  `rejected_early_data_discards_the_remembered_settings` shows that a server
  that rejects early data and lowers a remembered limit is not closed.
  The gate tests are in `crates/phantom-net/src/http3/tests/early_streams.rs`.
  `an_early_session_opens_only_on_a_published_acceptance` shows the early
  session waiting to open a stream after the handshake completed, refusing
  after a rejection without allocating a stream, waiting on Quinn's
  acceptance alone, and opening on the published acceptance.
  `a_request_between_the_handshake_and_a_rejection_is_sent_once` holds the
  published answer after Quinn's rejection arrives, before HTTP/3 starts
  again, sends a request in that interval, and the server sees it once, on
  the new session.
  `a_handshake_that_completes_after_the_permit_holds_the_stream` completes
  the handshake, through a hook, after the gate granted a handshake-time
  permit and before the stream opens; the stream is held and reset unused
  on the rejection.
  `a_parked_request_does_not_open_before_invalid_metadata_is_found` parks a
  request on stream credit through an accepted handshake whose ALPS then
  fails its checks, and the server never sees it.
  `a_rejection_between_two_polls_of_a_request_waiting_for_credit_refuses_it`
  shows the rejection waking such a request.
  `a_rejection_while_the_early_session_starts_keeps_the_connection` makes
  the early session's second and third streams wait until the handshake
  completed with a rejection; the connection reports the rejected early
  data, starts HTTP/3 again, and carries a request. The server reads the
  control stream type on client stream 2, the QPACK decoder stream type on
  6, and the QPACK encoder stream type on 10, Chrome's order. The stress
  test below found this case.
  `an_acceptance_while_the_early_session_starts_keeps_the_connection` does
  the same with the early data accepted: the session opens its last two
  streams in 1-RTT, the server reads the same three types on streams 2, 6,
  and 10, and two requests succeed. Both tests write the QPACK stream types
  when the session starts, so the server sees every type.
  Two tests force races that a multi-threaded runtime can produce on its
  own, through hooks, and check that the hook's race happened.
  `a_stream_opened_after_a_rejection_at_start_goes_to_the_new_session`
  opens the early session's control stream only after Quinn rejected the
  early data, a rejection between reading Quinn's answer and opening the
  stream; the stream is live on client stream 2 and becomes the new
  session's control stream.
  `a_discarded_session_polled_before_the_answer_keeps_the_connection` makes
  the driver poll the early session before it reads the rejection; the
  session's close is held and dropped, and HTTP/3 starts again. Both check
  the server's stream types on client streams 2, 6, and 10 and a request.
  `an_early_session_accepts_server_streams_only_after_an_acceptance` shows
  that a transport whose early data Quinn rejected accepts no server
  stream, and one whose early data Quinn accepted does.
  `an_acceptance_wakes_a_waiting_server_stream_accept` holds Quinn's answer
  while the transport waits to accept a server stream; the acceptance wakes
  it. The first three tests fail with their fix removed. A Linux run pinned to four CPUs under load
  failed about half of the stress runs below before these fixes, with the
  three failures these tests reproduce. After them, 1,500 iterations of
  each scenario passed on the same setup, 552 of the handshake-window ones
  with the rejection during the start.
  `rejection_scenarios_hold_under_a_multi_threaded_runtime` repeats the
  credit-wait and handshake-window rejections on a four-worker runtime with
  a random 0-3 ms delay before the gate sees Quinn's answer; 200 iterations
  of each passed. It varies when the answer reaches the gate relative to
  whole polls of the waiting requests and to the answer's publication. It
  does not reach windows inside one poll, such as the handshake completing
  between the permit and the open; the hook-driven tests above cover those.
  A connection whose rejection arrived while its early session was still
  starting is checked as such and counted apart. `PHANTOM_H3_STRESS_ITERATIONS`
  and `PHANTOM_H3_STRESS_SEED` set the repetitions and the delay seed, which
  each failure and the counts report; the seed reproduces the injected delays
  only, not the runtime's scheduling.
  `a_request_waiting_for_stream_credit_does_not_block_a_rejection` holds
  the send lock in a request waiting for 0-RTT stream credit when the
  rejection arrives; both requests fail as unprocessed and the connection
  then carries a request. `a_held_stream_is_reset_unused_after_a_rejection`
  shows a held stream reset after a rejection or when its opener is
  dropped, and the next stream numbered after it.
  `remembered_settings_stay_with_their_ticket_cache_and_server_name` shows
  that neither another pool entry's cache nor another server name starts
  from them.
- In `crates/phantom-quic-btls/src/backend/client_session/tests/resumption.rs`,
  `application_state_is_stored_with_held_tickets_and_read_back_for_early_data`
  shows a ticket held until its connection records the SETTINGS and read
  back only through the same cache;
  `early_data_needs_a_ticket_stored_with_application_state` and
  `held_tickets_are_bounded_and_dropped_with_oversized_state` cover the
  bounds.
- The Brave 154 and Opera 135 resumption fixtures predate the stream-type
  fields but keep each connection's stream numbers, and
  `brave_and_opera_captures_use_the_recipe_s_qpack_stream_numbers` checks
  them in all 116 connections: every connection wrote client stream 2, one
  that carried a request also wrote stream 10 and sometimes stream 6, and an
  idle one wrote nothing else. Their stream types are not recorded.
- `chromium_captures_open_qpack_streams_in_the_recipe_order`, in
  `crates/phantom-profile/src/chromium/http3_tests.rs`, reads the four
  `resumption-streams-*` fixtures, checks the stream order and types above,
  and checks that `chromium::v154_http3` opens the decoder stream first
  (`Http3QpackStreamOrder::DecoderFirst`) and defers both QPACK stream types.
  `chrome_request_matches_captured_qpack_on_a_live_connection`, in
  `crates/phantom-net/src/http3/tests/request.rs`, sends the recipe's request
  to a loopback server, which sees the control stream as stream 2, the
  encoder stream as stream 10 with the captured instructions after its type,
  and no decoder bytes. The vendored `h3` tests
  `chromium_stream_order_writes_the_encoder_stream_type_with_its_first_instructions`
  and `a_held_stream_type_is_written_with_the_first_field_section_instructions`
  show that the table-capacity instruction waits for the first field section
  and follows the type.
- The vendored `h3` tests `dynamic_request_uses_remembered_settings_before_any_peer_settings`,
  `remembered_settings_apply_until_compatible_control_settings_replace_them`,
  `control_settings_incompatible_with_remembered_settings_are_rejected`,
  `late_application_settings_incompatible_with_remembered_settings_are_rejected`,
  and `remembered_settings_do_not_stand_in_for_the_control_stream_settings`
  fix the encoder-stream and HEADERS bytes sent from remembered SETTINGS and
  each compatibility rule.

Phantom sends as `initial_rtt_us` the smoothed round-trip time that Quinn
last measured on a connection to the same server name through the same pool
entry. A connection records it when its handshake completes and again when
it closes. Phantom sends the parameter only on a connection that presents a
ticket. In every resumed Chromium connection in these captures, the ticket
came from the connection immediately before it, which was also the most
recent connection to the server, so the captures cannot tell a value that
follows the ticket from one that follows the latest connection. Phantom keeps
the latest measurement.

How to reproduce: `scripts/capture/quic_resumption.py`;
[Capture tools](../../scripts/capture/README.md#quic-resumption-and-0-rtt)
has the commands and launch flags.

Limits:

- Loopback only. Whether a navigation reaches 0-RTT depends on handshake time
  against preconnect timing, which the 50 ms delay only approximates.
- The server sends one ticket per connection, so how many tickets a browser
  keeps, and which it prefers, is not observed.
- Chromium's `initial_rtt_us` appeared only on connections that also resumed.
  These captures cannot tell whether it follows the ticket or Chromium's
  stored network statistics for the server. If it follows the statistics, a
  Chromium connection that has statistics but no usable ticket would send it
  and Phantom's would not; no capture shows such a connection.
- The `initial_rtt_us` value is Phantom's own measurement, so the tests
  compare its encoding, not its value.
- Phantom keeps only the SETTINGS it understands, where Chromium keeps the
  whole frame; the kept values are the same. Phantom also rejects a server
  that disables a remembered extended CONNECT, HTTP Datagram, or WebTransport
  setting, or lowers a remembered WebTransport session limit, which quiche
  does not check. The tests use a server built on the vendored `h3`, which
  advertises no QPACK table capacity, so they show a request sent from
  remembered SETTINGS but no dynamic-table insert in 0-RTT; the vendored
  `h3` test fixes those bytes.
- When a server that accepted early data changes or omits a remembered
  nonzero QPACK table capacity, Phantom closes with `H3_SETTINGS_ERROR`, as
  quiche does, where RFC 9204 section 3.2.3 names
  `QPACK_DECODER_STREAM_ERROR`.
- When the server rejects early data and then sends SETTINGS that lower a
  remembered limit, Chromium closes the connection with the transport error
  `INTERNAL_ERROR`. Phantom drops the remembered SETTINGS with the rejected
  session, uses the server's new SETTINGS, and keeps the connection open.
- After rejected early data, Chromium retransmits its encoder-stream and
  request bytes, encoded from the remembered SETTINGS. Phantom's new session
  encodes from the server's SETTINGS once they arrive, so its encoder-stream
  bytes match only when the server's QPACK settings did not change.
- Headless launches on one Windows build; no TCP TLS resumption capture.
- Chromium ran with `--disable-field-trial-config`; the retained Chrome 154
  startup captures ran without it. The fresh ClientHello of Chrome `accept`
  run 0 still has the same extension set and transport-parameter values as
  the retained `quic-client-hello-1.txt`, apart from the reserved version's
  position in `version_information`. Other fresh ClientHellos were not
  compared with the startup captures.

### TLS resumption over TCP evidence

What is claimed: over TCP, a resumed Phantom ClientHello has the extension
set the captures show for its recipe's browser, with `pre_shared_key` last,
when the server's ticket does not permit early data. With the Chromium-family
recipes this also holds when the ticket permits early data. Phantom keeps as
many tickets per origin as the browser did, presents the newest first, and
uses each once.

Evidence: `fixtures/tls/<browser>/<version>/windows-11-26200/` retains nine
`resumption-<scenario>.txt` fixtures, three runs each, for headless Chrome
154.0.8037.58, Edge 154.0.4258.37, Brave 154.1.96.59, Opera 135.0.5973.92,
and Firefox 156.0 on Windows 11 (10.0.26200). Each run used a fresh profile
against the `tls_resumption.py` loopback server, which sends two
NewSessionTickets after every handshake (eight after the first handshake
only, in `issue-once`), each permitting early data except in
`no-early-data`. [TLS resumption over TCP](../../scripts/capture/README.md#tls-resumption-over-tcp)
lists the scenarios and the fields each fixture keeps.

Observed:

| Behavior | Chrome 154, Edge 154, Brave 154, Opera 135 | Firefox 156 |
| --- | --- | --- |
| Resumed ClientHellos, all offering one 64-byte identity and one 32-byte binder, `pre_shared_key` last, PSK mode `psk_dhe_ke` (1) | 151, 146, 111, 154 | 131 |
| Added against the run's first, fresh ClientHello | `pre_shared_key` only | `early_data` (0x2a) and `pre_shared_key`; only `pre_shared_key` when the ticket does not permit early data (12 of 12) |
| Removed against the fresh ClientHello | Nothing; the empty `session_ticket` stays | The empty `session_ticket` (0x23), in all 131 |
| `early_data` offered over TCP | Never, including with tickets that permit it | 119 of 119 resumptions with such a ticket; placed after `key_share` and before `supported_versions` |
| Requests sent in early data | None | `GET` 106 times, and `HEAD` and `OPTIONS` once each; `POST`, `PUT`, and `DELETE` never (20 on connections that used early data) |
| Tickets used of eight issued by one connection (`issue-once`) | 2 of 8 in every run: the newest, then the one before it | 8 of 8 in every run, each once; newest first in 2 of 3 runs |
| Ticket presented twice | Never | Never |
| Six connections opened at once for slow requests (`parallel`) | Two or three resumed, each with its own ticket | Four to six resumed, each with its own ticket |
| First connection to the same host on another port (`origins`) | No ticket offered, in every run | No ticket offered, in every run |
| A `top.partition.test` page fetching the origin (`partition`) | No ticket offered; back on the origin's own page, a ticket learned before the switch | The same |

The Chromium-family browsers always presented the newest ticket they held;
Firefox's choice between the two tickets of one connection varied. Some
connections carried no request: the Chromium-family browsers often open a
first connection that closes before the navigation. Firefox sometimes made a
full handshake although earlier connections had received tickets, in 5 of
its 24 `sequential` and `sequential-http1` connections from the fourth on.

Replay against Phantom, in `crates/phantom-net/src/tls/tests/resumption.rs`:

- `chromium_resumed_client_hellos_match_the_tcp_resumption_captures` learns a
  ticket from a loopback server with each Chromium-family recipe and compares
  the resumed ClientHello with every resumed ClientHello its browser's
  `resumption-sequential.txt` keeps. Cipher suites, groups, key-share
  groups, signature algorithms, versions, ALPN, trust anchors, the PSK modes
  body, and the extension set are equal apart from GREASE; `pre_shared_key`
  is last, with one identity and one 32-byte binder; the empty
  `session_ticket` stays; and the resumed ClientHello adds only
  `pre_shared_key` to Phantom's fresh one.
- `firefox_resumed_client_hello_matches_the_capture_without_early_data` does
  the same with `firefox::v156_tls` and `resumption-no-early-data.txt`, and
  also requires the exact extension order, which is Firefox's fixed order
  without `session_ticket` and with `pre_shared_key` appended.
- `firefox_resumed_client_hello_lacks_only_the_early_data_firefox_offers`
  compares with `resumption-sequential.txt`, whose tickets permit early data:
  removing `early_data` from Firefox's order gives Phantom's order.
- `concurrent_connections_resume_up_to_the_recipes_tickets_per_origin`
  learns two tickets, resumes once (which stores two more), then opens three
  connections at once. With `chromium::v154_tls` two resume and one makes a
  full handshake, because only the two newest tickets remain; with
  `firefox::v156_tls` all three resume.

The recipes carry the retention as `TlsSettings::session_tickets_per_origin`
(2 for the Chromium family, 8 for Firefox) and the `session_ticket` choice as
`TlsSettings::session_ticket_extension_when_resuming`.

Limits:

- Firefox 156 offers early data over TCP and sends safe requests in it when
  its ticket permits early data. Phantom never offers early data over TCP, so
  against such a server a resumed Firefox-profile ClientHello lacks
  `early_data`, and its requests arrive after the handshake.
- A Phantom client has no network partitions. Its requests behave like one
  browser page's top-level site: each origin and route has one ticket cache.
- Firefox's order among the tickets it holds varied between runs; Phantom
  presents the newest first. Firefox held all eight tickets it was given, so
  its true limit may be higher than the recipe's eight.
- Loopback, headless, and HTTP/1.1 or HTTP/2 only. The captures cannot show
  how long a browser keeps a ticket; every ticket was valid for one day.

### Ordered request-trailer evidence

What is claimed: Phantom emits the trailer block the caller selects, with the
documented protocol semantics.

Evidence: request trailers produced by a declared streaming body are covered
through the public client on exact H1, H2, and H3 paths and on negotiated
H1/H2 paths. Static trailers are covered at each transport boundary and in the
public route and retry lifecycles. The regressions assert raw H1 bytes,
including casing, declaration, order, and interleaved duplicates; ordered H2
trailing fields, and the HPACK never-indexed representation for sensitive
values; and H3 trailing HEADERS encoded through the connection's stateful
QPACK encoder.

Lifecycle tests cover trailer-only, owned, and streaming bodies, matching of
declared names and multiplicity, refusal to replay a one-shot body, pre-I/O
validation, and suppression after a body error.

Limits:

- It does not claim that a built-in browser profile emits those
  application-defined trailers by default.

### Forward-proxy evidence

What is claimed: exact-H1 forwarding and WebSocket Upgrade through HTTP
forward proxies, with challenge-driven Basic authentication, never fall back
to CONNECT, a direct route, or another protocol.

Evidence: the public exact-H1 route tests forward an `http://` origin in
absolute form through plaintext and TLS-encrypted proxies. The TLS fixture
proves that Phantom verifies the proxy certificate and hostname with the
independent proxy trust store, sends the request directly after the proxy TLS
handshake with no CONNECT exchange, and returns the proxied response through
the normal streaming body path. Negative cases cover missing proxy trust,
non-H1 selections, and proxy failure without fallback to a direct route.

Authentication regressions prove that the first request to a proxy is sent
without credentials, and that only a strict, valid Basic `407` challenge
triggers one replay over the same route, on the challenged connection when
the `407` leaves it open. They assert
the position of the generated sensitive `Proxy-Authorization` field, after the
caller's fields and before framing; exact replay of owned bodies and static
trailers, and failure before a retry connection opens for a one-shot
streaming body; and typed proxy errors, without direct or protocol fallback,
for a second `407` and for malformed or unsupported challenges. Once the proxy
accepts the replay, later logical requests carry the credentials on their
first attempt over the pooled connection; with
`preemptive_proxy_authentication(false)` each starts without them
([Proxy authentication evidence](#proxy-authentication-evidence)). Without
configured credentials, a caller's own `Proxy-Authorization` field reaches
the proxy unchanged on the first request; on a direct route or a proxy with
configured credentials, it fails before any network I/O.

Lifecycle cases also cover a nonempty challenge body; a queued request that
installs an intervening pooled connection without capturing the
authenticated retry; one total deadline spanning both attempts; and
suppression of cookies from the challenge response, while cookies from the
final origin response are kept.

The HTTP/2 proxy transport has separate CONNECT regressions for H1 and H2
origins in `crates/phantom/tests/proxies/proxy_h2.rs`. The same file forwards an
exact H2 and a negotiated `http://` request over one HTTP/2 proxy
connection, and asserts `:scheme` `http`, the origin in `:authority`, the
fields, and an H2 `ResponseInfo::protocol`; it rejects exact H1 before
I/O, and answers a Basic `407` to a forwarded request with one replay on the
same proxy connection. H3 over SOCKS5 has its own
[evidence](#h3-socks5-udp-evidence).

Negotiated requests through plaintext, TLS, and HTTP/2 proxy transports have
regressions in `crates/phantom/tests/proxies/negotiated_proxy.rs`. They cover `h2`
and `http/1.1` selection inside the tunnel, the same CONNECT fields and Basic
retry as an exact request, a refused CONNECT that fails as an exact request
does, an Alt-Svc advertisement on the tunnel that is not stored, refusal on a
CONNECT-UDP route, pool isolation between routes, and a failed origin
handshake that is not retried.

Negotiated `http://` requests have regressions in
`crates/phantom/tests/sessions/negotiated.rs`, `proxies/socks5.rs`,
`http3/alt_svc_persistence.rs`, and `requests/redirects.rs`. They prove that the request reaches the origin as a
cleartext HTTP/1.1 head directly, in absolute form through a forward proxy,
and inside a SOCKS5 tunnel; that the response reports H1; that an `h3`
advertisement on it is not stored; and that a negotiated redirect to an
`http://` target is followed over H1.

WebSocket route regressions in `crates/phantom/tests/streams/websocket/routing.rs`
tunnel a plaintext `ws://` Upgrade through plaintext and TLS-encrypted HTTP
proxies. They assert the exact CONNECT head, then an origin-form opening
inside the tunnel with the caller-selected field order and no origin TLS,
no direct-origin traffic, independent proxy trust, and Ping/Pong traffic.
Authentication cases prove an anonymous first CONNECT; one replay of the
CONNECT with generated credentials on the challenged connection, which the
`407` left open, and the credentials never reach the opening; credentials
on the first CONNECT of a later WebSocket to the same proxy, or a fresh
challenge for each when the record is disabled; and
terminal behavior for malformed or repeated challenges and for a `407`
without credentials. An origin that
refuses the opening inside the tunnel is returned with its body. A
caller-supplied `Proxy-Authorization` is rejected before any proxy or origin
I/O. `websocket_http2_proxy.rs` opens `ws://` in a CONNECT stream on the
HTTP/2 proxy transport.

SOCKS5 WebSocket regressions cover plaintext `ws://` as well as TLS-backed
`wss://`. The plaintext cases prove remote-DNS Unicode canonicalization,
local-DNS address resolution, username/password negotiation, an origin-form
Upgrade with no origin TLS, and delivery of a WebSocket frame coalesced with
the `101` response.

Plaintext `http://` requests over SOCKS5 have regressions in
`crates/phantom/tests/proxies/socks5.rs`, `socks5_local.rs`, and `socks5/auth.rs`.
They prove that remote DNS sends the origin name in the SOCKS5 CONNECT, that
local DNS sends a resolved IP, that RFC 1929 authentication completes before
the CONNECT, and that the origin receives an origin-form HTTP/1.1 request
with no TLS inside the tunnel.

Limits:

- No browser-capture fidelity. [Proxy route browser
  evidence](#proxy-route-browser-evidence) records what browsers send on
  these routes, and where Phantom differs.
- Not covered: redirects, Basic authentication and request bodies on H2
  forwarding, other authentication schemes, forwarding an HTTPS origin, and
  H3 through an HTTP forward proxy.

### Proxy route browser evidence

What is claimed: these captures record what Chrome 154, Edge 154, and
Firefox 156 send to an HTTP proxy for plaintext `http://` and `ws://`
origins. Phantom's `ws://` route through an HTTP proxy follows them; the
remaining differences from the [route matrix](../reference/route-matrix.md)
are listed at the end of this section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains captures from
headless Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 156.0 on
Windows 11 (10.0.26200). Each of six scenarios ran three times on a fresh
profile, and the three runs agree on every request line, field order, and
forwarding choice. One page load makes a navigation, a `ws://` opening, and a
`fetch()`. The scenarios cross three routes with two origins:

- routes: direct, a plaintext HTTP proxy, and a TLS proxy for
  `proxy.phantom.test` that offers ALPN `h2` and `http/1.1`;
- origins: `127.0.0.1` and the name `origin.phantom.test`.

The loopback proxy answers as the origin itself, so nothing leaves the
machine.

Four more scenarios, `http-proxy-secure-hostname`,
`https-proxy-secure-hostname`, and their `-auth-` variants, record the
CONNECT for an `https://` fetch and a `wss://` opening from a named page.
The proxy answers each CONNECT with `200` and closes the tunnel before any
origin TLS, so these fixtures hold CONNECT heads and no origin request; the
browsers retry a closed tunnel, so a run holds several. In the `-auth-`
variants the proxy challenges only CONNECT, so the first `https://` CONNECT
is challenged and the later ones carry remembered credentials. Firefox's
plaintext-proxy launch for them also sets `network.proxy.ssl`, because its
manual `http` proxy covers only `http://` and `ws://`.

The fixtures keep H1 request lines and field lines in hex, the proxy
connection's ALPN offer and SNI, every H2 frame in both directions, and each
client HPACK block with its representations. Browser background traffic that
reached the proxy (Google, Microsoft, and Mozilla hosts) is kept as method
and authority only.

| Behavior | Chrome 154 and Edge 154 | Firefox 156 |
| --- | --- | --- |
| `ws://` through a plaintext proxy | `CONNECT host:port`, then the origin-form Upgrade inside the tunnel | Same |
| CONNECT field order | `Host`, `Proxy-Connection: keep-alive`, `User-Agent` | `User-Agent`, `Proxy-Connection: keep-alive`, `Connection: keep-alive`, `Host` |
| `http://` through a plaintext proxy | Absolute-form; `Proxy-Connection: keep-alive` second, where a direct request has `Connection: keep-alive` | Absolute-form; fields identical to a direct request, with `Connection: keep-alive` and no `Proxy-Connection` |
| `http://` through the TLS proxy | ALPN `h2` to the proxy; H2 request with `:scheme` `http` and the origin in `:authority` | Same |
| Pseudo-field order of that request | `:method`, `:authority`, `:scheme`, `:path` | `:method`, `:path`, `:authority`, `:scheme`, and `te: trailers` last |
| `ws://` through the TLS proxy | H2 CONNECT (`:method`, `:authority`, `user-agent`) on the page's proxy session, then the H1 Upgrade in the stream | Same CONNECT fields, on a second H2 connection to the proxy |
| Requests of one page on the TLS proxy | All on one H2 connection, as streams 1, 3, 5, and so on | Three H2 connections: forwarded requests, `https://` CONNECTs, and `ws://` or `wss://` CONNECTs; each connection's first stream is 3 |

`Accept-Encoding`, fetch metadata, and client hints depend on the origin,
not on the route. [Plaintext origin trust
evidence](#plaintext-origin-trust-evidence) gives the values for each origin
and how Phantom's templates follow them.

Further observations:

- Connection sharing on the TLS proxy holds in every run of the nine
  `https-proxy-*` scenarios. In `https-proxy-secure-hostname`, Chrome and
  Edge send the navigation on stream 1, two `https://` CONNECTs on streams 3
  and 5, two `wss://` CONNECTs on streams 7 and 9, and the final `fetch()` on
  stream 11 of one connection; Brave 154 and Opera 135 do the same. Firefox
  sends the navigation and final `fetch()` on streams 3 and 5 of one
  connection, ten `https://` CONNECTs on streams 5 to 23 of a second, whose
  stream 3 carried Firefox's own background CONNECT to
  `firefox.settings.services.mozilla.com`, and the `wss://` CONNECT on
  stream 3 of a third. In the `https-proxy-auth-*`
  scenarios the challenged request, its replay, and later requests stay on
  those connections, and Firefox's two `ws://` CONNECTs are streams 3 and 5
  of its WebSocket connection. The second navigation of
  `https-proxy-auth-remembered-hostname` reuses the first one's connection
  in every browser. The browsers' own background requests (Google and
  Mozilla hosts) use other connections to the proxy.
- The Upgrade inside a tunnel has the same fields in the same order as the
  direct Upgrade to the same origin.
- On Chromium's proxy session every HEADERS frame is exclusive with parent 0:
  weight 256 for the navigation, 147 for the CONNECT, and 220 for the
  `fetch()`, in all 12 Chrome and Edge runs.
- Chromium ignores its proxy setting for loopback origins unless
  `--proxy-bypass-list=<-loopback>` is passed. Firefox needs
  `network.proxy.allow_hijacking_localhost`.
- Chromium applies `--ignore-certificate-errors-spki-list` to the proxy
  certificate. Firefox accepts a `cert_override.txt` entry for the proxy's
  host and port in its disposable profile. Neither needs a system trust
  store change.

Against the route matrix:

- `http://` H1 through an H1 proxy: Phantom forwards in absolute form with
  the request template's fields. The Chrome and Edge templates send
  `Proxy-Connection: keep-alive` where a direct request has
  `Connection: keep-alive`, and Firefox's send their direct fields.
  `built_in_templates_send_the_captured_named_plaintext_fields` and
  `built_in_templates_forward_the_captured_loopback_plaintext_fields` in
  `crates/phantom/tests/requests/plaintext_templates.rs` compare every forwarded field
  and value with the `http-proxy-hostname` and `http-proxy-loopback`
  requests, and
  `chromium_templates_swap_connection_for_proxy_connection_only_when_forwarded`
  in `phantom-profile` checks the template data.
- `ws://` H1 through an H1 proxy: Phantom tunnels with CONNECT and sends
  the direct Upgrade inside, as every captured browser does.
  `plaintext_websocket_through_an_http_proxy_tunnels_the_captured_opening`
  in `crates/phantom/tests/streams/websocket_profile.rs` sends the Chromium and
  Firefox recipes' openings through a loopback CONNECT proxy and compares the
  field order with the `http-proxy-loopback` captures.
- CONNECT fields: a profile with `chromium::v154_proxy_connect` or
  `firefox::v156_proxy_connect` sends the captured CONNECT fields in the
  captured order on both proxy transports, with the `User-Agent` of the
  request or opening that opens the tunnel. Without the recipe, or when the
  route sets its own fields, the CONNECT carries only what the route names.
  The `*-secure-hostname` captures record the CONNECT for an `https://`
  fetch and a `wss://` opening through both proxies, with and without a
  challenge; every browser sends the same fields as for `ws://`.
  `connect_requests_send_the_captured_fields` and
  `wss_connect_sends_the_captured_fields` in
  `crates/phantom/tests/proxies/proxy_field_order.rs` compare Phantom's anonymous,
  challenged, replayed, and remembered-credential HTTP/1.1 CONNECT for
  `https://` and `wss://` with those captures;
  `h2_connect_sends_the_captured_profile_fields` and
  `h2_wss_connect_sends_the_captured_profile_fields` in `proxy_h2.rs` do the
  same on the HTTP/2 proxy transport. The `ws://` tests above and
  `plaintext_ws_over_h2_proxy_sends_the_profile_connect_fields` in
  `websocket_http2_proxy.rs` cover `ws://` tunnels. The captured CONNECT
  `User-Agent` equals the page request's in every run.
- `http://` through an H2 proxy: Phantom forwards exact H2 and negotiated
  requests over H2 with `:scheme` `http`, as every captured browser does.
  `chromium_forwards_http_over_h2_proxy_with_the_captured_pseudo_order` and
  its Firefox counterpart in `crates/phantom/tests/proxies/proxy_h2.rs` decode the
  first HEADERS block and compare its pseudo-field order with the
  `https-proxy` captures. Exact H1 stays rejected before I/O. Phantom does
  not reproduce the per-request HEADERS priority, `te: trailers`, or the
  other fields of a browser page load unless a request template supplies
  them.
- `ws://` H1 through an H2 proxy: Phantom opens a CONNECT stream and sends
  the Upgrade inside it, as every captured browser does.
- Connection sharing on an H2 proxy: each session keeps pooled proxy
  connections, and `ProxyConnectTemplate::http2_connections` decides which
  requests share one. `chromium::v154_proxy_connect` uses `Shared`, which
  puts forwarded requests, CONNECT tunnels, and WebSocket tunnels on one
  connection, as Chrome, Edge, Brave, and Opera do;
  `firefox::v156_proxy_connect` uses `ByPurpose`, which gives each of the
  three its own, as Firefox does.
  `connection_sharing_follows_the_captured_proxy_connections` in
  `crates/phantom-profile/src/proxy_connect/tests.rs` groups the page
  requests of every run of every `https-proxy-*` capture by connection and
  checks the recipe of each browser against them.
  `crates/phantom/tests/proxies/proxy_h2_multiplex.rs` checks that tunnels to three
  origins arrive as streams 1, 3, and 5 of one proxy connection, that the
  Chromium recipe adds forwarded requests and a `ws://` tunnel to it and the
  Firefox recipe keeps them on connections of their own, each starting at
  stream 3, that two sessions
  never share one, and that the opt-in
  `max_http2_proxy_connections_per_route` opens a second connection at the
  proxy's stream limit. `crates/phantom-net/src/proxy/tests/http2_pool.rs`
  checks the pool against a frame-level proxy: past the proxy's
  `SETTINGS_MAX_CONCURRENT_STREAMS`, the next CONNECT's HEADERS reaches the
  same connection only after a tunnel there ends; an opted-in route opens
  connections up to its ceiling instead; a rejected CONNECT gives its place
  back; concurrent tunnels wait for one setup, and a failed setup fails them
  all after one connection attempt; closing one tunnel and a proxy
  `RST_STREAM` on another leave the rest working; after a `GOAWAY`, the
  covered tunnel keeps working and a new tunnel opens a new connection, and a
  CONNECT that the `GOAWAY` left unprocessed is sent once more on a new one;
  other credentials or other HTTP/2 settings never share a connection; a
  forgotten route's open tunnel keeps working; and a challenged CONNECT on a
  shared connection is replayed as its next stream.

How to reproduce: `scripts/capture/proxy_route.py --browser <browser>
--scenario all --repeat 3`; see
[Proxy routes](../../scripts/capture/README.md#proxy-routes).

Limits:

- Plaintext origins only. `https://` and `wss://` origins through a proxy are
  not captured.
- No PAC-selected plaintext proxy or SOCKS proxy. Proxy authentication has
  its own scenarios; see
  [Proxy authentication evidence](#proxy-authentication-evidence).
- Firefox reaches the TLS proxy through a PAC result, because its manual
  settings cannot name a TLS proxy. Chromium uses `--proxy-server`.
- Chromium was launched with `--disable-field-trial-config`; field trials in
  a normal profile may change these results.
- The `ws://` opening inside the tunnel, the CONNECT fields, the fields of
  H1 forwarding, and the pseudo-field order of H2 forwarding are compared
  with a fixture. The
  `ws://` opening is compared for both origins; see
  [Plaintext origin trust evidence](#plaintext-origin-trust-evidence).

### Proxy authentication evidence

What is claimed: after an HTTP proxy challenges one request with a Basic
`407` and accepts the credentials, Chrome 154, Edge 154, and Firefox 156 send
`Proxy-Authorization` on the first attempt of every later CONNECT tunnel and
forwarded request to that proxy. Phantom does the same by default for CONNECT
tunnels on both proxy transports, including WebSocket tunnels, and for H1 and
H2 forwarding. The browsers send the replay after a `407` on the connection
that carried it when the proxy keeps that connection open, and so does
Phantom on HTTP/1.1 proxy connections. The differences that remain are
listed at the end of this section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains four
authentication scenarios per browser, `http-proxy-auth-*` and
`https-proxy-auth-*`, with loopback and named origins, from the same headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 156.0 builds on Windows
11 (10.0.26200). Each ran three times on a fresh profile, and the three runs
agree on the sequence of proxy requests, connection reuse, and field order.
The proxy answers any request for the test origin that lacks the expected
credentials with `407` and `Proxy-Authenticate: Basic realm="phantom-capture"`.
One page load makes a navigation, two `ws://` openings one after the other,
and a `fetch()`. The capture tool supplies the credentials through the
DevTools protocol (`Fetch.continueWithAuth`) for Chrome and Edge and through
WebDriver BiDi (`network.continueWithAuth`) for Firefox. The fixtures keep
the position of each `Proxy-Authorization` field and replace its value with a
marker.

| Behavior | Chrome 154 and Edge 154 | Firefox 156 |
| --- | --- | --- |
| `407` responses per page load | One, to the first navigation request | Same |
| Replay after that `407` | Same plaintext proxy connection; new stream on the same H2 proxy connection | Same |
| Later `ws://` CONNECTs and the `fetch()` | Carry `Proxy-Authorization` with no `407` | Same, including on a second H2 proxy connection opened for the WebSockets |
| H1 CONNECT fields | `Host`, `Proxy-Connection`, `User-Agent`, `Proxy-Authorization` | `User-Agent`, `Proxy-Connection`, `Connection`, `Host`, `Proxy-Authorization` |
| H2 CONNECT fields | `:method`, `:authority`, `user-agent`, `proxy-authorization` | Same |
| `Proxy-Authorization` in an H1 forwarded request | Third, after `Host` and `Proxy-Connection`, on the replay and on later requests | Last on the replay; before `Connection` on later requests |
| `proxy-authorization` in an H2 forwarded request | First field after the pseudo-fields | Before `te` on the replay; before `priority` on later requests |
| HPACK representation of `proxy-authorization` | Literal with incremental indexing (static name 49) on first use on a connection, then indexed | Same |

Browser source, checked on 2026-09-24 at Chromium tag 154.0.8037.58 and
Firefox tag `FIREFOX_156_0_RELEASE`, agrees and explains the mechanism:

- Chromium keys an entry by proxy origin (scheme, host, port), target,
  realm, and scheme, and looks proxy entries up by the path `/`
  (`net/http/http_auth_cache.cc` lines 376 to 427,
  `net/http/http_auth_controller.cc` line 102).
  `HttpAuthController::MaybeGenerateAuthToken` sends a cached identity before
  any challenge (`http_auth_controller.cc` lines 126 to 195) for CONNECT
  (`net/http/http_proxy_client_socket.cc` lines 339 to 367), H2 CONNECT
  (`net/spdy/spdy_proxy_client_socket.cc` lines 397 to 422), and forwarded
  requests (`net/http/http_network_transaction.cc` lines 1336 to 1347).
- Chromium adds the entry when credentials are supplied, before the retry
  (`http_auth_controller.cc` lines 365 to 389), removes it when the proxy
  rejects it (lines 428 to 438), and keeps at most 20 entries, evicting the
  least recently used (`net/http/http_auth_cache.h` line 124,
  `http_auth_cache.cc` lines 429 to 446).
- Firefox keys proxy entries by `host:port` and realm with an empty path
  (`netwerk/protocol/http/nsHttpAuthCache.cpp` lines 21 to 32,
  `nsHttpChannelAuthProvider.cpp` lines 214 to 217), also adds the entry
  before the credentials are validated (`nsHttpChannelAuthProvider.cpp` lines
  381 to 390), copies the transaction's `Proxy-Authorization` into each
  CONNECT (`nsHttpConnection.cpp` lines 2092 to 2099), and clears the entry
  when the proxy rejects it (`nsHttpChannelAuthProvider.cpp` lines 889 to
  899). Its cache has no size limit.
- Neither browser authenticates a CONNECT-UDP request to a proxy: Chromium
  leaves it as a TODO (`net/quic/quic_proxy_datagram_client_socket.cc` line
  367), and Firefox copies the value into `Authorization`
  (`netwerk/protocol/http/HttpConnectionUDP.cpp` lines 586 to 592).
- Chromium replays a challenged CONNECT on the same connection unless the
  `407` is not keep-alive, has no length, or the socket closed
  (`net/http/http_proxy_client_socket.cc` lines 207 to 240). It reads the
  body in 1,024-byte reads with no total limit (lines 534 to 553) and gives
  up the connection when bytes follow the body (lines 230 to 233).
  `HttpProxyConnectJob` then opens a new connection, and also retries once on
  a new connection when the proxy closed the reused one before answering
  (`net/http/http_proxy_connect_job.cc` lines 837 to 878). A forwarded
  request follows the same rules (`net/http/http_network_transaction.cc`
  lines 572 to 638 and 1812 to 1835; `net/http/http_stream_parser.cc` lines
  1189 to 1218). The response is keep-alive when the first `keep-alive` or
  `close` token in `Connection` and then `Proxy-Connection` says so, and
  otherwise unless it is HTTP/1.0 (`net/http/http_response_headers.cc` lines
  1523 to 1551).
- When a reused connection closes before any response byte, Chromium
  resends the request whatever its method
  (`HttpNetworkTransaction::ShouldResendRequest`,
  `net/http/http_network_transaction.cc` lines 2126 and 2319 to 2326).
  Phantom resends a forwarded replay only for an idempotent method, and
  returns the error for a POST, which the proxy may already have forwarded.
- Firefox decides keep-alive from the same two fields, but any `close`
  token wins over `keep-alive`, and HTTP/1.0 needs `keep-alive`
  (`netwerk/protocol/http/nsHttpConnection.cpp` lines 1072 to 1107). A
  challenged CONNECT leaves the connection in its tunnel-setup state
  (lines 1167 to 1230), and a keep-alive connection returns to the idle pool
  for the replay (`nsHttpConnection.cpp` lines 936 to 980,
  `nsHttpConnectionMgr.cpp` lines 2663 to 2755). Basic is not a sticky
  scheme, so the replay takes the connection from the pool; in the captures
  it is the only idle one.
- The `http-proxy-auth-secure-hostname` captures challenge a CONNECT for an
  `https://` origin: in all three runs, each browser sends the replay on the
  challenged connection. The capture proxy's `407` is keep-alive with
  `Content-Length: 0`; no capture covers a closing or body-bearing `407`, so
  those cases rest on the source above.
- The `https-proxy-auth-secure-hostname` captures do the same through the
  TLS proxy that offers `h2`. In all three runs, each browser sends the
  replay as the next stream on the HTTP/2 connection that carried the `407`:
  Chrome and Edge on stream 5 after the `407` on stream 3, Firefox on stream
  7 after stream 5. The `407` ends its stream. Chrome and Edge then end
  their side of it with an empty DATA frame that carries END_STREAM; Firefox
  sends nothing more on it. Both browsers also open other CONNECT streams on
  the same connection, so a browser's tunnels share proxy connections.
- Credentials supplied through `Fetch.continueWithAuth` and
  `network.continueWithAuth` reach the same caches as a prompt's
  (`content/browser/devtools/devtools_url_loader_interceptor.cc` lines 1433 to
  1446; `nsHttpChannelAuthProvider.cpp` lines 1363 to 1425).

Against Phantom:

- `sequential_tunnels_pay_for_one_challenge_instead_of_one_per_tunnel` in
  `crates/phantom/tests/proxies/proxy_credential_cache.rs` opens four tunnels one
  after the other through a plaintext proxy that challenges every request
  without credentials. With the record the proxy sees five connections and
  one `407`; with `preemptive_proxy_authentication(false)` it sees eight
  connections and four `407` responses. The same file proves that another
  proxy port, other credentials, and the origin never receive remembered
  credentials, and that each session starts with an empty record.
- `keep_alive_challenges_cost_no_extra_proxy_connection` in the same file
  sends the four tunnels through a proxy whose `407` keeps the connection
  open: the proxy sees four connections, with the record and without it.
- `crates/phantom-net/src/proxy/tests/challenged_connection.rs` checks the
  bytes on each proxy connection: the anonymous CONNECT and the replay on one
  connection after a keep-alive `407` with an empty, sized, or chunked body,
  on plaintext and TLS proxies and for HTTP/1.0 with `keep-alive`; two
  connections after `Connection: close`, `Proxy-Connection: close`, a body
  without a length, conflicting framing, bytes after the body, or a body over
  the bound; and a replay moved to a new connection when the proxy closes the
  challenged one. It also checks the strict chunk-size line and that an
  HTTP/1.0 `407` with `Transfer-Encoding` closes the connection.
  `forward_proxy.rs` checks the same for H1 forwarding, including a request
  queued behind the challenged one, which never takes the connection before
  the replay; a proxy that shuts its side after the `407`, whose replay goes
  on a new connection with nothing written to the old one; a POST whose
  replay the proxy closes, which fails with no second connection; and a
  stalled `407` body, which fails with the read-idle, response-head, or total
  timeout and sends no replay.
- `crates/phantom-net/src/proxy/tests/credential_cache.rs` covers the record:
  a pair is added only after the proxy accepts the replay; a `407` or an
  unusable challenge to remembered credentials forgets them and permits one
  replay; a proxy that never challenges is not recorded; entries are separate
  by scheme, host, port, and credentials; and a full record evicts the least
  recently used pair.
- `proxy_h2.rs` covers H2 CONNECT tunnels and H2 forwarding, including the
  replay on the same H2 proxy connection, a second `407`, and the
  never-indexed HPACK form of the forwarded `proxy-authorization` field.
  `h2_proxy_basic_challenge_replays_once_on_the_challenged_connection` checks
  that a challenged H2 CONNECT and its replay arrive as streams 1 and 3 of one
  proxy connection.
- `crates/phantom-net/src/proxy/tests/http2_challenge.rs` checks the frames
  of that exchange: an empty END_STREAM DATA frame ends stream 1 before the
  replay's HEADERS on stream 3, stream 1 is not reset, and the replay carries
  `proxy-authorization` as a never-indexed literal on static name 49. It also
  checks that remembered credentials go on stream 1 of a new connection, that
  a `407` to them brings one replay on stream 3 of that connection, that a
  second `407` fails with no other connection, and that a replay the proxy
  refuses with `REFUSED_STREAM` moves to a new connection.
- `http2_challenge_frames.rs` in the same directory drives the client
  against a frame-level proxy. `challenged_stream_frames_match_the_captures`
  compares the client frames on the challenged stream, between the `407` and
  the replay, with the same span of each browser's
  `https-proxy-auth-secure-hostname` capture: one empty END_STREAM DATA
  frame for the Chromium recipe, none for the Firefox recipe, whose stream
  also stays quiet while the tunnel runs. The file also checks the DATA
  frame before the replay 20 times on a multi-thread runtime, the replay on
  a proxy that allows one concurrent stream, a move to a new connection
  after a `GOAWAY` sent with the `407` or after the replay's HEADERS and
  after a close during the replay, a `407` whose body is still arriving
  (reset with `CANCEL`, its connection window returned, and the replay on
  the same connection), and a `502` that ends its stream with END_STREAM.
  `h2_connect_closes_the_challenged_stream_as_the_profile_does` in
  `proxy_h2.rs` checks that a client built with each recipe applies it.
  `plaintext_ws_over_h2_proxy_replays_a_challenged_connect_on_its_connection`
  and `h2_websocket_over_h2_proxy_replays_a_challenged_connect_on_its_connection`
  in `websocket_http2_proxy.rs` check the same one connection for `ws://`
  and HTTP/2 WebSocket openings.
  `forward_proxy.rs` covers H1 forwarding on the pooled proxy connection and
  a `407` to remembered credentials. `websocket/routing.rs` covers two
  `ws://` tunnels after one challenge.
- A CONNECT request places the field at the placeholder of the route's
  CONNECT fields, or of the profile's `with_proxy_connect` recipe, last in
  both built-in recipes, as both browsers do.
- A forwarded request with a built-in request template places the field at
  the template's `RequestField::ProxyAuthorization` slot for the attempt.
  `forwarded_requests_place_proxy_credentials_as_captured` in
  `crates/phantom/tests/proxies/proxy_field_order.rs` reads the
  `http-proxy-auth-hostname` and `http-proxy-auth-loopback` captures of each
  browser and compares the field names of Phantom's challenged navigation,
  its replay, and a `fetch()` with remembered credentials with the captured
  ones, `Host` included. `h2_forwarding_places_proxy_credentials_as_captured`
  in `proxy_h2.rs` does the same with the `https-proxy-auth-hostname`
  captures on an HTTP/2 proxy. The `*-auth-remembered-hostname` captures
  add the two cases those scenarios lack: a challenged `fetch()` with its
  replay, and a navigation sent with remembered credentials, which the
  capture tool starts over the remote protocol after the `fetch()`.
  `remembered_navigation_and_fetch_replay_place_credentials_as_captured` and
  `h2_remembered_navigation_and_fetch_replay_place_credentials_as_captured`
  compare Phantom with them. The `*-auth-nostore-hostname` and
  `*-auth-nostore-loopback` captures record a no-store `fetch()`, challenged,
  replayed, and then sent with remembered credentials, through both proxies:
  Chrome and Edge place the field after `Cache-Control` and before the client
  hints, and Firefox after `Cache-Control` on the replay and before
  `Connection` with remembered credentials. The tests above compare
  Phantom's no-store template with these captures, every field included.
  Without a template, or with a template that
  has no slot for the attempt, the field follows every other field. On a
  route without configured credentials, a caller's own `Proxy-Authorization`
  on a forwarded request takes the template's slot for a first attempt.

Remaining differences:

- H2 forwarding and H2 CONNECT send `proxy-authorization` as a never-indexed
  literal, where both browsers index it. Phantom keeps this on purpose, as of
  2026-09-25. The HPACK block goes only to the proxy, which already holds the
  credentials and re-encodes the request toward the origin, so the
  difference is visible to the proxy and not to an origin. RFC 7541 section
  7.1.3 recommends never indexing credentials, because a peer that can add
  chosen fields to requests on the same connection and observe their size
  can guess an indexed value. Indexing would also need a new marker: on
  every field but a `cookie` that a recipe splits into crumbs,
  `RequestHeader::sensitive` both selects the never-indexed form and hides
  the value from `Debug` output, and a field without it prints its value in
  `RequestHeader` and `http::HeaderValue` `Debug` output. The vendored
  `http2` frame `Debug` output leaves out every field, and Phantom never
  prints the connection whose HPACK table would hold the value, but the
  request fields pass through Phantom's own types first.
- No capture reaches a proxy's stream limit. Phantom queues a CONNECT past
  it on the route's one connection, as both browsers' sources do; the opt-in
  `max_http2_proxy_connections_per_route` opens another connection
  instead.
- With the Firefox recipe, a proxy that allows only one concurrent stream
  gets an END_STREAM on the challenged stream, so the replay can open; no
  capture shows what Firefox does there. The vendored `http2` encoder writes
  a new stream's HEADERS ahead of queued DATA, so Phantom waits for the
  challenged stream's END_STREAM to be written; if the proxy stops reading
  for about 50 ms, the replay's HEADERS can come first.
- A `407` body over 64 KiB closes the connection, where browsers read any
  length. A forwarded POST whose replay the proxy closes before answering
  fails, where Chromium sends it again. A forwarded `407` in HTTP/1.0 closes it even with `keep-alive`,
  because Phantom's HTTP/1.1 transport never reuses an HTTP/1.0 response's
  connection; a CONNECT `407` follows the browsers. When a `407` names both
  `keep-alive` and `close`, Phantom closes, as Firefox does; Chromium follows
  the first token.
- Phantom records a pair only after the proxy accepts it; browsers record it
  when the credentials are supplied.
- The record holds 128 pairs; Chromium holds 20 and Firefox has no limit.

How to reproduce: `scripts/capture/proxy_route.py --browser <browser>
--scenario http-proxy-auth-remembered-hostname
https-proxy-auth-remembered-hostname http-proxy-auth-nostore-hostname
https-proxy-auth-nostore-hostname http-proxy-auth-nostore-loopback
https-proxy-auth-nostore-loopback http-proxy-auth-secure-hostname
https-proxy-auth-secure-hostname http-proxy-auth-hostname https-proxy-auth-hostname
http-proxy-auth-loopback https-proxy-auth-loopback --repeat 3`; see
[Proxy routes](../../scripts/capture/README.md#proxy-routes).

Limits:

- One realm. Only the `*-secure-hostname` scenarios challenge a CONNECT;
  the others challenge a forwarded navigation first. Every captured `407` is
  keep-alive with an empty body, so reuse after a closing or body-bearing
  `407` comes from source reading only.
- The credentials come from browser automation, not a prompt. Firefox ran
  with `remote.prefs.recommended=false`, so its automation defaults did not
  change connection behavior.

### H3 SOCKS5 UDP evidence

What is claimed: exact H3 runs over local-DNS `socks5://` and remote-DNS
`socks5h://` through RFC 1928 UDP ASSOCIATE, reuses one connection per route,
and fails with typed errors instead of falling back.

Evidence: public exact-H3 loopback regressions cover both schemes, without
authentication and with RFC 1929 username/password authentication. They
verify end-to-end H3 traffic, reuse of one route-keyed H3 connection and
association across requests, and retention of the TCP control connection for
the client-owned lifetime of the association.

The local path fixes an IP target. The remote path uses an intentionally
unresolvable `.invalid` origin, proves the exact canonical DOMAIN target on
the proxy wire, and forwards it only through the fixture's proxy-owned
mapping. Rejected and malformed association replies produce typed proxy
errors, with no origin datagrams and no direct or protocol fallback. HTTP
forwarding and HTTP CONNECT routes fail before any proxy or origin I/O.

Transport-focused tests assert the exact authentication and UDP ASSOCIATE
exchanges, fixed IPv4 and IPv6 target headers, zero RSV and FRAG fields, and
fragment rejection. The adapter handles one datagram per send or receive and
accepts only packets from the negotiated relay that carry the configured
target. That boundary discards malformed, fragmented, spoofed-relay,
wrong-domain, and wrong-port datagrams:

| Tests | What they cover |
| --- | --- |
| `datagram_from_a_non_relay_source_is_dropped` (`crates/phantom-net/src/proxy/tests/socks5_udp.rs`) | A well-formed datagram from a second loopback socket is dropped; only the relay's next datagram is delivered |
| Codec and receive-policy unit tests (`crates/phantom-net/src/proxy/socks5_udp.rs`) | Fragments, truncation, wrong domains and ports, and IPs other than a local-DNS route's fixed target |
| Relay-reply tests | The compatibility rule that replaces an unspecified BND.ADDR with the established TCP proxy peer's IP and nothing else, and the rejection of a domain BND.ADDR or a zero BND.PORT |
| Remote-target tests | Exact-domain replies, case-insensitive domain comparison, same-port IP-form replies, and a stable logical Quinn peer |

Limits:

- No browser-capture fidelity for a proxied H3 route.
- CONNECT-UDP routes have their own loopback evidence against an h3 test
  proxy. No independent MASQUE implementation or browser capture backs them
  yet.
- Alt-Svc upgrade has separate, direct-route
  [evidence](#alt-svc-http3-upgrade-evidence).

### Connection-retry evidence

What is claimed: connection-setup and status retries stay inside their
budgets and boundaries, and recover from the failures they target.

Evidence: the shared exact-protocol acquisition state uses scripted, typed
setup failures to prove a finite, request-wide budget across separate
acquisitions; a fresh connect-phase deadline for each attempt; exclusion of
timeouts, and protocol-labelled timeout behavior; preservation of the last
error; and one total deadline that spans the retry delay.

Error-classification tables cover direct, forward-proxy, CONNECT-proxy,
SOCKS5, and QUIC setup variants. They exclude TLS, authentication,
rejection, timeout, protocol, and post-dispatch failures.

Public loopback H1 and H2 regressions start their servers only after they
observe the first refused setup, then verify the final request and response
metadata. The H1 case uses a one-shot streaming POST with static trailers.
Negotiated H1/H2 loopback regressions prove that a refused connect is retried
before ALPN, a TLS failure is terminal, the retry delay releases the
connection lock, pre-selection admission is bounded, the budget is shared
across redirects, and one-shot bodies are not polled before the retry.

Exact-H3 loopback regressions in `crates/phantom/tests/http3/http3_retries.rs`
recover from a refused setup through the public client:

- A direct QUIC handshake refused with `CONNECTION_REFUSED` fails without a
  policy and succeeds with one retry.
- Over local-DNS SOCKS5, a refused proxy TCP connect is retried, and the
  proxy is started only after the refusal is observed.
- Over local-DNS SOCKS5, a QUIC handshake refused through an established UDP
  association is retried through a second association with a different relay
  address. The fixture serves that association only after the first one's
  TCP control connection has closed.

Each successful response reports one setup retry.

Status-retry regressions in `crates/phantom/tests/requests/status_retry.rs` run over
H1 loopback servers, including one negotiated request that selects H1. The
retry loop sits above the transports, so H2 and H3 use the same code.

Limits:

- These tests prove lifecycle and routing behavior, not browser retry policy.
  Retries are configured by the caller and never become part of a named
  browser recipe.
- CONNECT-UDP evidence is narrower. An unresolvable outer proxy consumes the
  whole budget, and proxy rejection and inner TLS failure are terminal, but
  recovery after a CONNECT-UDP retry is not exercised.
- Remote-DNS SOCKS5 H3, and DNS or local endpoint failures, share the same
  classification but have no recovery test.
- No H2 or H3 status-retry test exists.

### Content-decoding evidence

What is claimed: opt-in content decoding decodes only advertised codings,
stays within its bounds, and fails closed.

Evidence: unit tests drive each decoder with single-byte and chunked input.
They cover gzip optional header fields and FHCRC; CRC32/ISIZE and Adler-32
mismatches, truncation, and trailing members or bytes; preset dictionaries
and raw DEFLATE selection; skippable and concatenated zstd frames, legacy zstd
frame magic, and the 8 MiB zstd window bound; stacked `gzip, br`, the 16 KiB
frame bound, and the inclusive decoded limit; and a 64 MiB high-ratio stream
stopped at its cap.

Field-grammar tests cover `Accept-Encoding` weights, wildcards, `x-gzip`,
duplicates, and malformed parameters, plus `Content-Encoding` case, empty
elements, identity mixing, and the three-coding bound.

Public loopback tests cover H1 gzip, H2 brotli, and H3 zstd decoding. They
also cover the wire-view fields; an unchanged request head; pre-I/O
`Accept-Encoding` rejection only when decoding is enabled; fail-closed
handling of unknown and unadvertised chains; HEAD, 204, and 304 responses;
redirect hops; trailers after decoded data; fresh H1 connection selection
after a decode failure; and the total deadline over buffered input.

Limits:

- Browser behavior was read from Chromium and Firefox source and informs only
  the documented divergences. No browser-parity claim is made.

### Response-body limit evidence

What is claimed: `ResponseBody::collect_with_limit` and the decoded-byte cap
enforce an inclusive limit.

Evidence: `collect_with_limit` shares one protocol-independent counter. Unit
tests cover the inclusive bound and arithmetic overflow. A public H1 loopback
test accepts a body exactly at the limit and rejects one byte more. H1
content-decoding tests cover the decoded-byte cap and the decoded bytes that
`collect_with_limit` counts.

Limits:

- No public H2 or H3 test exceeds either limit; H2 and H3 bodies are only
  collected within them.
- Stopping an oversized H2 or H3 body relies on the ordinary body-drop path.
  That path's stream cancellation is covered separately by the H2 and H3
  admission, drop, and timeout regressions.

## Robustness evidence

These checks prove that Phantom stays safe and bounded against hostile input.
None of them is browser evidence.

### Adversarial coverage

Scripted peers vary fragmentation, flow control, challenge sequences, resets,
shutdown, malformed input, and cancellation. Tests assert the ordered
outcome, the error category, connection reuse, and bounded completion.

Traffic that is valid but unusual may be compared with a retained browser
run. Malformed traffic is a robustness test: safety and bounds take precedence
over reproducing unsafe behavior. Each minimized failure becomes an ordinary
regression.

HTTP/2 receive bounds have raw-peer regressions in
`crates/phantom-net/src/http2/tests/adversarial_*.rs`:

| Peer input | Phantom's response |
| --- | --- |
| Floods of empty, padded-empty, and unread one-byte DATA frames | Exactly one `GOAWAY(ENHANCE_YOUR_CALM)` at the first frame over the backported RUSTSEC-2026-0258 limit. The empty flood runs with both the Chrome and Firefox profiles; 100 empty frames are tolerated and never surface as body chunks |
| A response header list over the receive limit | `Http2Error::ResponseHeaderListTooLarge` and one `RST_STREAM(PROTOCOL_ERROR)`, while a sibling request on the same connection succeeds. The limit is the 262,144 bytes the Chrome profile advertises, or the unadvertised 393,216-byte ceiling for Firefox; the tests also check that the Firefox SETTINGS still omit `SETTINGS_MAX_HEADER_LIST_SIZE` |
| Empty, nonempty, and cumulative CONTINUATION floods | The same bound, also run against the Firefox ceiling |
| A ninth informational response, alone or in a burst of 1,000 | `Http2Error::TooManyInformationalResponses` and one `RST_STREAM(ENHANCE_YOUR_CALM)`, while a sibling request succeeds. Eight may precede a final response |
| A peer `SETTINGS_HEADER_TABLE_SIZE` of 65,536 or 2^32 - 1 | The same uncapped dynamic-table-size update that Chromium's quiche encoder and Firefox's compressor emit; the connection stays usable. Upstream h2's 4 KiB encoder cap is not ported (see `vendor/http2/PHANTOM.md`) |

Post-handshake TLS input on a QUIC connection has crafted-peer regressions in
`crates/phantom-quic-btls/src/backend/client_session/tests/post_handshake.rs`.
Each case completes a real handshake with the loopback BoringSSL server, then
hands the client the bytes a hostile server would put in application-level
CRYPTO frames:

| Peer input | Phantom's response |
| --- | --- |
| A NewSessionTicket with an empty or truncated body, a nonce or extension longer than the body, an empty ticket field, a trailing byte, or a two-byte `early_data` extension | The connection fails with a `decode_error` alert, sent to Quinn as `CRYPTO_ERROR` 0x132, and no session is kept |
| A ticket whose `early_data` limit is not 0xffffffff (RFC 9001, section 4.6.1), or that repeats an extension | `illegal_parameter`, and no session is kept |
| A KeyUpdate (RFC 9001, section 6), or a Finished, CertificateRequest, or unassigned message type | `unexpected_message` |
| An incomplete message, even one whose header promises 16 MiB | Buffered until 16 KiB of application-level data is pending, then the connection fails without an alert |
| 64 well-formed tickets in one flight | Each becomes a session; only the newest four are kept until the connection collects them |
| A valid ticket, then a malformed message | The valid ticket's session never reaches the ticket cache and is released with the failed connection; BoringSSL replays the read error for later input, so no later ticket is kept |
| A ticket with a zero lifetime | Delivered by BoringSSL, then discarded by the ticket cache (RFC 8446, section 4.6.1) |

### Fuzzing and sanitizers

The [parser fuzzing workflow](../../.github/workflows/fuzz.yml) runs each
target under AddressSanitizer. The targets are the test-kit ClientHello and
H2 frame decoders, Quinn transport parameters, and these production paths:
HTTP/1.1 responses, HTTP CONNECT responses, proxy Basic challenges, cookie
storage, cookie and Alt-Svc snapshot import, and HTTPS DNS record
extraction. [`fuzz/README.md`](../../fuzz/README.md) lists each target's
entry point and the invariants it asserts. The workflow runs for 15
seconds on relevant pull requests and pushes, and for 300 seconds on its
weekly schedule or a manual dispatch. Every run starts from the newest
per-target corpus in the GitHub Actions cache, and only scheduled runs save a
grown corpus back. The corpus is therefore a cache that can expire or be
evicted, not a reviewed, committed seed set. A failing input is kept only as
a short-lived workflow artifact until it is minimized into a regression.

The [sanitizer workflow](../../.github/workflows/sanitizers.yml) runs
`phantom-quic-btls`'s own unit tests and `phantom-net`'s HTTP/3 loopback tests
under AddressSanitizer on the same pinned nightly, when QUIC, TLS, or vendored
paths change and on its weekly schedule. Fuzzing reaches the byte parsers;
this job covers the QUIC secret callbacks, the key schedule, and a live
handshake, which is where the crate's `unsafe` code is. BoringSSL itself is
compiled without instrumentation, so a fault inside its C code surfaces only
where it crosses an intercepted `mem*` call or touches memory the Rust
allocator owns. Interception is enough for leak detection, which stays on:
the allocator is replaced process-wide, so a `CallbackState` owner that the
ex-data destructor fails to free is reported whichever side allocated it. The
workflow is advisory, not a required check.

The job skips
`http3::tests::adversarial::ninth_informational_response_fails_the_request`.
That test bounds an informational flood with a five-second deadline, and
instrumentation slows the flood enough that the deadline expires before the
bound is reached, so it reports a timeout rather than a memory defect. It
asserts a deadline rather than an allocation, and the uninstrumented
workspace run covers it.

Four callback-failure paths carry most of that FFI risk. A null `SSL_CIPHER`
and a secret length that disagrees with the cipher are both rejected before
any copy, and both have tests. Dropping the `SSL` mid-handshake runs the
ex-data destructor, and the tests in
`crates/phantom-quic-btls/src/backend/client_session/tests/lifecycle.rs`
check the owner count after a drop mid full handshake as well as at each
point listed below. A panic inside a callback is contained by
`catch_unwind`, but the test calls the containment helper directly; nothing
panics across a real BoringSSL call edge, so running under a sanitizer proves
nothing about that path.

Session resumption adds its own paths through the FFI, each with a test:

- Hostile post-handshake input, in the adversarial table above.
- The new-session callback declining a session, when the `SSL` has no QUIC
  callback state or the session pointer is null. It returns 0, and the
  test then uses and releases the session itself, so a callback that had
  released it would be reported as a use after free.
- Dropping a client after `SSL_set_session`, before and after the
  ClientHello; while it sends early data, with and without the server's
  ServerHello; after the server rejected early data but before the handshake
  finished; and while it holds tickets nobody collected. After each drop,
  the offered session still resumes a later handshake.
- `SSL_reset_early_data_reject`, which aborts the process unless the
  handshake waits on an early-data rejection. The client calls it only after
  `SSL_do_handshake` returned -1 with `SSL_ERROR_EARLY_DATA_REJECTED`, on a
  connection that offered 0-RTT and had no rejection yet. A unit test covers
  that condition and the lifecycle test above drives a real rejection.
- `QuicClientConfig::enable_session_resumption` on a builder whose
  new-session callback belongs to other code: it fails with
  `QuicTlsProfileErrorKind::ContextConflict` and changes nothing.
  `with_tls_profile` refuses `session_tickets` when a later callback replaced
  Phantom's or client session caching was turned off.

The loopback QUIC server of the `server` feature adds its own paths, in
`crates/phantom-quic-btls/src/backend/server.rs`:

- Transport parameters longer than BoringSSL can carry fail
  `ServerSession::new` before any FFI call, and a session that failed to
  start answers its first input with `INTERNAL_ERROR` without reaching
  BoringSSL. A test covers both.
- A context without a certificate fails the handshake with BoringSSL's
  alert, carried as a QUIC crypto error. A test covers it.
- `SSL_set_min_proto_version`, `SSL_set_max_proto_version`, and
  `SSL_set_quic_transport_params` fail only on invalid arguments or
  allocation failure, and installing the QUIC callbacks fails only when
  BoringSSL cannot allocate an ex-data index or the state. No test forces
  these: BoringSSL offers no fault injection. Each failure drains the error
  queue and leaves the session failed as above, and a callback-state
  allocation that was not handed to the `SSL` is freed by the installer,
  as on the client.

## Other checks

### External suites

External projects serve as independent witnesses, not as pass badges:

| Suite | Purpose |
| --- | --- |
| Autobahn | Exercise the public WebSocket client and turn failures into focused regressions |
| QUIC Interop Runner | Exercise the public H3 client against an independent server |
| Web Platform Tests | Check selected EventSource behavior through Phantom's API |
| TLS-Anvil and BoringSSL tests | Probe TLS behavior and native dependency updates |

Each row has its own workflow under
[`.github/workflows/`](../../.github/workflows/).

Some sources are only read, never run. curl's test scenarios are a
reference for lifecycle, proxy, redirect, and timeout cases that become
Phantom's own deterministic regressions; no curl suite runs in CI. Likewise,
server-oriented h2spec and h3spec cases inform hostile client-peer tests;
they are not reported as client conformance.

### Diagnostics and performance

Tracing uses static fields and bounded values. It must not record headers,
cookies, credentials, payloads, certificates, endpoint names, or raw
secrets. H3 qlog and NSS key logging are explicit, default-off paths behind
the facade's `diagnostics` feature, which turns on `phantom-net/qlog` and
`phantom-net/keylog`.

Benchmarks state exactly what they measure. The
[benchmark report workflow](../../.github/workflows/benchmarks.yml) runs
weekly or on demand on one Linux runner and uploads Criterion output. It is
report-only, with no baseline comparison or regression threshold. It covers:

- `phantom-net`'s `transport` bench: construction of the Chrome 154 TLS
  connector, and H1/H2 request/response exchanges replayed over an in-memory
  stream (a warm reused H1 response head, a 12-field H1 head, 64 KiB H1
  content-length and chunked bodies, a 12-field H2 head, and a 64 KiB H2
  streaming body); and
- the vendored `tungstenite` `deflate` bench.

Nothing measures the `phantom-http` facade, pools, TLS or QUIC handshakes,
H3, real sockets, or end-to-end throughput. Optimization follows profiling and
must preserve wire fixtures.

### Contributor gates

Formatting, lint, test, documentation, MSRV, capture-tool, and vendor checks
live in [AGENTS.md](../../AGENTS.md), so there is one canonical command list.
A handoff records what ran and any remaining uncertainty.

See [HTTP/3 internals](../internals/http3.md) for H3 capture and packet
evidence.

## Next

- [Coverage](../reference/coverage.md): the support contract these records
  back.
- [Design](design.md): why Phantom returns an error when it cannot
  honor a request.
- [Capture tools](../../scripts/capture/README.md): record a capture
  yourself.
