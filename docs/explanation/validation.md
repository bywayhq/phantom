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
| [Chrome 154 recipes](#chrome-154-recipes) | Windows captures of every Chrome layer, replayed by recipe tests | One Windows build; no macOS or Linux; no Chrome for Testing build exists at this version |
| [Edge 153 and Firefox 156 recipes](#edge-153-and-firefox-156-recipes) | Windows browser captures, replayed by recipe tests | One Windows build per browser; no platform comparison |
| [TCP socket options and address racing](#tcp-socket-option-evidence) | Browser source at one tag per browser, plus socket read-back tests | No capture confirms the options; field trials cannot be ruled out |
| [HTTP/1.1 connection bound](#http11-connection-bound-evidence) | Browser source at one tag per browser, plus loopback tests | No capture counts a browser's connections; no Edge source |
| [Plaintext origin trust](#plaintext-origin-trust-evidence) | Chrome 154, Edge 153, and Firefox 156 proxy route captures, browser source, and loopback tests of Phantom | HTTP/1.1 and HTTP/2 page loads and default-mode `fetch()` only; WebSocket openings not adjusted |
| [SSE reconnect](#sse-browser-reconnect-evidence) | Chrome 154 and Firefox 156 captures, replayed against Phantom | Plaintext HTTP/1.1 on Windows only |
| [WebSocket openings](#websocket-browser-evidence) | Chrome 154, Edge 153, and Firefox 156 captures | No subprotocols, H3, proxies, macOS, or Safari |
| [Alt-Svc racing](#alt-svc-racing-evidence) | Chrome 154 captures and Chromium source, plus loopback tests of Phantom | Caller-supplied origin delay; several listed differences from Chromium |
| [Alt-Svc upgrade](#alt-svc-http3-upgrade-evidence) | Loopback tests | No browser `Alt-Used` ordering; no proxy routes |
| [QUIC resumption and 0-RTT](#quic-resumption-and-0-rtt-evidence) | Chrome 154, Edge 153, and Firefox 156 captures, with the Chromium ones replayed against Phantom's resumed H3 connections | Loopback and headless only; `initial_rtt_us` compared by encoding, not value; no Firefox H3 recipe |
| [Request trailers](#ordered-request-trailer-evidence), [forward proxies](#forward-proxy-evidence), [H3 over SOCKS5](#h3-socks5-udp-evidence) | Loopback tests | No browser-capture fidelity |
| [Proxy routes in browsers](#proxy-route-browser-evidence) | Chrome 154, Edge 153, and Firefox 156 captures, replayed against Phantom | Plaintext origins only; no `https://` or `wss://` origins or SOCKS |
| [Proxy authentication](#proxy-authentication-evidence) | Chrome 154, Edge 153, and Firefox 156 captures and browser source, plus loopback tests of Phantom | One realm; no `407` to a CONNECT captured; forwarded field position and H2 indexing differ |
| [Connection and status retries](#connection-retry-evidence) | Loopback tests | Not browser retry policy; some paths have no recovery test |
| [Content decoding](#content-decoding-evidence) | Unit and loopback tests; browser source for documented divergences | No browser-parity claim |
| [Response-body limits](#response-body-limit-evidence) | Unit tests and an H1 loopback test | No H2 or H3 test exceeds a limit |
| [H2 receive bounds](#adversarial-coverage) | Hostile-peer regressions | Not browser evidence |

Every capture comes from one Windows 11 build, and no third-party observer
backs any current recipe. [Recorded coverage losses](#recorded-coverage-losses)
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

Every recipe in this tree comes from Windows 11 (build 26200, x64) captures of
the browser build installed on the capture host. Phantom carries one version
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

- One Windows build, and one build per browser. No macOS or Linux capture of
  any current recipe exists, so platform independence is not claimed.
- Launches are headless, except the headful client-hint and SSE runs each
  section names.

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

`chromium::v154_http3_tls`, and `edge::v153_http3_tls` through it, enable
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
| `tls` | `client-hello.txt`, `trust-anchor-orders.txt` |
| `http2` | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-{1,2}.txt` |
| `client-hints` | `navigation.txt` |
| `websocket` | Nine scenarios |
| `sse` | Seventeen scenarios and `launch-mode/` |
| `alt-svc` | Seven scenarios |

Limits:

- One Windows build, and one branded Chrome build. No macOS or Linux capture
  of this version exists, and no Chrome for Testing build of it is published,
  so neither platform nor build flavor is isolated at 154 and there is no
  `*-chrome-for-testing` fixture. The Chrome for Testing 154 list ends at
  154.0.8037.57, a different build that would need its own version directory.
- `chromium::v154_tcp` rests on Chromium source at tag `154.0.8037.58`, not
  on a capture; see
  [TCP socket option evidence](#tcp-socket-option-evidence).
- `client-startup.txt` under `http3` is the only CRLF file under `fixtures/`,
  because `chrome_http3.py` opens that path in text mode. Its bytes and pinned
  SHA-256 are stable in the repository, but rerunning the documented command
  on another platform would not reproduce that hash; see
  [Capture tools](../../scripts/capture/README.md).
- The comparison with Chrome 153 is recorded, not reproducible; see
  [Comparison with Chrome 153](#comparison-with-chrome-153).
- Launches are headless, except one headful client-hint run and five headful
  `retry-750` SSE runs.

### Edge 153 and Firefox 156 recipes

What is claimed: the `edge::v153_*` recipes, with the Chromium recipes they
reuse, reproduce Edge 153.0.4234.48, and the `firefox::v156_*` recipes
reproduce Firefox 156.0, both on Windows 11.

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

The recipes follow from those results. `edge::v153_tls` and
`edge::v153_http3_tls` remove the trust-anchor IDs from the Chromium recipes.
The Chrome 153 and Chrome 154 ClientHellos differ only in that extension, so
the Edge captures replay against the surviving Chromium recipes unchanged.
Edge has no H2, QUIC, or H3 recipe of its own, because those layers equal the
Chromium recipes on every compared field. `edge::v153_windows_client_hints`
and the Edge request templates carry Edge's brand list and build values. The
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

The `edge_153_*` and `firefox_156_*` tests in `phantom-profile` and
`phantom-net` replay these fixtures. TLS and QUIC ClientHellos go through the
public TLS and H3 connector paths, and H2 startup frames through the public H2
path. H3, QUIC, H2 request, and client-hint fields are compared against the
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
| Edge 153.0.4234.48 | `tls` | `client-hello.txt` |
| Edge 153.0.4234.48 | `http2` | `client-startup.txt` |
| Edge 153.0.4234.48 | `http3` | `client-startup.txt`, `quic-client-hello-1.txt`, `quic-client-hello-2.txt` |
| Edge 153.0.4234.48 | `client-hints` | `navigation.txt` |
| Edge 153.0.4234.48 | `websocket` | Nine scenarios; see [WebSocket browser evidence](#websocket-browser-evidence) |
| Firefox 156.0 | `tls` | `client-hello.txt` (AES-128-GCM ECH GREASE), `client-hello-chacha20-ech.txt` |
| Firefox 156.0 | `websocket` | Nine scenarios |
| Firefox 156.0 | `sse` | Seventeen scenarios |

Limits:

- One Windows build per browser. No macOS or Linux capture of these versions
  exists.
- Headless launches only, except the headful client-hint check.
- Firefox 156 has no raw H2 startup fixture, so its SETTINGS and connection
  window rest on the H2 session captures rather than on raw startup bytes.

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
bound.

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

Loopback tests in `crates/phantom/tests/session_http1_parallel.rs`:

| Test | What it proves |
| --- | --- |
| `concurrent_requests_open_connections_up_to_the_bound_then_wait` | `max_concurrent_http1_requests_per_origin` replaces the recipe's bound; requests open connections up to it, and a further request waits for a free connection |
| `idle_connection_is_reused_before_another_opens` | A freed connection is reused before a new one opens |
| `bound_is_counted_per_route_to_one_origin` | Each route to one origin has its own bound |
| `named_recipe_opens_six_connections_to_one_origin` | Both recipes open six connections and hold a seventh request |
| `profile_without_http1_policy_keeps_one_connection_per_origin` | A profile without `Http1Settings` keeps one connection |
| `requests_cancelled_during_connection_setup_leave_the_full_bound` | Requests dropped while their connection is being set up do not use up the bound |
| `custom_profile_carries_its_own_http1_bound` | A custom `Http1Settings` bound reaches the client |

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- No capture confirms the limit or the reuse order.
- The source was read at one tag per browser, so field-trial changes would
  not be seen.

### Plaintext origin trust evidence

What is claimed: for a URL that is not
[potentially trustworthy](../reference/glossary.md#potentially-trustworthy),
such as `http://origin.phantom.test/`, the built-in request templates send
the fields Chrome 154, Edge 153, and Firefox 156 send there, in the same
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
- `crates/phantom/tests/plaintext_templates.rs` sends each built-in template
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
- `crates/phantom/tests/websocket_trust.rs` opens each built-in WebSocket
  recipe, through `Client::websocket` and through
  `Client::websocket_with_profile_policy`, to `ws://127.0.0.1` directly and
  to `ws://origin.phantom.test` through a loopback CONNECT proxy. It supplies
  only `User-Agent`, `Origin`, and `Accept-Language` and compares every
  received field and value, apart from the fresh key and the loopback `Host`,
  with the `direct-loopback` and `http-proxy-hostname` captures. It also
  checks that a caller `Accept-Encoding` replaces the recipe's value in place.

How to reproduce: `scripts/capture/proxy_route.py --browser <browser>
--scenario all --repeat 3`, then
`cargo test -p phantom-http --all-features --test plaintext_templates
--test websocket_trust` and
`cargo test -p phantom-profile plaintext_named_origin` and
`cargo test -p phantom-profile origin_trust`.

Limits:

- The request template tests hold the captured field lists as data; they do
  not read the fixtures. The WebSocket tests read them.
- The captured `fetch()` used the default cache mode. That the no-store
  template's `Pragma` and `Cache-Control` keep their positions on a named
  plaintext origin is inferred.
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

`crates/phantom/tests/sse_browser_reconnect.rs` reads the retained fixtures
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

### WebSocket browser evidence

What is claimed: Phantom's profile WebSocket connection policy and recipes
open a WebSocket the way Chrome 154, Edge 153, and Firefox 156 do, apart from
the [differences](../reference/websocket.md#differences-from-the-captures)
the WebSocket reference lists.

Evidence: `fixtures/websocket/` retains WebSocket openings from headless
Chrome 154.0.8037.58, Edge 153.0.4234.48, and Firefox 156.0 on Windows 11
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

| Behavior | Chrome 154 and Edge 153 | Firefox 156 |
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
  that rule and all 831 Firefox decisions follow the weaker one, coding
  whenever the result is no longer; the two differ only on the 105 and 135
  ties, such as `CONNECT`, `13`, `*/*`, `?0`, `?1`, and `1`.
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

`crates/phantom/tests/websocket_profile.rs` drives
`Client::websocket_with_profile_policy` against a loopback origin and
compares what the origin observes with these captures. It compares every
emitted CONNECT pseudo-field with the capture's HPACK `repr`, static
`index`, `name_huffman`, and `value_huffman`. A dynamic-table index itself is
not compared, because its value depends on earlier blocks on the connection.
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

- The captures do not cover subprotocols, H3, proxies, macOS, or Safari.
- WebSocket proxy routes are covered only by loopback tests; see
  [Forward-proxy evidence](#forward-proxy-evidence).

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
- `AltSvcBrokenBackoff::CHROMIUM_153` holds a 300 s initial period that
  doubles up to two days. A failure inside an active broken period counts
  toward the next period without extending the current one
  (`broken_alternative_services.cc` lines 137-154).

| Tests | What they cover |
| --- | --- |
| Unit tests with a paused clock: race coordinator | Origin start at the configured delay, immediate start after an alternative failure, cancellation of both candidates, and connect and total deadlines (the coordinator's permit tests use stand-in semaphores) |
| Unit tests with a paused clock: store | Brokenness per origin and alternative, expiry, doubling with a cap, a repeated failure inside one broken period, and clearing on success or `clear` |
| Unit tests with a paused clock: H3 connect turns | One location waits only for its own turn |
| Loopback, `crates/phantom/tests/alt_svc_race.rs`, real client pools | The default sequential terminal failure; one dispatch per request, with background pooling of the losing alternative; a one-shot streaming body sent only by the winner; route preservation |
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
to the origin, without an `Alt-Used` field and without delaying any request.

Evidence: `crates/phantom/tests/https_records.rs` runs a loopback DNS server
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
  from a second DNS client, and no request waits for them.
- An unanswered query is resent after 333 ms and again 333 ms later, on the
  resolver library's schedule rather than Chrome's.
- A record's `ech` value is kept as `ECHConfigList` bytes and not used.

### QUIC resumption and 0-RTT evidence

What is claimed: with the Chrome 154 or Edge 153 recipe, a resumed Phantom
H3 connection offers the ClientHello extensions and QUIC transport parameters
these captures show for that browser. Phantom sends `GET`, `HEAD`, and
`OPTIONS` requests issued before the handshake completes in 0-RTT packets,
as the browsers did, and never sends `POST`, `PUT`, or `DELETE` early. Like
Chromium, it starts a resumed connection from the server SETTINGS remembered
with the ticket, so the recipes' dynamic QPACK policy can encode a request
before the server's SETTINGS arrive. The Firefox 156 captures record browser
behavior only; Firefox has no H3 recipe.

Evidence: `fixtures/http3/<browser>/<version>/windows-11-26200/` retains
`resumption-accept.txt` (5 runs), `resumption-accept-delayed.txt` (3 runs),
and `resumption-reject.txt` (3 runs) for headless Chrome 154.0.8037.58,
Edge 153.0.4234.48, and Firefox 156.0 on Windows 11 (10.0.26200). Versions
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

| Behavior | Chrome 154 and Edge 153 | Firefox 156 |
| --- | --- | --- |
| Transport parameters added on resumption | `initial_rtt_us` (0x3127), carrying the previous connections' RTT: 952-6414 µs on loopback, 41449-59157 µs with the 50 ms delay | None |
| `version_information` | Unchanged apart from the reserved version's position, which varies per connection | Chosen version becomes QUIC v2 (0x6b3343cf), and the resumed connection starts in v2 packets; fresh connections start in v1 and are upgraded by aioquic |
| Later connections that resumed (`accept`, `reject`) | Chrome 39 of 39; Edge 37 of 37 | 22 of 32 |
| Resumption in `accept-delayed` | 12 of 12 | 0 of 12 |
| Second navigation in 0-RTT (`accept`) | 0 of 5 | 2 of 5 |
| Second navigation in 0-RTT (`accept-delayed`) | 3 of 3 | none resumed |

The Chromium navigation arrived in 1-RTT because of a preconnect. A
diagnostic Chrome run with `--log-net-log`, not retained, showed a preconnect
job (`is_preconnect: true`) open the QUIC session about 5 ms before the
navigation request, reach `QUIC_SESSION_ZERO_RTT_STATE
AttemptedAndSucceeded`, and complete the loopback handshake before the request
bound to it. With 50 ms of added delay the navigation was issued during the
handshake and arrived in 0-RTT on all three runs of both browsers.

The same log explains the extra connection at startup in 4 of 5 Chrome and
4 of 5 Edge `accept` runs. A first preconnect opened a fresh session
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
  `crates/phantom/tests/http3_early_data.rs`, uses the Chrome 154 recipes,
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
  connection. Other tests there show a rejected `POST` resent with its whole
  body, a failed handshake failing the request without a second connection,
  and the connect timeout bounding the wait for the early-data answer.
- `dynamic_qpack_sends_a_replay_safe_request_early_from_remembered_settings`,
  in `crates/phantom-net/src/http3/tests/early_data.rs`, shows the recipe's
  `GET` opening its stream before the handshake on a connection that started
  from remembered SETTINGS.
  `a_server_that_reduces_a_remembered_setting_is_closed_with_settings_error`
  resumes against a server that lowers the field-section limit it advertised
  on the ticket's connection, and the server sees the connection closed with
  `H3_SETTINGS_ERROR` (0x109).
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
- Phantom opens its QPACK encoder stream as client stream 6 and its decoder
  stream as stream 10, and writes the encoder stream's type byte when the
  connection starts. Chromium uses stream 10 for its encoder and writes the
  type byte with the first instruction. So Phantom's 0-RTT encoder
  instructions travel on stream 6, where Chromium's travel on stream 10.
  The [roadmap](../roadmap.md) has the item.
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
- When the server rejects early data and then sends SETTINGS incompatible
  with the remembered ones, Chromium closes the connection with the
  transport error `INTERNAL_ERROR` and skips the check for omitted settings;
  Phantom applies every check and closes with `H3_SETTINGS_ERROR`. Phantom
  does not reuse a rejected connection either way.
- When the server rejects early data, the captured browsers send the request
  again on the same connection. Phantom does not reuse the rejected
  connection: it sends the request on a new one, which offers no early data.
- A connection opened by an Alt-Svc racing attempt offers no early data.
- Headless launches on one Windows build; no TCP TLS resumption capture.
- Chromium ran with `--disable-field-trial-config`; the retained Chrome 154
  startup captures ran without it. The fresh ClientHello of Chrome `accept`
  run 0 still has the same extension set and transport-parameter values as
  the retained `quic-client-hello-1.txt`, apart from the reserved version's
  position in `version_information`. Other fresh ClientHellos were not
  compared with the startup captures.

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
triggers one replay on a fresh connection over the same route. They assert
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
origins in `crates/phantom/tests/proxy_h2.rs`. The same file forwards an
exact H2 and a negotiated `http://` request over one HTTP/2 proxy
connection, and asserts `:scheme` `http`, the origin in `:authority`, the
fields, and an H2 `ResponseInfo::protocol`; it rejects exact H1 before
I/O, and answers a Basic `407` to a forwarded request with one replay on the
same proxy connection. H3 over SOCKS5 has its own
[evidence](#h3-socks5-udp-evidence).

Negotiated requests through plaintext, TLS, and HTTP/2 proxy transports have
regressions in `crates/phantom/tests/negotiated_proxy.rs`. They cover `h2`
and `http/1.1` selection inside the tunnel, the same CONNECT fields and Basic
retry as an exact request, a refused CONNECT that fails as an exact request
does, an Alt-Svc advertisement on the tunnel that is not stored, refusal on a
CONNECT-UDP route, pool isolation between routes, and a failed origin
handshake that is not retried.

Negotiated `http://` requests have regressions in
`crates/phantom/tests/negotiated.rs`, `socks5.rs`, `alt_svc_persistence.rs`,
and `redirects.rs`. They prove that the request reaches the origin as a
cleartext HTTP/1.1 head directly, in absolute form through a forward proxy,
and inside a SOCKS5 tunnel; that the response reports H1; that an `h3`
advertisement on it is not stored; and that a negotiated redirect to an
`http://` target is followed over H1.

WebSocket route regressions in `crates/phantom/tests/websocket/routing.rs`
tunnel a plaintext `ws://` Upgrade through plaintext and TLS-encrypted HTTP
proxies. They assert the exact CONNECT head, then an origin-form opening
inside the tunnel with the caller-selected field order and no origin TLS,
no direct-origin traffic, independent proxy trust, and Ping/Pong traffic.
Authentication cases prove an anonymous first CONNECT; one replay of the
CONNECT on a fresh connection with generated credentials, which never reach
the opening; credentials on the first CONNECT of a later WebSocket to the
same proxy, or a fresh challenge for each when the record is disabled; and
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
`crates/phantom/tests/socks5.rs`, `socks5_local.rs`, and `socks5/auth.rs`.
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

What is claimed: these captures record what Chrome 154, Edge 153, and
Firefox 156 send to an HTTP proxy for plaintext `http://` and `ws://`
origins. Phantom's `ws://` route through an HTTP proxy follows them; the
remaining differences from the [route matrix](../reference/route-matrix.md)
are listed at the end of this section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains captures from
headless Chrome 154.0.8037.58, Edge 153.0.4234.48, and Firefox 156.0 on
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

| Behavior | Chrome 154 and Edge 153 | Firefox 156 |
| --- | --- | --- |
| `ws://` through a plaintext proxy | `CONNECT host:port`, then the origin-form Upgrade inside the tunnel | Same |
| CONNECT field order | `Host`, `Proxy-Connection: keep-alive`, `User-Agent` | `User-Agent`, `Proxy-Connection: keep-alive`, `Connection: keep-alive`, `Host` |
| `http://` through a plaintext proxy | Absolute-form; `Proxy-Connection: keep-alive` second, where a direct request has `Connection: keep-alive` | Absolute-form; fields identical to a direct request, with `Connection: keep-alive` and no `Proxy-Connection` |
| `http://` through the TLS proxy | ALPN `h2` to the proxy; H2 request with `:scheme` `http` and the origin in `:authority` | Same |
| Pseudo-field order of that request | `:method`, `:authority`, `:scheme`, `:path` | `:method`, `:path`, `:authority`, `:scheme`, and `te: trailers` last |
| `ws://` through the TLS proxy | H2 CONNECT (`:method`, `:authority`, `user-agent`) on the page's proxy session, then the H1 Upgrade in the stream | Same CONNECT fields, on a second H2 connection to the proxy |

`Accept-Encoding`, fetch metadata, and client hints depend on the origin,
not on the route. [Plaintext origin trust
evidence](#plaintext-origin-trust-evidence) gives the values for each origin
and how Phantom's templates follow them.

Further observations:

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
  `crates/phantom/tests/plaintext_templates.rs` compare every forwarded field
  and value with the `http-proxy-hostname` and `http-proxy-loopback`
  requests, and
  `chromium_templates_swap_connection_for_proxy_connection_only_when_forwarded`
  in `phantom-profile` checks the template data.
- `ws://` H1 through an H1 proxy: Phantom tunnels with CONNECT and sends
  the direct Upgrade inside, as every captured browser does.
  `plaintext_websocket_through_an_http_proxy_tunnels_the_captured_opening`
  in `crates/phantom/tests/websocket_profile.rs` sends the Chromium and
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
  `crates/phantom/tests/proxy_field_order.rs` compare Phantom's anonymous,
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
  its Firefox counterpart in `crates/phantom/tests/proxy_h2.rs` decode the
  first HEADERS block and compare its pseudo-field order with the
  `https-proxy` captures. Exact H1 stays rejected before I/O. Phantom does
  not reproduce the per-request HEADERS priority, `te: trailers`, or the
  other fields of a browser page load unless a request template supplies
  them.
- `ws://` H1 through an H2 proxy: Phantom opens a CONNECT stream and sends
  the Upgrade inside it, as every captured browser does. The stream is on a
  new proxy connection, as Firefox opens one; Chromium reuses the page's
  proxy session instead.

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
`407` and accepts the credentials, Chrome 154, Edge 153, and Firefox 156 send
`Proxy-Authorization` on the first attempt of every later CONNECT tunnel and
forwarded request to that proxy. Phantom does the same by default for CONNECT
tunnels on both proxy transports, including WebSocket tunnels, and for H1 and
H2 forwarding. The differences that remain are listed at the end of this
section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains four
authentication scenarios per browser, `http-proxy-auth-*` and
`https-proxy-auth-*`, with loopback and named origins, from the same headless
Chrome 154.0.8037.58, Edge 153.0.4234.48, and Firefox 156.0 builds on Windows
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

| Behavior | Chrome 154 and Edge 153 | Firefox 156 |
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
- Credentials supplied through `Fetch.continueWithAuth` and
  `network.continueWithAuth` reach the same caches as a prompt's
  (`content/browser/devtools/devtools_url_loader_interceptor.cc` lines 1433 to
  1446; `nsHttpChannelAuthProvider.cpp` lines 1363 to 1425).

Against Phantom:

- `sequential_tunnels_pay_for_one_challenge_instead_of_one_per_tunnel` in
  `crates/phantom/tests/proxy_credential_cache.rs` opens four tunnels one
  after the other through a plaintext proxy that challenges every request
  without credentials. With the record the proxy sees five connections and
  one `407`; with `preemptive_proxy_authentication(false)` it sees eight
  connections and four `407` responses. The same file proves that another
  proxy port, other credentials, and the origin never receive remembered
  credentials, and that each session starts with an empty record.
- `crates/phantom-net/src/proxy/tests/credential_cache.rs` covers the record:
  a pair is added only after the proxy accepts the replay; a `407` or an
  unusable challenge to remembered credentials forgets them and permits one
  replay; a proxy that never challenges is not recorded; entries are separate
  by scheme, host, port, and credentials; and a full record evicts the least
  recently used pair.
- `proxy_h2.rs` covers H2 CONNECT tunnels and H2 forwarding, including the
  replay on the same H2 proxy connection, a second `407`, and the
  never-indexed HPACK form of the forwarded `proxy-authorization` field.
  `forward_proxy.rs` covers H1 forwarding on the pooled proxy connection and
  a `407` to remembered credentials. `websocket/routing.rs` covers two
  `ws://` tunnels after one challenge.
- A CONNECT request places the field at the placeholder of the route's
  CONNECT fields, or of the profile's `with_proxy_connect` recipe, last in
  both built-in recipes, as both browsers do.
- A forwarded request with a built-in request template places the field at
  the template's `RequestField::ProxyAuthorization` slot for the attempt.
  `forwarded_requests_place_proxy_credentials_as_captured` in
  `crates/phantom/tests/proxy_field_order.rs` reads the
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
  compare Phantom with them. Without a template, or with a template that
  has no slot for the attempt, the field follows every other field. On a
  route without configured credentials, a caller's own `Proxy-Authorization`
  on a forwarded request takes the template's slot for a first attempt.

Remaining differences:

- The captured `fetch()` requests used the default cache mode, so where
  Firefox puts `Proxy-Authorization` on a replayed no-store `fetch()`
  relative to `Pragma` and `Cache-Control` is not captured. The template
  puts it after them, last, as on the captured replay.
- H2 forwarding and H2 CONNECT send `proxy-authorization` as a never-indexed
  literal, where both browsers index it. Phantom keeps this on purpose, as of
  2026-09-25. The HPACK block goes only to the proxy, which already holds the
  credentials and re-encodes the request toward the origin, so the
  difference is visible to the proxy and not to an origin. RFC 7541 section
  7.1.3 recommends never indexing credentials, because a peer that can add
  chosen fields to requests on the same connection and observe their size
  can guess an indexed value. Indexing would also need a new marker:
  `RequestHeader::sensitive` both selects the never-indexed form and hides
  the value from `Debug` output, and a field without it prints its value in
  `RequestHeader` and `http::HeaderValue` `Debug` output. The vendored
  `http2` frame `Debug` output leaves out every field, and Phantom never
  prints the connection whose HPACK table would hold the value, but the
  request fields pass through Phantom's own types first.
- The replay after a challenge to a CONNECT or H1 forwarded request opens a
  new proxy connection, where both browsers reuse a connection that the `407`
  left open. The record limits this cost to the first challenge for each
  proxy and credentials.
- Phantom records a pair only after the proxy accepts it; browsers record it
  when the credentials are supplied.
- The record holds 128 pairs; Chromium holds 20 and Firefox has no limit.

How to reproduce: `scripts/capture/proxy_route.py --browser <browser>
--scenario http-proxy-auth-remembered-hostname
https-proxy-auth-remembered-hostname http-proxy-auth-secure-hostname
https-proxy-auth-secure-hostname http-proxy-auth-hostname https-proxy-auth-hostname
http-proxy-auth-loopback https-proxy-auth-loopback --repeat 3`; see
[Proxy routes](../../scripts/capture/README.md#proxy-routes).

Limits:

- Plaintext origins only, one realm, and no CONNECT request that received a
  `407`, because each page's first request was a forwarded navigation.
  Connection reuse after a `407` to CONNECT comes from source reading only.
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

Exact-H3 loopback regressions in `crates/phantom/tests/http3_retries.rs`
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

Status-retry regressions in `crates/phantom/tests/status_retry.rs` run over
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
any copy, and both have tests. A panic inside a callback is contained by
`catch_unwind`, but the test calls the containment helper directly; nothing
panics across a real BoringSSL call edge. Dropping the `SSL` mid-handshake
runs the ex-data destructor; the tests that check the owner counts drop a
session that never started a handshake. Until those last two have tests,
running them under a sanitizer proves nothing about them.

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
