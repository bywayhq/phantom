# Validation

This page records the evidence behind each claim in
[Coverage](../reference/coverage.md), and what that evidence does not cover.

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
| [SSE reconnect](#sse-browser-reconnect-evidence) | Chrome 154 and Firefox 156 captures, replayed against Phantom | Plaintext HTTP/1.1 on Windows only |
| [WebSocket openings](#websocket-browser-evidence) | Chrome 154, Edge 153, and Firefox 156 captures | No subprotocols, H3, proxies, macOS, or Safari |
| [Alt-Svc racing](#alt-svc-racing-evidence) | Chrome 154 captures and Chromium source, plus loopback tests of Phantom | Caller-supplied origin delay; several listed differences from Chromium |
| [Alt-Svc upgrade](#alt-svc-http3-upgrade-evidence) | Loopback tests | No browser `Alt-Used` ordering; no proxy routes |
| [Request trailers](#ordered-request-trailer-evidence), [forward proxies](#forward-proxy-evidence), [H3 over SOCKS5](#h3-socks5-udp-evidence) | Loopback tests | No browser-capture fidelity |
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
rather than a delta over 153 (listed in
[Coverage](../reference/coverage.md#browser-profiles)), reproduce Google Chrome
154.0.8037.58 on Windows 11.

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

#### Comparison with Chrome 153

Chrome 154 was compared against the Chrome 153 Windows fixtures while those
were still in the tree. They have since been removed with the Chrome 153
recipes, so the comparison is recorded here rather than reproducible from the
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
  [the capture README](../../scripts/capture/README.md).
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
Firefox sends no user-agent client hints, and no Firefox QUIC or H3 capture
exists.

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
browser source rather than on retained fixtures. The socket-option and Happy
Eyeballs default citations are to Chromium tag `154.0.8037.58` and Firefox tag
`FIREFOX_156_0_RELEASE`. The line numbers for the rest of the racing
algorithm, which `TcpAddressRacing` and `phantom-net`'s `address_racing`
module document, were read at Chromium tag `153.0.8010.48` and have not been
re-read at 154; the defaults those recipes encode were.

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
[the capture README](../../scripts/capture/README.md) has the commands. The
Chrome 153 comparison is under
[Comparison with Chrome 153](#comparison-with-chrome-153).

Limits:

- The captures cover plaintext HTTP/1.1 only. H2, H3, macOS, and Safari
  behavior is not inferred from them.

### WebSocket browser evidence

What is claimed: Phantom's profile WebSocket connection policy and recipes
open a WebSocket the way Chrome 154, Edge 153, and Firefox 156 do, apart from
the differences the WebSocket guide lists.

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
  without indexing.
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
compares what the origin observes with these captures. The WebSocket guide
lists where Phantom's recipes still differ from the captured browsers, such
as Chrome's retry after `RST_STREAM(REFUSED_STREAM)`; see
[Browser recipes](../guides/websocket.md#open-a-websocket-the-way-the-browser-does).

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

Source citations are to tag `153.0.8010.48`.

| Question | Chrome 153 observation | Chrome 154 | Source cross-check |
| --- | --- | --- | --- |
| First new connection after learning (`race-after-learning`) | QUIC job starts first; main TCP job logs `should_wait:true`, then `HTTP_STREAM_JOB_DELAYED delay:0` and resumes 1-2 ms later; first TCP connect 0-1 ms after the first QUIC packet (server: 1.4-1.6 ms after the first datagram, one 11.9 ms outlier). QUIC bound 10/10; the main job was cancelled 10/10, yet its connection was still established and stayed idle without a request. | Main job waits 0 ms; alternative bound 10/10 | Main job blocked while an alternative job exists (`http_stream_factory_job_controller.cc` line 1084); wait is 0 while QUIC has never worked on the network (`quic_session_pool.cc` line 1590) |
| After QUIC worked (`race-after-quic-worked`, second race) | `HTTP_STREAM_JOB_DELAYED` 3-8 ms (median 7.5); QUIC connected within the wait, the main job never started, QUIC bound 10/10. | Main job waits 4-10 ms (median 8) | Wait is 1.5 x smoothed RTT, or 300 ms without RTT stats, plus a non-Android 0 ms additional delay (`quic_session_pool.cc` lines 1606-1616), capped at 3 s (`http_stream_factory_job_controller.cc` line 143); the RTT-dependent value is only what loopback produced |
| UDP blackhole (`udp-blackhole`) | TCP starts 0-1 ms after QUIC (fresh profile) and wins 10/10; the orphaned QUIC job fails with `-356` after the 4 s handshake idle timeout; the next request logs `is_broken:true` and creates only a main job; polled expiry 299-300 s after the failure. | TCP wins 10/10; orphaned QUIC job fails with `-356`; broken 299-300 s | Orphaned alternative runs to completion to report brokenness (lines 1160-1167); marked broken only when the main job succeeded (lines 1257-1302); the 4 s is `max_idle_time_before_crypto_handshake` = `kInitialIdleTimeoutSecs` (5 s; `net/quic/quic_context.h` line 172, quiche 2c4a1246 `quic_constants.h` line 159) less the one second quiche removes from a client idle timeout (`quic_connection.cc` lines 4983-4984) |
| QUIC certificate failure (`quic-bad-certificate`) | QUIC fails in about 1 ms; TCP wins 10/10; broken for 299-300 s; the next request does not use QUIC. | TCP wins 10/10; broken 299-300 s | Same reporting path |
| QUIC ALPN failure (`quic-bad-alpn`) | Same as the certificate failure: broken 10/10 for 299-300 s. | TCP wins 10/10; broken 299-300 s | Same reporting path |
| Existing H2 session (`existing-h2-session`) | The request after learning uses the existing H2 session at once (wait 0) 10/10 while the alternative job keeps running and connects QUIC; the next two same-page requests use that QUIC session 10/10. | Binds the H2 session at once while the alternative keeps connecting | Zero wait with an available SPDY session unless `delay_main_job_with_available_spdy_session` (`http_stream_factory_job_controller.cc` line 744; default false, `net/quic/quic_context.h` line 238) |
| Broken expiry and backoff (`broken-backoff`) | About 290 s after the first failure the alternative is still broken; about 305 s after it QUIC is tried again, fails, and is broken for 599 s, both runs. | Broken 299-300 s after the first failure and 599-600 s after the second | `ComputeBrokenAlternativeServiceExpirationDelay`: 300 s initial, `initial << broken_count`, capped at 2 days (`net/http/broken_alternative_services.cc` lines 22, 58, 62; `net/base/features.cc` lines 1027 and 1037; `exponential_backoff_on_initial_delay_` defaults to true in `broken_alternative_services.h` line 236) |

The Chrome 154 captures used the same scenarios and repeat counts. Two
observations vary per run rather than per version: in one `race-after-learning`
run the NetLog recorded the main job as having opened a
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
- Phantom does not persist brokenness, does not reset it on a network change,
  and has no DNS HTTPS-record (`dns_alpn_h3`) job.
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
QUIC connection per location in the same pool entry, rather than a
replacement on every switch.

Limits:

- Not covered: browser `Alt-Used` ordering, upgrades on proxy routes,
  snapshots on proxy routes, and racing among multiple alternatives. Racing
  between one alternative and the origin has its own
  [evidence](#alt-svc-racing-evidence).

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

Authentication regressions prove that every logical request is first sent
without credentials, and that only a strict, valid Basic `407` challenge
triggers one replay on a fresh connection over the same route. They assert
the position of the generated sensitive `Proxy-Authorization` field, after the
caller's fields and before framing; exact replay of owned bodies and static
trailers, and failure before a retry connection opens for a one-shot
streaming body; typed proxy errors, without direct or protocol fallback, for a
second `407` and for malformed or unsupported challenges; and an anonymous
start for the next logical request, which proves that no challenge state is
learned.

Lifecycle cases also cover a nonempty challenge body; a queued request that
installs an intervening pooled connection without capturing the
authenticated retry; one total deadline spanning both attempts; and
suppression of cookies from the challenge response, while cookies from the
final origin response are kept.

The HTTP/2 proxy transport has separate CONNECT regressions for H1 and H2
origins in `crates/phantom/tests/proxy_h2.rs`, including rejection of
plaintext forwarding before I/O. H3 over SOCKS5 has its own
[evidence](#h3-socks5-udp-evidence).

WebSocket route regressions apply the same contract to a plaintext `ws://`
Upgrade through plaintext and TLS-encrypted forward proxies. They assert the
normalized absolute-form request target, the caller-selected order of
opening fields, the absence of CONNECT and of direct-origin traffic,
independent proxy trust, upgraded bytes coalesced with the response, and
Ping/Pong traffic. Authentication cases prove an anonymous first attempt; one
replay on a fresh connection with the same WebSocket key and generated
credentials appended after the caller's fields; no learned state; and
terminal behavior for malformed or repeated challenges. A caller-supplied
`Proxy-Authorization` is rejected before any proxy or origin I/O.

SOCKS5 WebSocket regressions cover plaintext `ws://` as well as TLS-backed
`wss://`. The plaintext cases prove remote-DNS Unicode canonicalization,
local-DNS address resolution, username/password negotiation, an origin-form
Upgrade with no origin TLS, and delivery of a WebSocket frame coalesced with
the `101` response.

Limits:

- No browser-capture fidelity.
- Not covered: redirects, negotiated H1/H2 forwarding, H2 proxy transport,
  other authentication schemes, forwarding an HTTPS origin, and H3 through an
  HTTP forward proxy.

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
H2 frame decoders, Quinn transport parameters, and the production HTTP
CONNECT response and proxy Basic challenge parsers. The workflow runs for 15
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

Some sources are consulted rather than run. curl's test scenarios are a
reference for lifecycle, proxy, redirect, and timeout cases that become
Phantom's own deterministic regressions; no curl suite runs in CI. Likewise,
server-oriented h2spec and h3spec cases inform hostile client-peer tests;
they are not reported as client conformance.

### Diagnostics and performance

Tracing uses static fields and bounded values. It must not record headers,
cookies, credentials, payloads, certificates, endpoint names, or raw
secrets. H3 qlog and NSS key logging are explicit, bounded, default-off
paths. They are Cargo features of the internal crates (`phantom-net/qlog` and
`phantom-quic-btls/keylog`), used by capture tooling and tests. The
`phantom-http` facade exposes neither the features nor an API for them.

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
- [Design](design.md): why Phantom fails rather than falling back.
- [Capture tooling](../../scripts/capture/README.md): record a capture
  yourself.
