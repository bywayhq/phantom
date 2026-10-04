# Validation

Check the evidence behind each claim in [Coverage](../reference/coverage.md),
and what that evidence leaves unproven.

> For specialists checking a claim and evaluators deciding how far to trust
> one.

## Trust at a glance

Phantom's claims rest on five kinds of evidence:

- A **browser capture** records a named browser build's traffic against a
  loopback listener. Captures are retained under `fixtures/`, and most are
  replayed by tests.
- **Browser source** is the browser's code at a release tag. It is the
  evidence where a capture cannot see a behavior.
- A [hook log](../reference/glossary.md#hook-log) records a named browser
  build's own calls into the operating system's socket and resolver
  interfaces, from inside its network service process. It is the evidence
  for socket options, failed connection attempts, and cached lookups, which
  no listener sees.
- A **loopback test** drives Phantom's public client against a scripted local
  peer. It proves Phantom's own contract, not browser parity.
- A **hostile-peer regression** sends malformed or abusive traffic. It proves
  that Phantom stays safe and bounded, not that it matches a browser.

| Area | Strongest evidence | Main limits |
| --- | --- | --- |
| [Chrome 154 recipes](#chrome-154-recipes) | Windows captures of every Chrome layer, replayed by recipe tests; fingerprint snapshots and client-hint captures of 154.0.8037.97 | Per-layer captures of one Windows build, 154.0.8037.58; macOS only for client hints and request fields; no Linux; no Chrome for Testing build exists at this version |
| [Edge 153 and Firefox 157 recipes](#edge-153-and-firefox-157-recipes) | Windows browser captures, replayed by recipe tests | One Windows build per browser; macOS only for client hints and request fields |
| [Edge 154 recipes](#edge-154-recipes) | Fingerprint snapshots against Edge 153 and 154.0.4258.37, Windows and macOS captures of every scenario whose request fields carry the brand list, and hook logs for TCP, the HTTP/1.1 bound, and the address cache | One run of each QUIC resumption scenario and two H3 startups on Windows; ECH and the raw H2 startup rest on Edge 153 |
| [Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes) | Windows browser captures, replayed by recipe tests; Brave source at its release tag, and Opera hook logs, for TCP, the HTTP/1.1 bound, and the address cache | One Windows build per browser; no SSE or Alt-Svc capture; Opera's H2 and H3 startups launched through DevTools |
| [macOS recipes](#macos-recipes) | macOS 15.5 arm64 captures of Chrome 154, Edge 154, Opera 136, and Firefox 157 client hints and request fields, replayed by recipe tests | One Apple silicon host; headless only; single-sample parity runs for the other layers |
| [Opera for Android 102 recipes](#opera-for-android-102-recipes) | Android 17 emulator captures of the TLS ClientHello and client hints; Android 15 emulator captures of HTTP/1.1 requests to loopback | Opera takes no switches: no H2, QUIC, H3, or templates |
| [Firefox for Android 156 recipe](#firefox-for-android-156-recipe) | Android 15 emulator captures of the TLS ClientHello | No certificate trust on Android, so no other layer |
| [Chrome for Android 154 recipes](#chrome-for-android-154-recipes) | Android 17 emulator captures, reporting a Pixel 7, of TLS, H2, QUIC, H3, QUIC resumption, client hints, WebSocket openings, plaintext trust, and templates, replayed by recipe tests; one Chrome 153 cellular startup on an Android 15 emulator | An emulator, not a phone; no TCP layer; one process per transport layer |
| [Brave for Android 153 recipes](#brave-for-android-153-recipes) | Android 17 and Android 15 emulator captures of the same layers, replayed by recipe tests | As for Chrome for Android |
| [Edge for Android 153 recipes](#edge-for-android-153-recipes) | arm64 Android 17 emulator captures, reporting a Pixel 7, of TLS, H2, QUIC, H3, client hints, and templates, replayed by recipe tests | As for Chrome for Android; no WebSocket opening recipe, and no resumption or proxy capture |
| [TCP socket options and address racing](#tcp-socket-option-evidence) | Browser source at one tag per browser, Brave's included, plus socket read-back tests | No wire capture confirms the options; field trials cannot be ruled out |
| [UDP socket options](#udp-socket-option-evidence) | Browser source at Chromium's tags, hook logs of Chrome 154, Edge 154, and Opera 136, plus socket read-back tests | Firefox's hook logs hold no QUIC socket; its absence rests on source |
| [Socket hooks](#socket-hook-evidence) | Hook logs of Chrome 154, Edge 154, and Opera 136 on Windows: socket options, address racing, connections per origin, idle reuse, and lookups, replayed against the Chromium recipes | One run per scenario on one Windows host; loopback origins only |
| [Firefox socket hooks](#firefox-socket-hook-evidence) | Hook logs and MOZ_LOG lines of Firefox 157.0 on Windows: socket options, keepalive over each connection's life, the IPv4 backup connection and the slower connection it keeps, the idle close, and lookups, replayed against `firefox::v157_tcp` and `firefox::v157_http1` | One to five runs per scenario on one Windows host; loopback origins only |
| [Address cache](#address-cache-evidence) | Browser source at one tag per browser, Brave's included, plus unit and loopback tests, and hook logs for Chrome, Edge, and Opera | One hook log per browser; record TTLs only through Phantom's own DNS queries, which no recipe turns on; Firefox's grace period not modeled |
| [Chromium's built-in DNS client](#chromiums-built-in-dns-client) | Chromium source and the Chromium-family `lookups` hook logs, plus loopback tests against a scripted DNS server | Opt-in only; Chromium's nameserver choice per platform, retry timing, and address sort not modeled; no log shows an AAAA query |
| [HTTP/1.1 connection bound](#http11-connection-bound-evidence) | Browser source at one tag per browser, Brave's included, plus loopback tests, and hook logs for Chrome, Edge, and Opera | One hook log per browser; no Edge or Opera source |
| [Plaintext origin trust](#plaintext-origin-trust-evidence) | Chrome 154, Edge 154, and Firefox 157 proxy route captures, browser source, and loopback tests of Phantom | HTTP/1.1 and HTTP/2 page loads and default-mode `fetch()` only; WebSocket openings not adjusted |
| [ALPS `ACCEPT_CH` restart](#alps-accept_ch-restart-evidence) | Chromium source, two Chrome 154.0.8037.97 captures of a navigation that restarted, plus loopback tests against BoringSSL H2 and QUIC servers | H2 only; no capture over HTTP/3 |
| [SSE reconnect](#sse-browser-reconnect-evidence) | Chrome 154 and Firefox 157 captures, replayed against Phantom | Plaintext HTTP/1.1 on Windows only |
| [Cookie crumbs](#cookie-crumb-evidence) | Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 captures over H1, H2, and H3, replayed against Phantom | Five cookies on one origin |
| [WebSocket openings](#websocket-browser-evidence) | Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 captures | No subprotocols, H3, proxies, macOS, or Safari |
| [WebSocket handshake timers](#websocket-handshake-timer-evidence) | Browser source at one tag per browser, plus loopback tests | No capture shows a timer firing; no Edge source |
| [HPACK encoder](#hpack-encoder-evidence) | Every H2 HEADERS block in the cookie and WebSocket captures of five browsers, replayed byte for byte, and browser source | One origin, small fields; Chromium's size and field rules rest on source |
| [HTTP/2 stream numbering](#http2-stream-numbering-evidence) | The stream of every request in the H2 cookie, WebSocket, and TLS proxy captures of eight browsers on Windows, macOS, and Android, and browser source for the stream limit and its cap | No capture shows the stream limit or the cap |
| [HTTP/2 preface PING](#http2-preface-ping-evidence) | Chromium source, a retained loopback capture of Chrome 154 reusing an idle connection, replayed against Phantom, and one of Chrome 154.0.8037.97 closing a connection whose PING went unanswered | One Windows build; the PING after a DATA frame and the 10-second boundary rest on source |
| [TLS close](#tls-close-evidence) | Chrome 154.0.8037.97 and Firefox 157 captures of how each connection ended, Chromium source, and a loopback test of Phantom | One Windows build per browser; Edge, Brave, and Opera rest on Chromium source |
| [HTTP/2 idle PING](#http2-idle-ping-evidence) | Firefox source and a retained Firefox 157 capture of an idle pooled connection, replayed against Phantom | One Windows run; no capture shows an unanswered PING |
| [Revalidation and uploads](#revalidation-and-upload-evidence) | Chrome 154.0.8037.97 and Firefox 157 captures | One run per scenario; recorded for future work, no recipe uses them yet |
| [Alt-Svc racing](#alt-svc-racing-evidence) | Chrome 154 captures, an origin with two alternatives among them, and Chromium source, plus loopback tests of Phantom | Caller-supplied origin delay; Phantom keeps one alternative per origin; several listed differences from Chromium |
| [Alt-Svc upgrade](#alt-svc-http3-upgrade-evidence) | Loopback tests | No browser `Alt-Used` ordering; no proxy routes |
| [QUIC resumption and 0-RTT](#quic-resumption-and-0-rtt-evidence) | Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 captures, with the Chromium-family ones replayed against Phantom's resumed H3 connections | Loopback and headless only; `initial_rtt_us` compared by encoding, not value |
| [TLS resumption over TCP](#tls-resumption-over-tcp-evidence) | Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 captures, replayed against Phantom's resumed TCP ClientHellos | Loopback and headless only; no network partitions in Phantom |
| [Firefox ECH GREASE payload](#firefox-ech-grease-payload-evidence) | NSS source, and Firefox 157 fresh, resumed, and IP-literal ClientHellos over TCP and QUIC, replayed against Phantom and an independent model of NSS's rule | Resumed lengths with early data compared through the rule; no QUIC capture to an IPv6 literal |
| [Request trailers](#ordered-request-trailer-evidence), [forward proxies](#forward-proxy-evidence), [H3 over SOCKS5](#h3-socks5-udp-evidence) | Loopback tests | No browser-capture fidelity |
| [Proxy routes in browsers](#proxy-route-browser-evidence) | Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157 captures, replayed against Phantom | Plaintext origins only; no `https://` or `wss://` origins or SOCKS |
| [Proxy authentication](#proxy-authentication-evidence) | Chrome 154, Edge 154, and Firefox 157 captures and browser source, plus loopback tests of Phantom | One realm; no `407` to a CONNECT captured; forwarded field position and H2 indexing differ |
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
  per-connection randomness. `firefox::v157_tls` lists both AEADs in
  `ech_grease_aeads`, and the patched BoringSSL backend draws one uniformly
  per connection from fresh random bytes, keeping it across a
  HelloRetryRequest. `firefox_157_recipe_draws_either_ech_grease_aead_per_connection`
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
Google Chrome 154.0.8037.58 and 154.0.8037.97 on Windows 11.

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

On 2026-10-02 the Windows host updated Chrome to 154.0.8037.97; the file
version of `chrome.exe` read 154.0.8037.97 before and after the captures.
One `run_matrix.py` manifest ran `snapshot` and `client_hints`, three runs
each, side by side in 56 seconds of wall clock. The client-hint job's first
attempt timed out after an accept on its loopback listener failed with
`WinError 64`; its retry passed. `snapshot_compare.py` compared each
snapshot with the fixtures retained before the update. All three matched
the 154.0.8037.58 TCP and QUIC ClientHellos, H2 startup, first H2
navigation, and H3 SETTINGS, and differed only in `sec-ch-ua-full-version`
and the `Chromium` and `Google Chrome` entries of
`sec-ch-ua-full-version-list`, which report the new build. The three
`client_hints.py` runs agree, and their `navigation.txt` differs from the
154.0.8037.58 one only in those values and in the capture time and port.
`chromium::v154_windows_client_hints` carries the new values, and the
154.0.8037.58 Windows `navigation.txt` was removed. The three snapshots are
retained beside the new `navigation.txt` as `snapshot-1.txt` to
`snapshot-3.txt`, and each now compares equal to the retained fixtures.
The other 154.0.8037.58 Windows fixtures stay, because 154.0.8037.97 sends
their layers unchanged as far as the snapshots compare; none of them
carries a full version. The macOS captures are of 154.0.8037.95, so
`chromium::v154_macos_client_hints` reports that build.

#### Chrome 154 trust-anchor ID order

Chrome 153 serialized its trust-anchor ID list by iterating an
`absl::flat_hash_set`, so the order was fixed within a browser process and
differed between processes: 35 distinct orders across 60 processes, in a
capture that is no longer retained. Chromium commit `942bda4298c1`
(2026-08-28) sorts the list before encoding. Chrome 154 shows that change.

At the `154.0.8037.58` tag, nothing draws an order per process or per
connection. `SSLConfigServiceManager` builds the list when it starts
(`chrome/browser/ssl/ssl_config_service_manager.cc:158-175`) and again when
the PKI metadata component delivers new trust-anchor data (`:237-247`). Each
time, `InitializeTrustAnchorIDs` (`:211-235`) passes the identifiers to
`EncodeTlsRequestedTrustAnchorIDList`, which sorts them with `std::sort` and
encodes them into one byte string (`net/cert/x509_util.cc:708-717`).
`SSLClientSocketImpl` hands that byte string to BoringSSL's
`SSL_set1_requested_trust_anchors` on every connection
(`net/socket/ssl_client_socket_impl.cc:866-879`). `std::sort` compares the
byte vectors lexicographically, so the order is ascending byte order. A
component update can change which identifiers the list holds, not how they
are ordered; every capture below ran with `--disable-component-update`, so
each shows the compiled-in list. The recipe carries that compiled-in set of
28 identifiers and does not follow component-updated PKI metadata, so a
Chrome that has received the component may send a different set.

Sixty fresh headless processes, one TCP ClientHello each, produced one order.
It is the 28 Chrome 153 IDs in ascending byte order, from `82df130201` to
`d679090f`.
`fixtures/tls/chrome/154.0.8037.58/windows-11-26200/trust-anchor-orders.txt`
retains the order, its count, and the per-process sequence.

The other retained Chrome 154 desktop captures keep whole ClientHellos from
processes that opened several connections: the ClientHello, real ECH, and TLS
resumption fixtures under `fixtures/tls/chrome/154.0.8037.58/`, and the QUIC
ClientHello and QUIC resumption fixtures under
`fixtures/http3/chrome/154.0.8037.58/`. They hold 132 ClientHellos from 23
processes on Windows 11 and macOS 15.5, over TCP and QUIC. Eighteen of those
processes opened more than one connection, one of them 13. Every ClientHello,
the outer one in the ECH captures, carries the same trust-anchor extension, so the order is fixed within a
process as well as between processes.

`chromium::v154_tls` and `chromium::v154_http3_tls` list the 28 identifiers
in that ascending order, which is how a `TlsSettings` expresses trust-anchor
order: the wire order is the vector order. Because Chrome's order is fixed,
the recipe has no per-client draw to model; a caller who wants another order
sets `requested_trust_anchor_ids` to `TrustAnchorIds::Fixed` with it.
`chrome_154_tls_trust_anchor_ids_are_sorted_and_shared_by_every_process`
requires the aggregate fixture to hold one order, the recipe to equal it, and
the recipe list to be sorted;
`chrome_154_trust_anchor_ids_match_every_retained_client_hello_in_every_process`
decodes the extension from each of the 132 ClientHellos, requires it to equal
the recipe's encoding, and pins the process and connection counts; and
`chrome_154_tls_recipe_emits_the_sorted_trust_anchor_order` checks the order
the TLS connector actually emits.

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

The retained `chrome_http3.py` fixtures were taken with a fixed listen
address, whose port came from a loopback UDP socket bound to port 0 and then
released; every other listener bound port 0 itself. `startup_capture.py`
now passes `--listen 127.0.0.1:0`, and `chrome_http3.py` records the port
it bound. Fixture `listen_address` lines therefore hold the chosen
ephemeral port, and `trust-anchor-orders.txt`, which aggregates 60 separate
listeners, records `127.0.0.1:0`.

</details>

Retained fixtures, each under `fixtures/<area>/chrome/154.0.8037.58/windows-11-26200/`:

| Area | Files |
| --- | --- |
| `tls` | `client-hello.txt`, `trust-anchor-orders.txt`, `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| `http2` | `client-startup.txt` |
| `http3` | `client-startup.txt`, `quic-client-hello-{1,2}.txt` |
| `client-hints` | None; `navigation.txt` and `snapshot-{1,2,3}.txt` are under `154.0.8037.97` |
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
- The 154.0.8037.97 evidence for every layer but the client hints is the
  snapshot comparison, which leaves out HTTP/1.1 and HTTP/3 request fields,
  ALPS, and behavior across connections; the per-layer captures are of
  154.0.8037.58.
- Launches are headless, except one headful client-hint run and five headful
  `retry-750` SSE runs.

### Edge 153 and Firefox 157 recipes

What is claimed: Edge 153.0.4234.48 matched the Chromium recipes as below,
which the [Edge 154 recipes](#edge-154-recipes) build on, and the
`firefox::v157_*` recipes reproduce Firefox 157.0, both on Windows 11.

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
| Firefox 157.0 TLS | 5 snapshot processes | Its own fixed extension order and a 240-byte ECH GREASE payload |
| Firefox 157 H2 startup and request HEADERS | 3 retained H2 session runs, 6 connections | `m,p,a,s` pseudo-headers; non-exclusive parent 0 weight 42 |

The recipes follow from those results. `edge::v154_tls` and
`edge::v154_http3_tls` remove the trust-anchor IDs from the Chromium recipes.
The Chrome 153 and Chrome 154 ClientHellos differ only in that extension, so
the Edge captures replay against the surviving Chromium recipes unchanged.
Edge has no H2, QUIC, or H3 recipe of its own, because those layers equal the
Chromium recipes on every compared field. The Edge client hints carry
Edge's brand list and build values. The
complete Firefox set is `firefox::v157_tls`, `v157_tcp`, `v157_dns_cache`,
`v157_http1`, `v157_http2`, `v157_websocket`, `v157_proxy_connect`,
`v157_cookie_placement`, the recipes of the
[Firefox 157 HTTP/3 recipe](#firefox-157-http3-recipe), and the Firefox
request templates. Firefox sends no user-agent client hints.

Edge's full version list reports `"Chromium";v="153.0.8010.53"`, a newer
Chromium build than the branded Chrome 153 that was captured at the time.
Headful and headless runs produced identical client hints for both browsers.

Firefox 157 kept its fixed extension order. Of 69 TCP ClientHellos, the
five snapshots and the first run of each TLS resumption scenario, it chose
AES-128-GCM for ECH GREASE on 36 and ChaCha20-Poly1305 on 33, with a
240-byte payload on every fresh connection. One sample of each is
retained.

The H2 request evidence reuses the navigation in the retained WebSocket session
fixtures (`fixtures/websocket/*/accept.txt`, recorded through
`http2_session.py`). Those fixtures already hold each navigation's SETTINGS,
WINDOW_UPDATE, HEADERS priority, and HPACK field order. No raw Firefox 157 H2
startup fixture was taken: the raw startup tool needs WebDriver certificate
trust for Firefox, and geckodriver is not installed on the host. The extended
CONNECT pseudo-header order and priority in those fixtures differ from the
navigation's and are carried by the WebSocket recipes and `v157_http2`.

The `edge_154_*` and `firefox_157_*` tests in `phantom-profile` and
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
| Edge 154.0.4258.48 | `client-hints` | `navigation.txt`; see [Edge 154 recipes](#edge-154-recipes) |
| Edge 154.0.4258.37 | `cookies` | `crumbs-h1.txt`, `crumbs-h2.txt`, `crumbs-h3.txt` |
| Edge 154.0.4258.37 | `websocket` | Nine scenarios; see [WebSocket browser evidence](#websocket-browser-evidence) |
| Edge 154.0.4258.37 | `proxy` | Twenty scenarios; see [Proxy route browser evidence](#proxy-route-browser-evidence) |
| Firefox 157.0 | `tls` | `client-hello.txt` (AES-128-GCM ECH GREASE, split from `http3/.../snapshot-4.txt`), `client-hello-chacha20-ech.txt` (split from `snapshot-1.txt`), eleven `resumption-<scenario>.txt` files, two of them WebSocket openings; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Firefox 157.0 | `websocket` | Nine scenarios |
| Firefox 157.0 | `sse` | Seventeen scenarios |

The Firefox 157.0 rows replace a Firefox 156.0.1 set. After the capture host
updated to Firefox 157.0, every Windows Firefox scenario was captured again
on 2026-10-02, and the replaced 156.0.1 fixtures were removed; see
[Firefox 157 against Firefox 156.0.1](#firefox-157-against-firefox-15601).
The macOS Firefox fixtures were then captured again from 157.0; see
[macOS recipes](#macos-recipes). Three of the five snapshots
offered ECH GREASE with ChaCha20-Poly1305 and two with AES-128-GCM.

Limits:

- One Windows build per browser. On macOS only Edge's client hints, both
  browsers' request fields, and single parity runs are captured; see
  [macOS recipes](#macos-recipes). No Linux capture exists.
- Headless launches only, except the headful client-hint check.
- Firefox 157 has no raw H2 startup fixture, so its SETTINGS and connection
  window rest on the H2 session captures rather than on raw startup bytes.

#### Firefox 157 against Firefox 156.0.1

What is claimed: Firefox 157.0 sends what Firefox 156.0.1 sent on every
recaptured Windows layer, except the `User-Agent` version and the QUIC
ClientHello's signature lists. The `firefox::v157_*` recipes are the
`v156_*` recipes with those two changes.

Evidence: Firefox 157.0 (build ID 20260924084938) was the build installed
on the Windows 11 capture host on 2026-10-02; `application.ini` named the
same version and build before and after each batch. Other worktrees were
building with Cargo during every batch but the EventSource one, which ran on
a quiet host.

| Batch | Runs | Wall clock |
| --- | --- | --- |
| `snapshot.py --repeat 5` | 5 headless snapshots, 1.3 to 1.5 seconds each | 9 seconds |
| `run_matrix.py`, every job alone | 44 jobs: nine `tls_resumption`, three `quic_resumption`, three `cookie_crumbs`, nine `http2_websocket`, and twenty `proxy_route` scenarios | 565 seconds |
| `proxy_route.py --scenario https-proxy-auth-remembered-hostname --repeat 3` | 3 | 7 seconds |
| `run_matrix.py`, every job alone, on a quiet host | 17 `sse_reconnect` scenarios, ten runs each | 2,234 seconds |
| `sse_reconnect.py --scenario retry-persists-across-reconnect --repeat 10` | 10 | 58 seconds |

Under the runner, `https-proxy-auth-remembered-hostname` timed out on both
attempts, after the browser published no remote protocol endpoint, as it
did for 156.0.1, and so did one run of `retry-persists-across-reconnect` in
each of its two attempts; run directly, each passed on the first attempt.

| Layer | Compared | Result |
| --- | --- | --- |
| TCP ClientHello | 5 snapshots and 192 ClientHellos in the TLS resumption scenarios | Equal: cipher suites, the fixed extension order, every extension body, `record_size_limit` 16385, `extended_master_secret`, `renegotiation_info`, and ECH GREASE payloads of 240 bytes fresh and 368 bytes resumed |
| TLS resumption over TCP | 9 scenarios, 3 runs each | Equal extension orders, PSK lengths, and summary counts; in `sequential`, 15 requests arrived in early data against 14 |
| QUIC ClientHello | 5 snapshots and 55 resumption connections | ML-DSA-44, -65, and -87 gone from `signature_algorithms` and `delegated_credentials`, 12 bytes shorter; the same extensions, still permuted with `quic_transport_parameters` and then `encrypted_client_hello` last, the same transport parameters, and ECH GREASE payloads of 240 bytes fresh and 368 bytes resumed |
| QUIC resumption and 0-RTT | 3 scenarios | The same requests in 0-RTT on each resumed connection. More connections resumed in `accept` (15 of 20 against 13) and fewer in `reject` (9 of 12 against 11), and when the `/navigate` connection resumed, its `GET` went in 0-RTT |
| HTTP/2 | Snapshots, cookie, WebSocket, and proxy captures | Equal SETTINGS, connection window, priorities, pseudo-header orders, and HPACK representations |
| HTTP/3 | Snapshots and the cookie capture | Equal SETTINGS, reserved frame, stream order, QPACK encoding, and field orders |
| Request fields | Every request | Equal names, order, and values except `User-Agent`, which names `rv:157.0` and `Firefox/157.0` |
| Cookies, WebSocket openings, proxy routes | 3, 9, and 20 scenarios | Equal apart from `User-Agent`, ports, keys, and the position of the client's SETTINGS acknowledgment on proxy connections, which varied the same way in both builds |
| EventSource reconnects | 17 scenarios, 10 runs each | Equal request counts, fields, and terminations; reconnect delays as in [SSE browser reconnect evidence](#sse-browser-reconnect-evidence) |

Firefox 157 adds `security.tls.enable_mldsa`, off by default. `SetKyberPolicy`
then removes ML-DSA from NSS's TLS key-exchange policy
(`security/manager/ssl/nsNSSComponent.cpp:1025-1033` at
`FIREFOX_157_0_RELEASE`), and `ssl3_FilterSigAlgs` drops the three schemes
from both lists of a ClientHello that uses NSS's default signature
schemes. neqo uses those defaults; the TCP path sets its own list, which
never had ML-DSA. NSS 3.129 and neqo 0.31.1 left the QUIC extension
permutation, the ECH GREASE padding rule, `record_size_limit`,
`extended_master_secret`, and `renegotiation_info` as they were. Every
other Firefox source citation in the recipes was read again at
`FIREFOX_157_0_RELEASE`: the cited code and defaults are unchanged, and only
line numbers moved.

How to reproduce: the snapshot command in the
[capture README](../../scripts/capture/README.md#quick-fingerprint-snapshot)
with `--browser firefox --client-version 157.0 --repeat 5`, then a
`run_matrix.py` manifest with `tls_resumption`, `cookie_crumbs`,
`http2_websocket`, and `proxy_route` for scenarios `all`, and
`quic_resumption` for `accept` (`repeat` 5) and `accept-delayed` and
`reject`, and a second manifest with `sse_reconnect` for scenarios `all`
(`repeat` 10).

Limits:

- The QUIC resumption differences are counts of resumed connections, which
  depend on when a ticket arrives; three runs per scenario cannot tell a
  change in Firefox from host load.

### Edge 154 recipes

What is claimed: the `edge::v154_*` recipes, with the Chromium recipes they
reuse, reproduce Edge 154.0.4258.37 and 154.0.4258.48 on Windows 11. Edge
154 differs from Edge 153.0.4234.48 only in its client hints.

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
one H3 startup run. `edge::v154_macos_client_hints` then differed from the
Windows hints only in the platform data.

On 2026-10-02 the Windows host updated Edge to 154.0.4258.48. Three
snapshots matched the retained Edge 154.0.4258.37 TCP and QUIC ClientHellos,
H2 startup, first H2 navigation, and H3 SETTINGS, and differed only in
`sec-ch-ua-full-version` and the Edge entry of
`sec-ch-ua-full-version-list`, which report the new build. Only the client
hints were captured again: `client_hints.py --repeat 3`, in the
`run_matrix.py` manifest of the Opera 136 captures. The three runs agree,
and `edge::v154_windows_client_hints` carries their values. The other Edge
154.0.4258.37 Windows fixtures stay, because 154.0.4258.48 sends their
layers unchanged as far as the snapshots compare; the WebSocket, proxy, and
cookie captures carry no full version. The Mac then updated to
154.0.4258.48 as well, and its captures were taken again
([macOS recipes](#macos-recipes)), so `edge::v154_macos_client_hints`
reports that build.

Limits:

- On Windows, one run of each QUIC resumption scenario and two H3 startups,
  where Edge 153 had three or five.
- On Windows, the Edge 154.0.4258.48 evidence for every layer but the
  client hints is the snapshot comparison; the per-layer captures there are
  of 154.0.4258.37.
- The ECH behavior of `edge::v154_tls` and `edge::v154_http3_tls` rests on
  Edge 153 captures and on Edge 154 sending the same ClientHello without an
  HTTPS record.

### Brave 154 and Opera 136 recipes

What is claimed: the `brave::v154_*` recipes, with the Chromium recipes they
reuse, reproduce Brave 154.1.96.59, and the `opera::v136_*`
recipes, with the Chromium recipes they reuse, reproduce Opera 136.0.6008.52,
both on Windows 11. Brave 154 is built on Chromium 154. Opera 136 reports
Chromium 152.0.7977.130 in its client hints; Phantom carries no Chromium 152
recipe, so every Opera capture is compared with the Chrome 154 recipes.

Evidence: both are the builds installed on the Windows 11 capture host,
read from the file versions of `brave.exe` and of Opera's versioned
`opera.exe`. Brave had updated from 153.1.95.104, which the roadmap named,
before these captures. Every capture used a fresh profile, a loopback
listener, and the launch flags of the retained Chrome 154 fixture for the
same layer, with `--browser brave` or `--browser opera` in the Python tools.

After a restart on 2 October 2026 the host updated Opera from 135.0.5973.92
to 136.0.6008.52 and Brave to 154.1.96.60. Three
[fingerprint snapshots](#fingerprint-snapshot-evidence) of Brave
154.1.96.60 matched every layer `snapshot_compare.py` reads in the retained
Brave 154.1.96.59 fixtures, so the Brave fixtures and recipes stay. Three
snapshots of Opera 136 matched the Opera 135 H2 startup, first H2
navigation, and H3 SETTINGS, and differed in three places:

| Layer | Opera 135.0.5973.92 | Opera 136.0.6008.52 |
| --- | --- | --- |
| TCP ClientHello | No trust-anchor IDs extension; no GREASE at the head of `signature_algorithms` | A trust-anchor IDs extension with 32 IDs; GREASE at the head of `signature_algorithms`, as Chrome sends |
| QUIC ClientHello | No trust-anchor IDs extension | The same 32 trust-anchor IDs |
| `sec-ch-ua` | `"Not=A?Brand";v="99", "Opera";v="135", "Chromium";v="151"` | `"Chromium";v="152", "Not?A_Brand";v="24", "Opera";v="136"` |
| `sec-ch-ua-full-version-list` | `"Not=A?Brand";v="99.0.0.0", "Opera";v="135.0.5973.92", "Chromium";v="151.0.7922.176"` | `"Chromium";v="152.0.7977.130", "Not?A_Brand";v="24.0.0.0", "Opera";v="136.0.6008.52"` |

Every Opera layer was then captured again for Opera 136, and the Opera 135
Windows fixtures were removed. One `run_matrix.py` manifest ran 46 jobs:
`client_hints`, the nine `tls_resumption` scenarios, the three
`cookie_crumbs` scenarios, the nine `http2_websocket` scenarios, and the
twenty `proxy_route` scenarios three times each, and `quic_resumption`
`accept` five times and `accept-delayed` and `reject` three times each. All
passed on the first attempt, in 292 seconds of wall clock; the three
snapshots of each browser took 4 seconds. `startup_capture.py` then took
the TLS startup from 20 fresh processes and the H2 and H3 startups through
DevTools three times each, in 52 seconds.

Opera 136 sends Chromium 152's trust-anchor IDs: the 28 that Chrome 154
sends and `d6790902`, `d6790903`, `d6790909`, and `d679090e`, which Chrome
154 does not send
([Chrome 154 trust-anchor ID order](#chrome-154-trust-anchor-id-order)).
Chromium 152 encodes the list in hash-set order.
`fixtures/tls/opera/136.0.6008.52/windows-11-26200/trust-anchor-orders.txt`
tallies the order of every Opera 136 ClientHello in the retained startup
captures and in run 0 of the retained resumption captures, and names the
fixture that holds each one's bytes. The TLS startups other than
`client-hello.txt` are retained under `startup-runs/` beside it, and the
third H3 startup as `quic-client-hello-3.txt`:

| Transport | ClientHellos | Processes | Distinct orders | Within one process | Most frequent order |
| --- | --- | --- | --- | --- | --- |
| TCP | 100: 20 TLS startups and run 0 of the nine TLS resumption scenarios | 29 | 16 | One order on every connection (0 of 71 later ClientHellos changed) | 5 of 29 processes |
| QUIC | 20: 3 H3 startups and run 0 of the three QUIC resumption scenarios | 6 | 19 | A new order per connection: every resumption process used 5 or 6 orders | 2 of 20 ClientHellos, both in one process |

Across all runs of the QUIC resumption fixtures, the trust-anchor extension
of 58 of the 59 later connections differs from the run's first connection.
[Opera 136 trust-anchor ID order](#opera-136-trust-anchor-id-order) traces
the orders to Chromium 152's hash set and describes how the recipes draw
them.

| Browser and layer | Samples | Result against the Chromium recipes |
| --- | --- | --- |
| Brave TLS | 20 processes | The Chrome 154 ClientHello without the trust-anchor IDs extension |
| Opera TLS | 20 processes | The Chrome 154 ClientHello with Chromium 152's 32 trust-anchor IDs in a per-process order |
| Brave QUIC ClientHello | 3 processes | The Chrome 154 QUIC ClientHello without trust-anchor IDs |
| Opera QUIC ClientHello | 3 processes | The Chrome 154 QUIC ClientHello with the 32 trust-anchor IDs of the Opera TLS row, in an order drawn per connection |
| Brave and Opera H2 startup | 3 raw startups each | Byte-identical to the Chrome 154 SETTINGS and WINDOW_UPDATE frames |
| Brave and Opera H2 request HEADERS, pseudo-header order, priority, HPACK | 3 H2 session runs each | Equal to `chromium::v154_http2` |
| Brave and Opera QUIC transport parameters, H3 SETTINGS, H3 pseudo-header order | 3 processes each | Equal to `chromium::v154_quic`, `chromium::v154_http3`, and `chromium::v154_http3_request` |
| Brave client hints | 3 runs (plus 1 headful) | The Chromium names, order, and delivery without `sec-ch-ua-full-version` and `sec-ch-ua-form-factors`; every version reduced to `154.0.0.0` or `99.0.0.0` |
| Opera client hints | 3 runs | The Chromium names, order, and delivery; Opera brand list and version values |
| Brave request fields | 9 WebSocket scenarios, 20 proxy scenarios, H3 startup | Chromium order, plus `Sec-GPC: 1` after `Accept`; `Accept` without signed exchanges; `Accept-Language` q value drawn per session |
| Opera request fields | Same | Equal to the Chromium templates except `User-Agent` and brand values |
| WebSocket openings and connection choice | 9 scenarios, 3 runs each | Equal to `chromium::v154_websocket` |
| Proxy CONNECT fields | 20 proxy scenarios, 3 runs each | Equal to `chromium::v154_proxy_connect` |
| Brave ECH from an HTTPS record | 1 `accept` and 1 `reject` run | Chrome 154's outer extension fields; one retry with the server's configuration after a rejection |
| Brave ECH over QUIC | 3 `accept` and 3 `reject` runs | Chrome 154's outer QUIC fields without trust-anchor IDs; no QUIC connection after a rejection |
| Brave and Opera cookie placement and crumbs | 3 runs each over H1, H2, and H3 | Equal to `chromium::v154_cookie_placement`, `chromium::v154_http2`, and `chromium::v154_http3_request` |

The recipes follow from those results. `brave::v154_tls` and
`brave::v154_http3_tls` remove the trust-anchor IDs from the Chromium
recipes, and both keep `ech_from_https_records`.
`opera::v136_tls` and `opera::v136_http3_tls` replace the Chromium ID list
with Opera's 32 IDs, in an order drawn per client over TCP and per
connection over QUIC. Neither browser has an H2, QUIC, H3,
WebSocket, proxy CONNECT, or cookie placement recipe of its own, because
those layers equal the Chromium recipes on every compared field. The
client-hint recipes and request templates carry the brand lists and the
differences in the table.

In the cookie captures, both browsers send `Cookie` last over HTTP/1.1 and
split it over HTTP/2 and HTTP/3 into five crumbs right before `priority`,
with the representations, indexes, and QPACK inserts of Chrome 154. Brave's
`Sec-GPC` is one more field before them, and adds one more QPACK insert.
Brave opened one connection per run. Opera, as Chrome and Edge do in their
cookie captures, opened up to four more that carried no request; Phantom
opens no such spare connection.

The TCP options, the HTTP/1.1 connection bound, and the address cache rest
on a source reading of `brave-core` at tag `v1.96.59`, the build captured
here. Its `package.json` names Chromium tag `154.0.8037.58`, the tag the
Chromium recipes cite. Brave's patches and `chromium_src` overrides under
`net/socket/` touch only the SOCKS client, the SOCKS connect job, and the
TLS client socket. Three cited files are overridden, none in a way that
changes a recipe value: `net/dns/host_cache.cc` copies TXT records into a
copied entry, `net/dns/host_resolver_manager_job.cc` counts secure DNS
tasks, and `net/base/features.cc` changes three feature defaults, one of
them below. Its `net/dns/dns_client.cc` override adds a fallback
DNS-over-HTTPS server behind `kBraveFallbackDoHProvider`, which is off by
default, and its resolver configuration changes apply only while Brave VPN
is connected. So `chromium::v154_tcp`, `chromium::v154_http1`, and
`chromium::v154_dns_cache` serve Brave as they are.

Brave's `patches/net-base-features.cc.patch` enables
`kPartitionConnectionsByNetworkIsolationKey`, which Chromium leaves off
(`net/base/features.cc:213-214`); its `chromium_src/net/base/features.cc`
only includes the upstream file and adds Brave's own features. The flag
makes `NetworkAnonymizationKey::IsPartitioningEnabled` true
(`net/base/network_anonymization_key.cc:261-266`), and at Chromium tag
`154.0.8037.58` these keys then carry the top-level site's key:

| Key | Source |
| --- | --- |
| Socket pool group, so the HTTP/1.1 bound applies per site | `net/socket/client_socket_pool.cc:122-136` |
| TLS session cache | `net/socket/ssl_client_socket_impl.cc:1631-1644` |
| HTTP/2 session | `net/spdy/spdy_session_key.cc:36-44` |
| QUIC session, and the QUIC crypto configurations | `net/quic/quic_session_key.cc:80-88`, `net/quic/quic_session_pool.cc:733-734` |
| Host cache, with `kSplitHostCacheByNetworkAnonymizationKey`, on by default (`net/base/features.cc:216-217`) | `net/dns/host_resolver_manager_request_impl.cc:51-56`, `net/dns/host_resolver_manager_service_endpoint_request_impl.cc:56` |
| Learned server properties: HTTP/2 support, Alt-Svc, and their saved copy | `net/http/http_server_properties.cc:150-151`, `net/http/http_server_properties_manager.cc:323-324` |
| `HttpStreamPool` keys, used only with Happy Eyeballs v3, off by default | `net/http/http_stream_key.cc:36-39`, `net/http/http_stream_pool_request_info.cc:36` |
| Reporting and Network Error Logging, which Phantom does not implement | `net/reporting/reporting_service.cc:349`, `net/network_error_logging/network_error_logging_service.cc:354` |

The table lists every non-test call of `IsPartitioningEnabled` under
`net/` at that tag. The two outside `net/` in `services/network/`,
`content/browser/`, and `chrome/browser/net/`, and none in `brave-core`,
only check that a key is set. A Phantom client has no top-level site: it
behaves as Brave does within one site, sharing each of these across every
request it sends.

Opera's network source is not public. At Chromium tag `152.0.7977.130`, the
version Opera 136 reports, the recipes' values are those of 154:
`kTCPKeepAliveSeconds = 45` (`net/socket/tcp_socket_win.cc:50`),
`g_max_sockets_per_group` 6 (`net/socket/client_socket_pool_manager.cc:54-56`),
`kDefaultCacheSize = 1000` (`net/dns/resolve_context.cc:109`),
`kCacheEntryTTLSeconds = 60` and `kNegativeCacheEntryTTLSeconds = 0`
(`net/dns/host_resolver_manager_job.cc:54`, `:57`), `kIPv6FallbackTime` 300 ms
(`net/socket/tcp_connect_job.h:85`), and Happy Eyeballs v3 off
(`net/base/features.cc:111`). Frida hook logs of Opera 136 show what Opera
does with them: the options of `chromium::v154_tcp`, its 300 ms fallback,
six connections to one origin, and a 60-second system-resolver cache, as
Chrome 154's logs do ([Socket hook evidence](#socket-hook-evidence)). Opera
profiles therefore use `chromium::v154_tcp`, `chromium::v154_http1`, and
`chromium::v154_dns_cache`.

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

Opera 135 needed a different launch for two layers. At startup it opened a
preconnect to the page's origin, then logged `Cert verifier changed` and
abandoned every open connection. The raw H2 and QUIC capture tools serve only
their first connection, so with the page URL on the command line they saw
the abandoned preconnect and no request. (A diagnostic Opera NetLog run
showed the preconnect session and the
`QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY` event. It was not
retained and backs no claim; it only explained the failed captures.) The
Opera H2 and H3 startups were therefore taken by
`startup_capture.py --navigate devtools`, which starts Opera on
`about:blank` with `--remote-debugging-port=0` and calls `Page.navigate` over
DevTools five seconds later; their `launch_mode` is `devtools-navigate`. The
retained Opera 136 startups were taken the same way, so that their launch
matches the Opera 135 ones they replace; no Opera 136 command-line H2 or H3
startup was tried.

The DevTools launch does not change what the page's connection sends. One
Brave H3 run taken the same way is retained under
`fixtures/http3/brave/154.1.96.59/windows-11-26200/launch-mode/`
(`client-startup-devtools.txt` and `quic-client-hello-devtools.txt`, 1
process). `brave_154_devtools_launch_sends_the_command_line_h3_startup`
compares its H3 SETTINGS and request fields, apart from `:authority`, with
Brave's command-line startup, and the Brave QUIC tests replay its transport
parameters and ClientHello against the same recipes as the command-line
runs. The TLS capture tool records only the
first ClientHello, which for Opera may be the startup preconnect's; all
20 Opera 136 processes completed one. In two Opera 135 `refused-stream`
WebSocket runs, Opera had closed the page's H2 session before opening the
socket, so it opened an HTTP/1.1 Upgrade connection; all three Opera 136
runs opened over the page's session and had a stream refused, as Chrome's
do.

In the resumption captures every later Brave and Opera connection resumed
and offered early data, and the resumed ClientHellos match Phantom's for each
recipe. Brave's second navigation in `accept` arrived in 0-RTT in all 5 runs
where Chrome's and Opera's arrived in 1-RTT; Phantom does not model the
preconnect timing that decides this (see
[QUIC resumption and 0-RTT evidence](#quic-resumption-and-0-rtt-evidence)).

Opera 135 sent no DNS-over-HTTPS query with Chromium's `Local State`
preferences alone. Opera 136 overrides them at startup with its own
`dns_over_https.opera` preferences: `opera_browser.dll` in 136.0.6008.52
holds the names `dns_over_https.opera.doh_mode`,
`dns_over_https.opera.custom_servers`, and
`dns_over_https.opera.enabled_version` beside the source file name
`dns_over_https_prefs_observer.cc`, and a run with Chromium's preferences
alone timed out with no lookup. With Opera's set in the throwaway profile it
sent its lookups to the capture server and used the record's
`ech` over TCP and QUIC, as Chrome 154 does. `opera::v136_tls` and
`v136_http3_tls` therefore keep `ech_from_https_records`; see
[Real ECH evidence](#real-ech-evidence). Without a record, every Opera 135
and 136 ClientHello carried ECH GREASE.

Tests: the `brave_154_*` and `opera_136_*` tests in `phantom-profile` and
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

`startup_capture.py` was committed after the Brave and Opera 135 captures,
and took the Opera 136 startups. The earlier ones came from a scratch script
that ran the same listeners with the same launch arguments;
`test_startup_capture.py` checks that the tool records exactly the
`launch_arguments` and `launch_mode` of every retained Brave and Opera
startup fixture, and one run of each Opera 135 DevTools layer and of Brave
TLS, repeated with the committed tool, matched the retained fixtures on
every compared field. The other layers use `client_hints.py --repeat 3`,
`http2_websocket.py --scenario all --repeat 3`,
`proxy_route.py --scenario all --repeat 3`, `quic_resumption.py` as in its
section, and `chrome_ech.py --scenario accept` and `reject`, without and
with `--quic`. The cookie captures came from `cookie_crumbs.py --scenario
all --repeat 3` through `run_matrix.py`, which ran each scenario alone; a
`snapshot.py` run of each browser in the same batch matched every retained
fixture `snapshot_compare.py` reads.

Retained fixtures, each under `fixtures/<area>/<browser>/<version>/windows-11-26200/`:

| Browser | Area | Files |
| --- | --- | --- |
| Brave 154.1.96.59 | `tls` | `client-hello.txt`, `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) |
| Opera 136.0.6008.52 | `tls` | `client-hello.txt`, the other 19 TLS startups as `startup-runs/client-hello-<n>.txt`, `trust-anchor-orders.txt`, `ech-accept.txt`, `ech-reject.txt`, `ech-quic-accept.txt`, `ech-quic-reject.txt`, nine `resumption-<scenario>.txt` files; see [TLS resumption over TCP evidence](#tls-resumption-over-tcp-evidence) and [Real ECH evidence](#real-ech-evidence) |
| Both | `http2` | `client-startup.txt` |
| Both | `http3` | `client-startup.txt`, `quic-client-hello-{1,2}.txt`, `resumption-accept.txt`, `resumption-accept-delayed.txt`, `resumption-reject.txt` |
| Opera 136.0.6008.52 | `http3` | `quic-client-hello-3.txt`, the third H3 startup, for `trust-anchor-orders.txt` |
| Brave 154.1.96.59 | `http3` | `launch-mode/client-startup-devtools.txt`, `launch-mode/quic-client-hello-devtools.txt` |
| Both | `client-hints` | `navigation.txt` |
| Both | `cookies` | `crumbs-h1.txt`, `crumbs-h2.txt`, `crumbs-h3.txt` |
| Both | `websocket` | Nine scenarios |
| Both | `proxy` | Twenty scenarios |

Limits:

- Brave 154.1.96.60, the build installed since 2 October 2026, rests on
  three snapshots against the 154.1.96.59 fixtures; its other layers were
  not captured again.
- One Windows build per browser. Opera's macOS captures are of
  136.0.6008.52 and cover client hints, request fields, and single runs of
  the other layers ([macOS recipes](#macos-recipes)); Brave has none, and
  no Linux capture exists.
- Every retained capture ran headless. One headful client-hint run of Brave
  154 and of Opera 135 matched the headless runs, but it was not retained;
  no headful Opera 136 run was taken.
- Brave's TCP options, HTTP/1.1 bound, and address cache rest on source
  alone; no capture or hook log confirms them. Opera's rest on one hook log
  per scenario.
- Brave partitions connections, TLS sessions, the host cache, and learned
  server properties by top-level site; Phantom does not. A Phantom client
  matches Brave within one top-level site, but reuses a connection, a TLS
  session, or a cached address where Brave, under a second site, would
  open, handshake, or resolve again.
- No SSE or Alt-Svc racing capture exists for either browser.
- The Opera comparison is with Chrome 154, not with a Chromium 152 build.
- The Opera recipes draw only the 16 TCP and 19 QUIC trust-anchor orders
  retained, at their observed frequencies; Opera can send orders no capture
  holds ([Opera 136 trust-anchor ID order](#opera-136-trust-anchor-id-order)).
- Opera's H2 and H3 startups were launched through DevTools; its TLS
  ClientHello may be the startup preconnect's.

#### Opera 136 trust-anchor ID order

Opera 136 lists its trust-anchor IDs in the iteration order of a Chromium
152 hash set, which takes a new order each time the set is copied. Over TCP
a process keeps one copy, so one order; over QUIC each connection makes its
own copy.

At Chromium tag `152.0.7977.130`, `SSLContextConfig` keeps the IDs in an
`absl::flat_hash_set` (`net/ssl/ssl_config_service.h:100`), and
`SelectAllTrustAnchorIDs` encodes them in the set's iteration order
(`net/ssl/ssl_config_service.cc:101-123`). Chrome 154 sorts them instead
([Chrome 154 trust-anchor ID order](#chrome-154-trust-anchor-id-order)).
The network service hands out its configuration by value
(`services/network/ssl_config_service_mojo.cc:77-79`), and two callers keep
the copy for different spans:

| Transport | Copy | Encoding | One order per |
| --- | --- | --- | --- |
| TCP | `SSLClientContext` copies the configuration when it is created and when the configuration changes (`net/socket/ssl_client_socket.cc:233`, `:301`) | Every connection encodes that copy (`net/socket/tls_stream_attempt.cc:205-210`, `net/socket/ssl_connect_job.cc:416-418`) | Process |
| QUIC | `QuicChromiumClientSession::GetSSLConfig` copies it for each session (`net/quic/quic_chromium_client_session.cc:1750-1751`) | The session encodes its own copy (`:1768-1771`) | Connection |

Abseil, at the same tag under `third_party/abseil-cpp/absl/`, gives each
copy its own order. The copy constructor allocates a table for the source's
size and inserts every element again
(`container/internal/raw_hash_set.h:2624-2636`,
`container/internal/raw_hash_set.cc:2283-2339`). The allocation draws a new
per-table seed (`raw_hash_set.cc:1133`), 8 bits wide unless a build defines
`ABSL_SWISSTABLE_INTERNAL_ENABLE_CAPACITY_BY_VALUE`
(`raw_hash_set.h:633-634`, `:768-772`). The seed comes from a thread-local
counter that advances by `0xad53` for each table, XORed with the counter's
address (`raw_hash_set.cc:81-92`, `:144-147`). Each ID's hash starts from
that seed (`container/internal/container_memory.h:494-503`,
`hash/internal/hash.h:1460-1463`). A table for 32 IDs has 63 slots, the
last 5 blocked (`raw_hash_set.cc:2024-2035`), and iterates its slots in
index order.

`opera_136_trust_anchor_orders_are_chromium_152_hash_set_orders` checks the
retained orders against that layout. It hashes each ID as an x86-64 build
without SSE4.2 does and asks, for each of the 256 seeds, whether some
insertion order leaves the IDs in the retained order. Each of the 16 TCP
and 19 QUIC orders fits exactly one seed. The 32 IDs in ascending or in
descending order fit none.

`hash_set_fit_rejects_random_orders_but_not_neighbour_swaps` tests the fit
itself. None of 64 fixed pseudo-random permutations of the IDs fits a seed,
so an arbitrary order fails it. Swapping two neighbouring IDs in a retained
TCP order leaves an order that fits some seed in 130 of the 496 swaps, so
the fit does not tell a retained order from a nearby one. It shows that
Opera's orders follow the hash layout, not that the retained orders are
the only ones Opera sends.

The seed does not settle the order, and its distribution is not uniform.
Two QUIC orders from different processes share seed 94, because each copy
inserts the IDs in its source table's order, and that order differs between
processes. Over TCP, one seed served 5 of the 29 processes, where 29 draws
from 256 equally likely seeds would give no seed more than 2 or 3. The
counter makes the seed depend on how many tables the thread built before
the copy. Neither the source order nor the seed shows on the wire, so the
recipes draw from the retained orders instead of computing them:

- `opera::v136_tls` sets `TrustAnchorIds::PerClient` with one entry per
  tallied process: 29 entries holding 16 orders, so a client takes a
  process's order at its observed frequency and keeps it. A `phantom`
  client draws once when it is built, before it builds its HTTP/1.1,
  HTTP/2, HTTPS proxy, and WebSocket connectors, so they all send that
  order.
- `opera::v136_http3_tls` sets `TrustAnchorIds::PerConnection` with one
  entry per tallied QUIC ClientHello, 20 entries holding 19 orders, and
  each QUIC connection draws again.

Both draws use BoringSSL's random number generator, which also draws the
GREASE values. The tests:

| Test | Checks |
| --- | --- |
| `opera_136_trust_anchor_recipes_draw_from_the_retained_orders` | Each ClientHello's order, read again from the fixtures the tally names, matches the tally, and each recipe lists exactly the tallied observations |
| `opera_136_tcp_trust_anchor_order_is_drawn_once_per_connector` | Twelve TLS connectors, three connections each: every connector sends one of the recipe's orders on all of its connections, and the connectors send more than one order |
| `opera_136_client_keeps_one_tcp_trust_anchor_order_across_connectors` | Twelve clients: each sends one of the recipe's orders on its HTTP/1.1 and HTTP/2 connections, to an HTTPS proxy, through a plaintext proxy's tunnel, and, with the `websocket` feature, on a WebSocket connection; the clients send more than one order |
| `per_connection_trust_anchor_order_is_drawn_for_each_tcp_connection` | Sixteen TCP connections from one TLS connector, with the 29 TCP entries drawn per connection: each carries a listed order, and they carry more than one |
| `http3_per_client_orders_with_different_ids_fail_the_build` | A `PerClient` list in the HTTP/3 TLS settings whose orders hold different IDs fails `Client::build` with `InvalidProfile` |
| `opera_136_quic_trust_anchor_order_is_drawn_per_connection` | Sixteen QUIC ClientHellos from one connector each carry one of the recipe's orders, and they carry more than one |
| `opera_136_tls_recipe_matches_windows_capture` | The emitted IDs equal the capture's as a set, and the emitted and captured orders are both among the recipe's |
| `opera_136_quic_client_hello_recipe_matches_windows_capture` and the TCP and QUIC resumption replays | The emitted IDs equal the capture's as a set; the TCP replays also require the emitted order to be among the recipe's. The captured order is checked against the recipe only in `opera_136_tls_recipe_matches_windows_capture` |

Limits:

- Phantom sends only the 35 retained orders. Opera can send any order its
  seeds and source tables produce.
- One Opera process derives its TCP order and all of its QUIC orders from
  one source table. A Phantom client draws its TCP order and each QUIC order
  independently, from orders of 29 and 6 different processes.

### macOS recipes

What is claimed: `chromium::v154_macos_client_hints`,
`edge::v154_macos_client_hints`, `opera::v136_macos_client_hints`, the
Chrome templates `chromium::v154_macos_navigation_template` and
`chromium::v154_macos_fetch_no_store_template`, and the Firefox templates
`firefox::v157_macos_navigation_template` and
`firefox::v157_macos_fetch_no_store_template` reproduce what those browsers
send on macOS 15.5 on Apple silicon. On macOS, Opera 136 sends the fields
of its Windows request templates with the macOS client hints, and Edge 154
does too with its language list set to `en-US`; for another locale, override
`Accept-Language`. So neither has a separate macOS template. Every other
layer of Chrome, Edge, Opera, and Firefox is the Windows recipe, and the
replay tests compare it with the single macOS runs listed below.

Evidence: the capture host is a MacBook Air (M4) on macOS 15.5 (24F74). On
2026-10-02 it ran Chrome 154.0.8037.95 as Google's updater left it, Edge
154.0.4258.48 as Microsoft AutoUpdate left it, Opera 136.0.6008.52 from
Opera's release archive (`Opera_136.0.6008.52_Autoupdate_arm64.tar.xz`),
and Firefox 157.0 from Mozilla's release archive. The Opera and Firefox
bundles replaced Opera 135.0.5973.92 and Firefox 154.0 in `/Applications`,
after their SHA-256 sums matched the published ones and `codesign` and
`spctl` accepted their notarized Developer ID signatures. Waking Google's
updater found no newer Chrome. Google's VersionHistory API for the Mac
stable channel, queried on 2026-10-03, lists 154.0.8037.93, .95, and .97
served from 2026-10-02 to fractions 0.495, 0.2475, and 0.2475 of clients,
so the Mac's Chrome build differs from the Windows host's 154.0.8037.97 in
its last version component alone. Edge, Opera, and Firefox run the Windows host's builds. Every run was
headless, on a fresh profile in a throwaway directory, against a listener
on 127.0.0.1. Chromium launches on macOS add `--use-mock-keychain`
([Browser launcher](../../scripts/capture/README.md#browser-launcher)).

| Browser and layer | Samples | Result |
| --- | --- | --- |
| Chrome, Edge, Opera client hints | 3 runs each | Windows names, order, delivery, and brand values, with the Mac's own build in Chrome's full versions; `sec-ch-ua-platform` `"macOS"`, `sec-ch-ua-platform-version` `"15.5.0"`, `sec-ch-ua-arch` `"arm"`; `sec-ch-ua-bitness` `"64"` and `sec-ch-ua-wow64` `?0` as on Windows |
| Chrome, Edge, Opera page loads and no-store `fetch()` over H1 and H2 | 3 runs each | The Windows template fields and values. `User-Agent` is a caller slot in every macOS Chromium-family template, and the headless value names `Macintosh; Intel Mac OS X 10_15_7` |
| Chrome, Opera H3 page request | 1 startup each | The Windows template's H3 fields |
| Firefox page loads and no-store `fetch()` over H1 and H2 | 3 runs | The Windows template, with `User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101 Firefox/157.0` |
| Chrome, Edge, Opera, Firefox resumed TCP ClientHello | 1 `tls_resumption.py --scenario sequential` run each | The shape of the TLS recipe's resumed ClientHello, as for the Windows captures (`phantom-net` `tls::tests::resumption`); Opera's trust-anchor ID set is that of `opera::v136_tls`, in an order drawn per process |
| Chrome, Edge, Opera, Firefox H2 session | 3 page loads each | The H2 recipe's SETTINGS, WINDOW_UPDATE, priority, pseudo-header order, and static-name choice |
| Chrome, Edge, Opera QUIC ClientHello and H3 startup | 1 startup each | The transport parameters of `chromium::v154_quic` and the Chromium H3 control stream; Chrome's and Opera's H3 request fields equal their Windows startups apart from persona fields |

Each capture differed from the macOS capture it replaced only in the build
numbers it reports and in per-connection values, except Opera's: its client
hints and brand-bearing request fields carry Opera 136's brand list, where
Opera 135 put the greased brand first, and its TCP and QUIC ClientHellos
carry the trust-anchor IDs of `opera::v136_tls` and, over TCP, GREASE at
the head of `signature_algorithms`, as on Windows.

On macOS the page's final `fetch()` sometimes opened a new H2 connection,
where on Windows it reused the page's connection; one of the three Chrome
runs did. In that run the page's connection had closed before the
WebSocket opened, which then used HTTP/1.1. The H2 session replay therefore
takes the connection whose first request is the document.

Edge on macOS takes `Accept-Language` from the system's language list and
ignores `--lang`. On the capture host that list gave
`en-CA,en-US;q=0.9,en;q=0.8`. The Edge client-hint and WebSocket captures
therefore ran with `--accept-lang=en-US`, passed through `--browser-switch`,
and sent the Windows value `en-US,en;q=0.9`. The Edge H3 startup ran with
the shared startup launch arguments and sent the system value, so only its
field names are compared.

Capture commands, from the repository root on the Mac, with `TMPDIR` set to
a scratch directory. The Edge commands were:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.client_hints \
  --browser edge \
  --browser-path "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
  --client-version 154.0.4258.48 \
  --operating-system "macOS 15.5 (24F74) arm64" \
  --browser-switch=--accept-lang=en-US --repeat 3 \
  --output fixtures/client-hints/edge/154.0.4258.48/macos-15.5-arm64/navigation.txt
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.http2_websocket \
  --browser edge \
  --browser-path "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
  --client-version 154.0.4258.48 \
  --operating-system "macOS 15.5 (24F74) arm64" \
  --browser-switch=--accept-lang=en-US \
  --scenario accept h1-accept --repeat 3 \
  --output-dir fixtures/websocket/edge/154.0.4258.48/macos-15.5-arm64
```

Chrome, Opera, and Firefox ran the same commands with
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
`/Applications/Opera.app/Contents/MacOS/Opera`, and
`/Applications/Firefox.app/Contents/MacOS/firefox` and no switch. The
single runs used `tls_resumption.py --scenario sequential --repeat 1` for
all four browsers and `startup_capture.py --layer http3 --repeat 1` for the
Chromium browsers, with `--navigate devtools` for Opera; the startup's
`client-startup-1.txt` is retained as `client-startup.txt`. The 15 runs,
one browser after another, took 85 seconds of wall clock, 82 of them in the
runs: 18 for Chrome, 16 for Edge, 28 for Opera, and 20 for Firefox.

Retained fixtures, under `<area>/<browser>/<version>/macos-15.5-arm64/`:

| Browser | Area | Files |
| --- | --- | --- |
| Chrome 154.0.8037.95, Edge 154.0.4258.48, Opera 136.0.6008.52 | `client-hints` | `navigation.txt` |
| Chrome, Edge, Opera | `websocket` | `accept.txt`, `h1-accept.txt` |
| Chrome, Edge, Opera | `tls` | `resumption-sequential.txt` |
| Chrome, Edge, Opera | `http3` | `client-startup.txt`, `quic-client-hello-1.txt` |
| Firefox 157.0 | `client-hints` | `navigation.txt`, with no hints |
| Firefox 157.0 | `websocket` | `accept.txt`, `h1-accept.txt` |
| Firefox 157.0 | `tls` | `resumption-sequential.txt` |

They replace the macOS captures of Chrome 154.0.8037.58, Edge
154.0.4258.37, Opera 135.0.5973.92, and Firefox 156.0, which were removed.

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
ChaCha20-Poly1305. `firefox_android::v156_tls` returns `firefox::v157_tls`,
and `firefox_android_156_tls_recipe_matches_android_captures` replays one
retained sample of each AEAD through the TLS connector.

Retained fixtures, under
`fixtures/tls/firefox-android/156.0.1/android-35-emulator/`:
`client-hello.txt` (AES-128-GCM) and `client-hello-chacha20-ech.txt`.

`firefox_android::v156_tls` also keeps the desktop recipe's TCP early data,
from source only, since no Android capture could resume a session: at tag
`FIREFOX_156_0_RELEASE`, `security.tls.enable_0rtt_data` and
`network.http.remove_resumption_token_when_early_data_failed` default to
true on every platform
(`modules/libpref/init/StaticPrefList.yaml:19097-19100` and `:17033-17037`),
and `mobile/android/app/geckoview-prefs.js`, GeckoView's Android preference
file, overrides neither.

Limits: those of Chrome for Android, on the Android 15 emulator, and no
HTTP/2, WebSocket, request-field, proxy, or resumption capture, because none
can load a TLS page. Firefox for Android sends no user-agent client hints; a
plaintext probe request carried none. No client-hint capture ran on Android
17: the launcher's typed entry opens `about:blank` by `VIEW` intent, which
Firefox does not resolve.

### Firefox 157 HTTP/3 recipe

What is claimed: `firefox::v157_http3_tls`, `v157_quic`, `v157_http3`, and
`v157_http3_request`, with the HTTP/3 lists of the Firefox 157 templates,
reproduce the QUIC and HTTP/3 layers of Firefox 157.0 on Windows 11 that
the list below names, apart from the differences under Limits.

Evidence: `fixtures/http3/firefox/157.0/windows-11-26200/` retains five
headless [fingerprint snapshots](#fingerprint-snapshot-evidence)
(`snapshot-1.txt` to `snapshot-5.txt`, 1.3 to 1.5 seconds a run), the QUIC
ClientHello split from the first three (`quic-client-hello-1.txt` to
`-3.txt`), and the `quic_resumption.py` captures `resumption-accept.txt`
(five runs, 25 connections), `resumption-accept-delayed.txt`, and
`resumption-reject.txt` (three runs, 15 connections each), which record each
client unidirectional stream. Each process used a fresh profile against the
aioquic 1.3.0 capture servers. All 60 connections agree on the following.

- Transport parameters, in this order and never permuted: `max_idle_timeout`
  30000, `initial_max_data` 25165824, `initial_max_stream_data_bidi_local`
  12582912, `_bidi_remote` and `_uni` 1048576, both stream limits 100,
  `max_ack_delay` 20, `active_connection_id_limit` 8, a 3-byte
  `initial_source_connection_id`, `version_information`, the empty
  `reset_stream_at` (0x1d), draft 02's `min_ack_delay` (0xff02de1a, an
  8-byte identifier, 1000 µs), and `max_datagram_frame_size` 65535. There is
  no `max_udp_payload_size`, `grease_quic_bit`, or reserved parameter. The
  order is the order of neqo's parameter table.
- `version_information` lists the chosen version, then a reserved version,
  QUIC v2, and QUIC v1. A fresh connection chooses v1 and starts in v1
  packets; aioquic acknowledged the first Initial in v1 and then moved every
  fresh connection to v2 by compatible version negotiation. A connection that
  presented a ticket chose v2 and started in v2 packets.
- The control stream is client stream 2, the QPACK encoder stream 6, and the
  decoder stream 10. SETTINGS lists, in this order, `QPACK_MAX_TABLE_CAPACITY`
  65536, `QPACK_BLOCKED_STREAMS` 20, draft 02's `ENABLE_WEBTRANSPORT`
  (0x2b603742) 0, the draft (0xffd277) and final `H3_DATAGRAM` 1, and
  `ENABLE_CONNECT_PROTOCOL` 1. The control stream's first STREAM frame held
  33 to 40 bytes in the 55 resumption connections: its type and SETTINGS
  take 24, and the rest is one reserved frame, as neqo's `HFrame::Grease`
  writes after SETTINGS.
- The encoder stream's first frame carries its type and a Set Dynamic Table
  Capacity of 4096, the server's table; the decoder stream's first frame is
  its type alone.
- Requests send `:method`, `:scheme`, `:authority`, and `:path`, then the
  template's fields. The QPACK encoder indexes exact static and dynamic
  matches, sends a static or dynamic name reference with a literal value, and
  inserts only a field whose name matches no table entry, with a
  Huffman-coded literal name.
- The QUIC ClientHello differs from the TCP one: TLS 1.3 alone, three cipher
  suites, `h3`, ECDSA-SHA1 moved after the other ECDSA schemes in
  `signature_algorithms`, `compress_certificate` in the order zlib, zstd,
  brotli, and no `ec_point_formats`, `session_ticket`, or
  `signed_certificate_timestamp`. Its `delegated_credentials` list is the
  TCP one. Its extension order changes on every connection, except that
  `quic_transport_parameters` and `encrypted_client_hello` are always last,
  followed only by `pre_shared_key` when it resumes. Like the TCP one, it
  sends `record_size_limit` 16385, an empty `extended_master_secret`, and a
  `renegotiation_info` of one zero byte, although QUIC carries no TLS
  records and offers only TLS 1.3, and an ECH GREASE payload of 240 bytes
  fresh and 368 resumed
  ([Firefox ECH GREASE payload](#firefox-ech-grease-payload-evidence)).
  Firefox 156.0.1 also offered ML-DSA-44, -65, and -87 in both signature
  lists; Firefox 157.0 does not
  ([Firefox 157 against Firefox 156.0.1](#firefox-157-against-firefox-15601)).

The snapshot server records each client Initial datagram: its size,
version, and connection ID lengths. In all five snapshots every Initial
datagram was 1252 bytes, and the ClientHello with its X25519MLKEM768 key
share took two of them. The first Destination Connection IDs were 8, 14,
13, 8, and 8 bytes.

Firefox 157.0 vendors neqo 0.31.1
(`third_party/rust/neqo-*` at `FIREFOX_157_0_RELEASE`), and the rules
below are read from that version. Each rule's code is the same in neqo
0.30.1, which Firefox 156.0.1 vendored:

- `ConnectionId::generate_initial` (`neqo-transport/src/cid.rs`, lines 54
  to 59) draws the first Destination Connection ID's length as
  `max(8, 5 + (b & (b >> 4)))` for a random byte `b`. The recipe uses that
  rule.
- A path starts at a 1280-byte IP MTU, less 28 header bytes over IPv4 and
  48 over IPv6 (`neqo-transport/src/pmtud.rs`, lines 26 to 30 and 76 to
  81). The recipe's `initial_path_mtu` is 1280, so Phantom's Initial
  datagrams are 1252 bytes over IPv4 and 1232 over IPv6.
- `Http3Connection::send_settings` (`neqo-http3/src/connection.rs`, lines
  366 to 372) queues one reserved frame after SETTINGS, and
  `HFrame::Grease` (`neqo-http3/src/frames/hframe.rs`, lines 97 to 101 and
  124 to 128) draws its type and a payload of zero to seven bytes.
- `Encoder::encode_header_block` (`neqo-qpack/src/encoder.rs`, lines 404 to
  513) and `HeaderTable::lookup` (`neqo-qpack/src/table.rs`, lines 231 to
  261) set the QPACK rules.

The captures agree with each rule they exercise. They ran over IPv4
loopback, so the 1252-byte Initial datagrams are captured; no capture covers
IPv6, and its 1232 bytes come from source alone.

Tests replay the captures:

- `firefox_157_quic_offer_and_streams_match_windows_capture` connects the
  recipes to a loopback BoringSSL QUIC server. The ClientHello matches each
  retained one in cipher suites, groups, key shares, both signature lists,
  ALPN, server name, extension set, the last two extensions
  (`quic_transport_parameters`, then `encrypted_client_hello`), the ECH
  GREASE payload length, and the delegated-credential, status request,
  certificate-compression, PSK-mode, `extended_master_secret` (empty),
  `renegotiation_info` (`00`), and `record_size_limit` (`4001`) bodies. The
  order of the other extensions is drawn per connection by both, so it is
  not compared. The transport parameters match each snapshot in order,
  identifier and length widths, and value, apart from the connection ID
  bytes and the reserved version.
  The control stream carries the captured SETTINGS frame byte for byte and
  one reserved frame, and streams 2, 6, and 10 carry types 0, 2, and 3.
- `firefox_157_resumed_quic_client_hello_matches_the_resumption_captures`
  learns a ticket that permits early data and records the resumed
  ClientHello. Against each resumed ClientHello of the three resumption
  captures, it has the same extension set, ends with
  `quic_transport_parameters`, `encrypted_client_hello`, and
  `pre_shared_key`, and has the same `early_data`, PSK-mode,
  `extended_master_secret`, `renegotiation_info`, and `record_size_limit`
  bodies. Its ECH GREASE payload follows NSS's rule; see
  [Firefox ECH GREASE payload](#firefox-ech-grease-payload-evidence).
- `firefox_157_quic_client_hello_pads_ech_grease_by_an_ip_literal_host`
  records the ClientHellos to `127.0.0.1` and `::1`; see the same section.
- `firefox_157_initial_datagrams_match_the_capture` receives the two
  Initial datagrams on a bare IPv4 UDP socket and compares them with the
  first two of each snapshot: the size, the version, and the Source
  Connection ID length are equal, and both Destination Connection IDs are 8
  to 20 bytes. `firefox_157_initial_datagrams_leave_room_for_ipv6_headers`
  checks 1232-byte datagrams over IPv6, which no capture covers.
- `firefox_157_recipe_completes_a_request` sends a request with the Firefox
  recipes to a loopback `h3` server.
- `firefox_157_client_follows_a_server_to_version_2` runs the BoringSSL
  session through a v2-only Quinn server. A relay protects Phantom's v1
  Initials again as v2, the server answers in v2, and Phantom switches and
  completes the request in v2.
- `firefox_cookie_fields_match_the_captured_qpack_bytes` encodes the four
  requests of the Firefox 157.0 HTTP/3 cookie capture through the request
  recipe and the QPACK encoding; the encoder stream and all four field
  sections equal the capture. A unit test in the vendored `h3` does the same
  for the two requests of a Firefox 156.0.1 snapshot; Firefox 157.0's
  snapshots carry the same encoder stream.
- `firefox_157_http3_templates_follow_the_captured_field_order` compares
  both templates' HTTP/3 lists with the captured requests.

QUIC v2 is checked against RFC 9369's Appendix A vectors (Initial keys, the
protected server Initial, the Retry, and the ChaCha20 short header) in
`phantom-quic-btls`, and against aioquic 1.3.0 on loopback. There,
`scripts/conformance/aioquic_versions.py` with the `quic_version_interop`
example of `phantom-net`, three requests on fresh connections with the
Firefox recipes, reported on 2026-09-26:

```text
first_packet_version=0x00000001 negotiated_version=0x6b3343cf chosen_version=0x00000001 available_versions=0xdaeaca8a,0x6b3343cf,0x00000001 resumed=false early_data_accepted=false
first_packet_version=0x6b3343cf negotiated_version=0x6b3343cf chosen_version=0x6b3343cf available_versions=0x1a3a2a0a,0x6b3343cf,0x00000001 resumed=true early_data_accepted=true
first_packet_version=0x6b3343cf negotiated_version=0x6b3343cf chosen_version=0x6b3343cf available_versions=0x0ada3a1a,0x6b3343cf,0x00000001 resumed=true early_data_accepted=true
```

That is the pattern of the Firefox captures: v1 moved to v2 on the first
connection, and v2 from the first packet, with early data, on the resumed
ones.

How to reproduce: the snapshot and resumption commands in the
[capture README](../../scripts/capture/README.md#quick-fingerprint-snapshot),
with `--browser firefox` and `--client-version 157.0`, and, for the
resumption captures, `--scenario accept --repeat 5`, then `--scenario
accept-delayed reject --repeat 3`. For the interop run, start
`uv run --no-project --python 3.10 --with aioquic==1.3.0 python
scripts/conformance/aioquic_versions.py --root <dir>/root.der --port-file
<dir>/port`, then run `cargo run -p phantom-net --example
quic_version_interop -- <port> <dir>/root.der`.

Limits:

- The order of the shuffled extensions is drawn per connection, by
  BoringSSL for Phantom and by NSS for Firefox, so no two ClientHellos are
  expected to share it; only the fixed tail is compared.
- Firefox sends `Alt-Used` after `accept-encoding`, or after `referer` on a
  `fetch`, on requests to an origin it reached through Alt-Svc. Phantom
  generates the field and appends it last.
- neqo stops using the dynamic table once 1000 streams hold unacknowledged
  field sections; Phantom does not.
- Phantom never sends `ACK_FREQUENCY` or `RESET_STREAM_AT`. No capture shows
  whether Firefox sends either.
- A resumed connection starts in v2. If the server no longer offers v2, the
  connection fails on the Version Negotiation packet; how Firefox recovers
  there is not captured.
- Datagrams after the first flight, path MTU probing, and loss-probe sizes
  are not compared; Phantom's retransmitted Initials are 1200 bytes.
- The captures cover Windows only, and no extended CONNECT or WebSocket over
  HTTP/3.

### TCP socket option evidence

What is claimed: `chromium::v154_tcp` and `firefox::v157_tcp` set the socket
options and keepalive, and `chromium::v154_tcp` races addresses, as those
browsers do at the profiled release tags. `chromium::v154_tcp` does the same
for Brave 154, and for Edge 154 and Opera 136, whose hook logs match Chrome
154's ([Socket hook evidence](#socket-hook-evidence)). Firefox 157's own hook
logs confirm `firefox::v157_tcp` on Windows
([Firefox socket hook evidence](#firefox-socket-hook-evidence)).

Evidence: a capture cannot show socket options, so the TCP recipes rest on
browser source. The socket-option and Happy Eyeballs default citations are to
Chromium tag `154.0.8037.58` and Firefox tag `FIREFOX_157_0_RELEASE`. The line
numbers for the rest of the racing algorithm, which `TcpAddressRacing` and
`phantom-net`'s `address_racing` module document, were read at Chromium tag
`153.0.8010.48` and have not been re-read at 154; the defaults those recipes
encode were.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_tcp` | `TCPClientSocket` calls `SetDefaultOptionsForClient` when it opens each socket, before connecting (`net/socket/tcp_client_socket.cc:173`, `:558`). That sets `TCP_NODELAY` and a 45-second keepalive idle time and interval: `SIO_KEEPALIVE_VALS` on Windows (`net/socket/tcp_socket_win.cc:50`, `:55-72`, `:815-818`), `TCP_KEEPIDLE` and `TCP_KEEPINTVL` on Linux (`net/socket/tcp_socket_posix.cc:88-100`, `:493-517`). On Windows, right before `connect`, it also sets `SO_RANDOMIZE_PORT` when `kTcpPortRandomizationWin` is enabled, which it is by default, and `base::win::GetVersion()` is at least the feature's minimum, `WIN11_22H2`, build 22621 (`net/socket/tcp_socket_win.cc:105-110`, `:1046-1053`; `net/base/features.cc:308-314`; `base/win/windows_version.cc:386-404`). |
| `firefox::v157_tcp` | `nsSocketTransport::InitiateSocket` sets `PR_SockOpt_NoDelay` and, on Windows, a 524,288-byte send buffer on every socket before connecting (`netwerk/base/nsSocketTransport2.cpp:1449-1465`, `netwerk/base/nsSocketTransportService2.cpp:1536-1538`). Each HTTP/1 transaction starts short-lived keepalive (10 s idle, `network.http.tcp_keepalive.short_lived_idle_time`) with an interval of the connection's setup time in whole seconds, at least one, and arms a switch to the long-lived 600 s (`netwerk/protocol/http/nsHttpConnection.cpp:686`, `:2126-2241`; `modules/libpref/init/all.js:1263-1270`). The switch comes 60 s, less the remainder modulo the idle time, plus 10 probe intervals and 2 s later on Windows (`nsHttpConnection.cpp:2167-2190`, `netwerk/base/nsSocketTransportService2.h:63-70`), and is skipped for an idle pooled connection (`:1411-1414`). HTTP/2 disables keepalive (`:405-406`, `:2243-2262`), and taking the transport for an upgrade switches at once (`:1303-1320`). |
| `firefox::v157_tcp` address selection | Release builds keep Happy Eyeballs behind the nightly-only `network.http.happy_eyeballs_enabled` (`modules/libpref/init/StaticPrefList.yaml:17153-17156`). `DnsAndConnectSocket` arms a 250 ms backup timer once the primary attempt is connecting (`modules/libpref/init/all.js:1205`; `netwerk/protocol/http/DnsAndConnectSocket.cpp:242-265`, `:307-329`); without a learned family the backup resolves IPv4 only (`all.js:1237`; `DnsAndConnectSocket.cpp:179-186`, `:222-225`). An attempt moves to its next address only after a refused, unreachable, or timed-out connect (`netwerk/base/nsSocketTransport2.cpp:169-200`, `:1747-1755`), and a primary attempt that ends before the timer cancels it (`DnsAndConnectSocket.cpp:267-277`). The attempt that loses keeps connecting; its connection goes to the idle list, after a null transaction finishes its TLS handshake on a TLS origin (`:267-287`, `:671-745`), and a request may claim it meanwhile (`netwerk/protocol/http/ConnectionAttemptPool.cpp:141-163`; `netwerk/protocol/http/PendingTransactionInfo.cpp:20-44`, `:113-128`). Each connection records its address family on the connection entry, the first one setting it (`DnsAndConnectSocket.cpp:1152-1165`; `netwerk/protocol/http/ConnectionEntry.cpp:125-149`); later connections resolve that family alone, the backup with `network.http.fallback-connection-timeout`, 5 s, on each connect, and try the other family once it fails (`all.js:1220`; `DnsAndConnectSocket.cpp:167-178`, `:1014-1046`, `:1063`, `:1295-1303`; `nsSocketTransport2.cpp:1541`, `:1799-1825`). Once a connection reports HTTP/2, the entry's other attempts are closed and its other connections are not reused (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:921-1033`; `ConnectionEntry.cpp:627-650`). |
| `chromium::v154_tcp` address racing | Happy Eyeballs v2 is enabled and v3 disabled by default, so every TCP connection uses a `TcpConnectJob` (`net/base/features.cc:114-124`, `net/socket/transport_connect_job.cc:118-123`). It prefers IPv6 first (`net/socket/tcp_connect_job.h:211`), the other family after a failure (`net/socket/tcp_connect_job_connector.cc:298-303`), and starts a second, IPv4-preferring attempt `kIPv6FallbackTime = 300` ms after the first (`net/socket/tcp_connect_job.h:85`, `net/socket/tcp_connect_job.cc:443-466`, `:573-610`). No address is tried twice (`:703-746`); the first connection wins and a total failure returns the most recent error (`:406-431`, `:946-958`). The delay-changing trials `kAdjustIPv6FallbackTime` and `kIPv6FallbackBasedOnRTT` are disabled by default (`net/base/features.cc:128`, `:136`). |

Differences from the browsers:

- Chromium ignores a failure to set any of these options
  (`net/socket/tcp_socket_win.cc:70-71`, `:1046-1047`). Phantom fails that
  connection attempt instead, so no connection proceeds with options the
  profile did not ask for. Chromium's comment expects `SO_RANDOMIZE_PORT` to
  fail on a socket that is already bound; Phantom sets it before a source
  binding binds the socket, so a bound connection gets a random port too.
- Chromium on macOS sets only the keepalive idle time
  (`net/socket/tcp_socket_posix.cc:101-105`), and Android and iOS builds
  enable no keepalive. `chromium::v154_tcp` describes Windows and Linux; a
  macOS profile sets the interval of its `TcpKeepalivePolicy::Fixed` to
  `None`.
- Firefox applies keepalive after connecting, where Phantom's fixed
  keepalive and Chromium apply it before; no packet shows the difference.
  On macOS Firefox sets only the idle time and assumes 8 probes, and on
  Linux and Android it also sets `TCP_KEEPCNT` to 4
  (`netwerk/base/nsSocketTransport2.cpp:3311-3401`); Phantom's schedule sets
  the interval wherever the host can and never a probe count.
- Brave 1.96.59 builds Chromium tag `154.0.8037.58` and changes none of
  the values above, so it uses `chromium::v154_tcp`. Neither
  `patches/net-base-features.cc.patch` nor
  `rewrite/net/base/features.cc.yaml` in `brave-core` at `v1.96.59` changes
  `kTcpPortRandomizationWin`
  ([Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes)).
- Edge's and Opera's network-stack source is not public. Their hook logs,
  and Chrome's, show `TCP_NODELAY` and the 45-second keepalive on every
  socket, `SO_RANDOMIZE_PORT` after them, and a 300 ms IPv4 fallback, so
  both use `chromium::v154_tcp`. On Chromium 154 the logs also show
  `SIO_TCP_INITIAL_RTO` toward loopback peers, which Phantom does not set
  ([Socket hook evidence](#socket-hook-evidence)).
- Chromium races as DNS answers arrive and sorts addresses itself. Phantom
  races the system resolver's complete answer, keeping its order within each
  family. Chromium's QUIC job uses only the first resolved address
  (`net/quic/quic_session_pool_direct_job.cc:219-221`), so racing is not
  applied to HTTP/3, and Phantom's H3 connector keeps trying later addresses
  after a connection failure.
- Firefox skips an address that failed before on the same cached DNS
  record (`netwerk/base/nsSocketTransport2.cpp:1742-1745`); Phantom tries it
  again.
- Phantom keeps the slower attempt's connection, and remembers the address
  family, only on the direct route of the HTTP/1.1 and negotiated pools.
  Connections to a proxy, WebSocket connections, exact HTTP/2 requests, and
  connections that offer ECH from HTTPS records start the backup, close the
  slower attempt, and neither use nor learn the family; Firefox keeps the
  connection and the family on every connection entry.
- The slower attempt reaches the pool, and becomes claimable, once the
  first connection's handshake has finished. Firefox lets a request claim
  it as soon as the first connection takes its request.
- Phantom keeps one memory of an origin's address family per pool for the
  origin and route, shared by the origin's pool entries on every runtime,
  as per-origin admission is. A prune of the client's timer forgets it when
  none of those entries has a connection, setup, or slower attempt left.
  Firefox drops it with the connection entry at the same kind of prune,
  but it notices a server's close of an idle connection at once and stops
  its timer when no connection is left, where Phantom notices the close
  only when the timer fires; so Phantom may forget a family sooner. The
  HTTP/1.1 and negotiated pools of one client keep separate memories, and
  a memory ends when the pool has evicted every entry that held it.
  ([Firefox socket hook evidence](#firefox-socket-hook-evidence)).

Tests in `phantom-net` read the options back from connected sockets with
`socket2` getters:

| Test | What it proves |
| --- | --- |
| `tcp::address_racing::tests` | With scripted attempt outcomes and a test-controlled fallback delay: IPv6 preference, alternation, the IPv4 fallback attempt and role swap, the two-attempt bound, cancellation of the loser, and the returned error |
| `tcp::tests::racing_reaches_ipv4_when_nothing_listens_on_ipv6` | Real sockets raced to `[::1]` and `127.0.0.1` at the same port, with a listener only on IPv4, connect over IPv4 |
| `tcp::tests::host_check_*` | The build-time host check for every combination of platform capabilities. The facade rejects a Windows keepalive without an interval as `BuildErrorKind::InvalidProfile` |
| `tcp::tests::connected_socket_carries_requested_options` | `TCP_NODELAY` and `SO_KEEPALIVE`, and on Linux and macOS the idle time and interval. Windows exposes no getter for the `SIO_KEEPALIVE_VALS` values |
| `tcp::tests::paths` | Options on every socket opened by the direct, forward proxy, HTTP CONNECT (with and without Basic), HTTPS proxy, SOCKS5 (remote and local DNS), HTTP/1.1-or-HTTP/2, and SOCKS5 UDP control paths, `SO_RANDOMIZE_PORT` included on Windows |
| `tcp::tests::port_randomization` | On Windows, read back with `getsockopt`: `SO_RANDOMIZE_PORT` set by `chromium::v154_tcp` from build 22621 and not by `firefox::v157_tcp` or a minimum build past the host; a bound socket rejects it with `WSAEINVAL`; eight successive Chromium-profile connections, with and without a source binding, each have it set, and at least two successive ones take local ports more than 64 apart |
| `tcp::backup_connection::tests` | With scripted attempt outcomes and a test-controlled delay: no backup for a fast primary, an IPv4-only backup that can win, the next address only after a refused, unreachable, or timed-out connect, no backup after an early primary failure or for an IPv6-only host, and the returned error; the attempt that loses keeps connecting through its addresses; a remembered family restricts both attempts, gives each backup connect the timeout, and gives way to the other family, without the timeout, once its addresses fail; the first connection sets the family and only a switch replaces it |
| `tcp::keepalive_schedule::tests` | The interval from the setup time, the 72 s switch of `firefox::v157_tcp`, and the phases applied for an opened connection, HTTP/2, an upgrade, a reused connection, and, on a four-second schedule, an active against an idle connection and a switch moved later by a second request |
| `tcp::tests::keepalive_paths` | The phases a Firefox profile's connection goes through, and its idle state after each response, on plaintext HTTP/1.1 requests, a `101` upgrade, HTTP/1.1 or HTTP/2 chosen by ALPN, and an HTTP/2 connection to an HTTPS proxy; a Chromium profile opens no schedule; the send buffer is set before connecting |
| `tcp::tests::a_reset_connect_stops_firefox_at_the_first_address_but_not_chromium` | With scripted outcomes: a reset connect ends the Firefox recipe's sequential attempt at the first address, while the default sequential selection and the Chromium recipe's racing try the next |
| `tcp::tests::address_selection` | Over loopback, with `[::1]` refused: every selection reaches IPv4; on Windows, where the refusal takes about two seconds, a 250 ms backup connects after 250 ms and the Chromium profile's second attempt after 300 ms, and with two IPv6 addresses only racing takes the second early |
| `tcp::tests::slower_connection` | With a scripted slower attempt that connects to a loopback origin when the test lets it: a plaintext slower connection sets no keepalive until its first request, then short-lived keepalive with the interval of its setup time; a TLS one finishes its handshake with no request and waits idle; a negotiated one enters the protocol ALPN selects; and a first connection that selected HTTP/2 keeps the slower attempt only once it has connected |
| `session::http1_pool::tests::slower_connection` and `session::http1_or_2_pool::tests::slower_connection` (facade) | With a slower connection whose setup the test ends: it waits idle, counts toward the bound once connected, goes to the one request that claimed it, lets that request open a connection when it fails, returns to idle when the claimant leaves, and is skipped by a fresh-connection request; in the negotiated pool it closes when the key has HTTP/2, an HTTP/2 one closes in favor of the current connection, and one becomes the key's HTTP/2 connection when the key has none; a prune forgets the address family only of a key with no connection, setup, or slower attempt |
| `a_firefox_profile_keeps_the_slower_backup_connection_for_later_requests` (facade, Windows) | Over loopback, with `[::1]` refused slowly: the IPv4 backup carries the first request, the slower attempt's `127.0.0.1` connection opens with no request, and the next two requests use the two connections without a third |
| `profile_tcp_settings_reach_every_tcp_connector` (facade) | A profile's settings reach each TCP connector the client builds, including the WebSocket HTTP/1.1 connector |

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- Hook logs of Chrome 154, Edge 154, and Opera 136 confirm the Windows
  options and fallback delay, once each; no wire capture confirms them, and
  none shows keepalive probe timing on an idle connection.
- The source was read at one tag per browser, so build-time or field-trial
  changes to these options would not be seen. Branded Chrome receives
  server-side field-trial configuration, so the source cannot rule out a
  trial that enables Happy Eyeballs v3 or a different fallback delay for some
  users.

### UDP socket option evidence

What is claimed: `chromium::v154_udp` sets `SO_RANDOMIZE_PORT` on the UDP
socket of every QUIC connection, and on the query socket of every DNS query
Phantom sends itself with the `https-records` feature, as Chromium 154 sets
it on every UDP socket it connects on Windows, and as Chrome 154, Edge 154,
and Opera 136 do in their hook logs. Firefox 157 does not set it, and a
Firefox profile takes no UDP settings.

Evidence: browser source at Chromium tags `154.0.8037.58` and
`152.0.7977.130`, whose lines below are the same, and the hook logs of
[Socket hook evidence](#socket-hook-evidence).

| Browser | Source behavior |
| --- | --- |
| Chromium 154 | `UDPSocketWin::Connect` calls `InternalConnect`, which sets `SO_RANDOMIZE_PORT` and then calls `connect`, with no feature or Windows version check, and ignores a failure, which its comment expects on a socket that is already bound (`net/socket/udp_socket_win.cc:544-575`). `UDPClientSocket::Connect` opens the socket and calls it (`net/socket/udp_client_socket.cc:69-89`). The QUIC session pool connects each QUIC socket first and only then sets its receive buffer, do-not-fragment, ECN, and send buffer options (`net/quic/quic_session_pool.cc:1334-1378`, and `:1196-1268` for the asynchronous path), and the built-in DNS client opens its sockets the same way (`net/dns/dns_transaction.cc:696-700`). A socket that binds an address instead, through `UDPSocketWin::Bind`, does not get the option (`net/socket/udp_socket_win.cc:587-602`); WebRTC's sockets bind that way (`services/network/p2p/socket_udp.cc:112-113`, `:250-260`; `net/socket/udp_server_socket.cc:20`). |
| Brave 154 | Brave 1.96.59 builds Chromium tag `154.0.8037.58`, and `brave-core` at tag `v1.96.59` has no patch, `chromium_src` override, or rewrite for `net/socket/udp_socket_win.cc`, `udp_client_socket.cc`, `socket_descriptor.cc`, `net/quic/quic_session_pool.cc`, or `net/dns/dns_transaction.cc`; its `net/` changes touch SOCKS5, the TLS client socket, the QUIC proof verifier, and the DNS client, host cache, and resolver job. `chromium::v154_udp` therefore serves Brave, checked on 2026-10-02. |
| Firefox 157 | No Firefox code sets the option. On 2026-10-02 Searchfox's `firefox-release` tree, at 157.0.1, holds the name `SO_RANDOMIZE_PORT` only in the vendored `windows-sys` and `winapi` crates (`third_party/rust/`). |

The Windows SDK declares `SO_RANDOMIZE_PORT` for Windows Vista and later
(`ws2def.h`, `_WIN32_WINNT >= 0x0600`), so every Windows that Rust supports
has it. On the hook host, a loopback check that is not retained bound 200
IPv4 UDP sockets to port 0 one after another: without the option every port
was one above the last, and with it none was. The same check found that
Windows rejects the option on a bound UDP socket with `WSAEINVAL`, and that
20,000 binds with the option set returned no error.

Differences from the browsers:

- Chromium connects its UDP sockets and sets the option right before the
  `connect` that gives a socket its port. Phantom's QUIC sockets are bound,
  not connected, and Phantom sets the option before that bind. Quinn sets
  its own socket options after the bind, as Chromium sets its QUIC options
  after `connect`.
- Chromium ignores a failure to set the option. Phantom fails that
  connection attempt instead.
- Chromium sets `IPV6_V6ONLY` to 0 on each IPv6 socket when it creates it
  (`net/socket/socket_descriptor.cc:29-35`); Phantom does not. Phantom's
  IPv6 QUIC sockets send only to IPv6 peers, so no packet shows the
  difference.
- Address lookups through the operating system use its sockets, which take
  the host's port choice. Phantom's own DNS queries, for HTTPS records and
  for addresses through `AddressResolver::system_nameservers`, open each
  UDP socket through the same bind as a QUIC socket, with the profile's
  `UdpSettings`. With `port_randomization` on Windows the socket sets the
  option and binds port 0, so Windows picks the port at random, as it does
  for Chromium's DNS sockets at `connect`. Without it, and on other
  platforms, hickory binds a random port from 1024 to 65535 itself, as
  Chromium's `RandomBind` does outside Windows
  (`net/socket/udp_socket_posix.cc:1564-1575`).
- Chromium's IPv6 probe socket sets the option before its `connect`.
  `AddressResolver::system_nameservers` binds its probe socket to `[::]:0`
  with the profile's `UdpSettings`, then connects it; neither sends a
  packet.
- A TCP connection that carries a DNS query after a truncated UDP response
  is hickory's own and takes no profile TCP options. Chromium's goes through
  its TCP client socket, with `chromium::v154_tcp`'s options.

Tests:

| Test | What it proves |
| --- | --- |
| `udp::tests::port_randomization` (`phantom-net`) | On Windows, read back with `getsockopt`: `SO_RANDOMIZE_PORT` set by `chromium::v154_udp` and not without UDP settings; a bound UDP socket rejects it with `WSAEINVAL`; eight successive Chromium-profile sockets, with and without a source binding, each have it set, and at least two successive ones take local ports more than 64 apart; sixteen successive sockets without UDP settings take ascending ports at most 64 apart, all but two pairs, and the test prints how many were one apart |
| `udp::tests::paths` (`phantom-net`) | The UDP socket of a direct HTTP/3 connection, with and without a source binding, and of a SOCKS5 UDP association, with local and remote DNS, has the option exactly when the connector has Chromium's UDP settings |
| `udp::tests::a_socket_takes_port_randomization_only_when_the_settings_ask` (`phantom-net`) | On every platform, a socket has the option only on Windows and only with `chromium::v154_udp`, not with default or absent settings |
| `profile_udp_settings_reach_every_http3_connector` (facade) | A profile's UDP settings reach the HTTP/3 connector and the CONNECT-UDP proxy's HTTP/3 connector the client builds |
| `dns::address_lookup::tests::query_sockets_randomize_their_port_with_the_profiles_udp_settings`, `dns::tests::https_queries_randomize_their_port_with_the_profiles_udp_settings` (`phantom-net`) | Each A, AAAA, and HTTPS query socket to a loopback DNS server has the option exactly on Windows with `chromium::v154_udp`, not with default or absent settings |
| `profile_udp_settings_reach_the_dns_query_sockets` (facade) | A profile's UDP settings reach the client's address resolver and HTTPS record resolver, and a profile without them leaves both unchanged |
| `chromium_family_udp_sockets_randomize_their_port_before_connecting` (`phantom-profile`) | In every Chromium-family hook log, each UDP socket the browser's network code opened set `SO_RANDOMIZE_PORT` before `connect`, after only the `IPV6_V6ONLY` of an IPv6 socket; the Chrome and Edge logs include QUIC sockets |
| `firefox_sets_no_port_randomization_on_any_socket` (`phantom-profile`) | No call in the Firefox hook logs sets the option, and every UDP socket in them came from `ws2_32.dll` |

How to reproduce: read the cited files at the tags above, and run the listed
tests on Windows.

Limits:

- The Firefox hook scenarios open no HTTP/3 connection, so no log shows
  Firefox's QUIC socket; the claim for it rests on the source search.
- Opera's hook logs hold no QUIC socket; its DNS and IPv6 probe sockets set
  the option.
- No wire capture shows a browser's UDP source ports.

### HTTP/1.1 connection bound evidence

What is claimed: `chromium::v154_http1` and `firefox::v157_http1` allow 6
HTTP/1.1 connections to one origin and route, as those browsers do at the
profiled release tags and as Brave 154, Edge 154, and Opera 136 do, and the
client opens
connections up to the profile's bound. `chromium::v154_http1` stops reusing
a connection that has sat idle 300 s, as Chromium 154 does and as the Chrome
154, Edge 154, and Opera 136 hook logs show. Negotiated requests that select
HTTP/1.1 use the same bound and idle limit, and their TLS handshakes follow
the browsers' rule for a server whose protocol is not yet known.

Evidence: a capture of one page load cannot show a limit that the page never
reached, so the recipes rest on browser source at Chromium tag
`154.0.8037.58` and Firefox tag `FIREFOX_157_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_http1` | The normal socket pool allows six sockets per group, `g_max_sockets_per_group` (`net/socket/client_socket_pool_manager.cc:46-58`). A socket that carried a request is closed once it has sat idle `g_used_idle_socket_timeout_s = 300` seconds (`net/socket/client_socket_pool.cc:42`), checked when `RequestSocket` calls `CleanupIdleSockets` before it looks for a socket (`net/socket/transport_client_socket_pool.cc:242-263`, `:935-955`, `:969-1000`). A group is one scheme, host, and port within the pool of one proxy chain (`net/socket/client_socket_pool.h:130-153`, `net/socket/client_socket_pool_manager_impl.h:48`), which Phantom keys as one origin and route. Idle, connecting, and in-use sockets all occupy a slot (`net/socket/transport_client_socket_pool.h:356-363`), and a request takes the most recently used idle socket before it opens another (`net/socket/transport_client_socket_pool.cc:530-560`). |
| `firefox::v157_http1` | `network.http.max-persistent-connections-per-server` is 6 (`modules/libpref/init/all.js:1150-1153`). Firefox applies it to direct and CONNECT-tunneled connections and counts active connections together with those still connecting (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1202-1209`, `:1394-1430`; `netwerk/protocol/http/ConnectionEntry.cpp:289-297`). |

Differences from the browsers:

- Chromium also caps sockets at 256 per pool and 128 per proxy chain
  (`net/socket/client_socket_pool_manager.cc:37-44`, `:60-66`), and allows
  255 per group for WebSocket connections. Phantom does not model these caps.
- Firefox counts idle connections separately and reuses them before it opens
  another; Phantom counts them toward the bound. Firefox uses
  `network.http.max-persistent-connections-per-proxy`, 32, for plaintext
  requests forwarded through an HTTP proxy (`modules/libpref/init/all.js:1159-1162`),
  where the recipe keeps 6, and lets urgent-start requests exceed the limit
  by 3 (`modules/libpref/init/all.js:1155-1157`).
- Brave builds the same Chromium tag without changing the bound, and uses
  `chromium::v154_http1`. It keys each socket group by top-level site as
  well (`kPartitionConnectionsByNetworkIsolationKey`), so one origin under
  two top-level sites gets two groups; Phantom has one per origin and route
  ([Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes)).
- Edge's and Opera's network-stack source is not public. Their hook logs,
  and Chrome's, show ten concurrent requests to one origin holding at most
  six connections, so both use `chromium::v154_http1`
  ([Socket hook evidence](#socket-hook-evidence)).
- Chromium's cleanup on a request closes the expired idle sockets of every
  group in the proxy chain's pool (`net/socket/transport_client_socket_pool.cc:935-955`).
  Phantom closes only those of the request's own origin and route, so a
  server whose connection expired sees it close at its own origin's next
  request, not at the next request to any origin.
- Chromium closes an idle socket that never carried a request after
  `kPreconnectIntervalSec = 60` seconds
  (`net/socket/client_socket_pool_manager.cc:208-212`). Only a preconnect or
  a connect job whose request was served elsewhere leaves such a socket.
  Phantom pools a connection that carried no request only for a
  `TcpBackupConnection`, which no Chromium recipe uses, so the 60-second
  limit has nothing to apply to.
- Firefox reuses a connection only while it has been idle less than
  `network.http.keep-alive.timeout`, 115 s, or the response's `Keep-Alive`
  timeout (`modules/libpref/init/all.js:1136`;
  `netwerk/protocol/http/nsHttpConnection.cpp:965-983`, `:1120-1129`), and
  closes an expired idle connection on a timer, with no request pending
  (`nsHttpConnection.cpp:1009-1025`;
  `netwerk/protocol/http/nsHttpConnectionMgr.cpp:258-271`, `:2572-2625`,
  `:4075-4084`). `firefox::v157_http1` sets
  `Http1IdleTimeout::ClosedOnTimer` with 115 s, so one timer per client
  closes an idle connection 115 to 116 s after it became idle
  ([Firefox socket hook evidence](#firefox-socket-hook-evidence)). Phantom
  ignores the `Keep-Alive` field.

Negotiated requests: both browsers count a connection whose ALPN selected
HTTP/1.1 against the same per-group limit, and differ from each other only
while a handshake to a server known to speak HTTP/2 is in flight.

| Browser | Source behavior |
| --- | --- |
| Chromium 154 | Every HTTPS job registers with `SpdySessionPool::RequestSession` (`net/http/http_stream_factory_job.cc:749-775`). The first job for a session key is the blocking request (`net/spdy/spdy_session_pool.cc:269-303`). A later job is held only when `HttpServerProperties` says the server supports HTTP/2 (`net/http/http_stream_factory_job.cc:1417-1429`), until the blocking request finishes (`net/spdy/spdy_session_pool.cc:536-545`) or `kHTTP2ThrottleMs`, 300 ms, passes (`net/http/http_stream_factory_job.h:62`). Support is recorded when a connection negotiates HTTP/2 (`net/http/http_stream_factory_job.cc:1304-1306`). Without it, each job asks the socket pool for its own socket at once, up to the group limit. A job whose socket negotiated HTTP/2 after another session to the key appeared closes its socket and uses that session (`:1245-1280`), and a new session closes the group's idle sockets (`:1283-1287`). `HttpStreamPool`, which applies the same rule with the same 300 ms delay (`net/http/http_stream_pool_attempt_manager.cc:1597-1615`, `net/http/http_stream_pool_attempt_manager.h:100`), runs only with `kHappyEyeballsV3`, off by default (`net/base/features.cc:124`). |
| Firefox 157 | `nsHttpConnectionMgr::MakeNewConnection` opens no connection while `ConnectionEntry::RestrictConnections` holds (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1451-1461`). That requires `mUsingSpdy` and an attempt still negotiating, or an active connection whose ALPN result is pending or that can take another stream (`netwerk/protocol/http/ConnectionEntry.cpp:230-287`). `mUsingSpdy` starts false (`:38`) and is set only when a connection reports HTTP/2 (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1007-1024`), so a new entry opens connections in parallel up to the limit. |

Both browsers keep the fact once learned. Every writer of Chromium's flag
sets it to true (`net/http/http_stream_factory_job.cc:1304-1306`,
`net/http/http_stream_pool_attempt_manager.cc:823-825`), and so does every
writer of Firefox's (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1023`,
`:3987`). Chromium keys it by scheme, host, and port, plus the network
anonymization key when partitioning is on, but not by proxy
(`net/http/http_server_properties.cc:75-86`,
`net/http/http_stream_factory_job.cc:386-391`), and keeps the 500 most
recently used servers (`net/http/http_server_properties.h:97`,
`net/http/http_server_properties.cc:124-125`). Firefox keeps it on the
`ConnectionEntry`, whose key includes the proxy of a CONNECT tunnel or
SOCKS route (`netwerk/protocol/http/nsHttpConnectionInfo.cpp:211-231`).

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
| `connection_idle_past_the_idle_timeout_is_replaced_by_the_next_request` | With a 2-second `Http1IdleTimeout::CheckedOnRequest`, a connection idle less than that carries the next request; one idle longer is closed when the next request comes, and that request opens a new connection |

Unit tests in `crates/phantom/src/session/http1_pool/tests.rs` and
`http1_or_2_pool/tests.rs`, on a paused clock, check the 300-second edge:
`connection_idle_less_than_the_timeout_is_reused` (299 s),
`connection_idle_for_the_timeout_is_closed_and_replaced` (300 s, and the
peer sees the close),
`connection_without_a_timeout_is_reused_however_long_it_was_idle`, and
`idle_http1_connection_past_the_timeout_is_closed_instead_of_leased` for a
negotiated HTTP/1.1 connection. `profile_used_idle_timeout_reaches_both_http1_pools`
in `crates/phantom/src/session/tests.rs` checks that both recipes' values
reach the exact and negotiated pools, and that the Firefox recipe gives both
one 115-second prune timer. On a paused clock,
`session::prune_timer::tests` check that an idle connection sets the timer
for its whole seconds, at least one, that only a sooner expiry moves it, and
that firing prunes every pool key and sets it again for the soonest expiry
left; `the_prune_closes_a_connection_idle_for_the_limit` closes a connection
at 115 s and not 0.5 s before; and
`a_family_is_forgotten_only_when_every_runtime_key_of_its_origin_is_empty`
keeps an origin's address family while any runtime's key for it is in use.
On the wall clock with a one-second limit,
`the_timer_fires_after_the_runtime_that_set_it_is_dropped` and
`an_idle_connection_closes_after_the_runtime_that_set_the_timer_is_gone`
show that the timer, which runs on the deadline service, outlives the
runtime that set it and closes another runtime's idle connection, and
`a_slower_connection_stays_with_its_runtime_and_the_origin_state_is_shared`
shows that a slower connection counts only toward the key of the runtime
that opened it, while admission and the address family stay per origin.

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

- No wire capture confirms the limit or the reuse order; one hook log per
  browser confirms the limit for Chrome, Edge, and Opera.
- The source was read at one tag per browser, so field-trial changes would
  not be seen.

### Address cache evidence

What is claimed: `chromium::v154_dns_cache` and `firefox::v157_dns_cache`
keep as many names, and an answer and a failure for as long, as those
browsers do at the profiled release tags, and `chromium::v154_dns_cache` as
Brave 154, Edge 154, and Opera 136 do: an answer without a record TTL for
`ttl`, and an answer with one for that TTL or `min_record_ttl`, whichever is
longer. With a cache, the client makes one lookup per name it resolves
itself per answer lifetime, shares one lookup between concurrent
connections, keeps every resolved address as returned except its port, and
never resolves a proxy-resolved target. The shared lookup runs on the
starting runtime's blocking pool, which bounds the resolutions in flight,
and a connection on one Tokio runtime never waits on another runtime that
has stopped being driven.

`AddressResolver::system_nameservers`, with the `https-records` feature,
sends Phantom's own A and AAAA queries as Chromium's built-in DNS client
does, and reports each answer's record TTL. No recipe and no default turns
it on, so a client resolves through the operating system, which reports no
TTL, unless the caller passes that resolver to `ClientBuilder::dns_resolver`.

Evidence: a capture of one page load cannot show how long a browser reuses
an answer, so the recipes rest on browser source at Chromium tag
`154.0.8037.58` and Firefox tag `FIREFOX_157_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_dns_cache` | Each `URLRequestContext`, one per browser profile, creates its resolver with caching on (`net/url_request/url_request_context_builder.cc:363-382`), and its `ResolveContext` holds a `HostCache` of `kDefaultCacheSize = 1000` entries in builds with the built-in DNS client (`net/dns/resolve_context.cc:109-121`), which is every Blink build (`net/dns/BUILD.gn:9`). An answer from the system resolver is kept for `kCacheEntryTTLSeconds = 60` and a failure for `kNegativeCacheEntryTTLSeconds = 0` (`net/dns/host_resolver_manager_job.cc:54-58`, `:799-815`); a failure without a positive TTL is not cached (`net/dns/host_resolver_manager.cc:1284-1291`). An answer from the built-in DNS client takes the smallest TTL of its results (`net/dns/host_cache.cc:279-336`, `:729-740`), each the smallest TTL of its records or of an empty answer's SOA records (`net/dns/dns_response_result_extractor.cc:265-296`, `:330-354`), and is kept for that TTL or `kMinimumTTLSeconds`, which is `kCacheEntryTTLSeconds`, whichever is longer (`net/dns/host_resolver_manager_job.cc:61`, `:965-966`). A built-in lookup that fails, or finds no address, falls back to the system resolver (`net/dns/host_resolver_manager.cc:1415-1421`; `net/dns/host_resolver_manager_job.cc:932-946`), whose answer is then kept 60 s and whose failure is not kept. A full cache evicts the entry that expires soonest, stale entries first (`net/dns/host_cache.cc:886-916`, `:1289-1319`). A request joins the job already running for its key (`net/dns/host_resolver_manager.cc:993-1010`). |
| `firefox::v157_dns_cache` | `network.dnsCacheEntries` is 1600 outside nightly builds and `network.dnsCacheExpiration`, the lifetime of an answer without an OS TTL, is 60 seconds (`modules/libpref/init/StaticPrefList.yaml:15647-15661`; `netwerk/dns/nsHostResolver.cpp:1311-1318`). With `network.dns.get-ttl`, on in Windows builds (`:15663-15671`), Firefox looks a resolved name up again and reads the smallest record TTL from the operating system's cache with `DnsQuery_A` (`netwerk/dns/nsHostResolver.cpp:1625-1645`, `netwerk/dns/GetAddrInfo.cpp:150-175`), and that TTL replaces the lifetime without a bound (`netwerk/dns/nsHostResolver.cpp:1314-1315`). A failed lookup is kept for `NEGATIVE_RECORD_LIFETIME`, 60 seconds (`netwerk/dns/nsHostResolver.cpp:66-68`, `:1304-1309`). A request for a name being resolved is appended to that record's callbacks (`netwerk/dns/nsHostResolver.cpp:647-653`). |

Both browsers keep one cache per browser profile. Chromium keys an entry by
host, query type, flags, source, secure mode, target network, and network
anonymization key (`net/dns/host_cache.h:70-111`), but the key is empty
unless `kPartitionConnectionsByNetworkIsolationKey` is on, and it is off by
default (`net/dns/host_resolver_manager_request_impl.cc:51-56`,
`net/base/network_anonymization_key.cc:261-266`,
`net/base/features.cc:213-217`). Firefox keys a record by host, type, flags,
address family, private browsing, and origin-attributes suffix
(`netwerk/dns/nsHostRecord.h:77-93`). Phantom keys an entry by the
lowercased host name alone, one cache per client that its clones share; a
separately built client has its own cache, as it has its own cookies and
Alt-Svc state.

Differences from the browsers:

- Chromium's built-in DNS client is on by default on Windows, macOS, Linux,
  ChromeOS, and Android (`net/base/features.cc:42-48`), and Chrome, Edge,
  and Opera kept one answer past 120 s in their hook logs. A Phantom client
  resolves through the operating system unless the caller passes
  `AddressResolver::system_nameservers`, so by default its answers carry no
  TTL and are kept the 60 s of Chromium's system-resolver path. That
  resolver does not model the whole client; see
  [Chromium's built-in DNS client](#chromiums-built-in-dns-client) below.
- Firefox reads the record TTL only through `DnsQuery_A`, a Windows API
  that needs an FFI boundary Phantom does not have. Its hook logs show a
  1,757-second TTL kept, so connections opened 33, 68, and 98 s after the
  first needed no lookup
  ([Firefox socket hook evidence](#firefox-socket-hook-evidence)). A Phantom
  client with a Firefox profile resolves through the operating system and
  keeps each answer 60 s. Phantom's own DNS queries would report a TTL, but
  they leave from Phantom's process, where Firefox's lookups leave from the
  operating system's resolver.
- Firefox serves an expired answer for up to
  `network.dnsCacheExpirationGracePeriod`, 600 seconds, while it resolves
  the name again (`modules/libpref/init/StaticPrefList.yaml:15680-15685`,
  `netwerk/dns/nsHostResolver.cpp:1266-1284`). Phantom resolves an expired
  name before it connects.
- Both browsers flush the cache when the network changes
  (`net/dns/host_resolver_manager.cc:1803-1816`, `:1912-1925`;
  `netwerk/dns/nsDNSService2.cpp:1366-1383`,
  `netwerk/dns/nsHostResolver.cpp:219-256`). Phantom does not watch the
  network; `Client::clear_dns_cache` is the caller's equivalent.
- Firefox evicts from an LRU queue; Phantom, like Chromium, evicts the entry
  that expires soonest.
- Brave builds the same Chromium tag without changing these values, and
  uses `chromium::v154_dns_cache`. With
  `kPartitionConnectionsByNetworkIsolationKey` on, its cache key carries the
  top-level site, so Brave resolves a name again under another site
  ([Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes)).
- Edge's and Opera's network-stack source is not public. Their hook logs,
  and Chrome's, show system-resolver lookups of one name 60 to 70 s apart
  for fetches 10 s apart, so both use `chromium::v154_dns_cache`. With the
  built-in DNS client on, all three sent one query in 120 s, keeping the
  record's TTL ([Socket hook evidence](#socket-hook-evidence)).

Unit tests in `crates/phantom-net/src/address_cache/tests.rs`:

| Test | What it proves |
| --- | --- |
| `repeated_lookups_within_the_ttl_resolve_once` | A second lookup, on another port, uses the stored answer |
| `an_answer_with_a_record_ttl_is_kept_for_that_ttl_instead_of_the_ttl`, `a_record_ttl_below_the_minimum_is_kept_for_the_minimum` | An answer with a record TTL expires after that TTL, not after `ttl`, and is kept at least `min_record_ttl` |
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
`clones_share_the_cache_and_separate_clients_do_not`, and
`clear_dns_cache_resolves_the_host_again`.
`profile_dns_cache_reaches_every_connector` and
`builder_settings_replace_or_disable_the_profiles` check the wiring.

How to reproduce: read the cited files at the tags above, and run the listed
tests.

Limits:

- Only one hook log per browser counts DNS lookups, for one name; the
  failure lifetime and the 1,000-name bound rest on
  source alone.
- The source was read at one tag per browser, so field-trial changes would
  not be seen.

### Chromium's built-in DNS client

What is claimed: `AddressResolver::system_nameservers` resolves a name as
Chromium 154's built-in DNS client does in the steps below, and reports
the record TTL the address cache honors.

Evidence: Chromium source at tag `154.0.8037.58`, and the `lookups` hook
logs of Chrome 154, Edge 154, and Opera 136
([Socket hook evidence](#socket-hook-evidence)): with the default
resolver each browser sent one HTTPS query and then one A query, in the
same millisecond and each from its own socket, for the name in 120 s of
fetches, and no AAAA query, because the hook host has no IPv6 route.

| Step | Chromium source | Phantom |
| --- | --- | --- |
| `localhost` and names under it | `::1` and `127.0.0.1` without a lookup (`net/dns/host_resolver_manager.cc:334-344`, `:1260-1282`) | The same |
| Names under `local` | The system resolver (`:1459-1504`) | The same |
| The hosts file | Answers before DNS, IPv6 first (`:1169-1258`; `net/dns/host_cache.cc:306-318`) | The same, from the file read when the resolver is built; Chromium rereads it when it changes |
| AAAA | Only when a UDP socket connected to `2001:4860:4860::8888` gets a source address that is neither link-local nor Teredo, a result kept 1 s (`net/dns/host_resolver_manager.cc:155-160`, `:820-841`, `:1569-1694`); the probe socket sets `SO_RANDOMIZE_PORT` before its `connect` | The same probe, on a socket bound to `[::]:0` with the profile's `UdpSettings`, then connected; it sends nothing |
| Query order | HTTPS first, with `kPrioritizeHttpsResourceRecord` on by default, then AAAA, then A (`net/dns/host_resolver_dns_task.cc:39`, `:393-433`) | AAAA, then A once the AAAA datagram has left. The HTTPS query belongs to `ClientBuilder::https_record_discovery`, which spawns it as its own task, so its order against the address queries is not modeled |
| Query shape | One question, recursion desired, no OPT record (`net/dns/dns_transaction.cc:656`, `:1159`) | The same, as for HTTPS records |
| Answer order | IPv6 results before IPv4 (`net/dns/host_cache.cc:306-318`), then the address sorter | IPv6 then IPv4, each in response order, without a sort |
| Failure | The system resolver answers instead (`net/dns/host_resolver_manager.cc:1415-1421`), and after 16 lookups in a row that it answered, the built-in client stops until the DNS configuration changes (`net/dns/host_resolver_manager_job.cc:787-792`, `net/dns/host_resolver_manager.cc:1869-1880`, `net/dns/dns_client.h:67`, `net/dns/dns_client.cc:245-256`, `:385-391`) | The same, but the stop is permanent for the resolver, which never reads the configuration again |
| System resolver | Without a global IPv6 route, `getaddrinfo` for IPv4 only, and for both families again when every IPv4 address is a loopback address (`net/dns/host_resolver_system_task.cc:539-549`, `:628-645`) | `getaddrinfo` for both families, keeping the same addresses Chromium would get |
| TTL | The smallest TTL of the results, at least 60 s (see the table above) | The smallest TTL of the A, AAAA, and CNAME records and of an empty answer's SOA record; the cache applies `min_record_ttl` |

Phantom-net tests in `crates/phantom-net/src/dns/address_lookup/tests.rs`
run against a loopback DNS server, with the probe's answer and the system
resolver fixed so no test opens a probe socket or needs the network:

| Test | What it proves |
| --- | --- |
| `an_answer_lists_ipv6_first_and_carries_the_smallest_record_ttl` | AAAA is sent before A, each a single plain recursive question; IPv6 addresses come first; the answer's TTL is the smaller family's |
| `aaaa_is_sent_before_a_on_every_cold_lookup` | On a four-thread runtime, 50 lookups through new resolvers each reach the server AAAA first |
| `without_a_global_ipv6_route_only_a_is_queried`, `without_an_ipv6_route_the_system_resolver_answers_ipv4` | No AAAA query without an IPv6 route, and the system resolver's IPv4 addresses only, or all of them when IPv4 gives only loopback |
| `an_empty_family_counts_its_soa_ttl` | A NODATA answer's SOA record TTL, not its MINIMUM field, lowers the answer's TTL |
| `localhost_names_resolve_to_loopback_without_a_query`, `single_label_and_local_names_go_to_the_system_resolver`, `the_hosts_file_answers_without_a_query` | The local steps, with no query |
| `a_failed_or_empty_lookup_falls_back_to_the_system_resolver`, `sixteen_fallbacks_in_a_row_stop_the_dns_queries` | The fallback, and the stop after 16 fallbacks |
| `the_address_cache_keeps_a_dns_answer_for_its_record_ttl`, `the_address_cache_raises_a_short_record_ttl_to_the_minimum` | Through the cache: a 1-second record TTL keeps the answer 1 s although `ttl` keeps nothing, and `chromium::v154_dns_cache` keeps a 0-second record TTL 60 s |

Differences from the browser:

- Nameservers come from hickory's reading of the host configuration: on
  Windows, the DNS servers of every adapter that is up. Chromium takes
  those of the first such adapter that is not a loopback adapter, and
  falls back to the system resolver for every name when it finds a VPN
  adapter, a name resolution policy, a DNS proxy, or adapters with
  different servers (`net/dns/dns_config_service_win.cc:411-502`). On
  macOS and Linux it reads the configuration with its own rules. Phantom
  models none of these, so on such a host it queries servers Chrome would
  not.
- A name without a dot goes to the system resolver; Chromium queries it
  with the host's search suffixes.
- Retries follow hickory 0.26, as for HTTPS record queries: within each of
  two attempts, the query is sent again, from a new socket with the same
  message ID, after 1.2 times the server's smoothed round trip or 333 ms,
  whichever is longer, up to three sends in a 5-second timeout
  (`hickory-net-0.26.3/src/udp/udp_client_stream.rs:75-93`, `:456-486`;
  `hickory-resolver-0.26.3/src/name_server_pool.rs:365-369`). Chromium
  sends each attempt with a new message ID, after a fallback period that
  begins at 1 s and adapts to measured round trips
  (`net/dns/dns_transaction.cc:652`, `net/dns/dns_config.h:23`). Without
  loss, both send one query per type.
- Chromium folds the HTTPS record's TTL into the same entry; Phantom keeps
  HTTPS records in their own cache.
- Chromium sorts IPv6 and IPv4 addresses with the platform's address
  sorter; Phantom keeps IPv6 first, each family in response order.
- Chromium resolves a name again when the network or the DNS configuration
  changes; Phantom reads both once.

How to reproduce: read the cited files at the tag above, and run
`cargo test -p phantom-net --features https-records dns::address_lookup`.

Limits:

- No capture shows Phantom's queries beside a browser's on one network; the
  shape rests on the loopback tests and the HTTPS query evidence
  ([HTTPS DNS record evidence](#https-dns-record-evidence)).
- The hook host has no IPv6 route, so no log shows a browser's AAAA query
  or its order.

### Socket hook evidence

What is claimed: on Windows 11, Edge 154.0.4258.48 and Opera 136.0.6008.52
set the TCP and UDP options, race addresses, bound HTTP/1.1 connections to
one origin, and keep system-resolver answers as `chromium::v154_tcp`,
`chromium::v154_udp`, `chromium::v154_http1`, and `chromium::v154_dns_cache`
do, and as Chrome 154.0.8037.58 does. Edge and Opera profiles therefore use
those recipes.

Evidence: hook logs, a class of evidence distinct from wire captures. A wire
capture records what reached a loopback listener; a hook log records the
calls a browser's own network service process made into Winsock and the
Windows resolver, which no listener can see. Socket options, an address
attempt that failed, and a lookup a cache answered appear only there. The
logs are retained under
[`fixtures/socket-hooks/`](../../fixtures/socket-hooks/), one
`hooks-<scenario>.txt` per scenario and browser, written by
[`socket_hooks.py`](../../scripts/capture/README.md#socket-hooks). That tool
spawns the browser under Frida 17.9.10 with child gating, loads the agent
`scripts/capture/socket_hooks.js` into the network service process before it
runs, and serves the page from a loopback HTTP/1.1 origin that also records
every connection it accepts. Each log names the agent by its SHA-256, and
`test_socket_hooks.py` fails when the agent in the repository differs.

On 2026-10-02 the three browsers ran all seven scenarios at once, one fresh
headless profile per scenario, in 14 minutes 46 seconds of wall clock, most
of it the 600-second `idle` page. Chrome 154 is the control: its recipes come
from Chromium source, so the same hooks show whether the method reproduces
them. The calls came from `chrome.dll`, `msedge.dll`, and
`opera_browser.dll`, the browsers' own network code.

| Behavior | Chrome 154 | Edge 154 | Opera 136 | Recipe |
| --- | --- | --- | --- | --- |
| Options on every TCP socket to the origin, before `connect` (`single` and `parallel`: 13 sockets per browser) | `TCP_NODELAY` 1; `SIO_KEEPALIVE_VALS` on, 45,000 ms, 45,000 ms; `SO_RANDOMIZE_PORT` 1; to loopback, `SIO_TCP_INITIAL_RTO` with no SYN retransmissions | The same | The same without `SIO_TCP_INITIAL_RTO` | `chromium::v154_tcp`: `TCP_NODELAY`, keepalive 45 s and 45 s, then `SO_RANDOMIZE_PORT` from build 22621; no initial RTO |
| Most connections open to one origin for 10 concurrent slow requests (`parallel`) | 6 | 6 | 6 | `chromium::v154_http1`: 6 |
| IPv4 attempt after a pending `[::1]` attempt to `localhost` (`happy-eyeballs-slow`, two connect jobs) | 304 and 312 ms | 300 and 302 ms | 302 and 315 ms | 300 ms fallback delay |
| IPv4 attempt after a refused `[::1]` attempt (`happy-eyeballs`) | 3 ms, after the failure | 3 ms, after the failure | 301 and 301 ms: the refusal takes Windows' SYN retransmissions | The other family after a failure; 300 ms otherwise |
| System-resolver lookups of `127.0.0.1.nip.io` for fetches 10 s apart for 120 s (`lookups-system`) | At 0, 60, and 120 s | At 0, 60, and 120 s | At 0, 60, and 120 s | `chromium::v154_dns_cache`: an answer kept 60 s |
| Lookups with the default built-in DNS client (`lookups`) | One HTTPS and then one A query at 0 s, each from its own socket; no AAAA query | The same | The same | `chromium::v154_dns_cache`: an answer kept for its record TTL, at least 60 s, when the resolver reports one, which only `AddressResolver::system_nameservers` does |
| A used connection idle 290 s, then 310 s (`idle`) | Reused, then closed by the next request, which opened another | The same | The same | `chromium::v154_http1`: reused under 300 s idle, replaced at 300 s or more |

Each system-resolver lookup was two `getaddrinfo` calls from the browser
module within a few milliseconds; the calls those make inside `ws2_32.dll`
and `dnsapi.dll` are not counted. A lookup comes at the first fetch after
the answer expires, so an answer that expires right after a fetch is renewed
up to 10 s late; the test accepts gaps of 60 to 70 s. The
`happy-eyeballs` scenarios load the page from `127.0.0.1` and fetch
`http://localhost:<port>/done` on a second port where only `127.0.0.1`
listens, so the browser's startup connections to the page do not mix with
the attempts measured; each browser ran two connect jobs for that fetch.
In `happy-eyeballs-slow` the agent made the browser's `SIO_TCP_INITIAL_RTO`
call fail on IPv6 sockets, so the refused `[::1]` attempt stayed pending,
and the log names that change in `hook_intervention`.

These results reproduce Chromium source at the tags the recipes cite, which
is what validates the method on Chrome:

- `TCP_NODELAY` and the 45-second keepalive come from
  `SetDefaultOptionsForClient` (`net/socket/tcp_socket_win.cc:50`,
  `:815-818` at `154.0.8037.58`), and the same lines are at
  `152.0.7977.130`, the Chromium version Opera 136 reports.
- `SO_RANDOMIZE_PORT` comes from `kTcpPortRandomizationWin`, enabled by
  default with a minimum of `WIN11_22H2`, build 22621, and is set right
  before `connect`, ignoring a failure
  (`net/socket/tcp_socket_win.cc:105-110`, `:1046-1053`,
  `net/base/features.cc:308-314`, `base/win/windows_version.cc:386-404` at
  `154.0.8037.58`; the same `tcp_socket_win.cc` lines and
  `net/base/features.cc:298-304` at `152.0.7977.130`). The hook host, build
  26200, is past that minimum.
- `SIO_TCP_INITIAL_RTO` comes from `kEnableWindowsTcpLoopbackFastFail`, on by
  default at `154.0.8037.58` (`net/socket/tcp_socket_win.cc:1055-1072`,
  `net/base/features.cc:1058-1059`) and absent at `152.0.7977.130`. It
  applies only to loopback peers, so it changes nothing a remote server
  sees.
- The used-idle socket timeout is 300 s (`net/socket/client_socket_pool.cc:42`
  at both tags), and the pool checks it when a request arrives
  (`net/socket/transport_client_socket_pool.cc:263`, `:969-1000` at
  `154.0.8037.58`).
- `g_max_sockets_per_group` of 6, `kCacheEntryTTLSeconds = 60`, and
  `kIPv6FallbackTime` of 300 ms have the values the recipes cite at
  `152.0.7977.130` too (`net/socket/client_socket_pool_manager.cc:54-56`,
  `net/dns/host_resolver_manager_job.cc:54`,
  `net/socket/tcp_connect_job.h:85`).

Differences from the browsers:

- Phantom does not set `SIO_TCP_INITIAL_RTO`, which changes only connects
  to loopback peers.
- `chromium::v154_tcp` sets `SO_RANDOMIZE_PORT` through `phantom-net`'s
  Windows FFI module, as the last option before the socket is bound or
  connects ([Design](design.md#windows-port-randomization-audit)). With it,
  Windows picks each connection's local port at random instead of in
  sequence, which a server sees in the source ports of successive
  connections. Chromium sets it right before `connect` and ignores a
  failure, which Windows returns on a socket it has bound to a local
  address. Phantom sets it before binding, so its source-bound connections
  get random ports where Chromium's would not, and it fails a connection
  attempt that Windows rejects the option for.
- The logs show `SO_RANDOMIZE_PORT` on every UDP socket the browsers'
  network code opened, before `connect`: DNS sockets, the IPv6 reachability
  probe, and, for Chrome and Edge, QUIC sockets. `chromium::v154_udp` sets
  it on Phantom's QUIC sockets
  ([UDP socket option evidence](#udp-socket-option-evidence)).
- The browsers resolve with their built-in DNS client by default and keep an
  answer for its record TTL. A Phantom client resolves through the
  operating system, and keeps an answer for the 60 s the browsers use on
  that path, unless the caller passes `AddressResolver::system_nameservers`
  ([Chromium's built-in DNS client](#chromiums-built-in-dns-client)).

Tests in `crates/phantom-profile/src/chromium/hook_tests.rs` read the
retained logs of all three browsers:

| Test | What it checks |
| --- | --- |
| `chromium_family_sockets_set_the_chromium_tcp_options` | Every origin socket's options, in call order, are the recipe's `TCP_NODELAY`, keepalive, and `SO_RANDOMIZE_PORT`, whose minimum build the log host meets, then, for Chromium 154, `SIO_TCP_INITIAL_RTO` |
| `chromium_family_opens_the_http1_bound_to_one_origin` | The origin never had more than the recipe's 6 connections open |
| `chromium_family_starts_ipv4_after_the_racing_delay` | Each IPv4 attempt after a pending IPv6 one starts between 300 and 360 ms later |
| `chromium_154_tries_ipv4_right_after_a_failed_ipv6_attempt` | Chrome and Edge try IPv4 within 150 ms of a refused `[::1]` attempt |
| `chromium_family_system_resolver_keeps_an_answer_for_the_cache_ttl` | Successive system-resolver lookups are at least the recipe's 60 s and less than 70 s apart |
| `chromium_family_built_in_resolver_keeps_an_answer_for_its_record_ttl` | The built-in client sent one HTTPS query and, at most 1 ms later, one A query in 120 s, and no AAAA query; the recipe's `min_record_ttl` is its 60 s `ttl` |
| `chromium_family_udp_sockets_randomize_their_port_before_connecting` | Every UDP socket the browser's network code opened set `SO_RANDOMIZE_PORT` before `connect`, after only the `IPV6_V6ONLY` of an IPv6 socket, as `chromium::v154_udp` asks; the Chrome and Edge logs include QUIC sockets |
| `chromium_family_replaces_a_connection_idle_past_300_s_on_the_next_request` | The connection idle 290 s carried the next request; the one idle 310 s, past the recipe's `idle_timeout`, closed as the replacement opened |

How to reproduce: run `socket_hooks.py --scenario all` once per browser with
the command in the
[capture README](../../scripts/capture/README.md#socket-hooks), then the
tests above.

Limits:

- One run of each scenario per browser, on one Windows 11 host. No macOS,
  Linux, or Android hook log exists, and the logs back only the Windows
  values: on macOS Chromium sets only the keepalive idle time.
- The hooks see calls into `ws2_32.dll` and `dnsapi.dll`. A browser that set
  an option through another interface, such as a direct `NtDeviceIoControlFile`
  call, would not show it.
- Every run used loopback origins and the `127.0.0.1.nip.io` test name; the
  address cache's 1,000-name bound and failure caching were not exercised.
- The `happy-eyeballs-slow` delays rest on a hook that changes what the
  browser asked of Windows; the unchanged `happy-eyeballs` runs show the
  same 300 ms only for Opera.
- Field trials can change these values for some users of branded builds;
  the captures ran with each browser's default configuration on a fresh
  profile.

### Firefox socket hook evidence

What is claimed: on Windows 11, Firefox 157.0 sets `TCP_NODELAY` and a
524,288-byte `SO_SNDBUF` before it connects, changes keepalive over each
connection's life as `firefox::v157_tcp`'s `TcpKeepaliveSchedule` does, and
opens an IPv4 backup attempt 250 ms after a first attempt that has not
connected, whose slower connection it keeps, as `firefox::v157_tcp` does,
and closes an idle connection on a 115-second timer, as
`firefox::v157_http1` does.

Evidence: hook logs, the evidence class of
[Socket hook evidence](#socket-hook-evidence), retained under
[`fixtures/socket-hooks/firefox/`](../../fixtures/socket-hooks/firefox/) and
written by
[`firefox_socket_hooks.py`](../../scripts/capture/README.md#firefox-socket-hooks).
Firefox opens its HTTP connections in its parent process, so the tool loads
`socket_hooks.js`, unchanged, and the extension
`scripts/capture/firefox_socket_hooks.js` into that process. It attaches after
the first page request rather than at spawn: Firefox's launcher process marks
itself failed when it starts under Frida, and Firefox then runs without it.
The page waits until the hooks report ready before it reaches the measured
origin, `127.0.0.1.nip.io` on a second loopback port. Firefox's own MOZ_LOG
(`nsSocketTransport`, `nsHttp`, `nsHostResolver`, `GetAddrInfo`) ran beside
the hooks, and each log keeps the lines about the measured origin as a
cross-check. Each log names the agent, the extension, the tool, and the
decoders it reuses by their SHA-256, and `test_firefox_socket_hooks.py` fails
when any differs.

On 2026-10-02 Firefox 157.0 (build 20260924084938) ran each scenario on a
fresh headless profile with Frida 17.9.10: `h2` and `websocket` twice,
`backup` five times, and `http1-long`, `http1-idle`, and `dns-cache` once,
in 10 minutes of wall clock. The socket options came from `nss3.dll` (NSPR,
through `WSOCK32.dll`) and the keepalive calls from `xul.dll`.

| Behavior | Firefox 157.0 | `firefox::v157_tcp` |
| --- | --- | --- |
| Options before `connect`, on all 36 sockets to the origin | `TCP_NODELAY` 1; `SO_SNDBUF` 524,288; `SO_LINGER` on, 0 s; no `SO_RANDOMIZE_PORT` | `TCP_NODELAY`, `SO_SNDBUF` 524,288; no `SO_LINGER` or `SO_RANDOMIZE_PORT` |
| Keepalive on a connection opened for a request | Within 10 ms of `connect`: `SIO_KEEPALIVE_VALS` off, then on with 10,000 ms and 1,000 ms, then `SO_KEEPALIVE` 1. MOZ_LOG: `idle time[10s] retry interval[1s] packet count[10]` | 10 s idle and a 1 s interval once the socket connects |
| A response that took 85 s (`http1-long`) | `SIO_KEEPALIVE_VALS` on with 600,000 ms and 1,000 ms, 72.04 s after the first | The switch 72 s after the request |
| A pooled connection with requests at 0 and 99 s (`http1-idle`) | Stayed at 10 s; the second request made no call (MOZ_LOG: `already 10s`). Firefox closed it 115.5 s after the second response with `shutdown(SD_BOTH)`, and the origin read a FIN | Stays short-lived; `firefox::v157_http1`'s timer closes it 115 to 116 s after the response, with a FIN |
| HTTP/2 (`h2`) | 2 to 7 ms after keepalive went on: `SIO_KEEPALIVE_VALS` off and `SO_KEEPALIVE` 0 | Off once ALPN selects `h2` |
| WebSocket (`websocket`) | 600,000 ms 2 and 7 ms after `connect`, as the 101 arrived | Long-lived at the upgrade |
| `[::1]` refused slowly, `127.0.0.1` listening (`backup`, five runs) | `127.0.0.1` attempt 254 to 260 ms after the `[::1]` one; `[::1]` refused (10061) 2,040 to 2,046 ms in, then the first attempt tried `127.0.0.1` | An IPv4 backup 250 ms in; the first attempt moves on after the refusal |
| The first attempt's `127.0.0.1` connection | Kept, carried a request 2.9 s later, and got a 2,000 ms interval, its setup time | Kept idle with no keepalive until a request, then the interval of its setup time |
| Later connections to the origin, also after it closed them all | `127.0.0.1` alone; MOZ_LOG `SetupDnsFlags flags=8224` (IPv6 disabled) | IPv4 alone while the pool entry remembers the family |
| `getaddrinfo` hints | `AI_CANONNAME`, `AF_UNSPEC` or `AF_INET`, no `AI_ADDRCONFIG` | The operating system's resolver, without `AI_ADDRCONFIG` |
| Lookups for connections opened 0, 33, 68, and 98 s in (`dns-cache`) | Lookups in the first 31 ms only; `DnsQuery_A` read a TTL of 1,757 s and MOZ_LOG cached the answer that long | The record TTL, with no lower bound, for an answer that carries one; Phantom's system lookups carry none, so 60 s |

The `backup` scenario makes `getaddrinfo` resolve `localhost`, which Windows
answers with `[::1]` then `127.0.0.1`, in place of `127.0.0.1.nip.io`; the
log names the change in `hook_intervention`. Without the rewrite the name
has only an IPv4 address. A refused loopback connect takes about two seconds
on Windows, so the `[::1]` attempt stays pending past the backup timer
without any further change. The scenario's later steps fetch three `/slow`
requests at once while the origin still had both connections, then one more
after the origin closed every connection.

These results reproduce Firefox source at `FIREFOX_157_0_RELEASE`, cited in
[TCP socket option evidence](#tcp-socket-option-evidence). The switch time
is the source's `60 + 10 × 1 - 60 % 10 + 2` seconds for Windows' fixed
count of 10 probes and a one-second interval, and the kept connection's
two-second interval is its setup time in whole seconds
(`netwerk/protocol/http/nsHttpConnection.cpp:2146`,
`netwerk/protocol/http/DnsAndConnectSocket.cpp:941`, `:1134-1138`).

Differences from the browser:

- Firefox remembers the address family of an origin's connections and
  resolves only that family for later ones, until its connection entry is
  removed, which happens at a prune after the origin has no connection
  (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:2614-2618`). A trial run
  before the retained ones, with the later request 2 s after the origin
  closed every connection, tried `[::1]` again, so a prune fell in that
  window there. Phantom prunes on the client's idle timer, which noticed
  nothing of the origin's close and fires 115 s after the last connection
  went idle, so in the scenario it keeps the family past the later request;
  see [TCP socket option evidence](#tcp-socket-option-evidence) for the
  remaining differences.
- The `backup` scenario is plaintext HTTP/1.1. No log shows a slower
  connection's TLS handshake or a second HTTP/2 connection; Phantom follows
  the source cited in
  [TCP socket option evidence](#tcp-socket-option-evidence) there.
- `SO_LINGER` `{1, 0}` makes a bare `closesocket` abortive, but Firefox
  shuts the socket down with `SD_BOTH` first
  (`netwerk/base/ShutdownLayer.cpp:33`). The one close Firefox made while
  the origin listened, in `http1-idle`, reached the origin as a FIN, as a
  close from Phantom does; every other close in the logs was the origin's
  own or the end of the run. A loopback check on the capture host, which is
  not retained, gave the same FIN for a client that shuts down and closes
  with `{1, 0}`.
- Firefox's timer closes an idle connection from its own last read;
  Phantom's counts from the moment the connection returned to the pool
  ([HTTP/1.1 connection bound evidence](#http11-connection-bound-evidence)).
- Firefox keeps an answer for its record TTL on Windows; see
  [Address cache evidence](#address-cache-evidence).

Tests in `crates/phantom-profile/src/firefox/hook_tests.rs` read the
retained logs:

| Test | What it checks |
| --- | --- |
| `firefox_sockets_set_nodelay_and_the_send_buffer_before_connecting` | Every origin socket set the recipe's `TCP_NODELAY` and send buffer, then `SO_LINGER` `{1, 0}`, before connecting, and nothing else, so no `SO_RANDOMIZE_PORT`, which the recipe leaves unset |
| `firefox_starts_short_lived_keepalive_as_a_connection_opens` | Every connection that carried a request got the recipe's short-lived idle time and one-second interval within 50 ms of connecting |
| `firefox_switches_an_active_connection_to_long_lived_keepalive` | The 85 s response switched to the recipe's long-lived idle time between 72 and 72.5 s after the first keepalive call, the schedule's switch time |
| `firefox_keeps_an_idle_pooled_connection_short_lived` | The pooled connection carried two requests and never left the short-lived idle time |
| `firefox_closes_an_idle_connection_on_its_115_second_timer` | The recipe's `ClosedOnTimer` limit is 115 s, and the origin read a FIN 115 to 116 s after the last response |
| `firefox_turns_keepalive_off_after_http2` | Each HTTP/2 connection turned keepalive off within 100 ms and never on again |
| `firefox_switches_a_websocket_connection_to_long_lived_at_once` | Each WebSocket connection got the long-lived idle time within 100 ms |
| `firefox_starts_an_ipv4_backup_250_ms_after_a_slow_first_attempt` | In all five runs the IPv4 attempt started 250 to 310 ms after the `[::1]` one, the recipe's 250 ms delay, and the first attempt moved to `127.0.0.1` when `[::1]` was refused |
| `firefox_keeps_the_slower_connection_with_its_setup_time_interval` | The slower connection set no keepalive until it carried a later request, then a two-second interval |
| `firefox_remembers_the_address_family_of_an_origin` | Every later connection went to `127.0.0.1` alone; the recipe's backup timeout for a known family is 5 s |
| `firefox_sets_no_port_randomization_on_any_socket` | No call sets `SO_RANDOMIZE_PORT`, and every UDP socket came from `ws2_32.dll`, not Firefox's code; no scenario uses HTTP/3 |
| `firefox_resolves_without_ai_addrconfig` | Every `getaddrinfo` call passed `AI_CANONNAME` alone |
| `firefox_keeps_an_answer_for_its_record_ttl` | No lookup after the first second, and a TTL longer than the 95 s of fetches; the recipe's `min_record_ttl` is zero, and its `ttl` 60 s for an answer without a TTL |

How to reproduce: run `firefox_socket_hooks.py` with the command in the
[capture README](../../scripts/capture/README.md#firefox-socket-hooks) for
each scenario, then the tests above.

Limits:

- One Windows 11 host and one to five runs per scenario. No macOS or Linux
  log exists; there Firefox sets keepalive differently
  ([TCP socket option evidence](#tcp-socket-option-evidence)).
- The hooks attach after Firefox has started, so they miss the sockets of
  its first page load; every measured connection opened after they attached.
- The `backup` timing rests on a rewritten lookup answer and on Windows'
  slow refusal of a loopback connect; no remote dual-stack host was used.
- No packet capture shows the keepalive probes themselves; the logs show the
  values Firefox gave Windows.
- Phantom applies a keepalive change before the connection's next read or
  write. Firefox applies it when the event happens, so a Phantom
  connection that nobody reads or writes, such as an upgraded stream before
  its first frame, takes it later.

### Plaintext origin trust evidence

What is claimed: for a URL that is not
[potentially trustworthy](../reference/glossary.md#potentially-trustworthy),
such as `http://origin.phantom.test/`, the built-in request templates send
the fields Chrome 154, Edge 154, and Firefox 157 send there, in the same
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

| Behavior | Chromium `154.0.8037.58` | Firefox `FIREFOX_157_0_RELEASE` |
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

After the host updated Opera, Edge, and Brave on 2026-10-02, one
`run_matrix.py` manifest with a `snapshot` capture of Opera 136.0.6008.52,
Edge 154.0.4258.48, and Brave 154.1.96.60, `repeat` 3, ran in 4.0 seconds of
wall clock. Brave matched its retained fixtures on every compared layer.
Edge differed only in the full version its client hints report. Opera
differed from the retained Opera 135 fixtures in its trust-anchor IDs,
signature-algorithm GREASE, and client hints; see
[Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes) and
[Edge 154 recipes](#edge-154-recipes) for what each update changed.

After the host updated Chrome to 154.0.8037.97 the same day, a `snapshot`
capture of it, `repeat` 3, ran beside its client-hint capture in one
manifest. Each run took 1.5 to 9.9 seconds, used HTTP/3, and differed from
the 154.0.8037.58 fixtures only in the full version its client hints report;
see [Chrome 154 recipes](#chrome-154-recipes). These are the only retained
Chromium snapshots, under
`fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/`.

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
| Raw Firefox HTTP/2 startup bytes | The Firefox 154 `client-startup.txt` replay compared startup frames byte for byte | `firefox::v157_http2`'s SETTINGS and connection window rest on the HTTP/2 session captures of the WebSocket fixture set. No Firefox 157 equivalent exists: the raw startup tool needs WebDriver certificate trust, and geckodriver is not installed on the capture host |
| Cross-platform transport parity | The Chrome 152 and Firefox 154 macOS and Windows capture pairs showed that those transport layers did not depend on the host platform | No current recipe has a second platform, so platform independence is not claimed for any of them |
| Chrome for Testing field-trial comparison | The retained `client-hello-field-trial-config.txt` kept the testing configuration's differences visible; it went with the Chrome 152 fixtures | No Chrome for Testing build of 154.0.8037.58 is published, so build flavor is not isolated at the current version |

## Feature evidence

These sections cover individual client features. Most rest on loopback tests
of Phantom's own contract. Where a section also has browser captures, it says
so and states what they cover.

### ALPS `ACCEPT_CH` restart evidence

What is claimed: the Chromium-family recipes fix a request's client hints
when its field lists are built, on HTTP/1.1, HTTP/2, and HTTP/3 alike. On
HTTP/2 and HTTP/3, when the connection's ALPS `ACCEPT_CH` entry for the
origin names a hint a navigation lacks and the origin has not requested, the
request is not written; it starts again with the hints it lacked after
`Accept` and before `Sec-Fetch-Site`, as Chromium 154 restarts a navigation.
A `fetch` goes out as built.

Evidence: Chromium source at tag `154.0.8037.58`, and two captures of
headless Chrome 154.0.8037.97 on Windows 11 (10.0.26200), retained as
[`alps-accept-ch.txt`](../../fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/alps-accept-ch.txt)
and
[`alps-accept-ch-reordered.txt`](../../fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/alps-accept-ch-reordered.txt).
[`alps_accept_ch.py`](../../scripts/capture/README.md#alps-accept_ch-restart)
serves the page over HTTP/2 from a BoringSSL origin whose ALPS carries an
`ACCEPT_CH` frame for its own origin, and reads Chrome's NetLog. The page
fetches `/fetch` and then `/done`.

- With `ACCEPT_CH` naming `Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version`, the
  navigation's first URL request ended at
  `URL_REQUEST_DELEGATE_CONNECTED` with `ERR_ABORTED` (-3) and sent no
  headers. A second URL request for `/` sent them on the same connection,
  and the server received one request for `/`, carrying both hints right
  after `accept`: `... user-agent, accept, sec-ch-ua-arch,
  sec-ch-ua-platform-version, sec-fetch-site ...`.
- With the frame naming `Sec-CH-UA-Platform-Version, Sec-CH-UA-Model,
  Sec-CH-UA-Arch`, the restarted request carried `sec-ch-ua-arch,
  sec-ch-ua-platform-version, sec-ch-ua-model` after `accept`: Chrome's own
  hint order, which the Chromium client-hint recipes list in the same order,
  not the frame's.
- The `fetch` requests on the same connection went out once, without the
  hints, in both runs.

Phantom's restart matches: one request on the wire, the hints the
navigation lacked right after `Accept` in the profile's order, and no change
to a `fetch`.

| Step | Chromium source |
| --- | --- |
| Hints are request fields, set before a connection is chosen | The check compares the entry with the request's own fields, `url_request_->extra_request_headers()` (`services/network/url_loader.cc` lines 939-941) |
| The check runs once the request has a stream, before it is written | `URLLoader::ProcessAcceptCHFrameOnConnected` passes the connection's entry and the request's fields to `AcceptCHFrameInterceptor::OnConnected` (`services/network/url_loader.cc` lines 920-942; `services/network/accept_ch_frame_interceptor.cc` lines 90-146) |
| Only navigations restart | The network service takes the observer only from a request's trusted parameters (`services/network/url_loader_factory.cc` lines 341-371), which only `NavigationURLLoaderImpl` sets (`content/browser/loader/navigation_url_loader_impl.cc` lines 256-277, 2160-2181) and a renderer's factory refuses (`services/network/cors/cors_url_loader_factory.cc` lines 657-662). Without it no interceptor exists (`accept_ch_frame_interceptor.cc` lines 57-68), and the loader continues (`url_loader.cc` lines 933-937) |
| Only hints the request lacks count | `ComputeAcceptCHFrameHints` drops each hint already among the request's fields, and the width hints (`accept_ch_frame_interceptor.cc` lines 26-52) |
| Only hints the origin has not enabled restart | `NeedsObserverCheck` skips the browser when every missing hint is enabled (`accept_ch_frame_interceptor.cc` lines 159-200), and the browser restarts only when one is not (`GetCriticalHintsMissingStatus`, `content/browser/client_hints/client_hints.cc` lines 1074-1098) |
| The restart appends the hints the navigation lacked to its own fields | `OnAcceptCHFrameReceived` builds the fields with every enabled hint and merges them (`navigation_url_loader_impl.cc` lines 1838-1846, 1904); `MergeFrom` sets each with `SetHeaderInternal`, which appends a name the fields lack (`net/http/http_request_headers.cc` lines 191-195, 303-310) |
| The network stack adds its fields after them | The network service copies the navigation's fields first (`services/network/url_loader_util.cc` lines 550-555), then adds `Sec-Fetch-*` (lines 579-583; `services/network/sec_header_helpers.cc` lines 163-192); the request job adds `Accept-Encoding` and `Accept-Language` (`net/url_request/url_request_http_job.cc` lines 781-794); the transaction keeps that order after `Host` and `Connection` on every protocol (`net/http/http_network_transaction.cc` lines 1381-1429). So the hints go after `Accept` and before `Sec-Fetch-Site` |
| The restart carries the hints and nothing is stored | `OnAcceptCHFrameReceived` computes the fields with the entry's hints added and cleared again, merges them into the request, and restarts it (`navigation_url_loader_impl.cc` lines 1838-1846, 1904, 1922) |
| Brave adds `Sec-GPC` after the restart's hints | `BraveProxyingURLLoaderFactory` wraps the navigation's loader factory (brave-core `browser/brave_content_browser_client.cc` lines 1227-1255 at tag `v1.96.59`), copies the request (`browser/net/brave_proxying_url_loader_factory.cc` line 119), runs its start-transaction callbacks on the copy's fields (lines 496-497), and passes the copy on (lines 539-545); the Global Privacy Control callback (`browser/net/brave_request_handler_impl.cc` lines 99-103) appends `Sec-GPC` with `SetHeader` (`browser/net/global_privacy_control_network_delegate_helper.cc` line 30). So Brave's templates put `Sec-GPC` after the restart slot: `accept, <hints>, sec-gpc, sec-fetch-site` |
| Restarts are bounded | `accept_ch_restart_limit_ = kMaxRedirects`, 20, per navigation (`navigation_url_loader_impl.h` line 315, `navigation_url_loader_impl.cc` line 1873) |

Differences from Chromium:

- A template says whether its request kind restarts
  (`RequestTemplate::restarts_for_connection_accept_ch`): the Chromium-family
  navigation templates do, and every `fetch` and Firefox template does not.
  A request without a template is a top-level one in Phantom's client-hint
  model, so it restarts.
- Chromium's enabled-hint check reads the browser's stored hints and the
  permissions policy; Phantom reads the origin's stored `Accept-CH` hints and
  has no permissions policy.
- Phantom bounds restarts by the profile's hints: each restart adds at least
  one hint the request keeps for the rest of its hop, so a request restarts
  at most once per hint the profile sends on request, 8 with
  `chromium::v154_windows_client_hints`. Chromium's limit of 20 is never
  reached.
- A restarted Chromium navigation runs its whole loader again. Phantom
  restarts within the attempt it was in: the same exact protocol, or the
  same negotiated or Alt-Svc path, and the same route.

Tests:

| Test | What it proves |
| --- | --- |
| `client_hints::http2_alps_accept_ch_applies_to_the_first_request_without_a_probe` | An H2 server whose ALPS names two hints sees one request, carrying both and the caller's value |
| `client_hints::http2_fetch_template_on_an_alps_accept_ch_connection_is_sent_as_built` | A request with the Chrome `fetch` template is sent once, without the hint the entry names, and succeeds |
| `client_hints::http2_navigation_template_restart_places_the_hint_after_accept` | A request with the Chrome navigation template restarts over HTTP/2, and the added hint comes right after `accept` and before `sec-fetch-site` |
| `client_hints::http3_navigation_template_restart_places_the_hint_after_accept` | The same over HTTP/3, against a BoringSSL QUIC server |
| `client_hints::http2_alps_accept_ch_restart_sends_a_streaming_body_once` | A POST with a one-shot streaming body restarts, and the server receives the hint and the body once |
| `client_hints::http2_replacement_restart_keeps_the_hint_the_first_connection_asked_for` | After a graceful `GOAWAY`, the replacement connection's entry restarts the request again, which keeps the first connection's hint |
| `client_hints::http2_hint_learned_while_a_request_waits_reaches_only_the_next_request` | A hint an `Accept-CH` response teaches while a built request waits for admission is absent from that request and present on the next |
| `client_hints::http3_alps_accept_ch_restarts_the_request_with_the_missing_hint` | A BoringSSL QUIC server whose ALPS names a hint sees one H3 request, carrying it |
| `field_lists::tests::an_accept_ch_restart_builds_the_lists_again_with_the_hint` | A negotiated restart builds and checks its HTTP/1.1 and HTTP/2 lists a second time, and the server sees one request |
| `session::client_hints::tests::*` | Which entries ask for a restart: a missing requested hint does; a present, default, caller-supplied, unknown, width, already restarted, or since-stored one, an empty or malformed entry, and a `fetch` template do not; `template_slots::restart_added_hints_follow_accept_on_every_protocol` puts every hint a navigation lacked at a restart, one stored since included, right after `Accept` on the HTTP/1.1, HTTP/2, and HTTP/3 lists, while a hint stored before the build keeps the block |
| `request_template::tests::chromium_navigation_lists_place_restart_hints_before_sec_fetch_site`, `restart_hint_slots_must_be_single_and_agree_across_protocols` | Every Chromium-family navigation list has the restart slot right after `Accept`, followed by `Sec-GPC` on Brave's lists and `Sec-Fetch-Site` on the others, and validation rejects a second or misplaced one |
| `request_template::tests::only_chromium_navigation_templates_restart_for_connection_accept_ch` | Which built-in templates restart |

The first five are in `crates/phantom/tests/requests/client_hints.rs`, the
others in `crates/phantom/src`. Byte-for-byte replays of the captured
requests, which carry no ALPS `ACCEPT_CH`, are unchanged.

How to reproduce: read the cited files at the tag above, run the listed
tests, and capture as
[ALPS `ACCEPT_CH` restart](../../scripts/capture/README.md#alps-accept_ch-restart)
describes; each run took under 2 seconds.

Limits:

- The captures cover HTTP/2. The restart over HTTP/3 rests on source and the
  loopback test.
- The captured navigation lacked every hint the frame named; a navigation
  that lacks some of them, or whose origin stored hints through `Accept-CH`
  first, rests on source.
- The test servers send `ACCEPT_CH` only through ALPS; frames sent after the
  handshake are not supported.

### SSE browser reconnect evidence

What is claimed: Phantom's event source matches Chrome 154 and Firefox 157 on
`Last-Event-ID` handling, retry persistence, termination, reconnect delays,
and reconnect field order, over plaintext HTTP/1.1.

Evidence: `fixtures/sse/` retains HTTP/1.1 EventSource captures from headless
Chrome 154.0.8037.58 and Firefox 157.0 on Windows 11
(10.0.26200), recorded against a plaintext loopback server. Each of the
seventeen scenarios ran ten times on a fresh profile. Fixtures keep the raw
request lines and header lines in arrival order, connection reuse, and the
delay from each server stimulus to the next request. Each file records the
capture page and the exact launch arguments.

The Firefox set was captured on 2026-10-02 with `run_matrix.py`, one
scenario at a time, on a host with no build running: no Cargo, `rustc`, or
linker process appeared, and 205 CPU samples taken every 10 seconds averaged
8.8% and peaked at 19.1%. `retry-persists-across-reconnect`, whose first run
timed out in both of the runner's attempts, was captured by
`sse_reconnect.py` directly. The set replaces a Firefox 156.0.1 set captured
on 2026-09-26 while other builds loaded the host, which had replaced a
Firefox 156.0 set.

Observed on both browsers:

- `Last-Event-ID` is spelled that way, carries the committed id as raw UTF-8
  bytes, is omitted when the committed id is empty, and sits among the
  browser's ordinary fields rather than last. Chrome places it after
  `sec-ch-ua-mobile`; Firefox places it after `Accept-Encoding`.
- A valid `retry` value persists across later connections, and a non-digit
  value is ignored.
- The delay spread across ten runs stayed within about 50 ms, apart from
  run 2 of Firefox's `invalid-retry-ignored`, whose first reconnect came
  67 ms and third 71 ms late, and did not grow between attempts: neither browser showed jitter or
  backoff. Firefox 157.0's median overshoot was 12 to 19 ms on the first
  reconnect and 3 to 13 ms on later ones. The first reconnect comes about a
  second after launch, and it is the one host load delays: in the Firefox
  156.0.1 set, captured under load from other builds, its median was 12 to
  316 ms above the delay, while the 156.0 and 157.0 sets, both captured on
  quiet hosts, kept it within 25 ms.
- `204`, `404`, `500`, and a `text/plain` response each ended the
  EventSource, with no request during the observation window.
- A stream with only response headers stayed open for 90 seconds; neither
  browser has an idle timeout.
- A cookie set by the stream response was sent on the reconnect.

Where they differ:

| Behavior | Chrome 154 | Firefox 157 |
| --- | --- | --- |
| Delay without `retry` | 3 s | 5 s |
| `retry: 0` and `retry: 100` | honored (about 1 ms and 110 ms) | raised to 500 ms (observed 512 to 519 ms) |
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
- One run of Firefox 156.0 (build ID 20260909172920), the build before
  156.0.1, with
  `MOZ_LOG=nsHttp:5,EventSource:5` showed one channel whose transaction
  restarted three times after `NS_BASE_STREAM_CLOSED` on fresh connections.
  The `204` answered that same channel, so the EventSource never scheduled a
  reconnect.

The logs were kept outside the repository; the fixture timings of these runs
matched the captures of the same builds. Phantom's event source already waits the retry
delay after each failure, like Chrome's. By default its HTTP/1 layer does not
resend a request after a reused connection closes before a response;
`RetryPolicy::with_reused_connection_replay` opts into Chrome's single
resend. That request-layer policy is outside the SSE controller.

A five-run comparison of headless and headful Chrome on `retry-750`, retained
under `launch-mode/`, gave medians within 1 ms of each other, so headless
timers are not throttled.

Other background traffic continued during the captures. Firefox 156, the
last Firefox build checked for it, still contacted Remote Settings, and
Chrome contacted Google update and messaging
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
each crumb as Chrome 154, Edge 154, Brave 154, Opera 136, and Firefox 157
do, except for Firefox's name index noted below. Over HTTP/3, the Chromium
request recipe splits it and its QPACK encoder stream and field sections
equal Chrome's, Edge's, Brave's, and Opera's.

Evidence: `fixtures/cookies/` retains three runs per protocol from headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, Brave 154.1.96.59, Opera
136.0.6008.52, and Firefox 157.0 on Windows 11 (10.0.26200), each on a
fresh profile. A run loads `/start`, whose response sets five probe cookies, then
navigates to `/page`, which fetches `/fetch` and `/done`, so three requests
on one connection carry the cookies. The probes include crumbs of 19 and 20
bytes. Every run of a browser and protocol agrees.

| Behavior | Chrome 154, Edge 154, Brave 154, and Opera 136 | Firefox 157 |
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
all three runs byte for byte. Brave and Opera replay against
`chromium::v154_http2` and `chromium::v154_cookie_placement`, as Edge does.

The Brave and Opera HTTP/1.1 captures are compared with Phantom's
requests, not replayed:
`brave_and_opera_templates_place_the_jar_cookie_as_captured` in
`crates/phantom/tests/requests/request_templates.rs` sends each browser's
navigation and `fetch()` templates with a jar cookie and the Chromium
placement. It compares the `Cookie` position, last, with the captured
`/page` and `/done` requests, and the whole field order with the captured
`/done`. The captured `/page` is a script navigation, with `Referer` and
without `Sec-Fetch-User`, so its other fields are not compared with the
address-bar template. Chrome's HTTP/1.1 placement is
checked against its EventSource capture instead, by
`chrome_templates_place_the_jar_cookie_where_chrome_does` in the same file;
no test replays the Chrome or Edge HTTP/1.1 cookie captures.

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
- Firefox 157 does not split `cookie` over HTTP/3, so
  `firefox::v157_http3_request` sends one joined field; the
  [Firefox 157 HTTP/3 recipe](#firefox-157-http3-recipe) replays that
  capture.
- The HTTP/3 capture server advertised aioquic's QPACK limits (4,096 bytes,
  16 blocked streams), not Chrome's own.
- Indexing crumbs exposes cookie values to the compression side channel
  that RFC 7541 section 7.1.3 describes;
  [Design](design.md#cookie-crumbs-and-compression) explains the trade and
  the opt-out.

### WebSocket browser evidence

What is claimed: Phantom's profile WebSocket connection policy and recipes
open a WebSocket the way Chrome 154, Edge 154, and Firefox 157 do, apart from
the [differences](../reference/websocket.md#differences-from-the-captures)
the WebSocket reference lists.
The Brave 154 and Opera 136 openings match `chromium::v154_websocket` too;
[Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes) records
them.

Evidence: `fixtures/websocket/` retains WebSocket openings from headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 157.0 on Windows 11
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

| Behavior | Chrome 154 and Edge 154 | Firefox 157 |
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
- Firefox 157.0 is the build the machine had updated to.

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
240 seconds and `firefox::v157_websocket` to 20 seconds, as those browsers'
own handshake timers do. `WebSocketRequestBuilder::handshake_timeout` applies
that limit to the whole opening and fails with
`WebSocketErrorKind::Timeout`. `WebSocketRetryPolicy` retries only a
connection-setup failure that sent nothing to the origin.

Evidence: a capture cannot show a timer that never fired, so the recipes
rest on browser source at Chromium tag `154.0.8037.58` and Firefox tag
`FIREFOX_157_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v154_websocket` | `kHandshakeTimeoutIntervalInSeconds` is 240, set equal to the TCP connect timeout so that a page cannot tell which step timed out (`net/websockets/websocket_stream.cc:60-64`). `WebSocketStreamRequestImpl::Start` starts the one-shot timer before the opening request starts (`:248-255`), `PerformUpgrade` stops it once the handshake stream is upgraded (`:258-262`), and `OnTimeout` cancels the request with `ERR_TIMED_OUT` (`:338-340`). A failure is reported to the page (`:303-332`); nothing opens the WebSocket again. |
| `firefox::v157_websocket` | `mOpenTimeout` starts at 20,000 ms (`netwerk/protocol/websocket/WebSocketChannel.cpp:1200`) and is read from `network.websocket.timeout.open`, clamped to 1 to 1,800 seconds (`:3511-3514`), whose default is 20 (`modules/libpref/init/all.js:1317`). `BeginOpenInternal` starts the timer after it opens the HTTP channel (`WebSocketChannel.cpp:1403-1420`), `CallStartWebsocketData` cancels it when the handshake completes (`:2974-2982`), and when it fires the connection is aborted with `NS_ERROR_NET_TIMEOUT_EXTERNAL` (`:3342-3351`). |

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

What is claimed: over HTTP/2, `chromium::v154_http2` and `firefox::v157_http2`
encode request fields as Chrome 154 and Firefox 157 do, down to the byte of
every HEADERS block: which fields enter the dynamic table, which entry names a
literal, which strings are Huffman-coded, and when a dynamic-table size update
starts a block. Edge 154, Brave 154, and Opera 136 use the Chromium recipe
and match it too. On HTTP/2 proxy connections the same holds for the
representation, index, and length of every block the proxy captures let
Phantom replay, `proxy-authorization` included.

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
| Brave 154 | 21 | 66 | All |
| Opera 136 | 21 | 66 | All |
| Firefox 157 | 27 | 66 | All |

The proxy route captures under [`fixtures/proxy/`](../../fixtures/proxy/)
add the replayable HTTP/2 proxy connections of their nine `https-proxy-*`
scenarios: CONNECT tunnels and requests forwarded with `:scheme` `http`,
whose blocks carry 306 `proxy-authorization` fields. They keep each field's
representation, its index or size, and each block's length, not the block
bytes, and the credential is replaced with a marker. A connection that
starts with, or carries, a browser background request, whose fields the
capture tool does not retain, is not replayed, because its table state is
unknown.

| Browser | Proxy connections replayed | HEADERS blocks | Representations, indexes, and length equal to Phantom's |
| --- | --- | --- | --- |
| Chrome 154 | 27 | 129 | All |
| Edge 154 | 27 | 129 | All |
| Brave 154 | 27 | 129 | All |
| Opera 136 | 27 | 129 | All |
| Firefox 157 | 45 | 108 | All |

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
byte. For a proxy session it sends CONNECT and forwarded requests on the
same connection type, restores the capture tool's throwaway credential
behind the marker, marks it sensitive as Phantom marks the generated field,
and compares each block's representations, indexes, and length.
`never_indexed_proxy_authorization_does_not_reproduce_a_proxy_session`
checks that the default never-indexed form fails that comparison. Firefox
encodes its first request before applying the server's
SETTINGS on 3 connections, where its SETTINGS acknowledgement follows that
request; the replay applies the SETTINGS at the same point.
`chromium_recipe_does_not_reproduce_a_firefox_session` checks that the
comparison separates the families. With the recipes' earlier HPACK
settings, 24 of the 27 Firefox connections differed; every Chromium-family
connection already matched.

How to reproduce: capture with `scripts/capture/cookie_crumbs.py` and
`scripts/capture/http2_websocket.py`, as in the two sections above, and the
proxy sessions with `scripts/capture/proxy_route.py`
([Proxy authentication evidence](#proxy-authentication-evidence)), then run
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
  table entry matches it, although Chromium has no such form. Two
  exceptions follow the recipes: a `cookie` field sent as crumbs, whose
  crumb rule decides, and `proxy-authorization` on a connection to a proxy,
  which the recipes' field rule decides. Phantom marks the cookie jar's
  field (split into crumbs under both recipes) and the generated
  `proxy-authorization`
  ([Proxy authentication evidence](#proxy-authentication-evidence)).
- A proxy capture proves a block's representations, indexes, and length,
  not its bytes. With the fields known, only the Huffman flag of a string
  whose coded and raw forms are equally long is unchecked; the cookie and
  WebSocket replays check that rule byte for byte.
- Six Firefox proxy connections, with 36 retained blocks, begin with or
  carry a background request whose fields the capture omits, so they are not
  replayed.
- When a browser applies the server's SETTINGS depends on timing; Phantom
  applies them as soon as they arrive, so a Firefox profile announces the
  table size in whichever block follows their arrival.

### HTTP/2 stream numbering evidence

What is claimed: on every HTTP/2 connection, `chromium::v154_http2` sends
the first request on stream 1 and `firefox::v157_http2` on stream 3, and each
later request takes the next odd stream, as Chrome 154 and Firefox 157 do.
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
| Chrome 154 | macOS | 4 | 8 | 1 | +2 each |
| Edge 154 | Windows | 156 | 459 | 1 | +2 each |
| Edge 154 | macOS | 3 | 9 | 1 | +2 each |
| Brave 154 | Windows | 48 | 195 | 1 | +2 each |
| Opera 136 | Windows | 99 | 352 | 1 | +2 each |
| Opera 136 | macOS | 3 | 9 | 1 | +2 each |
| Chrome for Android 154 | Android 17 emulator | 18 | 54 | 1 | +2 each |
| Brave for Android 153 | Android 15 and 17 emulators | 21 | 63 | 1 | +2 each |
| Edge for Android 153 | Android 17 emulator | 3 | 9 | 1 | +2 each |
| Firefox 157 | Windows | 99 | 246 | 3 | +2 each |
| Firefox 157 | macOS | 3 | 9 | 3 | +2 each |

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
tag `FIREFOX_157_0_RELEASE` the stated value is assigned as it is at
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
PING. `firefox::v157_http2` sends none.

When the PING goes unanswered and nothing is read from the peer, the
Chromium recipe closes the connection as Chrome 154 does, sending `GOAWAY`
with last stream ID 0, `PROTOCOL_ERROR`, and the debug data `Failed ping.`,
then closing, 10 seconds after the later of the PING and the last frame
read. Every request still open on the connection fails with
`Http2Error::PingTimeout`, and the client's pool drops the connection. A
request that failed so before its response head is sent again at once on
another connection, up to twice per redirect hop
(`Http2Settings::ping_failure_retries`), whatever its method and the retry
policy, unless its body is a one-shot stream. A negotiated request sends the
field lists of the failed attempt, as Chrome resends the same fields; an
exact request builds its list again. A request that reaches the
closed connection before the pool drops it sends nothing and fails with
`Http2Error::ReusedConnectionClosed`, which reused-connection replay covers.

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
Firefox 157 sends a PING of its own only from its read-timeout tick, which
`firefox::v157_http2` models as its
[idle PING](#http2-idle-ping-evidence), and on a network change
(`netwerk/protocol/http/Http2Session.cpp:436-503`, `:4190-4212` at tag
`FIREFOX_157_0_RELEASE`).

Sending the PING posts `SpdySession::CheckPingStatus` to run after
`kHungIntervalSeconds`, 10 (`:102`, `:2500-2510`). The check does nothing if
the ACK has arrived. Otherwise, if nothing has been read since the check was
posted or for 10 seconds, it drains the session with `ERR_HTTP2_PING_FAILED`;
if not, it runs again 10 seconds after the last read (`:2512-2538`).
`DoDrainSession` (`:2701-2757`) takes the session out of the pool
(`:1360-1366`), queues `GOAWAY` with last stream ID 0, the code
`MapNetErrorToGoAwayStatus` gives, `PROTOCOL_ERROR` (`:547-564`), and the
description as debug data, and `StartGoingAway` (`:1368-1417`) fails every
stream with the error and drops their queued frames, sending no RST_STREAM.
Once the GOAWAY is written, the pool destroys the session (`:2082-2093`),
which disconnects the socket (`:893`).

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

The close was captured later, from Chrome 154.0.8037.97, by
[`http_lifecycle.py --scenario ping-unanswered`](../../scripts/capture/README.md#connection-lifecycle),
and retained as
[`ping-unanswered.txt`](../../fixtures/lifecycle/chrome/154.0.8037.97/windows-11-26200/ping-unanswered.txt).
The page fetched `/a`, waited 11.5 seconds, and fetched `/b`; from `/b` on,
the server wrote nothing more on that connection. Chrome sent `/b`, then
PING 1, and 10.003 seconds after the PING a `GOAWAY` with last stream ID 0,
`PROTOCOL_ERROR`, and the debug data `Failed ping.`, then ended the TCP
connection with no TLS `close_notify`. In the same millisecond it opened a
new connection and sent `/b` again, with the same field list; the server
answered it, and the page saw status 200 10.006 seconds after it asked. The
run took 23 seconds of wall clock.

`crates/phantom-net/src/http2/tests/preface_ping.rs` checks the fixture's
order and payloads, then drives the Chromium recipe through the same
timeline with its idle time scaled to 1 second against a loopback peer and
compares the request frames and PINGs with the fixture's. Other tests there
check no PING after the first request, PING 1 right after the HEADERS of a
request sent 1.5 seconds later, none right after its ACK, PING 2 after the
next idle period, and none with the setting off. The vendored `http2`
crate's tests add the PING after a 4,096-byte DATA frame, none after an
empty END_STREAM DATA frame, and none while PING 1 is unanswered.

The same file checks the close with the timeout shortened: a PING
unanswered for 2 seconds brings that GOAWAY between 1 and 4 seconds after the
peer reads the PING, then the end of the byte stream; the open request fails
with `Http2Error::PingTimeout`, and a later one with
`Http2Error::ReusedConnectionClosed`. A WINDOW_UPDATE 2 seconds into a
4-second timeout moves the GOAWAY to between 5 and 7 seconds after the PING,
where Chrome's rule gives 6, ignoring the read gives 4, and a second full
timeout after it would give 8,
and an acknowledged PING leaves the connection usable 2 seconds past a
1-second timeout. The vendored `http2` crate's tests add a peer that stops
reading for three timeouts while a request body fills the pipe, then drains
it and sends the ACK, and sees no GOAWAY.
`crates/phantom/tests/requests/ping_failure_replay.rs` checks through the
client that the failed request goes out again on a second connection, a
`GET` and a `POST` with its body, exact, negotiated, and through a CONNECT
tunnel, and that a one-shot streaming body fails with
`Http2Error::PingTimeout` and opens no other connection;
`a_ping_failure_resend_builds_each_list_once` in
`crates/phantom/src/request/field_lists/tests.rs` shows a negotiated resend
sending the lists built for the failed attempt. `crates/phantom/tests/requests/unprocessed_replay.rs` checks
that with `ping_failure_retries` at 0 the request fails, even with
unprocessed replay on, and the next request opens a new connection.

How to reproduce:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  python -m scripts.capture.http2_preface_ping --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --output-dir fixtures/http2/chrome/154.0.8037.58/windows-11-26200
cargo test -p phantom-net --lib http2::tests::preface_ping
cargo test -p phantom-http --test requests ping_failure_replay
cargo test -p phantom-http --test requests \
  unprocessed_replay::ping_timeout_fails_the_request_without_replay_and_retires_the_connection
```

Limits:

- One Windows build and one retained run.
- The capture shows no PING after a DATA frame alone; a `POST` after an idle
  period gets its PING from the HEADERS. That case and the exact 10-second
  boundary rest on source.
- Chrome retries a request that fails with `ERR_HTTP2_PING_FAILED` before
  its response headers, whatever its method, up to twice on a new connection
  (`HttpNetworkTransaction::HandleIOError`,
  `net/http/http_network_transaction.cc:2073-2074`, `:2222-2233`, with
  `kMaxRetryAttempts` of 2 at `:108`). The capture shows the first retry,
  sent at once on a new connection; a second needs the new connection's
  PING to fail too, which a fresh connection cannot reach, so the limit of
  two rests on source, and no test drives a second failure. Chrome counts
  these retries in one `retry_attempts_` with its retries after a refused
  stream and on QUIC (`:2231`, `:2251`, `:2263`); Phantom counts them apart
  from its retry policy's replays. Phantom returns the error for a
  streaming body. An exact request builds its list again, so a cookie
  another request stored meanwhile reaches the resend, where Chrome resends
  the `Cookie` it set before the first attempt.
- Phantom counts reads per whole frame for the idle time and the PING
  timeout, where Chrome counts every socket read, including part of a frame.
  Phantom also does not check the PING timeout while its writes are
  blocked, since it then reads nothing either; Chrome reads and checks
  independently of its writes.
- The close sends no TLS `close_notify`, in Chrome and in the Chromium
  recipes; see [TLS close evidence](#tls-close-evidence).

### HTTP/2 idle PING evidence

What is claimed: on an HTTP/2 connection that has read nothing from the peer
for 58 seconds, `firefox::v157_http2` sends a PING with an all-zero payload,
whether or not requests are open, as Firefox 157 does. Only one is
outstanding at a time, and any frame read clears it, so the next goes out 58
seconds after that read. When one goes 8 seconds with nothing read, the
connection sends `GOAWAY` with last stream ID 0, `INTERNAL_ERROR`, and no
debug data, then closes. Every request still open on it fails with
`Http2Error::PingTimeout` and is not sent again, and the client's pool drops
the connection. The Chromium recipes send no such PING.

Evidence: Firefox source at tag `FIREFOX_157_0_RELEASE` and one retained
capture. The connection manager's one-second tick runs
`Http2Session::ReadTimeoutTick`
(`netwerk/protocol/http/Http2Session.cpp:436-503`). Once
`network.http.http2.ping-threshold`, 58 seconds, has passed since the last
read, it records the time and sends a PING; a read before the threshold
passes again clears that time; and once `network.http.http2.ping-timeout`, 8
seconds, has passed since the PING, it closes the session with
`NS_ERROR_NET_TIMEOUT` (`modules/libpref/init/StaticPrefList.yaml:16497-16505`).
`GeneratePing` writes a zero payload (`Http2Session.cpp:977-995`), and
`Http2Session::Close` sends `GOAWAY` with `INTERNAL_ERROR` for that error,
with last stream ID 0 and no debug data (`:1033-1051`, `:3597-3610`).
`nsHttpTransaction::Close` does not restart a transaction failed so
(`netwerk/protocol/http/nsHttpTransaction.cpp:1546-1553`).

[`http_lifecycle.py --scenario idle-ping`](../../scripts/capture/README.md#connection-lifecycle)
served a page that fetched `/a` over HTTP/2, left the connection idle for 75
seconds, then fetched `/b`, to headless Firefox 157.0 on Windows 11. The
retained
[`idle-ping.txt`](../../fixtures/lifecycle/firefox/157.0/windows-11-26200/idle-ping.txt)
keeps every client frame. Firefox sent `/a` at 0.609 seconds, one PING with
payload `0000000000000000` at 60.558 seconds, 59.9 seconds after the
server's last frame, and nothing else until `/b` at 79.823 seconds. A trial
run, not retained, sent the PING after 60.2 seconds. The two seconds past the
threshold are the tick's.

`crates/phantom-net/src/http2/tests/idle_ping.rs` checks the fixture's
order and payload, then drives the Firefox recipe through the same timeline
with its idle time scaled to 1 second against a loopback peer and compares
the request frames and PING with the fixture's. With the timeout scaled to 2
seconds, a PING the peer never answers brings that GOAWAY between 1 and 4
seconds after the peer reads it, then the end of the byte stream; the open
request fails with `Http2Error::PingTimeout`, and a later one with
`Http2Error::ReusedConnectionClosed`. A WINDOW_UPDATE written while the PING
is outstanding keeps the connection usable past a 1-second timeout. The
vendored `http2` crate's tests add a second zero PING 1 second after the
first one's ACK, and a peer that reads nothing for 3 seconds while a request
body fills the pipe, which sees no GOAWAY under a 1-second timeout.

How to reproduce:

```sh
cargo test -p phantom-net --lib http2::tests::idle_ping
cargo test -p phantom-profile --lib idle_ping
```

The capture commands are under
[Connection lifecycle](../../scripts/capture/README.md#connection-lifecycle).

Limits:

- One Windows run; no capture shows an unanswered PING, so the timeout and
  the close rest on source.
- Phantom sends the PING at 58 seconds rather than on the next one-second
  tick, so a capture of Firefox shows it up to about two seconds later.
- Neither the PING nor its timeout is checked while the connection cannot
  write, because it then reads nothing either; Firefox keeps reading while
  its writes wait.
- A read is a whole frame the connection handles, where Firefox counts any
  bytes read; a frame of an unknown type, a CONTINUATION before its header
  block ends, and a large frame still arriving do not count.
- A request that reaches the connection after the close fails with
  `Http2Error::ReusedConnectionClosed`, which reused-connection replay
  covers, where Firefox's `Http2Session::AddStream` restarts it on a new
  connection (`Http2Session.cpp:577-594`).
- Firefox's PING on a network change and its close of a connection idle for
  170 seconds (`network.http.http2.timeout`) are not modeled.

### TLS close evidence

What is claimed: `TlsSettings::close_notify` decides whether Phantom sends
a TLS `close_notify` alert before the TCP FIN when it shuts a connection
down. The Chromium-family recipes leave it unset and send only the FIN, as
Chrome 154 did on every close captured; `firefox::v157_tls` sets it, as
Firefox 157 did when it aborted a response and at exit. It applies wherever
Phantom shuts a TLS connection down, such as an HTTP/2 connection that ends
after a `GOAWAY` or a PING timeout.

Evidence: headless Chrome 154.0.8037.97 and Firefox 157.0 on Windows 11
(10.0.26200), captured by
[`http_lifecycle.py`](../../scripts/capture/README.md#connection-lifecycle)
and retained under `fixtures/lifecycle/<browser>/<version>/windows-11-26200/`.
The server reads each connection through memory BIOs and records whether a
`close_notify` arrived before the TCP end. The `close` scenario fetches over
HTTP/2, aborts an HTTP/1.1 response mid-body at a second origin, fetches
over a new HTTP/1.1 connection there, and then closes the browser over its
remote protocol (CDP `Browser.close`, WebDriver BiDi `browser.close`).

| Close | Chrome 154.0.8037.97 | Firefox 157.0 |
| --- | --- | --- |
| Connections opened at startup and abandoned | FIN, no `close_notify` | None opened |
| HTTP/1.1 response aborted by the page | FIN, no `close_notify` | `close_notify`, then FIN |
| HTTP/2 connection after an unanswered PING (`ping-unanswered`) | `GOAWAY`, then FIN, no `close_notify` | Not captured |
| Idle HTTP/2 connection at browser exit | FIN, no `close_notify`, no `GOAWAY` | `GOAWAY` (`NO_ERROR`, last stream 0), `close_notify`, then FIN |
| Idle HTTP/1.1 connection at browser exit | FIN, no `close_notify` | `close_notify`, then FIN |

Chromium source agrees: `SSLClientSocketImpl::Disconnect`
(`net/socket/ssl_client_socket_impl.cc:400-418` at `154.0.8037.58`) closes
the transport, and the file never calls `SSL_shutdown`. Edge, Brave, and
Opera use the same socket class; their recipes rest on that source.

`tls::tests::shutdown_sends_close_notify_only_when_the_profile_does`, in
`crates/phantom-net/src/tls/tests.rs`, shuts down a connection made with
`chromium::v154_tls` and one made with `firefox::v157_tls` and reads the raw
bytes each sent after the handshake: nothing before the FIN for Chromium,
and for Firefox exactly one 24-byte encrypted record holding the alert.
`http2::tls::tests::ping_close::chromium_ping_timeout_close_sends_nothing_after_goaway`,
in `crates/phantom-net/src/http2/tls/tests/ping_close.rs`, lets an HTTP/2
connection made with the Chromium TLS and HTTP/2 recipes time out its PING
against a BoringSSL server, and checks that no byte follows the `GOAWAY`
on the TCP stream, as in Chrome's `ping-unanswered.txt`.

How to reproduce: the `close` and `ping-unanswered` commands in
[Connection lifecycle](../../scripts/capture/README.md#connection-lifecycle);
each `close` run took about 5 seconds, `ping-unanswered` 23. Then run
`cargo test -p phantom-net --lib tls::tests::shutdown`.

Limits:

- A connection Phantom drops without shutting it down sends neither an
  alert nor a FIN of its own; the operating system closes it. Firefox's
  `GOAWAY` at exit is not reproduced.
- One run per scenario on one Windows host; the Firefox recipe's setting
  for HTTP/2 closes other than at exit rests on the HTTP/1.1 abort and on
  NSS, which sends the alert from `ssl_SecureClose`.
- No Android browser's close was captured. The Chrome, Edge, Brave, and
  Opera for Android recipes, which leave the setting unset, rest on
  `SSLClientSocketImpl::Disconnect` in Chromium source;
  `firefox_android::v156_tls`, which sets it, rests on desktop Firefox 157
  and NSS's `ssl_SecureClose`.

### Revalidation and upload evidence

What is recorded: two browser behaviors that no recipe models yet, from
the same `http_lifecycle.py` captures of Chrome 154.0.8037.97 and Firefox
157.0, one run each, retained under `fixtures/lifecycle/`. The `idle-ping`
run of the same tool is the [idle PING evidence](#http2-idle-ping-evidence).

- Revalidation (`revalidate`): the page fetched four resources twice
  each with the default cache mode. Three carried `Cache-Control: no-cache`
  with an `ETag`, a `Last-Modified`, or both; the server answered a second
  request with a matching validator with `304`. Both browsers sent
  `If-None-Match` with the `ETag` and `If-Modified-Since` with the
  `Last-Modified` value, and the page saw status 200 with the cached body.
  Chrome put the validators after `accept-language` and before `priority`,
  `if-none-match` first; Firefox put them after `sec-fetch-site` and before
  `priority`, `if-modified-since` first when both were sent. A resource with
  only a year-old `Last-Modified` and no `Cache-Control` was served from the
  cache with no second request, in both browsers.
- Uploads (`upload-h1`, `upload-h2`): a 100-byte `fetch` POST, 1 MiB
  string and `Blob` bodies, a 1 MiB multipart `FormData`, and a form that
  submitted a 1 MiB file into an iframe, over HTTP/1.1 and over HTTP/2.
  Neither browser sent `Expect: 100-continue` on any of them; each body
  carried `Content-Length`.

How to reproduce: the commands in
[Connection lifecycle](../../scripts/capture/README.md#connection-lifecycle);
each `revalidate` and `upload` run took 1 to 2 seconds.

Limits:

- One run per scenario, headless, on one Windows host; Edge, Brave, and
  Opera were not captured.
- Phantom has no HTTP cache, so revalidation fields come from the caller.

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

Chrome 154.0.8037.97 was also captured against an origin that lists two
`h3` alternatives, a QUIC-only listener on a port of its own first and the
origin's own port second, three runs per scenario, retained under
[`fixtures/alt-svc/chrome/154.0.8037.97/windows-11-26200/`](../../fixtures/alt-svc/chrome/154.0.8037.97/windows-11-26200/):

- `two-alternatives`, both serving: every race used the first alternative,
  and the second received no datagram, 3/3. Chrome does not race the
  alternatives against each other.
- `first-alternative-blackholed`: the first race used the first alternative,
  which lost to TCP and was marked broken for 299 to 300 seconds. The next new
  connection's alternative job connected to the second alternative, and
  later requests were bound to that QUIC session, 3/3.

So Chrome uses the first alternative that is not broken, in the order the
field lists them, as `GetAlternativeServiceInfoInternal` reads them
(`net/http/http_stream_factory_job_controller.cc`). Phantom keeps only the
first `h3` entry of a field and does not fall back to the next one. The two
scenarios took 57 seconds together.

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
- Phantom stores only the first `h3` entry of an `Alt-Svc` field. Chrome
  moves to the next listed alternative once the first is broken.
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

What is claimed: with the Chrome 154, Edge 154, Brave 154, or Opera 136
recipe and HTTPS record discovery, a direct negotiated connection to an
origin whose HTTPS record carries `ech` encrypts its ClientHello with that
configuration, as Chrome 154.0.8037.58, Edge 153.0.4234.48, Brave
154.1.96.59, and Opera 136.0.6008.52 do: the outer server name is the
configuration's public name, the `encrypted_client_hello` extension has the
kind, cipher suite, config ID, encapsulated key length, and payload length
the browser sent, and the outer ClientHello carries the extension set the
browser's did. After a rejection it
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

Opera 136.0.6008.52 behaves the same way. Opera overrides Chromium's two
`Local State` preferences with its own, so `chrome_ech.py --browser opera`
also sets
`dns_over_https.opera.doh_mode` to `custom` and
`dns_over_https.opera.custom_servers` to the capture server's template in
the throwaway profile; the fixture's `dns_configuration` line records them.
Opera sent one `HTTPS` and one `A` query. Its retained `ech-accept.txt` and
`ech-reject.txt`, under
`fixtures/tls/opera/136.0.6008.52/windows-11-26200/`, show the same outer
server name and extension fields as Chrome's, with Opera's trust-anchor IDs,
and, after each of two rejections, one connection with retry configuration
2 that the origin accepted. `outer_client_hello_has_the_shape_opera_136_sent`
replays the accept capture with `opera::v136_tls`, and
`opera_136_rejection_is_retried_as_opera_retried_it` replays the reject
capture: the rejected connection and its retry have Opera's outer name,
extension fields, acceptance, and inner name. One run of each scenario
was taken, on 2 October 2026; the ClientHellos' trust-anchor orders are not
among those `trust-anchor-orders.txt` tallies.

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

Firefox 157, at tag `FIREFOX_157_0_RELEASE`, does not follow these rules, and
its recipe keeps GREASE:

- It builds the ClientHelloOuter with NSS, not BoringSSL.
- A transaction waits for the HTTPS record only when DNS over HTTPS is active
  (`nsHttpChannel.cpp` lines 8277-8292, `nsHttpConnectionMgr.cpp` lines
  1721-1726); otherwise a record that arrives after the transaction is
  activated is not used (`nsHttpTransaction.cpp` lines 3672-3676).
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

What is claimed: with the Chrome 154, Edge 154, Brave 154, or Opera 136
HTTP/3 recipe and HTTPS record discovery, a direct QUIC connection to the
origin's own host and port, whose first record that lists `h3` carries
`ech`, encrypts its ClientHello with that configuration, as Chrome
154.0.8037.58, Edge 153.0.4234.48, Brave 154.1.96.59, and Opera
136.0.6008.52 do. The outer server name is the
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
- Opera 136.0.6008.52, in one run of each scenario retained under
  `fixtures/tls/opera/136.0.6008.52/windows-11-26200/`, matched Chrome: two
  QUIC connections with the accepted configuration in `accept`; in `reject`,
  three QUIC connections offering config ID 1, each closed with `0x179`,
  then the page over TCP after one rejection and one retry with config ID 2.
  `quic_outer_client_hello_has_the_shape_opera_136_sent` replays the accept
  capture with `opera::v136_http3_tls`, and
  `opera_136_quic_rejection_is_not_retried_as_opera_did_not_retry_it` the
  reject capture: the connection has Opera's outer fields, closes with
  `0x179`, and no second QUIC connection arrives.
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
and `brave::v154_http3_tls`; `opera::v136_http3_tls` clears it. The
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
these captures show for that browser. The Brave 154 and Opera 136 recipes
are compared with their own resumption captures the same way; see
[Brave 154 and Opera 136 recipes](#brave-154-and-opera-136-recipes). Phantom sends `GET`, `HEAD`, and
`OPTIONS` requests issued before the handshake completes in 0-RTT packets,
as the browsers did, and never sends `POST`, `PUT`, or `DELETE` early. Like
Chromium, it starts a resumed connection from the server SETTINGS remembered
with the ticket, so the recipes' dynamic QPACK policy can encode a request
before the server's SETTINGS arrive. The
[Firefox 157 HTTP/3 recipe](#firefox-157-http3-recipe) starts a resumed
connection in QUIC v2, as these Firefox captures show.

Evidence: `fixtures/http3/<browser>/<version>/windows-11-26200/` retains
`resumption-accept.txt` (5 runs), `resumption-accept-delayed.txt` (3 runs),
and `resumption-reject.txt` (3 runs) for headless Chrome 154.0.8037.58 and
Firefox 157.0, and one run of each for Edge 154.0.4258.37, on Windows 11
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

| Behavior | Chrome 154 and Edge 154 | Firefox 157 |
| --- | --- | --- |
| Transport parameters added on resumption | `initial_rtt_us` (0x3127), carrying the previous connections' RTT: 952-6414 µs on loopback, 41449-59157 µs with the 50 ms delay | None |
| `version_information` | Unchanged apart from the reserved version's position, which varies per connection | Chosen version becomes QUIC v2 (0x6b3343cf), and the resumed connection starts in v2 packets; fresh connections start in v1 and are upgraded by aioquic |
| Later connections that resumed (`accept`, `reject`) | Chrome 39 of 39; Edge 8 of 8 | 24 of 32 |
| Resumption in `accept-delayed` | Chrome 12 of 12; Edge 4 of 4 | 0 of 12 |
| Second navigation in 0-RTT (`accept`) | Chrome 0 of 5; Edge 0 of 1 | 3 of 5, and a fourth sent partly in 0-RTT |
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
- The Brave 154 resumption fixtures predate the stream-type fields but keep
  each connection's stream numbers, and
  `brave_captures_use_the_recipe_s_qpack_stream_numbers` checks them in all
  55 connections: every connection wrote client stream 2, one
  that carried a request also wrote stream 10 and sometimes stream 6, and an
  idle one wrote nothing else. Their stream types are not recorded.
- `chromium_captures_open_qpack_streams_in_the_recipe_order`, in
  `crates/phantom-profile/src/chromium/http3_tests.rs`, reads the four
  `resumption-streams-*` fixtures and the three Opera 136 `resumption-*`
  fixtures, which record stream types too, checks the stream order and types
  above in all 132 connections,
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
set the captures show for its recipe's browser, with `pre_shared_key` last.
With a ticket that permits early data, a direct Firefox-profile connection
offers `early_data` where Firefox does and sends replay-safe requests as early
data, including a WebSocket opening's HTTP/1.1 Upgrade GET; the
Chromium-family recipes never offer it. Phantom keeps as many tickets per
origin as the browser did, presents the newest first, and uses each once. A
`Client` WebSocket opening shares the tickets of its origin's request pool,
so it resumes a ticket an earlier request was issued, as Firefox's
WebSocket connections did. A later request resumes one the opening was
issued, which Chrome 154's session cache allows; no capture shows it.

Evidence: `fixtures/tls/<browser>/<version>/windows-11-26200/` retains nine
`resumption-<scenario>.txt` fixtures, three runs each, for headless Chrome
154.0.8037.58, Edge 154.0.4258.37, Brave 154.1.96.59, Opera 136.0.6008.52,
and Firefox 157.0 on Windows 11 (10.0.26200). Each run used a fresh profile
against the `tls_resumption.py` loopback server, which sends two
NewSessionTickets after every handshake (eight after the first handshake
only, in `issue-once`), each permitting early data except in
`no-early-data`. [TLS resumption over TCP](../../scripts/capture/README.md#tls-resumption-over-tcp)
lists the scenarios and the fields each fixture keeps. Two more scenarios,
`websocket` and `websocket-http1`, ran only with Firefox 157.0, three runs
each, since only Firefox offers early data over TCP: the page's connection
closes, then the page opens a `wss://` WebSocket to the same origin, which
needs a new connection.

Observed:

| Behavior | Chrome 154, Edge 154, Brave 154, Opera 136 | Firefox 157 |
| --- | --- | --- |
| Resumed ClientHellos, all offering one 64-byte identity and one 32-byte binder, `pre_shared_key` last, PSK mode `psk_dhe_ke` (1) | 151, 146, 111, 154 | 120 |
| Added against the run's first, fresh ClientHello | `pre_shared_key` only | `early_data` (0x2a) and `pre_shared_key`; only `pre_shared_key` when the ticket does not permit early data (12 of 12) |
| Removed against the fresh ClientHello | Nothing; the empty `session_ticket` stays | The empty `session_ticket` (0x23), in all 120 |
| `early_data` offered over TCP | Never, including with tickets that permit it | 108 of 108 resumptions with such a ticket; placed after `key_share` and before `supported_versions`, with `record_size_limit` (0x1c) still sent |
| Requests sent in early data | None | `GET` 102 times, and `HEAD` and `OPTIONS` 3 times each; `POST`, `PUT`, and `DELETE` never (18 on connections that used early data) |
| A resumed connection that opens a WebSocket (`websocket`, `websocket-http1`) | Not captured | Offers `early_data` in 3 of 3 runs over each protocol. Over HTTP/1.1 the Upgrade GET arrives in early data, 563 bytes each time. Over HTTP/2 the early data is 70 bytes: the preface, SETTINGS, and WINDOW_UPDATE; the extended CONNECT follows the handshake |
| Tickets used of eight issued by one connection (`issue-once`) | 2 of 8 in every run: the newest, then the one before it | 8 of 8 in every run, each once; newest first in 2 of 3 runs |
| Ticket presented twice | Never | Never |
| Six connections opened at once for slow requests (`parallel`) | Two or three resumed, each with its own ticket | Two resumed in every run, each with its own ticket |
| First connection to the same host on another port (`origins`) | No ticket offered, in every run | No ticket offered, in every run |
| A `top.partition.test` page fetching the origin (`partition`) | No ticket offered; back on the origin's own page, a ticket learned before the switch | The same |

The Chromium-family browsers always presented the newest ticket they held;
Firefox's choice between the two tickets of one connection varied. Some
connections carried no request: the Chromium-family browsers often open a
first connection that closes before the navigation. Firefox sometimes made a
full handshake although earlier connections had received tickets, in 6 of
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
- `firefox_resumed_client_hello_matches_the_capture_without_early_data`
  learns a 64-byte ticket, as long as the capture server's, from a loopback
  rustls server, and compares the resumed `firefox::v157_tls` ClientHello
  with every resumed ClientHello of `resumption-no-early-data.txt` byte for
  byte apart from the random, the session ID, key-share keys, the ECH GREASE
  AEAD, configuration ID, encapsulated key, and payload bytes, and the PSK
  identity, ticket age, and binder bytes. The ECH GREASE payload is 368
  bytes in both. The extension order is Firefox's fixed order without
  `session_ticket` and with `pre_shared_key` appended.
- `firefox_resumed_client_hello_with_early_data_matches_the_capture`
  learns a ticket that permits early data and compares the resumed ClientHello
  with every resumed ClientHello of the Windows and macOS
  `resumption-sequential.txt` the same way, apart from the ECH GREASE payload
  length. The extension order is Firefox's fixed order without
  `session_ticket`, with an empty `early_data` between `key_share` and
  `supported_versions`, `record_size_limit` still sent, and `pre_shared_key`
  last. Only a BoringSSL loopback server issues tickets that permit early
  data here, and its tickets are longer than the capture server's, so the
  payload length is compared through NSS's rule; see
  [Firefox ECH GREASE payload](#firefox-ech-grease-payload-evidence).
- `chromium_recipes_never_offer_early_data_over_tcp` resumes a ticket that
  permits early data with the Chrome, Edge, Brave, and Opera recipes; none
  offers `early_data`.
- `concurrent_connections_resume_up_to_the_recipes_tickets_per_origin`
  learns two tickets, resumes once (which stores two more), then opens three
  connections at once. With `chromium::v154_tls` two resume and one makes a
  full handshake, because only the two newest tickets remain; with
  `firefox::v157_tls` all three resume.

The recipes carry the retention as `TlsSettings::session_tickets_per_origin`
(2 for the Chromium family, 8 for Firefox), the `session_ticket` choice as
`TlsSettings::session_ticket_extension_when_resuming`, and early data as
`TlsSettings::tcp_early_data`, set by `firefox::v157_tls` and, from source,
by `firefox_android::v156_tls`
([Firefox for Android](#firefox-for-android-156-recipe)).

Early data follows Firefox 157's source at tag `FIREFOX_157_0_RELEASE` where
no capture shows the behavior, since every capture server accepted early
data:

- Only a direct connection offers it; Firefox disables it on every proxy
  connection (`netwerk/protocol/http/TlsHandshaker.cpp:134-137`).
- A WebSocket opening is an ordinary transaction to this rule, which the
  `websocket` captures confirm.
  `TlsHandshaker::Check0RttEnabled` asks the connection's transaction
  whether it may send early data (`TlsHandshaker.cpp:304-320`), and
  `nsHttpTransaction::Do0RTT` admits any safe method, the WebSocket `GET`
  included (`nsHttpTransaction.cpp:3383-3392`). When the resumed session's
  protocol is `h2`, `nsHttpConnection::Start0RTTSpdy` starts the HTTP/2
  session in early data and puts the WebSocket transaction back in the
  pending queue until the server's settings are known
  (`nsHttpConnection.cpp:203-221` and `272-305`), so the extended CONNECT
  never travels in early data.
- A request travels as early data when its method is safe and it has no body
  and no trailers, the rule Phantom's HTTP/3 early data uses. Firefox's
  `nsHttpRequestHead::IsSafeMethod` (`nsHttpRequestHead.cpp:345-360`) also
  admits a body and `PROPFIND`, `REPORT`, and `SEARCH`. Any other request
  waits until the server answers, as Firefox's does
  (`TlsHandshaker.cpp:304-320`). On HTTP/2 the connection preface and
  SETTINGS go out as early data whatever the request
  (`Http2Session.cpp:2683-2707`), as the `methods` captures show.
- After a rejection with the same ALPN protocol, the connection finishes the
  handshake and sends the same bytes again: Firefox rewinds an HTTP/1.1
  request (`nsHttpTransaction.cpp:3414-3424`) and resends HTTP/2 from the
  preface (`Http2Session.cpp:3384-3393`).
- After a rejection under another ALPN protocol the connection fails, and a
  negotiated request is sent again once on a new connection, as Firefox
  restarts its transactions without early data
  (`nsHttpTransaction.cpp:1546-1579`). Before that, the pool removes the
  origin's tickets, as Firefox removes every resumption token for the peer
  on that restart (`nsHttpTransaction::Restart`,
  `nsHttpTransaction.cpp:1993-1999`, under
  `network.http.remove_resumption_token_when_early_data_failed`), so the new
  connection makes a full handshake. A rejection under the same ALPN
  protocol removes no tickets: Firefox resends on the same connection
  without a restart (`nsHttpConnection.cpp:2608-2647`), and each token is
  used once anyway (`NSSSocketControl.cpp:718-737`).
- A handshake that fails after early data, a certificate failure after a
  rejected ticket for instance, fails the request with the TLS error a fresh
  connection's handshake reports; an exact request whose server selects an
  ALPN protocol its transport cannot use fails as a fresh connection that
  selects it does.

Tests in `crates/phantom-net/src/tls/tests/early_data.rs`,
`crates/phantom-net/src/http1_or_2/tests/early_data.rs`, and
`crates/phantom/tests/sessions/session_tcp_early_data.rs` prove this against
loopback BoringSSL servers that hold their ClientHello answer until the early
data has arrived:

- `accepted_early_data_carries_the_writes_made_before_the_answer`,
  `rejected_early_data_is_sent_again_on_the_same_connection`, and
  `another_alpn_after_a_rejection_fails_the_connection` cover the TLS stream.
- `http1_sends_a_get_as_early_data_and_holds_a_post_until_the_answer` and
  `http2_sends_the_preface_and_a_get_as_early_data_and_holds_a_post` show the
  server reading a `GET` as early data, and a `POST` only after the handshake
  on a connection whose early data it accepted.
- `http1_sends_a_rejected_get_once_more_on_the_same_connection` and
  `http2_sends_a_rejected_get_once_more_on_the_same_connection` show the
  server reading one copy of the request after a rejection.
- `a_connection_through_a_proxy_offers_no_early_data` resumes a ticket that
  permits early data through a CONNECT tunnel without offering it, and
  `the_plain_handshake_offers_no_early_data` covers the handshake proxy
  connections use, WebSocket openings through a proxy included.
- In `crates/phantom-net/src/tls/tests/websocket_early_data.rs`, a Firefox
  connector with a ticket cache opens two WebSockets.
  `a_resumed_http1_websocket_opening_sends_its_upgrade_get_as_early_data`
  shows the second opening's whole Upgrade GET read as early data, and
  `a_rejected_http1_websocket_opening_is_sent_once_more_on_the_same_connection`
  one copy of it after a rejection.
  `a_resumed_http2_websocket_opening_holds_its_connect_until_the_answer`
  shows early data of the preface, SETTINGS, and WINDOW_UPDATE, as the
  capture does, and the extended CONNECT after it;
  `a_rejected_http2_websocket_opening_resends_its_preface_on_the_same_connection`
  shows one copy after a rejection. For each protocol,
  `an_http1_websocket_opening_reports_a_handshake_failure_after_early_data`
  and its HTTP/2 twin show the TLS error of a failed handshake, and
  `an_http1_websocket_opening_reports_an_alpn_change_after_early_data` and
  its HTTP/2 twin the ALPN error after a rejection and another ALPN
  protocol.
- In `crates/phantom/tests/sessions/websocket_resumption.rs`, a `Client`
  opens a WebSocket after a request to the same origin, or the reverse.
  `a_firefox_websocket_after_a_negotiated_request_sends_its_preface_early`
  replays the `websocket` capture: the profile-policy opening's new HTTP/2
  connection resumes the page's ticket and sends the preface, SETTINGS,
  and WINDOW_UPDATE as early data, and no HEADERS.
  `a_firefox_upgrade_after_an_http1_request_travels_as_early_data` replays
  `websocket-http1` with an exact HTTP/1.1 opening: the Upgrade GET arrives
  as early data. `a_chromium_upgrade_resumes_the_ticket_of_a_negotiated_request`
  shows a Chromium-profile Upgrade connection that offers only `http/1.1`
  resuming the ticket of an `h2` connection without early data, as
  Chrome 154's session cache, keyed by host and port, network anonymization
  key, privacy mode, and proxy chain, offers it
  (`SSLClientSocketImpl::GetSessionCacheKey`,
  `net/socket/ssl_client_socket_impl.cc` lines 1631-1644 at
  `154.0.8037.58`); no Chromium-family capture covers it.
  `a_negotiated_request_resumes_the_ticket_of_a_chromium_upgrade` and
  `an_exact_http2_websocket_resumes_the_ticket_of_an_exact_http2_request`
  cover the other direction and the exact HTTP/2 pool, and
  `a_chromium_upgrade_through_a_proxy_resumes_the_ticket_of_a_proxied_request`
  a CONNECT tunnel.
  `a_firefox_upgrade_beside_an_incapable_session_resumes_without_early_data`
  shows an Upgrade that offers only `http/1.1` resuming an `h2` page's
  ticket without offering early data, since the ticket's ALPN protocol is
  not in its offer, and
  `a_negotiated_request_after_a_firefox_upgrade_restarts_on_an_alpn_change`
  the restart after a later request resumes that Upgrade's ticket.
  `a_connector_with_the_websocket_alpn_list_sends_the_policy_client_hello`
  in `crates/phantom-net/src/tls/tests/alps.rs` shows that the Upgrade
  connection's ClientHello is the one the policy's TLS settings build.
- `a_resumed_negotiated_get_travels_as_early_data`,
  `an_alpn_change_restarts_a_get_on_a_full_handshake`, and
  `an_alpn_change_restarts_a_post_without_sending_its_body_early` drive the
  negotiated public client; the last shows the rejected connection received
  nothing and the POST and its body reached only the new connection.
- `exact_http1_reports_an_alpn_change_after_early_data`,
  `exact_http2_reports_an_alpn_change_after_early_data`,
  `exact_http1_reports_a_handshake_failure_after_early_data`, and
  `exact_http2_reports_a_handshake_failure_after_early_data` check the
  errors of exact requests, and
  `negotiated_request_reports_a_handshake_failure_after_early_data` the
  error of a negotiated one.
- `a_lease_whose_alpn_change_settled_before_dispatch_restarts`, in
  `crates/phantom/src/session/http1_or_2_pool/tests/early_data.rs`, hands
  the negotiated pool a connection whose rejection and ALPN change were
  already processed, and the request still restarts on a full handshake.
- `a_post_waits_for_early_data_within_its_own_connect_attempt` holds a POST
  in pool admission longer than its connect limit; its wait for the early
  data answer still fits that limit, which counts from its own connection
  attempt.

Limits:

- No capture shows a server rejecting early data; the rejection paths follow
  Firefox's source. Firefox's other early-data rules are not modeled: it
  stops offering early data to an origin after certain TLS alerts, and
  restarts a request without early data after a `425 Too Early` response.
- Early data is offered on negotiated and exact HTTP/1.1 and HTTP/2
  connections and on direct WebSocket openings that resume a ticket. A
  `Client` WebSocket opening takes its tickets from one request pool, the
  negotiated pool for a profile-policy opening and the exact pool of its
  protocol otherwise, and from the pool key of the current Tokio runtime,
  as requests do. After `websocket-http1`'s opening, Firefox's `/done`
  request resumed a ticket the page's connection was issued, where Phantom
  presents the newest ticket it holds, one the WebSocket's connection was
  issued ([roadmap](../roadmap.md)). When that ticket came from an Upgrade
  connection that offered only `http/1.1`, a Firefox-profile negotiated
  request sends its GET as early data under `http/1.1`, and a server that
  selects `h2` rejects it, so the request starts again on a full handshake. Firefox's profile-policy opening
  in `websocket-http1` offered `h2` and `http/1.1` and sent an Upgrade
  when the server selected `http/1.1`; Phantom's opening without an
  HTTP/2 session takes a new HTTP/2 connection and fails when the server
  selects `http/1.1`, so the replay of that capture opens exactly
  HTTP/1.1. Phantom offers none on a
  connection that offers ECH from an HTTPS record, which Firefox does not
  exclude: NSS offers `early_data` in a resumed ECH connection's outer
  ClientHello when the ticket permits it, and copies it into the inner one
  (`tls13_ClientSendEarlyDataXtn`, `tls13_ClientAllow0Rtt`, and
  `tls13_ConstructInnerExtensionsFromOuter`,
  `security/nss/lib/ssl/tls13exthandle.c:864-873`, `tls13con.c:7041-7078`,
  and `tls13ech.c:1350-1558`). No Firefox recipe offers ECH from HTTPS
  records, so only a custom profile that sets both
  `TlsSettings::tcp_early_data` and `TlsSettings::ech_from_https_records`
  meets this ([roadmap](../roadmap.md)). An exact request or a WebSocket
  opening whose server picks another ALPN protocol after a rejection fails
  instead of restarting, as Firefox restarts the transaction.
- The early data's record boundaries are BoringSSL's, not NSS's.
- A Phantom client has no network partitions. Its requests behave like one
  browser page's top-level site: each origin and route has one ticket cache.
- Firefox's order among the tickets it holds varied between runs; Phantom
  presents the newest first. Firefox held all eight tickets it was given, so
  its true limit may be higher than the recipe's eight.
- Loopback, headless, and HTTP/1.1 or HTTP/2 only. The captures cannot show
  how long a browser keeps a ticket; every ticket was valid for one day.

### Firefox ECH GREASE payload evidence

What is claimed: `firefox::v157_tls` and `firefox::v157_http3_tls` size the
ECH GREASE payload as Firefox 157 does, from the ClientHello that carries
it, so a fresh ClientHello to a host name carries 240 payload bytes, one
that resumes with the capture servers' tickets 368, and one to an IP
literal the length Firefox pads it to.

Evidence: NSS at tag `FIREFOX_157_0_RELEASE` sizes the payload in
`tls13_MaybeGreaseEch` (`security/nss/lib/ssl/tls13ech.c:2143`, called from
`ssl3con.c:5889`) after every other extension, `pre_shared_key` included, is
built and before padding. It encodes the EncodedClientHelloInner a real ECH
offer of that ClientHello would encrypt: `server_name` and `pre_shared_key` in
full, `supported_versions` with TLS 1.3 alone, no `ec_point_formats`,
`extended_master_secret`, `session_ticket`, or `renegotiation_info`, and every
other extension named in `ech_outer_extensions`. `tls13_PadChInner` pads it by
a `maximum_name_length` of 100 less the length of the URL host, to a multiple
of 32 bytes, and the AEAD adds 16. Firefox sets the 100 from
`security.tls.ech.grease_size` over TCP; neqo leaves NSS's default, also 100.
The rule gives the payload of every retained Firefox 157.0 ClientHello: the 87
ClientHello records under `fixtures/tls/firefox/157.0/` and
`fixtures/http3/firefox/157.0/`, some repeated between a snapshot and the file
split from it, and every one under `ip-literal/`.

| ClientHellos | Payload bytes | Fixtures |
| --- | --- | --- |
| Fresh, TCP and QUIC, to a host name | 240 | `client-hello*.txt`, `resumption-*.txt`, and the QUIC snapshots and resumption captures |
| Resumed, TCP and QUIC, each with a 64-byte ticket; a 32-byte binder over TCP and a 48-byte one over QUIC | 368 | The same resumption captures |
| Fresh TCP to `127.0.0.1` and `[::1]`, at the default `grease_size` | 240 | `ip-literal/tcp-ipv4.txt`, `tcp-ipv6.txt` |
| Fresh QUIC to `127.0.0.1` | 208 | `ip-literal/quic-ipv4.txt` and three runs at other `grease_size` values |

`fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/` keeps ClientHellos
Firefox 157.0 sent on 2026-10-02 on the Windows 11 capture host, headless with
fresh profiles, to `https://127.0.0.1:<port>/` and `https://[::1]:<port>/`,
recorded with `scripts/capture/ip_literal_client_hello.py`
([capture README](../../scripts/capture/README.md#clienthellos-to-ip-literals)).
Over TCP a listener read each ClientHello and closed the connection, so
Firefox retried, and its later ClientHellos drop `compress_certificate`. Over
QUIC the alt-svc test mapping pointed Firefox at `h3` on the same port, and a
UDP socket decrypted the client's Initial packets with the Initial keys.
Neither listener answered.

Firefox sends no `server_name` to an IP literal, yet pads by the address
text, an IPv6 address without brackets. The first evidence is an earlier TCP
sweep of `grease_size`, kept as `tcp-ipv4-sweep-<label>.txt` and
`tcp-ipv6-sweep-<label>.txt`, whose script recorded each run's label but not
the size it set. The 32-byte boundary, where the first ClientHello's payload
moves from 208 to 240 bytes, falls at label 10 for `127.0.0.1` and at label
4 for `::1`. Those boundaries are six labels apart, the 9-byte `127.0.0.1`
less the 3-byte `::1`. Padding by no host would put both at one label, and
padding by `[::1]` four labels apart. Turning labels into sizes assumes one
offset for both sweeps; with 84 plus the label, IPv4 crosses between 93 and 94
and IPv6 between 87 and 88. The committed tool then recaptured those four
sizes and records each in a `prefs=` line (`tcp-ipv4-grease-size-93.txt` to
`tcp-ipv6-grease-size-88.txt`): 93 gives 208 bytes and 94 gives 240 for
`127.0.0.1`, and 87 gives 208 and 88 gives 240 for `::1`. The QUIC runs record
their size too (77, 85, and 86), and all gave 208, as QUIC does not read the
preference. No QUIC capture to `[::1]` received a datagram, with the alt-svc
mapping written as `::1` or as `[::1]`, so the IPv6 literal is verified over
TCP only.

The recipes set `EchGreasePayloadLength::FromClientHello` with a
`maximum_name_length` of 100. The backend builds the same inner ClientHello
from the ClientHello it is about to send (native patch 0017 of the btls fork,
described in `vendor/btls/PHANTOM.md`). For the padding, TCP and QUIC
connections pass `EchGreasePayloadLength::ip_literal_host` of the server
name: an IP literal without brackets, or nothing for a host name, which pads
by the server name itself.

Tests, in `crates/phantom-net`, check the lengths against
`tls::test_support::nss_ech_grease`, a model of the rule written from NSS
rather than from the patch:

- `firefox_157_captured_ech_grease_payloads_follow_the_nss_rule` checks the
  model against the 87 TCP and QUIC records: 41 fresh at 240 bytes and 46
  resumed at 368.
- `firefox_157_tls_recipe_matches_windows_capture` and the QUIC
  `firefox_157_quic_offer_and_streams_match_windows_capture` send 240 bytes,
  as the fresh captures do.
- `firefox_resumed_client_hello_matches_the_capture_without_early_data`
  resumes with a 64-byte ticket and sends 368 bytes, byte for byte as the
  capture apart from per-connection values
  ([TLS resumption over TCP](#tls-resumption-over-tcp-evidence)).
- `firefox_resumed_client_hello_with_early_data_matches_the_capture` and
  `firefox_157_resumed_quic_client_hello_matches_the_resumption_captures`
  resume with a loopback server's ticket, whose length differs from the
  capture server's. Each payload equals the model's length for Phantom's own
  ClientHello, every captured payload equals the model's 368, and the model
  gives 368 for Phantom's ClientHello with the captured `pre_shared_key`
  length.
- `firefox_157_ip_literal_captures_pad_ech_grease_by_the_host_text` checks
  the model against every ClientHello of the TCP runs at a known size, the
  retries included, at the size each records.
- `firefox_157_ip_literal_sweep_boundaries_follow_the_host_length` finds the
  sweep's boundaries at labels 10 and 4 and checks that their gap is the
  difference in host length, not zero or the gap `[::1]` would give.
- `firefox_157_recipe_matches_the_ip_literal_captures` sends the first TCP
  ClientHello shape of each IP-literal capture, without `server_name`, with
  the same extension layout and a 240-byte payload, to `127.0.0.1` and
  `::1`.
- `firefox_157_quic_client_hello_pads_ech_grease_by_an_ip_literal_host`
  sends 208 bytes over QUIC to `127.0.0.1`, with the extension set and tail
  of the four QUIC captures, and the model's length to `::1`.

How to reproduce: the fresh and resumed lengths come from the snapshot and
resumption captures above. The IP-literal runs come from the
[capture README](../../scripts/capture/README.md#clienthellos-to-ip-literals)
commands, with `--grease-size` for each size of a sweep.

Limits:

- A resumed payload depends on the ticket and the binder hash the server
  chose. The early-data cases are compared through the model, because no
  loopback server here issues early-data tickets as short as the capture
  servers'.
- The IPv6 literal is captured over TCP only; over QUIC the recipe follows
  the rule.
- An IPv4-mapped IPv6 literal pads by the text Phantom has for it, which Rust
  writes as `::ffff:127.0.0.1`. How Firefox writes such a host, and so how
  many bytes it pads by, is not verified.
- The rule is read from the NSS of Firefox 157.0. A later NSS that changes the
  inner ClientHello or the padding changes the length.

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
Firefox 157 send to an HTTP proxy for plaintext `http://` and `ws://`
origins. Phantom's `ws://` route through an HTTP proxy follows them; the
remaining differences from the [route matrix](../reference/route-matrix.md)
are listed at the end of this section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains captures from
headless Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 157.0 on
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

| Behavior | Chrome 154 and Edge 154 | Firefox 157 |
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
  stream 11 of one connection; Brave 154 and Opera 136 do the same. Firefox
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
  `firefox::v157_proxy_connect` sends the captured CONNECT fields in the
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
- Connection sharing on an H2 proxy: each client keeps pooled proxy
  connections, and `ProxyConnectTemplate::http2_connections` decides which
  requests share one. `chromium::v154_proxy_connect` uses `Shared`, which
  puts forwarded requests, CONNECT tunnels, and WebSocket tunnels on one
  connection, as Chrome, Edge, Brave, and Opera do;
  `firefox::v157_proxy_connect` uses `ByPurpose`, which gives each of the
  three its own, as Firefox does.
  `connection_sharing_follows_the_captured_proxy_connections` in
  `crates/phantom-profile/src/proxy_connect/tests.rs` groups the page
  requests of every run of every `https-proxy-*` capture by connection and
  checks the recipe of each browser against them.
  `crates/phantom/tests/proxies/proxy_h2_multiplex.rs` checks that tunnels to three
  origins arrive as streams 1, 3, and 5 of one proxy connection, that the
  Chromium recipe adds forwarded requests and a `ws://` tunnel to it and the
  Firefox recipe keeps them on connections of their own, each starting at
  stream 3, that two separately built clients
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
`407` and accepts the credentials, Chrome 154, Edge 154, and Firefox 157 send
`Proxy-Authorization` on the first attempt of every later CONNECT tunnel and
forwarded request to that proxy. Phantom does the same by default for CONNECT
tunnels on both proxy transports, including WebSocket tunnels, and for H1 and
H2 forwarding. The browsers send the replay after a `407` on the connection
that carried it when the proxy keeps that connection open, and so does
Phantom on HTTP/1.1 proxy connections. On an HTTP/2 proxy connection both
browsers index `proxy-authorization` in HPACK, and so do Phantom's recipes
([HPACK encoder evidence](#hpack-encoder-evidence)). The differences that
remain are listed at the end of this section.

Evidence: [`fixtures/proxy/`](../../fixtures/proxy/) retains four
authentication scenarios per browser, `http-proxy-auth-*` and
`https-proxy-auth-*`, with loopback and named origins, from the same headless
Chrome 154.0.8037.58, Edge 154.0.4258.37, and Firefox 157.0 builds on Windows
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

| Behavior | Chrome 154 and Edge 154 | Firefox 157 |
| --- | --- | --- |
| `407` responses per page load | One, to the first navigation request | Same |
| Replay after that `407` | Same plaintext proxy connection; new stream on the same H2 proxy connection | Same |
| Later `ws://` CONNECTs and the `fetch()` | Carry `Proxy-Authorization` with no `407` | Same, including on a second H2 proxy connection opened for the WebSockets |
| H1 CONNECT fields | `Host`, `Proxy-Connection`, `User-Agent`, `Proxy-Authorization` | `User-Agent`, `Proxy-Connection`, `Connection`, `Host`, `Proxy-Authorization` |
| H2 CONNECT fields | `:method`, `:authority`, `user-agent`, `proxy-authorization` | Same |
| `Proxy-Authorization` in an H1 forwarded request | Third, after `Host` and `Proxy-Connection`, on the replay and on later requests | Last on the replay; before `Connection` on later requests |
| `proxy-authorization` in an H2 forwarded request | First field after the pseudo-fields | Before `te` on the replay; before `priority` on later requests |
| HPACK representation of `proxy-authorization` | Literal with incremental indexing (static name 49) on first use on a connection, then indexed | Same |

Browser source, checked at Chromium tag 154.0.8037.58 on 2026-09-24 and at
Firefox tag `FIREFOX_157_0_RELEASE` on 2026-10-02, agrees and explains the mechanism:

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
  CONNECT (`nsHttpConnection.cpp` lines 2094 to 2101), and clears the entry
  when the proxy rejects it (`nsHttpChannelAuthProvider.cpp` lines 889 to
  899). Its cache has no size limit.
- Neither browser authenticates a CONNECT-UDP request to a proxy: Chromium
  leaves it as a TODO (`net/quic/quic_proxy_datagram_client_socket.cc` line
  367), and Firefox copies the value into `Authorization`
  (`netwerk/protocol/http/HttpConnectionUDP.cpp` lines 609 to 615).
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
  (`netwerk/protocol/http/nsHttpConnection.cpp` lines 1074 to 1109). A
  challenged CONNECT leaves the connection in its tunnel-setup state
  (lines 1169 to 1232), and a keep-alive connection returns to the idle pool
  for the replay (`nsHttpConnection.cpp` lines 938 to 982,
  `nsHttpConnectionMgr.cpp` lines 2715 to 2807). Basic is not a sticky
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
  credentials, and that a separately built client starts with an empty
  record.
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
  replay on the same H2 proxy connection, a second `407`, and the HPACK form
  of the forwarded `proxy-authorization` field: absent on the challenged
  request, a literal with incremental indexing on static name 49 on the
  replay, and no field naming static entry 49 on the next request.
  `h2_proxy_basic_challenge_replays_once_on_the_challenged_connection` checks
  that a challenged H2 CONNECT and its replay arrive as streams 1 and 3 of one
  proxy connection.
- `crates/phantom-net/src/proxy/tests/http2_challenge.rs` checks the frames
  of that exchange: an empty END_STREAM DATA frame ends stream 1 before the
  replay's HEADERS on stream 3, stream 1 is not reset, and the replay carries
  `proxy-authorization` as a literal with incremental indexing on static
  name 49. It also
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
