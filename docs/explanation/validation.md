# Validation

Phantom makes per-layer claims about matching recorded browsers. This page records the evidence behind each of those claims and what
that evidence does not cover. It is for reviewers, contributors, and anyone
deciding how far to trust a claim.

After [Trust at a glance](#trust-at-a-glance), the page has four parts:

- [Evidence rules](#evidence-rules) define what counts as proof.
- [Browser recipes](#browser-recipes) record the captures and browser source
  behind the named browser profiles.
- [Feature evidence](#feature-evidence) records the tests behind individual
  client features, and the browser captures where they exist.
- [Other checks](#other-checks) covers external suites, diagnostics,
  benchmarks, and contributor gates.

Each evidence section ends with its limits. Read them before relying on a
claim.

## Trust at a glance

The evidence falls into four kinds:

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
| [TLS, H2, QUIC, and H3 recipes](#cross-platform-transport-parity) | Chrome 152 and Firefox 154 captures on macOS and Windows, replayed by recipe tests | One macOS build and one Windows build; no Linux; headless launches |
| [Chrome 153, Edge 153, and Firefox 156 recipes](#chrome-153-edge-153-and-firefox-156-recipes) | Windows browser captures, replayed by recipe tests | One Windows build per browser; platform independence inferred from 152 and 154 |
| [TCP socket options and address racing](#tcp-socket-option-evidence) | Browser source at one tag per browser, plus socket read-back tests | No capture confirms the options; field trials cannot be ruled out |
| [SSE reconnect](#sse-browser-reconnect-evidence) | Chrome 153 and Firefox 156 captures, replayed against Phantom | Plaintext HTTP/1.1 on Windows only |
| [WebSocket openings](#websocket-browser-evidence) | Chrome 153, Edge 153, and Firefox 156 captures | No subprotocols, H3, proxies, macOS, or Safari |
| [Alt-Svc racing](#alt-svc-racing-evidence) | Chrome 153 captures and Chromium source, plus loopback tests of Phantom | Caller-supplied origin delay; several listed differences from Chromium |
| [Alt-Svc upgrade](#alt-svc-http3-upgrade-evidence) | Loopback tests | No browser `Alt-Used` ordering; no proxy routes |
| [Request trailers](#ordered-request-trailer-evidence), [forward proxies](#forward-proxy-evidence), [H3 over SOCKS5](#h3-socks5-udp-evidence) | Loopback tests | No browser-capture fidelity |
| [Connection and status retries](#connection-retry-evidence) | Loopback tests | Not browser retry policy; some paths have no recovery test |
| [Content decoding](#content-decoding-evidence) | Unit and loopback tests; browser source for documented divergences | No browser-parity claim |
| [Response-body limits](#response-body-limit-evidence) | Unit tests and an H1 loopback test | No H2 or H3 test exceeds a limit |
| [H2 receive bounds](#adversarial-coverage) | Hostile-peer regressions | Not browser evidence |

## Evidence rules

### Evidence ladder

A claim about wire-sensitive behavior needs every level that applies to it:

1. A deterministic local assertion for parsing, validation, and lifecycle.
2. A normalized differential against a pinned capture, at the level of bytes,
   frames, packets, or qlog events.
3. A hostile-peer regression for relevant unusual or malformed input.
4. Supplemental evidence from interoperability tests or a live observer.

A working connection and a matching summary fingerprint do not show that
behavior is browser-compatible.

### Fixtures and normalization

A fixture records the client, version, platform, launch conditions, and raw
evidence needed to reproduce a claim. Strict decoders keep the ordered
semantic fields that differentials compare.

Normalization may remove values that must vary: random bytes, cryptographic
key material, timestamps, connection IDs, packet numbers, and measured GREASE
values. It must not erase order, presence, lengths, negotiated values, or any
other behavior a profile controls.

Built-in recipes are compared through the same public path that users
exercise. A profile component is not complete when it merely parses or
connects.

### Adversarial coverage

Scripted peers vary fragmentation, flow control, challenge sequences, resets,
shutdown, malformed input, and cancellation. Tests assert the ordered
outcome, the error category, connection reuse, and bounded completion.

Traffic that is valid but unusual may be compared with a retained browser
run. Malformed traffic is a robustness test: safety and bounds take precedence
over reproducing unsafe behavior. Each minimized failure becomes an ordinary
regression.

The [parser fuzzing workflow](../../.github/workflows/fuzz.yml) runs each
target under AddressSanitizer. It runs for 15 seconds on relevant pull
requests and pushes, and for 300 seconds on its weekly schedule or a manual
dispatch. Every run starts from the newest per-target corpus in the GitHub
Actions cache, and only scheduled runs save a grown corpus back. The corpus is
therefore a cache that can expire or be evicted, not a reviewed, committed
seed set. A failing input is kept only as a short-lived workflow artifact
until it is minimized into a regression.

HTTP/2 receive bounds have raw-peer regressions in
`crates/phantom-net/src/http2/tests/adversarial_*.rs`:

- Floods of empty, padded-empty, and unread one-byte DATA frames each end with
  exactly one `GOAWAY(ENHANCE_YOUR_CALM)` at the first frame over the
  backported RUSTSEC-2026-0258 limit. The empty flood runs with both the
  Chrome and Firefox profiles. 100 empty frames are tolerated and never
  surface as body chunks.
- A response header list over the receive limit fails with
  `Http2Error::ResponseHeaderListTooLarge` and one
  `RST_STREAM(PROTOCOL_ERROR)`, while a sibling request on the same connection
  succeeds. The limit is the 262,144 bytes the Chrome profile advertises, or
  the unadvertised 393,216-byte ceiling for Firefox. The tests also check that
  the Firefox SETTINGS still omit `SETTINGS_MAX_HEADER_LIST_SIZE`.
- The empty, nonempty, and cumulative CONTINUATION floods also run against the
  Firefox ceiling.
- Eight informational responses may precede a final response. The ninth,
  alone or in a burst of 1,000, fails with
  `Http2Error::TooManyInformationalResponses` and one
  `RST_STREAM(ENHANCE_YOUR_CALM)`, while a sibling request succeeds.
- A peer `SETTINGS_HEADER_TABLE_SIZE` of 65,536 or 2^32 - 1 produces the same
  uncapped dynamic-table-size update that Chromium's quiche encoder and
  Firefox's compressor emit, and the connection stays usable. Upstream h2's
  4 KiB encoder cap is not ported (see `vendor/http2/PHANTOM.md`).

These are robustness tests against a hostile peer, not browser-capture
evidence.

## Browser recipes

A recipe is the wire data for one browser build at one protocol layer, such
as `chromium::v153_tls`. The sections below record the captures and source
reading behind each recipe and the tests that replay them.

### Cross-platform transport parity

The retained Chrome 152 and Firefox 154 recipes were captured on macOS. A
second capture set on Windows 11 (build 26200, x64) tests whether their
transport layers depend on the host platform. Safari evidence remains
macOS-only.

Branded Chrome 152 can no longer be installed on Windows. The Chrome
comparison is therefore triangulated, so that platform is not confounded with
build flavor or version:

| Comparison | Isolates | Result |
| --- | --- | --- |
| Chrome for Testing 152.0.7977.83 (Windows) vs retained branded 152.0.7977.83 (macOS) | platform | equal on TLS, H2 startup, QUIC ClientHello, QUIC transport parameters, H3 SETTINGS and pseudo-header order, and captured H3 request field order and non-persona values |
| Chrome for Testing 153.0.8010.48 vs branded Chrome 153.0.8010.48 (both Windows) | build flavor | equal on the same layers |
| Firefox 154.0 (Windows) vs retained Firefox 154.0 (macOS) | platform | equal on TLS and H2 startup |

By default, Chrome for Testing applies its bundled field-trial testing
configuration. With that configuration it:

- adds extension `0x12e0` (empty payload) to TCP and QUIC ClientHellos;
- raises QUIC `max_idle_timeout` from 30000 ms to 300000 ms;
- sends Google connection options `ORIGNOIP` instead of `ORIG`; and
- moves `accept-language` before `upgrade-insecure-requests` in the H3
  navigation request.

Every equal result above therefore comes from Chrome for Testing launched with
`--disable-field-trial-config`. Branded Chrome 153 on Windows matches that
configuration, not the testing one. The testing-configuration capture is
retained as
`fixtures/tls/chrome/152.0.7977.83/windows-11-26200/client-hello-field-trial-config.txt`
so that the difference stays visible.

Comparisons normalize only per-connection randomness:

- TLS and QUIC GREASE values normalize to one sentinel. Extension order is
  compared as a multiset, because Chrome permutes it per connection. At least
  five fresh-profile samples per build were compared.
- Client random, session ID, key-share bytes, ECH GREASE config ID and
  payload bytes, and the QUIC initial source connection ID reduce to lengths
  or are ignored. Chrome chooses its ECH GREASE payload length per connection,
  so that length is excluded from record-length comparison.
- Chrome's trust-anchor ID order differs between browser processes on both
  platforms but not between connections of one process (see
  [Chrome trust-anchor ID order](#chrome-trust-anchor-id-order)), so the list
  is compared as a set. Its GREASE `version_information` entry changes
  position; the chosen version stays first.
- Firefox 154 on Windows chooses its ECH GREASE AEAD per connection, between
  AES-128-GCM (`0x0001`) and ChaCha20-Poly1305 (`0x0003`): 7 and 8 of 15
  samples. The retained macOS sample carries `0x0001`. A follow-up
  multi-connection capture saw both values in each of three processes (359
  and 337 of 696 connections, all with a 239-byte payload). That is
  consistent with NSS taking the choice from the low bit of fresh
  per-handshake random bytes. The comparison therefore treats the AEAD as
  per-connection randomness. The Firefox 154 and 156 recipes list both AEADs
  in `ech_grease_aeads`, and the patched BoringSSL backend draws one uniformly
  per connection from fresh random bytes, keeping it across a
  HelloRetryRequest. Each Firefox recipe test replays both retained captures,
  then requires 200 loopback connections from one connector to contain only
  these two values, with each count in 60..=140. A fair draw fails that bound
  with probability below 1e-7. Only the distribution is reproduced; NSS and
  BoringSSL draw from different random sources.
- Every retained Chrome ClientHello, over TCP and QUIC, and all 1,248
  follow-up Chrome connections use HKDF-SHA256 with AES-128-GCM for ECH
  GREASE. The Chrome TLS recipe tests compare that cipher suite exactly, and
  `chromium_recipes_emit_aes_128_gcm_ech_grease_on_every_connection` checks it
  on 64 connections from one connector for each of Chrome 152, Chrome 153,
  and Edge 153. Chromium-family recipes leave `ech_grease_aeads` empty and
  rely on the backend default, which selects AES-128-GCM because the recipes
  set `aes_hardware`.
- `user-agent`, `sec-ch-ua`, `sec-ch-ua-mobile`, and `sec-ch-ua-platform` are
  persona data and differ by platform and flavor by design. Only their
  positions in the request field order are compared.

The Chrome H3 recipe models only the request pseudo-header order; ordinary
navigation fields are caller data. Their cross-platform equality is therefore
checked capture to capture
(`chrome_152_windows_h3_request_fields_match_macos_capture_except_persona_values`),
not by replaying a recipe. The flavor comparison at 153 was made with a
scratch comparator and is not replayed by a test.

Deterministic recipe tests replay the retained Windows fixtures:

- `chrome_152_tls_recipe_matches_windows_chrome_for_testing_capture`
- `chrome_152_http2_recipe_matches_windows_chrome_for_testing_capture`
- `chrome_152_quic_client_hello_recipe_matches_windows_chrome_for_testing_capture`
- `chrome_152_quic_recipe_matches_windows_chrome_for_testing_capture`
- `chrome_152_http3_recipe_matches_windows_chrome_for_testing_capture`
- `firefox_154_tls_recipe_matches_windows_capture`
- `firefox_154_recipe_draws_either_ech_grease_aead_per_connection`
- `firefox_154_http2_recipe_matches_windows_capture`

Limits:

- Chrome 152 parity rests on Chrome for Testing plus the flavor comparison at
  153. It assumes that the flavor equivalence observed at 153 also held
  at 152.
- One Windows build and one macOS build were compared. Linux, other Windows
  releases, and other macOS releases are not covered.
- Chrome for Testing publishes no checksums, so the archive hashes were
  recorded on first use (SHA-256 below). Firefox 154.0 was verified against
  Mozilla's signed `SHA512SUMS`.
- Only headless launches were compared, matching the retained fixtures.

| Artifact | Source | SHA-256 |
| --- | --- | --- |
| Chrome for Testing 152.0.7977.83 win64 | `https://storage.googleapis.com/chrome-for-testing-public/152.0.7977.83/win64/chrome-win64.zip` | `6ed70e277c5dd6cb7a31e2ccb8f88d071b4928984e3b47d846920764eab712e7` |
| Chrome for Testing 153.0.8010.48 win64 | `https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.48/win64/chrome-win64.zip` | `9a4d427ec9193ef8347e864076757f7e1e9c486f0a21c4781f5ea845bffd8dd1` |
| Firefox 154.0 win64 en-US | `https://archive.mozilla.org/pub/firefox/releases/154.0/win64/en-US/Firefox%20Setup%20154.0.exe` | SHA-512 `514dfa9f…1bd35398`, signed by Mozilla release subkey `827E 6586 0867 9618 CD34 9F93 678E 455D 7676 7AA3` |
| geckodriver 0.37.1 win64 (H2 WebDriver launch) | GitHub release asset | `dfed9315abe8d2fbc1b6161a2ee8002452e79cf05ee92fdc653a4e26bc35edd8` |

Launch arguments are recorded in each fixture. Chrome captures use the same
flags as the retained macOS fixtures, plus `--disable-field-trial-config` for
Chrome for Testing. The Firefox H2 capture uses WebDriver with
`acceptInsecureCerts` and `network.dns.forceResolve=127.0.0.1`.

#### Chrome trust-anchor ID order

A follow-up capture on the same Windows 11 host loaded one loopback page per
fresh headless process. Each page opened 48 TLS connections to loopback
listeners that recorded the ClientHello and closed. Launch flags matched the
retained Chrome fixtures, with `--disable-field-trial-config` for Chrome for
Testing.

| Build | Processes | Connections | Orders per process | Distinct orders |
| --- | --- | --- | --- | --- |
| Chrome for Testing 152.0.7977.83 | 13 | 624 | 1 | 5; the most frequent (5 of 13) equals the retained macOS order |
| Chrome 153.0.8010.48 | 13 | 624 | 1 | 7; the most frequent occurred 5 times |

Every connection repeated its process's trust-anchor order, while the
extension order differed on all 1,248 connections. The orders are neither
rotations nor uniform permutations. Distinct orders share adjacent ordered ID
pairs far more often than uniform shuffles would: 32 shared pairs among the
five 152 orders against a uniform mean of 9.7, and 49 against 20.2 among the
seven 153 orders. None of 5,000 simulated uniform sets reached either count.
This matches the Chromium source of that period, which serialized the list by
iterating an `absl::flat_hash_set`. Chromium commit `942bda4298c1`
(2026-08-28) later sorts the list before encoding.

The Chrome 152 recipe therefore keeps one fixed order, the retained macOS
order. Per-connection shuffling would contradict the observed behavior. These
multi-connection captures are not retained as fixtures.

Chrome 153 advertises 28 IDs: the four `d67909xx` IDs `02`, `03`, `09`, and
`0e` are absent, and none is new. A later capture for the Chrome 153 recipe
recorded one ClientHello from each of 60 fresh branded Chrome 153.0.8010.48
processes, with the retained Chrome TLS launch flags (no
`--disable-field-trial-config`). It saw 35 distinct orders. The most frequent
occurred 6 times and the next two 5 times each. The retained
`client-hello.txt` from the earlier capture has an order not among the 60.

`chromium::v153_tls` carries the order seen in 6 processes. Its lead over the
runner-up is one process, so it is one real observed order, not evidence of a
preferred Chrome order.
`fixtures/tls/chrome/153.0.8010.48/windows-11-26200/trust-anchor-orders.txt`
retains every order, its count, and the per-process sequence.
`chrome_153_tls_trust_anchor_order_is_the_most_frequent_process_order` and
`chrome_153_tls_recipe_emits_the_most_frequent_trust_anchor_order` check it.

### Chrome 153, Edge 153, and Firefox 156 recipes

The browsers installed on the Windows 11 capture host (build 26200, x64) were
captured again to add version recipes. Every capture used a fresh profile, a
loopback listener, and the launch flags of the retained fixture for the same
layer. Chrome and Edge ran without `--disable-field-trial-config`, as the
retained branded Chrome 153 fixtures did.

| Browser and layer | Samples | Result against the prior recipe |
| --- | --- | --- |
| Chrome 153.0.8010.48 TLS | 60 processes | Equal to `v152_tls` except the 28 trust-anchor IDs |
| Chrome 153 H2 startup | Retained raw startup | Equal to `v152_http2` |
| Chrome 153 H2 request HEADERS | 3 retained H2 session runs | Pseudo-headers `m,a,s,p`; exclusive, parent 0, weight 256; equal to `v152_http2` |
| Chrome 153 QUIC ClientHello | 3 processes | Equal to `v152_http3_tls` except the 28 trust-anchor IDs |
| Chrome 153 QUIC, H3 SETTINGS and request | Retained startup plus 3 | Equal to `v152_quic`, `v152_http3`, and `v152_http3_request`; request fields equal except persona values |
| Chrome 153 client hints | 3 runs (plus 1 headful) | Same 11 names, order, and delivery as the 152 macOS recipe; Windows and 153 values |
| Edge 153.0.4234.48 TLS | 20 processes | Chrome 153 ClientHello without the trust-anchor IDs extension |
| Edge 153 QUIC ClientHello | 3 processes | Chrome 153 QUIC ClientHello without the trust-anchor IDs extension |
| Edge 153 H2 startup and request HEADERS | 1 raw startup, 3 H2 session runs | Equal to `chromium::v153_http2` |
| Edge 153 QUIC, H3 SETTINGS and request | 3 processes | Equal to the Chrome 153 recipes; request fields equal except persona values |
| Edge 153 client hints | 3 runs (plus 1 headful) | Chrome 153 names, order, and delivery; Edge brand list and version values |
| Firefox 156.0 TLS | 12 processes | `v154_tls` without the FFDHE-2048 and FFDHE-3072 groups, with a 240-byte (was 239) ECH GREASE payload |
| Firefox 156 H2 startup and request HEADERS | 3 retained H2 session runs, 6 connections | Equal to `v154_http2` |

The new recipes follow from those differences:

- `chromium::v153_tls` and `chromium::v153_http3_tls` replace only the
  trust-anchor list of the 152 recipes.
  `chromium::v153_{http2,http3,http3_request,quic}` return the 152 recipes
  unchanged.
- `edge::v153_tls` and `edge::v153_http3_tls` remove the trust-anchor IDs from
  the Chrome 153 recipes. Edge has no H2, QUIC, or H3 recipe of its own,
  because those layers equal Chrome 153 on every compared field.
- `firefox::v156_tls` changes the two differing fields of `v154_tls`, and
  `firefox::v156_http2` returns `v154_http2`.
- Client hints carry platform and build data on the wire, so their recipes are
  `chromium::v153_windows_client_hints` and
  `edge::v153_windows_client_hints`.

Comparisons used the normalization of
[Cross-platform transport parity](#cross-platform-transport-parity), which
covers GREASE values, Chromium extension order, random bytes, key shares, ECH
GREASE payload bytes, and Chromium's per-connection ECH payload length. They
also normalized the H3 reserved setting and its value width, the QUIC GREASE
transport parameter length, and the position of the reserved QUIC version.

Every Chrome and Edge sample, over TCP and QUIC, used HKDF-SHA256 with
AES-128-GCM for ECH GREASE. Firefox 156 kept its fixed extension order and
chose AES-128-GCM on 7 and ChaCha20-Poly1305 on 5 of 12 connections, each with
a 240-byte payload. One sample of each is retained. As for 154, the recipe
lists both AEADs, and
`firefox_156_recipe_draws_either_ech_grease_aead_per_connection` bounds the
per-connection split.

Edge's full version list reports `"Chromium";v="153.0.8010.53"`, a newer
Chromium build than branded Chrome 153.0.8010.48. Headful and headless runs
produced identical client hints for both browsers.

The H2 request evidence reuses the navigation in the retained WebSocket
session fixtures (`fixtures/websocket/*/accept.txt`, recorded through
`http2_session.py`). Those fixtures already hold each navigation's SETTINGS,
WINDOW_UPDATE, HEADERS priority, and HPACK field order. No raw Firefox 156 H2
startup fixture was taken: the raw startup tool needs WebDriver certificate
trust for Firefox, and geckodriver is not installed on the host. The extended
CONNECT pseudo-header order and priority in those fixtures differ from the
navigation's and stay outside the named H2 recipes.

Retained fixtures:

- `fixtures/tls/chrome/153.0.8010.48/windows-11-26200/trust-anchor-orders.txt`
- `fixtures/http3/chrome/153.0.8010.48/windows-11-26200/quic-client-hello-{1,2}.txt`
- `fixtures/client-hints/chrome/153.0.8010.48/windows-11-26200/navigation.txt`
- `fixtures/tls/edge/153.0.4234.48/windows-11-26200/client-hello.txt`
- `fixtures/http2/edge/153.0.4234.48/windows-11-26200/client-startup.txt`
- `fixtures/http3/edge/153.0.4234.48/windows-11-26200/{client-startup,quic-client-hello-1,quic-client-hello-2}.txt`
- `fixtures/client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt`
- `fixtures/tls/firefox/156.0/windows-11-26200/client-hello.txt` (AES-128-GCM
  ECH GREASE) and `client-hello-chacha20-ech.txt`

Capture commands, one run per fresh browser process:

| Capture | Command |
| --- | --- |
| TLS ClientHellos | `cargo run -p phantom-testkit --example capture_client_hello` |
| Edge H2 startup | `cargo run -p phantom-net --example capture_http2_tls` |
| QUIC | `scripts/capture/chrome_http3.py --client-hello` |
| Client hints | `scripts/capture/client_hints.py` |

Chromium TLS and H2 launches use the arguments recorded in the retained Chrome
fixtures, with `https://server.phantom.test:<port>/`. Firefox TLS uses
`--headless --no-remote --profile <temporary-profile>` with
`https://localhost:9446/`. Per-process samples beyond the retained ones are
not kept; the table gives their counts.

The `chrome_153_*`, `edge_153_*`, and `firefox_156_*` tests in
`phantom-profile` and `phantom-net` replay these fixtures. TLS and QUIC
ClientHellos go through the public TLS and H3 connector paths, and H2 startup
frames through the public H2 path. H3, QUIC, H2 request, and client-hint
fields are compared against the recipe data.

Limits:

- One Windows build, and one build per browser. No macOS or Linux capture of
  these versions exists. The platform-free 153 and 156 transport names rest
  on the 152 and 154 finding that these layers did not depend on the
  platform.
- Headless launches only, except the headful client-hint check.

### TCP socket option evidence

A capture cannot show socket options, so the TCP recipes rest on browser
source at the profiled release tags rather than on retained fixtures. The
citations are to Chromium tag `153.0.8010.48` and Firefox tag
`FIREFOX_156_0_RELEASE`.

| Recipe | Source behavior |
| --- | --- |
| `chromium::v153_tcp` | `TCPClientSocket` calls `SetDefaultOptionsForClient` when it opens each socket, before connecting (`net/socket/tcp_client_socket.cc:173`, `:558`). That sets `TCP_NODELAY` and a 45-second keepalive idle time and interval: `SIO_KEEPALIVE_VALS` on Windows (`net/socket/tcp_socket_win.cc:50`, `:55-73`, `:815-818`), `TCP_KEEPIDLE` and `TCP_KEEPINTVL` on Linux (`net/socket/tcp_socket_posix.cc:88-100`, `:463-486`). |
| `firefox::v156_tcp` | `nsSocketTransport::InitiateSocket` sets `PR_SockOpt_NoDelay` on every socket before connecting (`netwerk/base/nsSocketTransport2.cpp:1449-1454`). |
| `chromium::v153_tcp` address racing | Happy Eyeballs v2 is enabled and v3 disabled by default, so every TCP connection uses a `TcpConnectJob` (`net/base/features.cc:114-124`, `net/socket/transport_connect_job.cc:118-123`). It prefers IPv6 first (`net/socket/tcp_connect_job.h:211`), the other family after a failure (`net/socket/tcp_connect_job_connector.cc:300-303`), and starts a second, IPv4-preferring attempt `kIPv6FallbackTime = 300` ms after the first (`net/socket/tcp_connect_job.h:85`, `net/socket/tcp_connect_job.cc:450-473`, `:580-616`, `:691-694`). No address is tried twice (`:703-746`); the first connection wins and a total failure returns the most recent error (`:406-431`, `:946-958`). The delay-changing trials `kAdjustIPv6FallbackTime` and `kIPv6FallbackBasedOnRTT` are disabled by default (`net/base/features.cc:128`, `:136`). |

Differences from the browsers:

- Chromium ignores a failure to set either option
  (`net/socket/tcp_socket_win.cc:71-72`). Phantom fails that connection
  attempt instead, so no connection proceeds with options the profile did not
  ask for.
- Chromium on macOS sets only the keepalive idle time
  (`net/socket/tcp_socket_posix.cc:101-105`), and Android and iOS builds
  enable no keepalive. `chromium::v153_tcp` describes Windows and Linux; a
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

- `tcp::address_racing::tests` drive the racing algorithm with scripted
  attempt outcomes and a test-controlled fallback delay. They cover IPv6
  preference, alternation, the IPv4 fallback attempt and role swap, the
  two-attempt bound, cancellation of the loser, and the returned error.
- `tcp::tests::racing_reaches_ipv4_when_nothing_listens_on_ipv6` races real
  sockets to `[::1]` and `127.0.0.1` at the same port, with a listener only on
  IPv4.
- The `tcp::tests::host_check_*` tests cover the build-time host check for
  every combination of platform capabilities. The facade rejects a Windows
  keepalive without an interval as `BuildErrorKind::InvalidProfile`.
- `tcp::tests::connected_socket_carries_requested_options` checks
  `TCP_NODELAY` and `SO_KEEPALIVE`, and on Linux and macOS the idle time and
  interval. Windows exposes no getter for the `SIO_KEEPALIVE_VALS` values.
- `tcp::tests::paths` reads back every socket opened by the direct, forward
  proxy, HTTP CONNECT (with and without Basic), HTTPS proxy, SOCKS5 (remote
  and local DNS), HTTP/1.1-or-HTTP/2, and SOCKS5 UDP control paths.
- The facade test `profile_tcp_settings_reach_every_tcp_connector` checks that
  a profile's settings reach each TCP connector the client builds, including
  the WebSocket HTTP/1.1 connector.

Limits:

- No capture confirms the options, including keepalive probe timing on an
  idle connection.
- The source was read at one tag per browser, so build-time or field-trial
  changes to these options would not be seen. Branded Chrome receives
  server-side field-trial configuration, so the source cannot rule out a
  trial that enables Happy Eyeballs v3 or a different fallback delay for some
  users.

## Feature evidence

These sections cover individual client features. Most rest on loopback tests
of Phantom's own contract. Where a section also has browser captures, it says
so and states what they cover.

### Ordered request-trailer evidence

Request trailers produced by a declared streaming body are covered through
the public client on exact H1, H2, and H3 paths and on negotiated H1/H2
paths. Static trailers are covered at each transport boundary and in the
public route and retry lifecycles. The regressions assert:

- raw H1 bytes, including casing, declaration, order, and interleaved
  duplicates;
- ordered H2 trailing fields, and the HPACK never-indexed representation for
  sensitive values; and
- H3 trailing HEADERS encoded through the connection's stateful QPACK
  encoder.

Lifecycle tests cover trailer-only, owned, and streaming bodies, matching of
declared names and multiplicity, refusal to replay a one-shot body, pre-I/O
validation, and suppression after a body error.

This evidence proves that Phantom emits the trailer block the caller selects,
with the documented protocol semantics.

Limits:

- It does not claim that a built-in browser profile emits those
  application-defined trailers by default.

### Forward-proxy evidence

The public exact-H1 route tests forward an `http://` origin in absolute form
through plaintext and TLS-encrypted proxies. The TLS fixture proves that
Phantom:

- verifies the proxy certificate and hostname with the independent proxy
  trust store;
- sends the request directly after the proxy TLS handshake, with no CONNECT
  exchange; and
- returns the proxied response through the normal streaming body path.

Negative cases cover missing proxy trust, non-H1 selections, and proxy
failure without fallback to a direct route.

Authentication regressions prove that every logical request is first sent
without credentials, and that only a strict, valid Basic `407` challenge
triggers one replay on a fresh connection over the same route. They assert:

- the position of the generated sensitive `Proxy-Authorization` field, after
  the caller's fields and before framing;
- exact replay of owned bodies and static trailers, and failure before a
  retry connection opens for a one-shot streaming body;
- typed proxy errors, without direct or protocol fallback, for a second `407`
  and for malformed or unsupported challenges; and
- an anonymous start for the next logical request, which proves that no
  challenge state is learned.

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

Public exact-H3 loopback regressions cover local-DNS `socks5://` and
remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE, both without
authentication and with RFC 1929 username/password authentication. They
verify:

- end-to-end H3 traffic;
- reuse of one route-keyed H3 connection and association across requests;
  and
- retention of the TCP control connection for the client-owned lifetime of
  the association.

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

- `datagram_from_a_non_relay_source_is_dropped` in
  `crates/phantom-net/src/proxy/tests/socks5_udp.rs` sends a well-formed
  datagram from a second loopback socket and proves that only the relay's
  next datagram is delivered.
- Codec and receive-policy unit tests in
  `crates/phantom-net/src/proxy/socks5_udp.rs` cover fragments, truncation,
  wrong domains and ports, and IPs other than a local-DNS route's fixed
  target.
- Relay-reply tests cover the compatibility rule that replaces an
  unspecified BND.ADDR with the established TCP proxy peer's IP and nothing
  else, and the rejection of a domain BND.ADDR or a zero BND.PORT.
- Remote-target tests cover exact-domain replies, case-insensitive domain
  comparison, same-port IP-form replies, and a stable logical Quinn peer.

Limits:

- No browser-capture fidelity for a proxied H3 route.
- CONNECT-UDP routes have their own loopback evidence against an h3 test
  proxy. No independent MASQUE implementation or browser capture backs them
  yet.
- Alt-Svc upgrade has separate, direct-route
  [evidence](#alt-svc-http3-upgrade-evidence).

### Alt-Svc HTTP/3 upgrade evidence

An authenticated loopback H2 origin and H3 alternative share one test
identity while listening on distinct transport locations. Public negotiated
requests prove:

- default-off and explicit bounded activation;
- learning from the ordered response fields;
- an H2 first response followed by H3;
- retention of the original authority, SNI, and certificate identity; and
- selected-protocol metadata.

The managed H3 attempt carries one automatically generated `Alt-Used` value
with the canonical alternative host and explicit port. Regressions prove that
exact H3 requests and the tested negotiated H2 origin request do not receive
the field. A request-field regression proves that a caller-supplied
`Alt-Used` is rejected before any network I/O. `Alt-Used` is reserved in both
request fields and trailers; the trailer rule is part of the pre-I/O
validation contract, not additional protocol coverage claimed here. This
evidence verifies the field's value and scope, not a browser-specific
position among ordinary request fields.

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
import learns nothing. Constructed snapshots prove:

- removal of expired entries;
- non-increasing expiry across repeated export/import round trips;
- clamping of far-future expiry;
- retention of the newest entries at capacity, with held entries winning;
- all-or-nothing typed rejection of noncanonical origins and alternatives;
- the disabled-store error; and
- `Debug` output that contains no host.

A loopback fixture serves exact H3 on the origin's own UDP port and Alt-Svc
H3 on a second port. Alternating requests between the two locations prove one
QUIC connection per location in the same pool entry, rather than a
replacement on every switch.

Limits:

- Not covered: browser `Alt-Used` ordering, upgrades on proxy routes,
  snapshots on proxy routes, and racing among multiple alternatives. Racing
  between one alternative and the origin has its own
  [evidence](#alt-svc-racing-evidence).

### Alt-Svc racing evidence

Chrome 153.0.8010.48 on Windows 11 26200 was captured with
`scripts/capture/alt_svc_race.py`. The loopback origin served H2 over TCP and
H3 over UDP on the same port, advertised as `h3=":<port>"; ma=86400`.
Fixtures are in
[`fixtures/alt-svc/chrome/153.0.8010.48/windows-11-26200/`](../../fixtures/alt-svc/chrome/153.0.8010.48/windows-11-26200/).

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
- Chrome 153 keeps `HappyEyeballsV3` disabled (`net/base/features.cc`
  line 124), so these are `HttpStreamFactory::JobController` decisions.

Source citations are to tag `153.0.8010.48`.

| Question | Observation | Source cross-check |
| --- | --- | --- |
| First new connection after learning (`race-after-learning`) | QUIC job starts first; main TCP job logs `should_wait:true`, then `HTTP_STREAM_JOB_DELAYED delay:0` and resumes 1-2 ms later; first TCP connect 0-1 ms after the first QUIC packet (server: 1.4-1.6 ms after the first datagram, one 11.9 ms outlier). QUIC bound 10/10; the main job was cancelled 10/10, yet its connection was still established and stayed idle without a request. | Main job blocked while an alternative job exists (`http_stream_factory_job_controller.cc` line 1084); wait is 0 while QUIC has never worked on the network (`quic_session_pool.cc` line 1590) |
| After QUIC worked (`race-after-quic-worked`, second race) | `HTTP_STREAM_JOB_DELAYED` 3-8 ms (median 7.5); QUIC connected within the wait, the main job never started, QUIC bound 10/10. | Wait is 1.5 x smoothed RTT, or 300 ms without RTT stats, plus a non-Android 0 ms additional delay (`quic_session_pool.cc` lines 1606-1616), capped at 3 s (`http_stream_factory_job_controller.cc` line 143); the RTT-dependent value is only what loopback produced |
| UDP blackhole (`udp-blackhole`) | TCP starts 0-1 ms after QUIC (fresh profile) and wins 10/10; the orphaned QUIC job fails with `-356` after the 4 s handshake idle timeout; the next request logs `is_broken:true` and creates only a main job; polled expiry 299-300 s after the failure. | Orphaned alternative runs to completion to report brokenness (lines 1160-1167); marked broken only when the main job succeeded (lines 1257-1302); the 4 s is `max_idle_time_before_crypto_handshake` = `kInitialIdleTimeoutSecs` (5 s; `net/quic/quic_context.h` line 172, quiche 2c4a1246 `quic_constants.h` line 159) less the one second quiche removes from a client idle timeout (`quic_connection.cc` lines 4983-4984) |
| QUIC certificate failure (`quic-bad-certificate`) | QUIC fails in about 1 ms; TCP wins 10/10; broken for 299-300 s; the next request does not use QUIC. | Same reporting path |
| QUIC ALPN failure (`quic-bad-alpn`) | Same as the certificate failure: broken 10/10 for 299-300 s. | Same reporting path |
| Existing H2 session (`existing-h2-session`) | The request after learning uses the existing H2 session at once (wait 0) 10/10 while the alternative job keeps running and connects QUIC; the next two same-page requests use that QUIC session 10/10. | Zero wait with an available SPDY session unless `delay_main_job_with_available_spdy_session` (`http_stream_factory_job_controller.cc` line 744; default false, `net/quic/quic_context.h` line 238) |
| Broken expiry and backoff (`broken-backoff`) | About 290 s after the first failure the alternative is still broken; about 305 s after it QUIC is tried again, fails, and is broken for 599 s, both runs. | `ComputeBrokenAlternativeServiceExpirationDelay`: 300 s initial, `initial << broken_count`, capped at 2 days (`net/http/broken_alternative_services.cc` lines 22, 58, 62; `net/base/features.cc` lines 1027 and 1037; `exponential_backoff_on_initial_delay_` defaults to true in `broken_alternative_services.h` line 236) |

Phantom's opt-in `AltSvcPolicy::race` follows these rows:

- Alternative setup starts first. Origin setup starts after the caller's
  delay, at once when the alternative fails, or at once when the origin has a
  reusable pooled H2 connection (`existing-h2-session`).
- The request is sent once, on the winner.
- A losing alternative that has begun connecting continues, and is then
  pooled or marked broken. Nothing is marked when both candidates fail, and a
  broken alternative is not raced.
- Each alternative connection attempt is limited to 4 seconds, and reaching
  the limit marks it broken, matching the blackhole rows.
- Brokenness doubles with a cap: `AltSvcBrokenBackoff::CHROMIUM_153` holds a
  300 s initial period that doubles up to two days. A failure inside an
  active broken period counts toward the next period without extending the current one
  (`broken_alternative_services.cc` lines 137-154).

Known differences from Chromium:

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

Deterministic unit tests with a paused clock cover:

- the race coordinator: origin start at the configured delay, immediate start
  after an alternative failure, cancellation of both candidates, and connect
  and total deadlines (the coordinator's permit tests use stand-in
  semaphores);
- the store: brokenness per origin and alternative, expiry, doubling with a
  cap, a repeated failure inside one broken period, and clearing on success
  or `clear`; and
- H3 connect turns: one location waits only for its own turn.

Loopback integration tests in `crates/phantom/tests/alt_svc_race.rs` use the
real client pools and cover:

- the default sequential terminal failure;
- one dispatch per request, with background pooling of the losing
  alternative;
- a one-shot streaming body sent only by the winner;
- a blackholed alternative that loses after the origin delay under a short
  connect timeout, and, with default timeouts, one that stops at the 4 s
  limit, is marked broken, and is not raced again, while a second race queued
  behind it never opens a QUIC connection;
- exact H3 to the origin that does not wait for a background alternative
  setup;
- an available H2 connection that skips a 5 s origin delay;
- with one H3 admission per origin, release of the alternative's permit after
  a win, after cancellation, and at the 4 s limit of a background setup,
  while a race still waiting for admission gives its place back; and
- route preservation.

### Connection-retry evidence

The shared exact-protocol acquisition state uses scripted, typed setup
failures to prove:

- a finite, request-wide budget across separate acquisitions;
- a fresh connect-phase deadline for each attempt;
- exclusion of timeouts, and protocol-labelled timeout behavior;
- preservation of the last error; and
- one total deadline that spans the retry delay.

Error-classification tables cover direct, forward-proxy, CONNECT-proxy,
SOCKS5, and QUIC setup variants. They exclude TLS, authentication,
rejection, timeout, protocol, and post-dispatch failures.

Public loopback H1 and H2 regressions start their servers only after they
observe the first refused setup, then verify the final request and response
metadata. The H1 case uses a one-shot streaming POST with static trailers.
Negotiated H1/H2 loopback regressions prove that:

- a refused connect is retried before ALPN;
- a TLS failure is terminal;
- the retry delay releases the connection lock;
- pre-selection admission is bounded;
- the budget is shared across redirects; and
- one-shot bodies are not polled before the retry.

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

### SSE browser reconnect evidence

`fixtures/sse/` retains HTTP/1.1 EventSource captures from headless Chrome
153.0.8010.48 and Firefox 156.0 (build ID 20260909172920) on Windows 11
(10.0.26200). They were recorded with `scripts/capture/sse_reconnect.py`
against a plaintext loopback server. Each of the seventeen scenarios ran ten
times on a fresh profile. Fixtures keep the raw request lines and header lines
in arrival order, connection reuse, and the delay from each server stimulus
to the next request. Each file records the capture page and the exact launch
arguments; [the capture README](../../scripts/capture/README.md) has the
commands.

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

| Behavior | Chrome 153 | Firefox 156 |
| --- | --- | --- |
| Delay without `retry` | 3 s | 5 s |
| `retry: 0` and `retry: 100` | honored (about 1 ms and 110 ms) | raised to 500 ms (observed about 510 ms) |
| Request after a reset before any response | one HTTP-stack resend on a new connection when the failed request reused a connection, then the retry delay | HTTP-stack transaction restarts on new connections |
| Reconnect target after a followed `307` | redirected URL | original URL |
| `Cookie` position on the reconnect | last of 16 fields | after `Referer`, before `Sec-Fetch-Dest` |

The immediate requests after a reset are HTTP-stack resends, not EventSource
reconnects:

- Three `reset-before-head` runs of Chrome 153.0.8010.48 with
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

`crates/phantom/tests/sse_browser_reconnect.rs` reads the retained fixtures
and replays the same server stimuli against Phantom with a paused clock. It
asserts that Phantom matches both browsers on:

- `Last-Event-ID` spelling and raw value, and omission of an empty id;
- retry persistence, and ignoring a non-digit retry; and
- termination on `204`, `404`, `500`, and `text/plain`.

With Firefox options (`initial_retry` 5 s, `min_retry` 500 ms) and Chrome
defaults, each browser's median delay per attempt must lie between Phantom's
exact delay and 30 ms above it. This covers `retry-0`, `retry-100`,
`retry-750`, and the default delay. A template built from each browser's
captured reconnect fields, with `SseHeader::last_event_id` at the captured
position, reproduces the browser's field lines except the `Host` port.

Other background traffic continued during the captures. Firefox 156 still
contacted Remote Settings, and Chrome contacted Google update and messaging
services, because release builds ignore those services' test-only switches.
That traffic used separate remote connections and never reached the loopback
listener.

Limits:

- The captures cover plaintext HTTP/1.1 only. H2, H3, macOS, and Safari
  behavior is not inferred from them.

### WebSocket browser evidence

`fixtures/websocket/` retains WebSocket openings from headless Chrome
153.0.8010.48, Edge 153.0.4234.48, and Firefox 156.0 on Windows 11
(10.0.26200), recorded with `scripts/capture/http2_websocket.py`. Each of nine
scenarios ran three times on a fresh profile against loopback listeners: TLS
for `server.phantom.test` (ALPN `h2` and `http/1.1`, a throwaway certificate)
and plaintext HTTP/1.1. The page sends a fixed corpus and closes with 1000
after the echoes return. The corpus is empty text, 1 B text, 100 B
compressible text, 64 KiB of seeded random binary, and 1 MiB of patterned
binary.

The fixtures keep:

- the ClientHello ALPN offer per connection;
- every H2 frame in both directions, with ordered details;
- each client HPACK block in hex, with every representation and decoded
  field in order;
- H1 opening lines in hex; and
- per message, the opcode, RSV1, frame payload lengths, and whether the
  decoded payload matches the corpus.

Masks and payload bytes are not retained. Chromium trusts the certificate
through `--ignore-certificate-errors-spki-list`; Firefox trusts it through a
`cert_override.txt` written only into its disposable profile. Both are
recorded with the launch arguments.

| Behavior | Chrome 153 and Edge 153 | Firefox 156 |
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

Chromium opens idle speculative connections that never send a request; they
remain in the fixtures. In one Chrome `refused-stream` run, the page session
closed before the socket opened, so that run used the `http/1.1`-only path
instead of a refused stream. Firefox 156.0 is the build the machine had
updated to.

`crates/phantom/tests/websocket_profile.rs` drives
`Client::websocket_with_profile_policy` against a loopback origin and
compares what the origin observes with these captures. The WebSocket guide
lists where Phantom's recipes still differ from the captured browsers, such
as Chrome's retry after `RST_STREAM(REFUSED_STREAM)`; see
[Browser recipes](../guides/websocket.md#browser-recipes).

Direct H2 WebSocket regressions use an authenticated loopback peer that
advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. They assert that Phantom:

- waits for the initial peer SETTINGS before dispatch;
- emits CONNECT with `:protocol = websocket` and the configured five-field
  pseudo-header order;
- omits the H1 Upgrade and key fields;
- preserves ordered ordinary fields; and
- exchanges framed messages over simultaneous request and response DATA.

Negative cases cover an absent peer setting without CONNECT dispatch or H1
fallback, streaming non-2xx rejection responses, direct-`wss://` route
validation, and a stream-scoped reset. These are standards-level
deterministic fixtures, not named-browser evidence.

Limits:

- The captures do not cover subprotocols, H3, proxies, macOS, or Safari.
- WebSocket proxy routes are covered only by loopback tests; see
  [Forward-proxy evidence](#forward-proxy-evidence).

### Content-decoding evidence

Unit tests drive each decoder with single-byte and chunked input. They cover:

- gzip optional header fields and FHCRC;
- CRC32/ISIZE and Adler-32 mismatches, truncation, and trailing members or
  bytes;
- preset dictionaries and raw DEFLATE selection;
- skippable and concatenated zstd frames, legacy zstd frame magic, and the
  8 MiB zstd window bound;
- stacked `gzip, br`, the 16 KiB frame bound, and the inclusive decoded
  limit; and
- a 64 MiB high-ratio stream stopped at its cap.

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

`ResponseBody::collect_with_limit` shares one protocol-independent counter.
Unit tests cover the inclusive bound and arithmetic overflow. A public H1
loopback test accepts a body exactly at the limit and rejects one byte more.
H1 content-decoding tests cover the decoded-byte cap and the decoded bytes
that `collect_with_limit` counts.

Limits:

- No public H2 or H3 test exceeds either limit; H2 and H3 bodies are only
  collected within them.
- Stopping an oversized H2 or H3 body relies on the ordinary body-drop path.
  That path's stream cancellation is covered separately by the H2 and H3
  admission, drop, and timeout regressions.

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

- `phantom-net`'s `transport` bench: construction of the Chrome 152 TLS
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
