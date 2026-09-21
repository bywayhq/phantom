# Validation

This document is for contributors and reviewers. It defines the evidence
required for claims about observable behavior.

## Evidence ladder

A wire-sensitive claim needs all applicable levels:

1. A deterministic local assertion for parsing, validation, and lifecycle.
2. A normalized byte, frame, packet, or qlog differential against a pinned
   capture.
3. A hostile-peer regression for relevant unusual or malformed input.
4. Supplemental interoperability or live-observer evidence.

Connectivity and a matching summary fingerprint are not sufficient evidence of
browser-compatible behavior.

## Fixtures and normalization

Fixtures record the client, version, platform, launch conditions, and raw
evidence required to reproduce a claim. Strict decoders retain the ordered
semantic fields used by differentials.

Normalization may remove values that must vary: random bytes, cryptographic key
material, timestamps, connection IDs, packet numbers, and measured GREASE
values. It must not erase order, presence, lengths, negotiated values, or other
profile-controlled behavior.

Built-in recipes are compared through the public path users exercise. A profile
component is not complete when it merely parses or connects.

## Adversarial coverage

Scripted peers vary fragmentation, flow control, challenge sequences, resets,
shutdown, malformed input, and cancellation. Tests assert the ordered outcome,
error category, connection reuse, and bounded completion.

Valid-but-unusual traffic may be compared with a retained browser run.
Malformed traffic is a robustness test: safety and bounds take precedence over
reproducing unsafe behavior. Minimized failures become ordinary regressions;
fuzzing expands the corpus on a schedule.

## Ordered request-trailer evidence

Declared streaming-body-produced request trailers are covered through the
public client on exact H1, H2, and H3 paths and on negotiated H1/H2 paths.
Static trailer coverage remains at each transport boundary and in public route
and retry lifecycles. The regressions assert raw H1 bytes,
including casing, declaration, order, and interleaved duplicates; ordered H2
trailing fields and the HPACK never-indexed representation for sensitive
values; and H3 trailing HEADERS encoded through the connection's stateful QPACK
encoder. Lifecycle tests cover trailer-only, owned, and streaming bodies,
declared name/multiplicity matching, one-shot replay refusal, pre-I/O
validation, and suppression after a body error.

This evidence proves that Phantom emits the caller-selected trailer block with
the documented protocol semantics. It does not claim that a built-in browser
profile emits those application-defined trailers by default.

## Forward-proxy evidence

The public exact-H1 route tests cover an `http://` origin forwarded in absolute
form through plaintext and TLS-encrypted proxies. The TLS fixture proves that
Phantom verifies the proxy certificate and hostname with the independent proxy
trust store, emits the request directly after the proxy TLS handshake without a
CONNECT exchange, and returns the proxied response through the normal streaming
body path. Negative cases cover missing proxy trust, non-H1 selections, and
proxy failure without direct-route fallback.

Authentication regressions prove that every logical request is first sent
without credentials; only a strict, valid Basic `407` challenge triggers one
replay on a fresh same-route connection. They assert the generated sensitive
`Proxy-Authorization` position after caller fields and before framing, exact
owned-body and static-trailer replay, and failure before opening a retry
connection for a one-shot streaming body. A second `407` and malformed or
unsupported challenges return typed proxy errors without direct or protocol
fallback. A subsequent logical request begins anonymously, proving that no
challenge state is learned. Lifecycle cases also cover a nonempty challenge
body, a queued request installing an intervening pooled connection without
capturing the authenticated retry, one total deadline spanning both attempts,
and suppression of challenge-response cookies while retaining cookies from the
final origin response.

This evidence does not claim browser-capture fidelity, redirects, negotiated
H1/H2 forwarding, H2 proxy transport, other authentication schemes, forwarding
an HTTPS origin, or H3 through an HTTP forward proxy. H3's separate SOCKS5 UDP
evidence is described below.

The WebSocket route regressions apply the same contract to plaintext `ws://`
Upgrade through plaintext and TLS-encrypted forward proxies. They assert the
normalized absolute-form request target, caller-selected opening-field order,
the absence of CONNECT and direct-origin traffic, independent proxy trust,
coalesced upgraded bytes, and Ping/Pong traffic. Authentication cases prove an
anonymous first attempt, one fresh-connection replay with the same WebSocket
key and generated credentials appended after caller fields, no learned state,
and terminal behavior for malformed or repeated challenges. A caller-supplied
`Proxy-Authorization` is rejected before proxy or origin I/O.

SOCKS5 WebSocket regressions cover plaintext `ws://` as well as TLS-backed
`wss://`. The plaintext cases prove remote-DNS Unicode canonicalization,
local-DNS address resolution, username/password negotiation, an origin-form
Upgrade with no origin TLS, and delivery of a WebSocket frame coalesced with
the `101` response.

Direct H2 WebSocket regressions use an authenticated loopback peer that
advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. They assert that Phantom waits
for the initial peer SETTINGS before dispatch, emits CONNECT with
`:protocol = websocket` and the configured five-field pseudo order, omits H1
Upgrade/key fields, preserves ordered ordinary fields, and exchanges framed
messages over simultaneous request/response DATA. Negative cases cover an
absent peer setting without CONNECT dispatch or H1 fallback, non-2xx streaming
rejection responses, direct-`wss://` route validation, and stream-scoped reset.
These are standards-level deterministic fixtures, not named-browser evidence.

## H3 SOCKS5 UDP evidence

Public exact-H3 loopback regressions cover local-DNS `socks5://` and
remote-DNS `socks5h://` through RFC 1928 UDP ASSOCIATE, both without
authentication and with RFC 1929 username/password authentication. They verify
end-to-end H3 traffic, reuse of one route-keyed H3 connection and association
across requests, and retention of the TCP control connection for the
client-owned association lifetime. The local path fixes an IP target. The
remote path uses an intentionally unresolvable `.invalid` origin, proves the
exact canonical DOMAIN target on the proxy wire, and forwards it only through
the fixture's proxy-owned mapping. Rejected and malformed association replies
produce typed proxy errors without origin datagrams, direct fallback, or
protocol fallback. HTTP forwarding and HTTP CONNECT routes fail before proxy
or origin I/O.

Transport-focused tests assert the exact authentication and UDP ASSOCIATE
exchanges, fixed IPv4 and IPv6 target headers, zero RSV and FRAG fields, and
fragment rejection. The adapter bounds operation to one datagram per send or
receive and accepts only packets from the negotiated relay carrying the
configured target; malformed, fragmented, spoofed-relay, wrong-domain, or
wrong-port datagrams are discarded by that boundary. Relay-reply tests cover the
compatibility rule that
substitutes only the established TCP proxy peer IP for an unspecified
BND.ADDR, and rejection of domain BND.ADDR or a zero BND.PORT. Remote-target
tests cover exact-domain replies, case-insensitive domain comparison,
same-port IP-form replies, and a stable logical Quinn peer.

This evidence does not claim HTTP proxy or CONNECT routing for H3,
CONNECT-UDP/MASQUE, H3 extended CONNECT, or browser-capture fidelity for a
proxied H3 route. Alt-Svc upgrade has separate direct-route evidence below.

## Alt-Svc HTTP/3 upgrade evidence

An authenticated loopback H2 origin and H3 alternative share one test
identity while listening on distinct transport locations. Public negotiated
requests prove default-off and explicit bounded activation, learning from the
ordered response fields, an H2 first response followed by H3, retention of the
original authority, SNI, and certificate identity, and selected-protocol
metadata. The managed H3 attempt carries one automatically generated
`Alt-Used` value with the canonical alternative host and explicit port.
Regressions prove that exact H3 requests and the tested negotiated H2 origin
request do not receive the field. A request-field regression proves that
caller-supplied `Alt-Used` is rejected before any network I/O. `Alt-Used` is
reserved in both request fields and trailers; the trailer rule is part of the
pre-I/O validation contract, not additional protocol coverage claimed here.
This evidence verifies the field's value and scope, not a browser-specific
position among ordinary request fields.

Parser regressions cover ordered duplicate fields, canonical host forms,
default and explicit `ma`, `Age` subtraction and expiry, replacement, `clear`,
unsupported alternatives, malformed-field retention, bounded LRU eviction,
and explicit removal.

Failure regressions close the authenticated alternative before request
dispatch and prove a typed H3 error, no same-request H1/H2 fallback, eviction,
and recovery through the origin on a later request. A `421` remains visible as
an H3 response, evicts the advertisement, and cannot cause the alternative
connection generation to be reused for the origin transport location. Manual
clearing is covered through the public client.

This evidence does not claim browser policy or `Alt-Used` ordering, connection
racing, persistence, H2 ALTSVC frames, proxy-route upgrades, or
multiple-alternative racing.

## Connection-retry evidence

The shared exact-protocol acquisition state uses scripted typed setup failures
to prove its finite request-wide budget across separate acquisitions, fresh
connect-phase deadlines, timeout exclusion, protocol-labelled timeout
behavior, last-error preservation, and one total deadline across retry delay.
Error-classification tables cover direct,
forward-proxy, CONNECT-proxy, SOCKS5, and QUIC setup variants while excluding
TLS, authentication, rejection, timeout, protocol, and post-dispatch failures.
Public loopback H1 and H2 regressions start their servers only after observing
the first refused setup, then verify the final request and response metadata.
The H1 case uses a one-shot streaming POST with static trailers. A negotiated
H1/H2 refusal proves that configured exact-protocol retries remain excluded.
Live H3 recovery is not claimed: H3 coverage currently consists of the typed
QUIC classification table, shared acquisition lifecycle tests, static pool
wiring review, and the workspace gates.

These tests prove lifecycle and routing behavior, not browser retry policy.
Retries are caller-configured and do not become part of a named browser recipe.

## SSE browser reconnect evidence

`fixtures/sse/` retains HTTP/1.1 EventSource captures from headless Chrome
153.0.8010.48 and Firefox 156.0 (build ID 20260909172920) on Windows 11
(10.0.26200), recorded with `scripts/capture/sse_reconnect.py` against a
plaintext loopback server. Each of the seventeen scenarios ran ten times on a
fresh profile. Fixtures keep raw request lines and header lines in arrival
order, connection reuse, and the delay from each server stimulus to the next
request. The capture page and the exact launch arguments are recorded in each
file; [the capture README](../scripts/capture/README.md) has the commands.

The Firefox captures were first recorded under the label 155.0.1, which was
passed to the capture tool by hand. Every Firefox request in them sends
`Firefox/156.0` in its user-agent, and the machine's update history shows
Firefox 156.0 (build ID 20260909172920) installed before the first Firefox
capture, so they were moved to `firefox/156.0/` and their `client_version`
corrected. Nothing else in them changed; they were not re-captured.

Observed on both browsers:

- `Last-Event-ID` is spelled that way, carries the committed id as raw UTF-8
  bytes, is omitted when the committed id is empty, and sits among the
  browser's ordinary fields rather than last. Chrome places it after
  `sec-ch-ua-mobile`; Firefox after `Accept-Encoding`.
- A valid `retry` value persists across later connections, and a non-digit
  value is ignored.
- Delay spread across ten runs stayed within about 50 ms and did not grow
  between attempts: neither browser showed jitter or backoff.
- `204`, `404`, `500`, and a `text/plain` response each ended the EventSource
  with no request during the observation window.
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

The immediate requests after a reset are HTTP-stack resends, not EventSource
reconnects. Three `reset-before-head` runs of Chrome 153.0.8010.48 with
`--log-net-log --net-log-capture-mode=Everything` each showed one URL request
that sent on a reused keep-alive socket, failed with `ERR_CONNECTION_CLOSED`,
logged `HTTP_TRANSACTION_RESTART_AFTER_ERROR`, and resent on a new connection,
where it failed with `ERR_EMPTY_RESPONSE`. Each later request was a new URL
request about 3 s later, so Chrome's EventSource waited the retry delay after
every failure. One run of the same Firefox 156.0 build with
`MOZ_LOG=nsHttp:5,EventSource:5` showed one channel whose transaction
restarted three times after `NS_BASE_STREAM_CLOSED` on fresh connections; the
`204` answered that same channel, so the EventSource never scheduled a
reconnect. The logs were kept outside the repository; the fixture timings of
these runs matched the retained captures. Phantom's event source already waits
the retry delay after each failure, like Chrome's. Its HTTP/1 layer does not
resend a request after a reused connection closes before a response, and
that request-layer policy is outside the SSE controller.

A five-run headless and headful Chrome comparison of `retry-750`, retained
under `launch-mode/`, gave medians within 1 ms of each other, so headless
timers are not throttled.

`crates/phantom/tests/sse_browser_reconnect.rs` reads the retained fixtures
and replays the same server stimuli against Phantom with a paused clock. It
asserts that Phantom matches both browsers on `Last-Event-ID` spelling and
raw value, empty-id omission, retry persistence, ignored non-digit retry, and
termination on `204`, `404`, `500`, and `text/plain`. With Firefox options
(`initial_retry` 5 s, `min_retry` 500 ms) and Chrome defaults, each browser's
median delay per attempt must lie between Phantom's exact delay and 30 ms
above it; this covers `retry-0`, `retry-100`, `retry-750`, and the default
delay. A template built from each browser's captured reconnect fields, with
`SseHeader::last_event_id` at the captured position, reproduces the browser's
field lines except the `Host` port.

Other background traffic remained during the captures. Firefox 156 still
contacted Remote Settings, and Chrome contacted Google update and messaging
services, because release builds ignore those services' test-only switches.
That traffic used separate remote connections and never reached the loopback
listener. These captures cover plaintext HTTP/1.1 only; H2, H3, macOS, and
Safari behavior is not inferred from them.

## Content-decoding evidence

Unit tests drive each decoder with single-byte and chunked input and cover
gzip optional header fields and FHCRC, CRC32/ISIZE and Adler-32 mismatches,
truncation, trailing members or bytes, preset dictionaries, raw DEFLATE
selection, skippable and concatenated zstd frames, legacy zstd frame magic,
the 8 MiB zstd window bound, stacked `gzip, br`, the 16 KiB frame bound, the
inclusive decoded limit, and a 64 MiB high-ratio stream stopped at its cap.
Field-grammar tests cover `Accept-Encoding` weights, wildcards, `x-gzip`,
duplicates, and malformed parameters, plus `Content-Encoding` case, empty
elements, identity mixing, and the three-coding bound.

Public loopback tests cover H1 gzip, H2 brotli, and H3 zstd decoding; wire-view
fields; an unchanged request head; pre-I/O `Accept-Encoding` rejection only
when enabled; fail-closed unknown and unadvertised chains; HEAD/204/304;
redirect hops; trailers after decoded data; fresh H1 connection selection
after a decode failure; and the total deadline over buffered input.

Browser behavior was read from Chromium and Firefox source and informs only
the documented divergences; no browser-parity claim is made.

## WebSocket browser evidence

`fixtures/websocket/` retains WebSocket openings from headless Chrome
153.0.8010.48, Edge 153.0.4234.48, and Firefox 156.0 on Windows 11
(10.0.26200), recorded with `scripts/capture/http2_websocket.py`. Each of nine
scenarios ran three times on a fresh profile against loopback listeners: TLS
for `server.phantom.test` (ALPN `h2` and `http/1.1`, a throwaway certificate)
and plaintext HTTP/1.1. The page sends a fixed corpus (empty text, 1 B text,
100 B compressible text, 64 KiB seeded random binary, 1 MiB patterned binary)
and closes with 1000 after the echoes return.

Fixtures keep the ClientHello ALPN offer per connection, every H2 frame in
both directions with ordered details, each client HPACK block in hex with every
representation and decoded field in order, H1 opening lines in hex, and per
message the opcode, RSV1, frame payload lengths, and decoded corpus match.
Masks and payload bytes are not retained. Chromium trusts the certificate
through `--ignore-certificate-errors-spki-list`; Firefox trusts it through a
`cert_override.txt` written only into its disposable profile. Both are recorded
with the launch arguments.

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

Chromium sends no `sec-websocket-key`, fetch metadata, or client hints on H2
CONNECT. Its HPACK encoder sends `:method`, `:path`, and `:protocol` without
indexing. Firefox H2 CONNECT adds fetch metadata (and
`sec-fetch-storage-access` from a cross-site page) and follows it with a stream
`WINDOW_UPDATE`. Both compress a 64 KiB random message even though the output
grows to 65,558 bytes. The HTTP/1.1 opening-field order differs by family and
is retained verbatim; Chromium sends `Connection: Upgrade` second, Firefox
sends it tenth with `Upgrade` last.

Chromium opens idle speculative connections that never send a request; they
remain in the fixtures. In one Chrome `refused-stream` run the page session
closed before the socket opened, so that run used the `http/1.1`-only path
instead of a refused stream. Firefox 156.0 is the build the machine had
updated to. These captures do not
cover subprotocols, H3, proxies, macOS, or Safari.

## Cross-platform transport parity

The retained Chrome 152 and Firefox 154 recipes were captured on macOS. A
second capture set on Windows 11 (build 26200, x64) tests whether their
transport layers depend on the host platform. Safari evidence remains
macOS-only.

Branded Chrome 152 cannot be installed on Windows any more, so the Chrome
comparison is triangulated so that platform is not confounded with build
flavor or version:

| Comparison | Isolates | Result |
| --- | --- | --- |
| Chrome for Testing 152.0.7977.83 (Windows) vs retained branded 152.0.7977.83 (macOS) | platform | equal on TLS, H2 startup, QUIC ClientHello, QUIC transport parameters, H3 SETTINGS and pseudo-header order, and captured H3 request field order and non-persona values |
| Chrome for Testing 153.0.8010.48 vs branded Chrome 153.0.8010.48 (both Windows) | build flavor | equal on the same layers |
| Firefox 154.0 (Windows) vs retained Firefox 154.0 (macOS) | platform | equal on TLS and H2 startup |

Chrome for Testing applies its bundled field-trial testing configuration by
default. With that configuration it adds extension `0x12e0` (empty payload)
to TCP and QUIC ClientHellos, raises QUIC `max_idle_timeout` from 30000 ms to
300000 ms, sends Google connection options `ORIGNOIP` instead of `ORIG`, and
moves `accept-language` before `upgrade-insecure-requests` in the H3
navigation request. Every equal result above is therefore from Chrome for
Testing launched with `--disable-field-trial-config`; branded Chrome 153 on
Windows matches that configuration, not the testing one. The testing
configuration capture is retained as
`fixtures/tls/chrome/152.0.7977.83/windows-11-26200/client-hello-field-trial-config.txt`
so the difference stays visible.

Comparisons normalize only per-connection randomness:

- TLS and QUIC GREASE values normalize to one sentinel; extension order is
  compared as a multiset because Chrome permutes it per connection (at least
  five fresh-profile samples per build were compared).
- Client random, session ID, key-share bytes, ECH GREASE config ID and
  payload bytes, and the QUIC initial source connection ID reduce to lengths
  or are ignored. Chrome's ECH GREASE payload length is chosen per
  connection and is excluded from record-length comparison.
- Chrome's trust-anchor ID order differs between browser processes on both
  platforms but not between connections of one process (see
  [Chrome trust-anchor ID order](#chrome-trust-anchor-id-order)); the list is
  compared as a set. Its GREASE `version_information` entry changes position;
  the chosen version stays first.
- Firefox 154 chooses its ECH GREASE AEAD between AES-128-GCM (`0x0001`) and
  ChaCha20-Poly1305 (`0x0003`) per connection on Windows (7 and 8 of 15
  samples); the retained macOS sample carries `0x0001`. A follow-up
  multi-connection capture saw both values in each of three processes (359
  and 337 of 696 connections, all with a 239-byte payload), consistent with
  NSS taking the choice from the low bit of fresh per-handshake random bytes.
  Phantom's Firefox recipe emits `0x0001` on every connection because the TLS
  backend has no per-connection ECH GREASE AEAD control; this difference
  remains open.
- Every retained Chrome ClientHello, TCP and QUIC, and all 1,248 follow-up
  Chrome connections use HKDF-SHA256 with AES-128-GCM for ECH GREASE. The
  Chrome TLS recipe tests compare that cipher suite exactly.
- `user-agent`, `sec-ch-ua`, `sec-ch-ua-mobile`, and `sec-ch-ua-platform` are
  persona data and differ by platform and flavor by design. Their positions in
  the request field order are compared.

The Chrome H3 recipe models only the request pseudo-header order; ordinary
navigation fields are caller data. Their cross-platform equality is therefore
a capture-to-capture test
(`chrome_152_windows_h3_request_fields_match_macos_capture_except_persona_values`),
not a recipe replay. The flavor comparison at 153 was made with the scratch
comparator and is not replayed by a test.

Deterministic recipe tests replay the retained Windows fixtures:
`chrome_152_tls_recipe_matches_windows_chrome_for_testing_capture`,
`chrome_152_http2_recipe_matches_windows_chrome_for_testing_capture`,
`chrome_152_quic_client_hello_recipe_matches_windows_chrome_for_testing_capture`,
`chrome_152_quic_recipe_matches_windows_chrome_for_testing_capture`,
`chrome_152_http3_recipe_matches_windows_chrome_for_testing_capture`,
`firefox_154_tls_recipe_matches_windows_capture`,
`firefox_154_recipe_emits_the_aes_128_gcm_ech_grease_choice`, and
`firefox_154_http2_recipe_matches_windows_capture`.

Limits:

- Chrome 152 parity rests on Chrome for Testing plus the flavor comparison at
  153. It assumes the flavor equivalence observed at 153 also held at 152.
- One Windows build and one macOS build were compared. Linux, other Windows
  releases, and other macOS releases are not covered.
- Chrome for Testing publishes no checksums; the archives were recorded on
  first use (SHA-256 below). Firefox 154.0 was verified against Mozilla's
  signed `SHA512SUMS`.
- Headless launches only, matching the retained fixtures.

| Artifact | Source | SHA-256 |
| --- | --- | --- |
| Chrome for Testing 152.0.7977.83 win64 | `https://storage.googleapis.com/chrome-for-testing-public/152.0.7977.83/win64/chrome-win64.zip` | `6ed70e277c5dd6cb7a31e2ccb8f88d071b4928984e3b47d846920764eab712e7` |
| Chrome for Testing 153.0.8010.48 win64 | `https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.48/win64/chrome-win64.zip` | `9a4d427ec9193ef8347e864076757f7e1e9c486f0a21c4781f5ea845bffd8dd1` |
| Firefox 154.0 win64 en-US | `https://archive.mozilla.org/pub/firefox/releases/154.0/win64/en-US/Firefox%20Setup%20154.0.exe` | SHA-512 `514dfa9f…1bd35398`, signed by Mozilla release subkey `827E 6586 0867 9618 CD34 9F93 678E 455D 7676 7AA3` |
| geckodriver 0.37.1 win64 (H2 WebDriver launch) | GitHub release asset | `dfed9315abe8d2fbc1b6161a2ee8002452e79cf05ee92fdc653a4e26bc35edd8` |

Launch arguments are recorded in each fixture. Chrome captures use the same
flags as the retained macOS fixtures plus `--disable-field-trial-config` for
Chrome for Testing; the Firefox H2 capture uses WebDriver with
`acceptInsecureCerts` and `network.dns.forceResolve=127.0.0.1`.

### Chrome trust-anchor ID order

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
rotations nor uniform permutations: distinct orders share adjacent ordered ID
pairs far more often than uniform shuffles (32 shared pairs among the five 152
orders against a uniform mean of 9.7, and 49 against 20.2 among the seven 153
orders; none of 5,000 simulated uniform sets reached either). This matches the
Chromium source of that period, which serialized the list by iterating an
`absl::flat_hash_set`; Chromium commit `942bda4298c1` (2026-08-28) later sorts
the list before encoding.

The Chrome 152 recipe therefore keeps one fixed order, the retained macOS
order. Per-connection shuffling would contradict the observed behavior. Chrome
153 advertises 28 IDs (four `d67909xx` IDs are absent) and has no recipe. These
multi-connection captures are not retained as fixtures.

## External suites

External projects are witnesses, not pass badges:

| Suite | Purpose |
| --- | --- |
| Autobahn | Exercise the public WebSocket client and turn failures into focused regressions |
| QUIC Interop Runner | Exercise the public H3 client against an independent server |
| Web Platform Tests | Check selected EventSource behavior through Phantom's API |
| curl scenarios | Source mature lifecycle, proxy, redirect, and timeout cases |
| TLS-Anvil and BoringSSL tests | Probe TLS behavior and native dependency updates |

Server-oriented h2spec and h3spec cases inform hostile client-peer tests; they
are not reported as client conformance.

## Diagnostics and performance

Tracing uses static fields and bounded values. It must not record headers,
cookies, credentials, payloads, certificates, endpoint names, or raw secrets.
H3 qlog and NSS key logging are explicit, bounded, default-off paths.

Benchmarks state exactly what they measure. Current deterministic replays cover
connector construction and public H1/H2 request paths, not TLS handshakes or
end-to-end throughput. Optimization follows profiling and must preserve wire
fixtures.

## Contributor gates

Formatting, lint, test, documentation, MSRV, capture-tool, and vendor checks
live in [AGENTS.md](../AGENTS.md) so there is one canonical command list. A
handoff records what ran and any remaining uncertainty.

See [HTTP/3 internals](http3.md) for its capture and packet proof.
