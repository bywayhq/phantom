# Validation

This document is for contributors, reviewers, and anyone deciding how far to
trust a claim. It defines the evidence required for claims about observable
behavior, then records the evidence behind each feature and what that evidence
does not cover.

- Evidence rules: [evidence ladder](#evidence-ladder),
  [fixtures and normalization](#fixtures-and-normalization),
  [adversarial coverage](#adversarial-coverage).
- Feature evidence: [request trailers](#ordered-request-trailer-evidence),
  [forward proxies](#forward-proxy-evidence),
  [H3 over SOCKS5](#h3-socks5-udp-evidence),
  [Alt-Svc](#alt-svc-http3-upgrade-evidence),
  [connection retries](#connection-retry-evidence),
  [SSE](#sse-browser-reconnect-evidence),
  [content decoding](#content-decoding-evidence),
  [response-body limits](#response-body-limit-evidence),
  [WebSocket](#websocket-browser-evidence).
- Browser captures: [cross-platform parity](#cross-platform-transport-parity),
  [Chrome 153, Edge 153, and Firefox 156](#chrome-153-edge-153-and-firefox-156-recipes).
- Other: [external suites](#external-suites),
  [diagnostics and performance](#diagnostics-and-performance),
  [contributor gates](#contributor-gates).

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
reproducing unsafe behavior. Minimized failures become ordinary regressions.

The [parser fuzzing workflow](../../.github/workflows/fuzz.yml) runs each target
under AddressSanitizer for 15 seconds on relevant pull requests and pushes, and
for 300 seconds on its weekly schedule or a manual dispatch. Every run starts
from the newest per-target corpus restored from the GitHub Actions cache; only
scheduled runs save a grown corpus back. The corpus is therefore a cache that
can expire or be evicted, not a reviewed, committed seed set, and a failing
input is kept only as a short-lived workflow artifact until it is minimized
into a regression.

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
an HTTPS origin, or H3 through an HTTP forward proxy. The HTTP/2 proxy
transport has separate CONNECT regressions for H1 and H2 origins in
`crates/phantom/tests/proxy_h2.rs`, including rejection of plaintext
forwarding before I/O. H3's separate SOCKS5 UDP evidence is described below.

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
wrong-port datagrams are discarded by that boundary. The spoofed-relay case is
`datagram_from_a_non_relay_source_is_dropped` in
`crates/phantom-net/src/proxy/tests/socks5_udp.rs`, which sends a well-formed
datagram from a second loopback socket and proves that only the relay's next
datagram is delivered; codec and receive-policy unit tests in
`crates/phantom-net/src/proxy/socks5_udp.rs` cover fragments, truncation,
wrong domains and ports, and IPs other than a local-DNS route's fixed target.
Relay-reply tests cover the compatibility rule
that substitutes only the established TCP proxy peer IP for an unspecified
BND.ADDR, and rejection of domain BND.ADDR or a zero BND.PORT. Remote-target
tests cover exact-domain replies, case-insensitive domain comparison,
same-port IP-form replies, and a stable logical Quinn peer.

This evidence does not claim browser-capture fidelity for a proxied H3 route.
CONNECT-UDP routes have their own loopback evidence against an h3 test proxy;
no independent MASQUE implementation or browser capture backs them yet. Alt-Svc upgrade has separate direct-route evidence below.

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

H2 ALTSVC frame evidence has two layers. Vendored `phantom-http2` regressions
write raw frames to a real client connection and prove stream-0 and
request-stream delivery in arrival order, the ignore rules for a stream-0 frame
without an origin and a request-stream frame with one, truncated or oversized
frames without a connection error, the 16-frame drop-oldest bound, and server
indifference. Facade tests use a raw loopback H2 origin, because the vendored
server cannot emit ALTSVC, and prove that stream-0 and request-stream frames
upgrade the next negotiated request, while frames for another origin, frames
on exact H2 requests, and frames with Alt-Svc disabled do not. A frame followed
by a `clear` field on the same response proves arrival-order application.

Persistence tests use only the public client API. A learned `ma=3600`
alternative exports its canonical origin, location, and remaining lifetime;
importing that export into a fresh client upgrades its first negotiated
request without contacting the origin, while an independent client without an
import learns nothing. Constructed snapshots prove expired-entry removal,
non-increasing expiry across repeated export/import round trips, far-future
clamping, capacity retention of the newest entries with held entries winning,
all-or-nothing typed rejection of noncanonical origins and alternatives, the
disabled-store error, and host-free `Debug` output.

A loopback fixture serves exact H3 on the origin's own UDP port and Alt-Svc H3
on a second port. Alternating requests between the two locations prove one
QUIC connection per location in the same pool entry rather than a replacement
on every switch.

This evidence does not claim browser `Alt-Used` ordering, proxy-route
upgrades, proxy-route snapshots, or multiple-alternative racing. Racing has
its own evidence below.

## Alt-Svc racing evidence

Chrome 153.0.8010.48 on Windows 11 26200 was captured with
`scripts/capture/alt_svc_race.py` against one loopback origin serving H2 over
TCP and H3 over UDP on the same port, advertised as `h3=":<port>"; ma=86400`.
Fixtures are in
[`fixtures/alt-svc/chrome/153.0.8010.48/windows-11-26200/`](../../fixtures/alt-svc/chrome/153.0.8010.48/windows-11-26200/),
ten headless runs per scenario (two for `broken-backoff`), each on a fresh
profile, with every other host name unresolvable so browser background
traffic neither leaves the machine nor records QUIC success. The
certificate's SPKI is allowed with `--ignore-certificate-errors-spki-list`;
because Chromium's QUIC proof verifier rejects unknown roots for hosts not
named by `--origin-to-force-quic-on` (`net/quic/crypto/proof_verifier_chromium.cc`
line 430), the capture names the same host on a decoy port that is never
requested. Every race in the NetLogs is an `alternative` job created from
`ALT_SVC_FOUND`, never a forced-QUIC main job. Chrome 153 keeps
`HappyEyeballsV3` disabled (`net/base/features.cc` line 124), so these are
`HttpStreamFactory::JobController` decisions. Source citations are to tag
`153.0.8010.48`.

| Question | Observation | Source cross-check |
| --- | --- | --- |
| First new connection after learning (`race-after-learning`) | QUIC job starts first; main TCP job logs `should_wait:true`, then `HTTP_STREAM_JOB_DELAYED delay:0` and resumes 1-2 ms later; first TCP connect 0-1 ms after the first QUIC packet (server: 1.4-1.6 ms after the first datagram, one 11.9 ms outlier). QUIC bound 10/10; the main job was cancelled 10/10, yet its connection was still established and stayed idle without a request. | Main job blocked while an alternative job exists (`http_stream_factory_job_controller.cc` line 1084); wait is 0 while QUIC has never worked on the network (`quic_session_pool.cc` line 1590) |
| After QUIC worked (`race-after-quic-worked`, second race) | `HTTP_STREAM_JOB_DELAYED` 3-8 ms (median 7.5); QUIC connected within the wait, the main job never started, QUIC bound 10/10. | Wait is 1.5 x smoothed RTT, or 300 ms without RTT stats, plus a non-Android 0 ms additional delay (`quic_session_pool.cc` lines 1606-1616), capped at 3 s (`http_stream_factory_job_controller.cc` line 143); the RTT-dependent value is only what loopback produced |
| UDP blackhole (`udp-blackhole`) | TCP starts 0-1 ms after QUIC (fresh profile) and wins 10/10; the orphaned QUIC job fails with `-356` after the 4 s handshake idle timeout; the next request logs `is_broken:true` and creates only a main job; polled expiry 299-300 s after the failure. | Orphaned alternative runs to completion to report brokenness (lines 1160-1167); marked broken only when the main job succeeded (lines 1257-1302); the 4 s is `max_idle_time_before_crypto_handshake` = `kInitialIdleTimeoutSecs` (5 s; `net/quic/quic_context.h` line 172, quiche 2c4a1246 `quic_constants.h` line 159) less the one second quiche removes from a client idle timeout (`quic_connection.cc` lines 4983-4984) |
| QUIC certificate failure (`quic-bad-certificate`) | QUIC fails in about 1 ms; TCP wins 10/10; broken for 299-300 s; the next request does not use QUIC. | Same reporting path |
| QUIC ALPN failure (`quic-bad-alpn`) | Same as the certificate failure: broken 10/10 for 299-300 s. | Same reporting path |
| Existing H2 session (`existing-h2-session`) | The request after learning uses the existing H2 session at once (wait 0) 10/10 while the alternative job keeps running and connects QUIC; the next two same-page requests use that QUIC session 10/10. | Zero wait with an available SPDY session unless `delay_main_job_with_available_spdy_session` (`http_stream_factory_job_controller.cc` line 744; default false, `net/quic/quic_context.h` line 238) |
| Broken expiry and backoff (`broken-backoff`) | About 290 s after the first failure the alternative is still broken; about 305 s after it QUIC is tried again, fails, and is broken for 599 s, both runs. | `ComputeBrokenAlternativeServiceExpirationDelay`: 300 s initial, `initial << broken_count`, capped at 2 days (`net/http/broken_alternative_services.cc` lines 22, 58, 62; `net/base/features.cc` lines 1027 and 1037; `exponential_backoff_on_initial_delay_` defaults to true in `broken_alternative_services.h` line 236) |

Phantom's opt-in `AltSvcPolicy::race` follows these rows as follows.
Alternative setup starts first; origin setup starts after the caller's delay,
at once when the alternative fails, or at once when the origin has a reusable
pooled H2 connection (`existing-h2-session`). The request is sent once, on
the winner. A losing alternative that has begun connecting continues and is
pooled or marked broken; nothing is marked when both candidates fail, and a
broken alternative is not raced. Each alternative connection attempt is
limited to 4 seconds, and reaching the limit marks it broken, matching the
blackhole rows. Brokenness doubles with a cap
(`AltSvcBrokenBackoff::CHROMIUM_153` holds 300 s, doubling, two days), and a
failure inside an active broken period counts toward the next period without
extending the current one (`broken_alternative_services.cc` lines 137-154).

Known differences: the origin delay is caller-supplied because Chromium's
depends on QUIC history and measured RTT. Chromium restarts its 4 s idle
timer on every received packet and allows a responsive handshake up to 10 s,
while Phantom limits the whole attempt, including name resolution and proxy
setup, to 4 s. Phantom cancels a losing
origin setup instead of keeping its connection idle, does not persist
brokenness, does not reset it on a network change, and has no DNS
HTTPS-record (`dns_alpn_h3`) job. A background alternative keeps its H3
admission permit for the origin and route until it ends.

Deterministic unit tests with a paused clock cover the race coordinator
(origin start at the configured delay, immediate start after an alternative
failure, cancellation of both candidates, and connect and total deadlines;
the coordinator's permit tests use stand-in semaphores), the store
(brokenness per origin and alternative, expiry, doubling with a cap, a
repeated failure inside one broken period, and clearing on success or
`clear`), and H3 connect turns (one location waits for its own turn only).
Loopback integration tests in `crates/phantom/tests/alt_svc_race.rs` use the
real client pools and cover:

- the default sequential terminal failure;
- one dispatch per request, with background pooling of the losing
  alternative;
- a one-shot streaming body sent only by the winner;
- a blackholed alternative that loses after the origin delay under a short
  connect timeout, and, with default timeouts, one that stops at the 4 s limit,
  is marked broken, and is not raced again, while a second race queued behind
  it never opens a QUIC connection;
- exact H3 to the origin that does not wait for a background alternative
  setup;
- an available H2 connection that skips a 5 s origin delay;
- with one H3 admission per origin, release of the alternative's permit after
  a win, after cancellation, and at the 4 s limit of a background setup, while
  a race still waiting for admission gives its place back;
- route preservation.

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
The H1 case uses a one-shot streaming POST with static trailers. Negotiated
H1/H2 loopback regressions prove a refused connect is retried before ALPN, TLS
failure is terminal, the retry delay releases the connection lock, pre-selection
admission is bounded, the budget is shared across redirects, and one-shot
bodies are not polled before the retry.

Exact-H3 loopback regressions in `crates/phantom/tests/http3_retries.rs`
recover from a refused setup through the public client. A direct QUIC
handshake refused with `CONNECTION_REFUSED` fails without a policy and
succeeds with one retry. Over local-DNS SOCKS5, a refused proxy TCP connect is
retried and the proxy is started only after the refusal is observed, and a
QUIC handshake refused through an established UDP association is retried
through a second association with a different relay address; the fixture
serves that association only after the first one's TCP control connection has
closed. Each successful response reports one setup retry. CONNECT-UDP
evidence is narrower: an unresolvable outer proxy consumes the whole budget,
and proxy rejection and inner TLS failure are terminal, but recovery after a
CONNECT-UDP retry is not exercised. Remote-DNS SOCKS5 H3 and DNS or local
endpoint failures share the same classification but have no recovery test.

These tests prove lifecycle and routing behavior, not browser retry policy.
Retries are caller-configured and do not become part of a named browser recipe.

Status-retry regressions in `crates/phantom/tests/status_retry.rs` run over
H1 loopback servers, including one negotiated request that selects H1. The
retry loop sits above the transports, so H2 and H3 use the same code, but no
H2 or H3 status-retry test exists.

## SSE browser reconnect evidence

`fixtures/sse/` retains HTTP/1.1 EventSource captures from headless Chrome
153.0.8010.48 and Firefox 156.0 (build ID 20260909172920) on Windows 11
(10.0.26200), recorded with `scripts/capture/sse_reconnect.py` against a
plaintext loopback server. Each of the seventeen scenarios ran ten times on a
fresh profile. Fixtures keep raw request lines and header lines in arrival
order, connection reuse, and the delay from each server stimulus to the next
request. The capture page and the exact launch arguments are recorded in each
file; [the capture README](../../scripts/capture/README.md) has the commands.

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
| `Cookie` position on the reconnect | last of 16 fields | after `Referer`, before `Sec-Fetch-Dest` |

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
the retry delay after each failure, like Chrome's. By default its HTTP/1 layer
does not resend a request after a reused connection closes before a response;
`RetryPolicy::with_reused_connection_replay` opts into Chrome's single resend.
That request-layer policy is outside the SSE controller.

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

## Response-body limit evidence

`ResponseBody::collect_with_limit` shares one protocol-independent counter.
Unit tests cover the inclusive bound and arithmetic overflow, a public H1
loopback test accepts a body exactly at the limit and rejects one byte more,
and H1 content-decoding tests cover the decoded-byte cap and decoded bytes
counted by `collect_with_limit`. No public H2 or H3 test exceeds either limit;
H2 and H3 bodies are only collected within them. Stopping an oversized H2 or H3
body relies on the ordinary body-drop path, whose stream cancellation is
covered separately by H2 and H3 admission, drop, and timeout regressions.

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
  The Firefox 154 and 156 recipes list both AEADs in `ech_grease_aeads`, and the patched
  BoringSSL backend draws one uniformly per connection from fresh random
  bytes, keeping it across a HelloRetryRequest. The comparison therefore
  treats the AEAD as per-connection randomness. Each Firefox recipe test
  replays both retained captures, then requires 200 loopback connections from one
  connector to contain only these two values with each count in 60..=140; a
  fair draw fails that bound with probability below 1e-7. Only the
  distribution is reproduced; NSS and BoringSSL draw from different random
  sources.
- Every retained Chrome ClientHello, TCP and QUIC, and all 1,248 follow-up
  Chrome connections use HKDF-SHA256 with AES-128-GCM for ECH GREASE. The
  Chrome TLS recipe tests compare that cipher suite exactly, and
  `chromium_recipes_emit_aes_128_gcm_ech_grease_on_every_connection`
  checks it on 64 connections from one connector for each of Chrome 152,
  Chrome 153, and Edge 153. Chromium-family recipes leave
  `ech_grease_aeads` empty and rely on the backend default, which selects
  AES-128-GCM because the recipes set `aes_hardware`.
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
`firefox_154_recipe_draws_either_ech_grease_aead_per_connection`, and
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
order. Per-connection shuffling would contradict the observed behavior. These
multi-connection captures are not retained as fixtures.

Chrome 153 advertises 28 IDs: the four `d67909xx` IDs `02`, `03`, `09`, and
`0e` are absent and none is new. A later capture for the Chrome 153 recipe
recorded one ClientHello from each of 60 fresh branded Chrome 153.0.8010.48
processes with the retained Chrome TLS launch flags (no
`--disable-field-trial-config`). It saw 35 distinct orders; the most frequent
occurred 6 times and the next two 5 times each. The retained
`client-hello.txt` from the earlier capture has an order not among the 60.
`chromium::v153_tls` carries the 6-process order. Its lead over the runner-up
is one process, so it is one real observed order, not evidence of a preferred
Chrome order.
`fixtures/tls/chrome/153.0.8010.48/windows-11-26200/trust-anchor-orders.txt`
retains every order, its count, and the per-process sequence;
`chrome_153_tls_trust_anchor_order_is_the_most_frequent_process_order` and
`chrome_153_tls_recipe_emits_the_most_frequent_trust_anchor_order` check it.

## Chrome 153, Edge 153, and Firefox 156 recipes

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

New recipes follow from those differences. `chromium::v153_tls` and
`chromium::v153_http3_tls` replace only the trust-anchor list of the 152
recipes, and `chromium::v153_{http2,http3,http3_request,quic}` return the 152
recipes unchanged. `edge::v153_tls` and `edge::v153_http3_tls` remove the
trust-anchor IDs from the Chrome 153 recipes. `firefox::v156_tls` changes the
two differing fields of `v154_tls`, and `firefox::v156_http2` returns
`v154_http2`. Edge has no H2, QUIC, or H3 recipe of its own because those
layers equal Chrome 153 on every compared field. Client hints carry platform
and build data on the wire, so they are `chromium::v153_windows_client_hints`
and `edge::v153_windows_client_hints`.

Comparisons used the normalization of
[Cross-platform transport parity](#cross-platform-transport-parity): GREASE
values, Chromium extension order, random bytes, key shares, ECH GREASE payload
bytes and Chromium's per-connection ECH payload length, the H3 reserved
setting and its value width, the QUIC GREASE transport parameter length, and
the position of the reserved QUIC version. Every Chrome and Edge sample, TCP
and QUIC, used HKDF-SHA256 with AES-128-GCM for ECH GREASE. Firefox 156 kept
its fixed extension order and chose AES-128-GCM on 7 and ChaCha20-Poly1305 on
5 of 12 connections, each with a 240-byte payload. One sample of each is
retained; like 154, the recipe lists both AEADs and
`firefox_156_recipe_draws_either_ech_grease_aead_per_connection` bounds the
per-connection split.

Edge's full version list reports `"Chromium";v="153.0.8010.53"`, a newer
Chromium build than branded Chrome 153.0.8010.48. Headful and headless runs
produced identical client hints for both browsers.

The H2 request evidence reuses the navigation on the retained WebSocket
session fixtures (`fixtures/websocket/*/accept.txt`, recorded through
`http2_session.py`), which already hold each navigation's SETTINGS,
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

TLS ClientHellos were recorded with
`cargo run -p phantom-testkit --example capture_client_hello`, one run per
fresh browser process; the Edge H2 startup with
`cargo run -p phantom-net --example capture_http2_tls`; QUIC captures with
`scripts/capture/chrome_http3.py --client-hello`; and client hints with
`scripts/capture/client_hints.py`. Chromium TLS and H2 launches use the
arguments recorded in the retained Chrome fixtures with
`https://server.phantom.test:<port>/`. Firefox TLS uses
`--headless --no-remote --profile <temporary-profile>` with
`https://localhost:9446/`. Per-process samples beyond the retained ones are
not kept; the table gives their counts.

The `chrome_153_*`, `edge_153_*`, and `firefox_156_*` tests in
`phantom-profile` and `phantom-net` replay these fixtures: TLS and QUIC
ClientHellos through the public TLS and H3 connector paths, H2 startup frames
through the public H2 path, and H3, QUIC, H2 request, and client-hint fields
against the recipe data.

Limits:

- One Windows build and one build per browser. No macOS or Linux capture of
  these versions exists; the platform-free 153 and 156 transport names rest
  on the 152 and 154 finding that these layers did not depend on the platform.
- Headless launches, except the headful client-hint check.

## External suites

External projects are witnesses, not pass badges:

| Suite | Purpose |
| --- | --- |
| Autobahn | Exercise the public WebSocket client and turn failures into focused regressions |
| QUIC Interop Runner | Exercise the public H3 client against an independent server |
| Web Platform Tests | Check selected EventSource behavior through Phantom's API |
| TLS-Anvil and BoringSSL tests | Probe TLS behavior and native dependency updates |

Each row has its own workflow under [`.github/workflows/`](../../.github/workflows/).

Some sources are consulted rather than run. curl's test scenarios are a
reference for lifecycle, proxy, redirect, and timeout cases that become
Phantom's own deterministic regressions; no curl suite runs in CI. Likewise,
server-oriented h2spec and h3spec cases inform hostile client-peer tests; they
are not reported as client conformance.

## Diagnostics and performance

Tracing uses static fields and bounded values. It must not record headers,
cookies, credentials, payloads, certificates, endpoint names, or raw secrets.
H3 qlog and NSS key logging are explicit, bounded, default-off paths. They are
Cargo features of the internal crates (`phantom-net/qlog` and
`phantom-quic-btls/keylog`) used by capture tooling and tests; the
`phantom-http` facade exposes neither feature nor an API for them.

Benchmarks state exactly what they measure. The
[benchmark report workflow](../../.github/workflows/benchmarks.yml) runs weekly or
on demand on one Linux runner and uploads Criterion output; it is
report-only, with no baseline comparison or regression threshold. It covers:

- `phantom-net`'s `transport` bench: Chrome 152 TLS connector construction and
  H1/H2 request/response exchanges replayed over an in-memory stream (a warm
  reused H1 response head, a 12-field H1 head, 64 KiB H1 content-length and
  chunked bodies, a 12-field H2 head, and a 64 KiB H2 streaming body); and
- the vendored `tungstenite` `deflate` bench.

Nothing measures the `phantom-http` facade, pools, TLS or QUIC handshakes,
H3, real sockets, or end-to-end throughput. Optimization follows profiling and
must preserve wire fixtures.

## Contributor gates

Formatting, lint, test, documentation, MSRV, capture-tool, and vendor checks
live in [AGENTS.md](../../AGENTS.md) so there is one canonical command list. A
handoff records what ran and any remaining uncertainty.

See [HTTP/3 internals](../internals/http3.md) for its capture and packet proof.
