# Capture tools

These tools record what a real browser sends to a loopback server and write
the result as a fixture under [`fixtures/`](../../fixtures/). A fixture is
raw evidence recorded on the capture machine, not a report from a third-party
fingerprinting service. Phantom's profiles and tests are compared against
these fixtures.

This page covers how to run each tool. Why each retained capture exists, and
what it proves, belongs in
[Validation](../../docs/explanation/validation.md).

Run every command from the repository root with Python 3.10. Every listener
refuses a non-loopback address.

## Browser launcher

The capture tools start browsers through `browser_launch.py`. Each run gets a
new temporary profile, and the launcher removes the profile and the browser's
process tree afterwards. Fixtures record the exact launch arguments, with the
profile path replaced by `<temporary-profile>`.

| `--browser` | How it starts |
| --- | --- |
| `chrome`, `edge` | `--headless=new` unless `--headful`, `--user-data-dir`, the flags in `CHROMIUM_FLAGS`, then the page URL |
| `firefox` | `--headless` unless `--headful`, `--wait-for-browser`, `--no-remote --profile`, then the page URL |
| `manual` | Starts no process. Each run prints its URL on standard error for a person to open |

`CHROMIUM_FLAGS` suppresses background requests from a fresh profile: first
run and default-browser checks, background networking, component updates,
default apps, proxies, phishing detection, background extensions, domain
reliability, sync, pings, and the `MediaRouter` and `OptimizationHints`
features. Firefox has no matching switches, so the launcher writes a `user.js`
that turns off the same classes of traffic, including updates, captive-portal
and connectivity checks, telemetry, Safe Browsing, DNS over HTTPS, and
proxies.

Use `manual` for Safari and for any browser that cannot be launched from the
command line.

Fixtures record `launch_mode` (`headless`, `headful`, or `manual`). Captures
made in different modes are compared, never assumed equal.

## EventSource reconnects

`sse_reconnect.py` records how a browser's `EventSource` reconnects after a
server-sent events stream ends. It serves plaintext HTTP/1.1 to one
`new EventSource(...)` page per run and writes one
`format=phantom-sse-reconnect-v1` fixture per scenario.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.sse_reconnect \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all --repeat 10 \
  --output-dir fixtures/sse/chrome/154.0.8037.58/windows-11-26200
```

For Firefox, use
`--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`.
Pass `--scenario <name> ...` to run a subset, and `--browser manual` to open
each printed URL by hand.

Each scenario is a fixed sequence of server responses that ends in exactly one
terminal response: `204`, an error status, or a content type other than
`text/event-stream`. The server answers any later request with `204` and
records it as `extra:true`. A run ends `observation_ms` after the terminal
response.

| Scenario | Question |
| --- | --- |
| `id-then-close` | `Last-Event-ID` value, spelling, and position |
| `retry-750`, `retry-100`, `retry-0` | Honored retry delay and any clamp |
| `default-delay` | Delay without a `retry` field |
| `retry-persists-across-reconnect` | Retry value kept by later connections |
| `invalid-retry-ignored` | A non-digit `retry` leaves the delay unchanged |
| `empty-id-resets` | An empty `id` removes `Last-Event-ID` |
| `non-ascii-id` | Byte encoding of a non-ASCII id |
| `reconnect-204` | `204` ends the EventSource |
| `reconnect-404`, `reconnect-500`, `reconnect-wrong-content-type` | Permanent failure |
| `reset-before-head` | Interval after resets before any response |
| `idle-headers-only-90s` | Whether the browser closes an idle stream |
| `redirect-307-then-close` | Reconnect target after a followed redirect |
| `set-cookie-then-close` | Cookies on the reconnect request |

For each run the fixture keeps:

- every accepted connection, its request count, and when the client closed it;
- every request in arrival order, with its raw request line and header lines
  in hex so that name spelling and field order survive;
- the delay from the previous server stimulus (FIN, reset, or response) to
  each request, and whether the request reused a connection.

Across runs, the fixture summarizes each attempt's delay as `min`, `median`,
`max`, `spread`, and the list of all values.

The tool refuses to write `authorization` or `proxy-authorization`, or any
cookie other than the scenario's own `phantom_probe=1`.

The tool cannot observe a refused connection, because a refusal never reaches
a listener. It measures reconnects after a network error with resets instead.

## WebSocket openings

`http2_websocket.py` records how a browser opens a WebSocket over HTTP/2
(extended CONNECT) and over HTTP/1.1 (Upgrade). It serves one WebSocket page
per run and writes one `format=phantom-http2-websocket-v1` fixture per
scenario.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  --with cryptography==50.0.1 python -m scripts.capture.http2_websocket \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all --repeat 3 \
  --output-dir fixtures/websocket/chrome/154.0.8037.58/windows-11-26200
```

For the other retained captures, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`
or
`--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`.
The tool refuses `h2` and `hpack` versions other than the ones pinned above.

`http2_session.py` provides two loopback listeners:

- TLS for `server.phantom.test`, offering ALPN `h2` and `http/1.1`, with a
  certificate generated for the capture;
- plaintext HTTP/1.1.

The HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` unless a
scenario omits it. The tool records client bytes before any parser sees them:
first the ClientHello, for the ALPN offer and SNI, then the decrypted HTTP/2 or
HTTP/1.1 bytes.

The page opens `/echo` and sends this corpus:

- empty text;
- 1 B of text;
- 100 B of compressible text;
- 64 KiB of xorshift32 binary with seed `0x5048414e`;
- 1 MiB of `i % 251` bytes.

It waits for every echo and closes with code 1000. It then reports the close
code, `wasClean`, and the negotiated extensions to `/done`, which ends the run
after `--observation` seconds.

| Scenario | Question |
| --- | --- |
| `accept` | CONNECT fields, representations, priority, and send policy |
| `accept-deflate` | RSV1 and fragmentation with `permessage-deflate` accepted |
| `no-connect-protocol` | Fallback connection ALPN offer and Upgrade lines |
| `reject-403` | Stream termination and retry after `403` with a body |
| `refused-stream` | Reaction to `RST_STREAM(REFUSED_STREAM)`; later openings are accepted |
| `extension-mismatch` | Reaction to an unoffered extension in a `200` |
| `fresh-origin` | ALPN offer when the WebSocket is the first connection to its origin |
| `h1-accept`, `h1-accept-deflate` | Plaintext `ws://` opening lines and send policy |

For each run the fixture keeps:

- every connection with its listener, ALPN offer, SNI, negotiated protocol,
  and client close time;
- for HTTP/2, every frame in both directions in time order, with SETTINGS
  pairs, priority fields, error codes, and window increments;
- for HTTP/2, every client header block in hex, with each field's HPACK
  representation (`indexed`, `incremental`, `without-indexing`,
  `never-indexed`, or `size-update`), table or name index, Huffman flags, and
  decoded field, in order;
- every HTTP/1.1 request line and header line in hex;
- for each WebSocket, its outcome and its extension offer and selection;
- for each message, the opcode, RSV1, frame payload lengths, compressed and
  decoded length, and the matching corpus index.

Masks are never retained. The tool refuses to write `cookie`,
`authorization`, or `proxy-authorization`.

To reach the loopback server under its test hostname and certificate, each
browser gets extra settings. Nothing is installed outside the temporary
profile, and fixtures record these arguments, preferences, and profile file
names.

- Chromium browsers receive `--host-resolver-rules`, the certificate's
  `--ignore-certificate-errors-spki-list` value, and `--disable-quic`.
- Firefox receives the `network.dns.localDomains`,
  `network.dns.disableIPv6`, and `network.http.http3.enable=false`
  preferences, plus a `cert_override.txt` in its temporary profile.
  `--firefox-skip-tls-trust` omits the override.

## Client hints

`client_hints.py` records which user-agent client hints a browser sends by
default and which it adds after a server asks for them with `Accept-CH`. It
serves two plaintext HTTP/1.1 navigations on a loopback origin per run and
writes one `format=phantom-client-hints-v2` fixture. Chromium treats loopback
HTTP origins as potentially trustworthy, so it sends hints to them.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.client_hints \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --repeat 3 \
  --output fixtures/client-hints/chrome/154.0.8037.58/windows-11-26200/navigation.txt
```

For Edge, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`.
Firefox sends no client hints, and its capture records an empty list.

The first response carries `Accept-CH` for every user-agent client hint and
replaces the page with the second navigation. `--accept-ch` overrides the
requested list.

For each run the fixture keeps both navigations' request field names in wire
order, and every `sec-ch-*` or requested field with its exact value. From
these it derives one ordered hint list in second-navigation order. A hint is
marked `default` when the first navigation already carried it, and
`accept-ch` otherwise.

The tool writes nothing unless the runs agree exactly and every default hint
keeps its value and relative order. It refuses to retain `cookie`,
`authorization`, or `proxy-authorization`.

## HTTP/3 startup

`chrome_http3.py` records one browser HTTP/3 connection against an aioquic
server, through the first request.
[Validation](../../docs/explanation/validation.md) lists its retained fixtures
and the launch commands used for them, and
[HTTP/3 internals](../../docs/internals/http3.md#capture-workflow) describes
what it retains.

Known defect, to fix at the next Chrome capture: the tool opens
`client-startup.txt` in text mode, so on Windows it writes CRLF where every
other capture tool writes LF.
`fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt` is
the one CRLF file under `fixtures/`. `.gitattributes` marks `fixtures/**` as
`-text`, so the bytes and the SHA-256 that
`scripts/capture/tests/test_chrome_http3.py` pins are stable in the
repository, and every parser reads the file with line splitting that strips
the carriage return. But rerunning the documented command on a non-Windows
host would produce LF and a different hash, so that pinned hash is not
reproducible across platforms. Open the output path in binary mode, or with
`newline=""`, before the next capture; do not rewrite the retained file's
line endings.

## Alt-Svc racing

`alt_svc_race.py` records how Chromium races a learned `h3` alternative
(advertised in an `Alt-Svc` response field) against a new TCP connection to
the origin. It writes one `format=phantom-alt-svc-race-v1` fixture per
scenario.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.alt_svc_race \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario race-after-learning race-after-quic-worked udp-blackhole \
    quic-bad-certificate quic-bad-alpn existing-h2-session \
  --repeat 10 --netlog-dir <scratch-directory> \
  --output-dir fixtures/alt-svc/chrome/154.0.8037.58/windows-11-26200
```

The retained `broken-backoff` fixture used
`--scenario broken-backoff --repeat 2`.

Each run serves `server.phantom.test` on one port number twice: over TLS/TCP
with ALPN `h2`, and over QUIC/UDP. UDP is bound first. The run loads a
scripted page in a fresh profile and writes a Chrome NetLog to
`--netlog-dir`. NetLogs are not retained; the fixture keeps only the decisions
derived from them. `chrome_netlog.py` reads a NetLog, including one truncated
by a killed browser.

The page drives these server paths:

- `/learn` sends `Alt-Svc: h3=":<port>"; ma=86400`.
- `/learn-retire` does the same and also sends `GOAWAY` on its connection, so
  the next request needs a new connection.
- `/retire` retires every open connection.
- `/hold` is an image that keeps the load event pending until `/done`. As a
  result `--dump-dom` exits cleanly, and the NetLog ends with `polledData`,
  whose Alt-Svc mappings give each broken alternative's expiry.

| Scenario | QUIC listener | Question |
| --- | --- | --- |
| `race-after-learning` | serves H3 | First new connection after learning on a fresh profile |
| `race-after-quic-worked` | serves H3 | Main-job delay once QUIC has worked and its sessions closed |
| `udp-blackhole` | drops datagrams | When TCP starts; brokenness of a blackholed alternative |
| `quic-bad-certificate` | untrusted certificate | Whether a QUIC certificate failure marks the alternative broken |
| `quic-bad-alpn` | no common ALPN | Whether a QUIC ALPN failure marks the alternative broken |
| `existing-h2-session` | serves H3 | Requests while an H2 session exists when h3 is learned |
| `broken-backoff` | drops datagrams | Brokenness expiry and the period after a second failure (about 5.5 minutes per run) |

Chromium receives `--enable-quic`, the certificate's
`--ignore-certificate-errors-spki-list`, `--log-net-log`,
`--net-log-capture-mode=Everything`, and
`--host-resolver-rules=MAP server.phantom.test <listen>, MAP * ~NOTFOUND`.
The resolver rule keeps browser background traffic off the network and out of
QUIC history.

QUIC rejects a certificate from an unknown root unless
`--origin-to-force-quic-on` names its host. The tool therefore passes
`--origin-to-force-quic-on=server.phantom.test:9`. Port 9 is a decoy that is
never requested, so the captured origin is not forced onto QUIC, and every
alternative job comes from Alt-Svc. The NetLog shows `ALT_SVC_FOUND` and an
`alternative` job for each race.

For each run the fixture keeps:

- each page step's status and `nextHopProtocol`;
- the transport of each scripted request as the server saw it;
- connection counts;
- the gap between the first UDP datagram and the race's TCP accept;
- for every job controller after learning: whether the alternative was
  broken, the jobs created, the main job's wait and resume times, the first
  QUIC packet and TCP connect attempt, each job's outcome, and the bound job.

Brokenness lifetimes are measured from the failed controller's end to the
polled expiry. Aggregates summarize each request path.

Loopback adds no latency, so delays that depend on round-trip time appear
only as the values Chrome logged.
