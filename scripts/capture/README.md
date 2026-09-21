# Capture tools

These tools record browser behavior against loopback servers so fixtures under
[`fixtures/`](../../fixtures/) are local raw evidence, not observer reports.
Rationale for each retained capture belongs in
[Validation](../../docs/explanation/validation.md); this page covers how to run the tools.

Run every command from the repository root with Python 3.10. Listeners refuse
non-loopback addresses.

## Browser launcher

`browser_launch.py` starts Chrome, Edge, or Firefox on a new temporary profile
per run and removes the profile and process tree afterwards. Fixtures record
the exact arguments with the profile path replaced by `<temporary-profile>`.

- Chromium (`chrome`, `edge`): `--headless=new` unless `--headful`, then
  `--user-data-dir`, `--no-first-run`, `--no-default-browser-check`,
  `--disable-background-networking`, `--disable-component-update`,
  `--disable-default-apps`, `--no-proxy-server`, and the page URL.
- Firefox: `--headless` unless `--headful`, `--no-remote --profile`, and a
  `user.js` that disables updates, captive-portal and connectivity checks,
  telemetry, Safe Browsing, and proxies.
- `manual`: no process is started; each run prints its URL on standard error
  for a person to open. Use it for Safari and for any browser that cannot be
  launched from the command line.

Fixtures record `launch_mode` (`headless`, `headful`, or `manual`). Captures
made in different modes are compared, never assumed equal.

## EventSource reconnects

`sse_reconnect.py` serves plaintext HTTP/1.1 scenarios to one
`new EventSource(...)` page per run and writes one
`format=phantom-sse-reconnect-v1` fixture per scenario. Each scenario is a
fixed sequence of server responses ending in exactly one terminal response
(`204`, an error status, or a non-event-stream content type); requests after
it are answered with `204` and recorded as `extra:true`. The run ends
`observation_ms` after the terminal response.

For each run the fixture keeps:

- every accepted connection, its request count, and when the client closed it;
- every request in arrival order with its raw request line and raw header
  lines in hex, so name spelling and field order survive;
- the delay from the previous server stimulus (FIN, reset, or response) to the
  request, and whether the request reused a connection.

Per attempt it summarizes `min`, `median`, `max`, `spread`, and all values
across runs. The tool refuses to write `authorization` or
`proxy-authorization`, and any cookie other than the scenario's
`phantom_probe=1`.

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

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.sse_reconnect \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 153.0.8010.48 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all --repeat 10 \
  --output-dir fixtures/sse/chrome/153.0.8010.48/windows-11-26200
```

Use `--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`
for Firefox, `--scenario <name> ...` for a subset, and `--browser manual` to
open each printed URL by hand.

The tool does not observe connection refusals, which never reach a listener;
reconnect after a network error is measured with resets instead.

## WebSocket openings

`http2_websocket.py` serves one WebSocket page per run and writes one
`format=phantom-http2-websocket-v1` fixture per scenario. `http2_session.py`
provides two loopback listeners: TLS for `server.phantom.test` with ALPN `h2`
and `http/1.1` and a certificate generated for the capture, and plaintext
HTTP/1.1. The H2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` unless
a scenario omits it. Client bytes are recorded before any parser sees them:
the ClientHello for the ALPN offer and SNI, then decrypted H2 or HTTP/1.1 bytes.

The page opens `/echo`, sends the corpus (empty text, 1 B text, 100 B
compressible text, 64 KiB xorshift32 binary with seed `0x5048414e`, and 1 MiB of
`i % 251` bytes), waits for the echoes, and closes with 1000. It reports the
close code, `wasClean`, and negotiated extensions to `/done`, which ends the run
after `--observation` seconds.

For each run the fixture keeps:

- every connection with its listener, ALPN offer, SNI, negotiated protocol,
  and client close time;
- for H2, every frame in both directions in time order with SETTINGS pairs,
  priority fields, error codes, and window increments, and every client header
  block in hex with each HPACK representation (`indexed`, `incremental`,
  `without-indexing`, `never-indexed`, `size-update`), table or name index,
  Huffman flags, and decoded field in order;
- every HTTP/1.1 request line and header line in hex;
- for each WebSocket, its outcome and extension offer and selection, then per
  message the opcode, RSV1, frame payload lengths, compressed and decoded
  length, and the matching corpus index. Masks are never retained.

The tool refuses to write `cookie`, `authorization`, or `proxy-authorization`.

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

Chromium browsers receive `--host-resolver-rules`, the certificate's
`--ignore-certificate-errors-spki-list` value, and `--disable-quic`. Firefox
receives `network.dns.localDomains`, `network.dns.disableIPv6`, and
`network.http.http3.enable=false` preferences, plus a `cert_override.txt` in its
disposable profile; `--firefox-skip-tls-trust` omits the override. Nothing is
installed outside the temporary profile. Fixtures record these arguments,
preferences, and profile file names.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  --with cryptography==50.0.1 python -m scripts.capture.http2_websocket \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 153.0.8010.48 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all --repeat 3 \
  --output-dir fixtures/websocket/chrome/153.0.8010.48/windows-11-26200
```

Use `--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`
or `--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`
for the other retained captures. The tool refuses other `h2` and `hpack`
versions.

## Client hints

`client_hints.py` serves two plaintext HTTP/1.1 navigations on a loopback
origin per run and writes one `format=phantom-client-hints-v2` fixture. The
first response carries `Accept-CH` for every user-agent client hint (override
the list with `--accept-ch`) and replaces the page with the second
navigation. Loopback HTTP origins are potentially trustworthy, so Chromium
sends hints to them.

For each run the fixture keeps both navigations' request field names in wire
order and every `sec-ch-*` or requested field with its exact value. It then
derives one ordered hint list in second-navigation order, marking a field
`default` when the first navigation already carried it and `accept-ch`
otherwise. Runs must agree exactly and a default hint must keep its value and
relative order, or the tool writes nothing. It refuses to retain `cookie`,
`authorization`, or `proxy-authorization`.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.client_hints \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 153.0.8010.48 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --repeat 3 \
  --output fixtures/client-hints/chrome/153.0.8010.48/windows-11-26200/navigation.txt
```

Use `--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`
for Edge. Firefox sends no client hints and records an empty list.

## HTTP/3 startup

`chrome_http3.py` records one browser HTTP/3 startup against an aioquic
server. [Validation](../../docs/explanation/validation.md) lists its retained fixtures and
the launch commands used for them.

## Alt-Svc racing

`alt_svc_race.py` records how Chromium races a learned `h3` alternative
against its origin and writes one `format=phantom-alt-svc-race-v1` fixture
per scenario. Each run serves `server.phantom.test` over TLS/TCP with ALPN
`h2` and over QUIC/UDP on the same port number (UDP is bound first), loads a
scripted page in a fresh profile, and writes a Chrome NetLog to
`--netlog-dir`. NetLogs are not retained; the fixture keeps derived decisions
only. `chrome_netlog.py` reads a NetLog, including one truncated by a killed
browser.

The page learns `Alt-Svc: h3=":<port>"; ma=86400` from `/learn` (or
`/learn-retire`, which also sends `GOAWAY` on its connection so the next
request needs a new one), and `/retire` retires every open connection. A
`/hold` image keeps the load event pending until `/done`, so `--dump-dom`
exits cleanly and the NetLog ends with `polledData`, whose Alt-Svc mappings
name each broken alternative's expiry.

Chromium receives `--enable-quic`, the certificate's
`--ignore-certificate-errors-spki-list`, `--log-net-log`,
`--net-log-capture-mode=Everything`, and
`--host-resolver-rules=MAP server.phantom.test <listen>, MAP * ~NOTFOUND`,
which keeps browser background traffic off the network and out of QUIC
history. QUIC rejects a certificate from an unknown root unless its host is
named by `--origin-to-force-quic-on`, so the tool passes
`--origin-to-force-quic-on=server.phantom.test:9`: a decoy port that is never
requested, so the captured origin is not forced onto QUIC and every alternative
job comes from Alt-Svc (the NetLog shows `ALT_SVC_FOUND` and an `alternative`
job for each race).

For each run the fixture keeps the page's per-step status and
`nextHopProtocol`, the transport of each scripted request as seen by the
server, connection counts, the gap between the first UDP datagram and the
race's TCP accept, and for every post-learning job controller: whether the
alternative was broken, the jobs created, the main job's wait and resume
times, the first QUIC packet and TCP connect attempt, each job's outcome, and
the bound job. Brokenness lifetimes are measured from the failed controller's
end to the polled expiry. Aggregates summarize each request path.

| Scenario | QUIC listener | Question |
| --- | --- | --- |
| `race-after-learning` | serves H3 | First new connection after learning on a fresh profile |
| `race-after-quic-worked` | serves H3 | Main-job delay once QUIC has worked and its sessions closed |
| `udp-blackhole` | drops datagrams | When TCP starts; brokenness of a blackholed alternative |
| `quic-bad-certificate` | untrusted certificate | Whether a QUIC certificate failure marks the alternative broken |
| `quic-bad-alpn` | no common ALPN | Whether a QUIC ALPN failure marks the alternative broken |
| `existing-h2-session` | serves H3 | Requests while an H2 session exists when h3 is learned |
| `broken-backoff` | drops datagrams | Brokenness expiry and the period after a second failure (about 5.5 minutes per run) |

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.alt_svc_race \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 153.0.8010.48 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario race-after-learning race-after-quic-worked udp-blackhole \
    quic-bad-certificate quic-bad-alpn existing-h2-session \
  --repeat 10 --netlog-dir <scratch-directory> \
  --output-dir fixtures/alt-svc/chrome/153.0.8010.48/windows-11-26200
```

The retained `broken-backoff` fixture used `--scenario broken-backoff --repeat 2`.
Loopback has no added latency, so RTT-dependent delays appear only as the
values Chrome logged.
