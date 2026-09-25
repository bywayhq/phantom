# Capture tools

Record what a real browser sends to a loopback server and keep it as a
fixture under [`fixtures/`](../../fixtures/). Start with
[Which tool to run](#which-tool-to-run).

> For contributors recording browser evidence. Read
> [Add a browser recipe](../../docs/internals/browser-recipes.md) first when
> the capture is for a new recipe.

A fixture is raw evidence recorded on the capture machine, not a report from a
third-party fingerprinting service. Why each retained capture exists, and what
it proves, belongs in [Validation](../../docs/explanation/validation.md).
Run every command from the repository root; the Python tools need Python
3.10. Every listener refuses a non-loopback address.

## Which tool to run

| To record | Run | Fixture area |
| --- | --- | --- |
| A TLS ClientHello over TCP | `cargo run -p phantom-testkit --example capture_client_hello` | `fixtures/tls/` |
| HTTP/2 startup frames | `cargo run -p phantom-net --example capture_http2_tls` | `fixtures/http2/` |
| A QUIC ClientHello and HTTP/3 startup | [`chrome_http3.py`](#http3-startup) | `fixtures/http3/` |
| QUIC session resumption and 0-RTT requests | [`quic_resumption.py`](#quic-resumption-and-0-rtt) | `fixtures/http3/` |
| Client hints, default and after `Accept-CH` | [`client_hints.py`](#client-hints) | `fixtures/client-hints/` |
| WebSocket openings over HTTP/2 and HTTP/1.1 | [`http2_websocket.py`](#websocket-openings) | `fixtures/websocket/` |
| EventSource reconnects | [`sse_reconnect.py`](#eventsource-reconnects) | `fixtures/sse/` |
| Alt-Svc racing between QUIC and TCP | [`alt_svc_race.py`](#alt-svc-racing) | `fixtures/alt-svc/` |
| Plaintext requests and `ws://` openings through HTTP proxies | [`proxy_route.py`](#proxy-routes) | `fixtures/proxy/` |

The two Cargo examples are Rust programs, not scripts in this directory.
[Capture commands and launches](../../docs/explanation/validation.md#capture-commands-and-launches)
has their arguments and the browser launch flags used with them.
`quic_packet_diff.py` and `compare_quic_flights.py` compare QUIC captures; see
[HTTP/3 internals](../../docs/internals/http3.md#capture-workflow).

## Browser launcher

The Python tools start browsers through `browser_launch.py`. Each run gets a
new temporary profile, which the launcher removes with the browser's process
tree afterwards. Fixtures record the exact launch arguments, with the profile
path replaced by `<temporary-profile>`.

| `--browser` | How it starts |
| --- | --- |
| `chrome`, `edge` | `--headless=new` unless `--headful`, `--user-data-dir`, the flags in `CHROMIUM_FLAGS`, then the page URL |
| `firefox` | `--headless` unless `--headful`, `--wait-for-browser`, `--no-remote --profile`, then the page URL |
| `manual` | Starts no process. Each run prints its URL on standard error for a person to open. Use it for Safari and any browser that cannot be launched from the command line |

`CHROMIUM_FLAGS` suppresses background requests from a fresh profile: first
run and default-browser checks, background networking, component updates,
default apps, proxies, phishing detection, background extensions, domain
reliability, sync, pings, and the `MediaRouter` and `OptimizationHints`
features. Firefox has no matching switches, so the launcher writes a `user.js`
that turns off the same classes of traffic, including updates, captive-portal
and connectivity checks, telemetry, Safe Browsing, DNS over HTTPS, and
proxies.

Fixtures record `launch_mode` (`headless`, `headful`, or `manual`). Captures
made in different modes are compared, never assumed equal. A coding agent
needs the human's approval before it launches a local browser.

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

For Edge, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`,
and for Firefox,
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
[Validation](../../docs/explanation/validation.md#capture-commands-and-launches)
lists its retained fixtures and launch commands, and
[HTTP/3 internals](../../docs/internals/http3.md#capture-workflow) describes
what it retains. Pass `--client-hello <path>` to also write the QUIC
ClientHello.

Known defect, to fix before the next Chrome capture: the tool opens
`client-startup.txt` in text mode, so on Windows it writes CRLF where every
other tool writes LF.
`fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt` is
therefore the one CRLF file under `fixtures/`. Its bytes and the SHA-256 that
`scripts/capture/tests/test_chrome_http3.py` pins are stable in the
repository, because `.gitattributes` marks `fixtures/**` as `-text`, and every
parser strips the carriage return. A rerun on a non-Windows host would write
LF and a different hash. Open the output path in binary mode, or with
`newline=""`, before the next capture. Do not rewrite the retained file's line
endings.

## QUIC resumption and 0-RTT

`quic_resumption.py` records what a browser sends when it resumes a QUIC
session: the resumed ClientHello, whether it offers early data, and which
requests travel in 0-RTT packets. It writes one
`format=phantom-quic-resumption-v1` fixture per scenario, named
`resumption-<scenario>.txt`.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt   python -m scripts.capture.quic_resumption   --browser chrome   --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe"   --client-version 154.0.8037.58   --operating-system "Windows 11 Home 10.0.26200 x64"   --scenario accept --repeat 5   --output-dir fixtures/http3/chrome/154.0.8037.58/windows-11-26200
```

The retained `accept-delayed` and `reject` fixtures used `--repeat 3`. For
Edge, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`,
and for Firefox,
`--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`.
The tool refuses an aioquic version other than 1.3.0.

Each run serves `server.phantom.test` over HTTP/3 from aioquic on a loopback
UDP port bound to port 0. The server sends one NewSessionTicket per
connection, with `max_early_data_size` 0xffffffff. After it answers
`/retire`, it sends an H3 `GOAWAY` and, 50 ms later, closes the connection
with `H3_NO_ERROR`. The page then waits 300 ms, so each step below starts on a
new connection:

1. the first navigation and `/retire`;
2. `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, and `DELETE` issued together;
3. a `POST` alone;
4. a `GET` alone;
5. a navigation to `/navigate`, which then requests `/done` and ends the run.

| Scenario | Server | Question |
| --- | --- | --- |
| `accept` | Accepts early data | Resumed ClientHello shape and which requests travel in 0-RTT |
| `accept-delayed` | Accepts early data; holds each connection's datagrams 50 ms before handling the first | Whether requests issued during a slower handshake travel in 0-RTT |
| `reject` | Resumes the ticket but ignores the `early_data` offer | Whether the browser resends its early requests in 1-RTT |

For each connection the fixture keeps:

- client packet counts per type, and the QUIC version of the first packet
  and of the handshake;
- whether the server resumed a ticket, which connection issued it, and
  whether early data was offered and accepted;
- the ClientHello's extension order, key-share groups, PSK modes, PSK
  identity and binder lengths, transport-parameter order,
  `version_information`, and Chromium's `initial_rtt_us` parameter;
- how the ClientHello differs from the run's first, fresh ClientHello;
- the packet-number spaces each client stream arrived in.

For each request it keeps the method, path, body length, and the spaces its
stream arrived in. Run 0 also keeps each raw ClientHello and each request's
field names in order. Summary lines count these across runs.

The server decrypts in memory. No TLS secret or key log is written.

Chromium receives `--enable-quic`,
`--origin-to-force-quic-on=server.phantom.test:<port>`,
`--host-resolver-rules=MAP server.phantom.test 127.0.0.1, MAP * ~NOTFOUND`,
the certificate's `--ignore-certificate-errors-spki-list`, and
`--disable-field-trial-config`. `--keep-field-trial-config` omits the last
flag. `--netlog-dir` adds `--log-net-log` for diagnosis; NetLogs are not
fixture inputs.

Firefox receives `network.http.http3.enable=true`,
`network.http.http3.alt-svc-mapping-for-testing` naming the loopback port,
`network.dns.localDomains`, and a `cert_override.txt` in its temporary
profile. It also receives
`network.http.http3.disable_when_third_party_roots_found=false`: without it,
Firefox verifies the overridden certificate and then closes the HTTP/3
connection because the chain ends at a third-party root.

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

## Proxy routes

`proxy_route.py` records what a browser sends for a plaintext `http://` page
and its `ws://` opening, directly and through an HTTP proxy. It writes one
`format=phantom-proxy-route-v1` fixture per scenario.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  --with cryptography==50.0.1 python -m scripts.capture.proxy_route \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all --repeat 3 \
  --output-dir fixtures/proxy/chrome/154.0.8037.58/windows-11-26200
```

For Edge, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`,
and for Firefox,
`--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`.

The tool binds three loopback listeners on port 0:

- the origin, plaintext HTTP/1.1;
- a plaintext HTTP proxy;
- a TLS proxy for `proxy.phantom.test`, offering ALPN `h2` and `http/1.1`,
  with a certificate generated for the capture.

Neither proxy forwards anything. Each answers as the origin, so an
absolute-form request, a CONNECT tunnel, and an HTTP/2 stream all reach the
same page handler. The page opens `ws://` on its own origin, waits for one
server message, and reports to `/done`.

| Scenario | Route | Origin |
| --- | --- | --- |
| `direct-loopback` | none | `127.0.0.1` |
| `direct-hostname` | none | `origin.phantom.test` |
| `http-proxy-loopback` | plaintext HTTP proxy | `127.0.0.1` |
| `http-proxy-hostname` | plaintext HTTP proxy | `origin.phantom.test` |
| `https-proxy-loopback` | TLS proxy offering `h2` | `127.0.0.1` |
| `https-proxy-hostname` | TLS proxy offering `h2` | `origin.phantom.test` |

Browsers send `Accept-Encoding`, client hints, and fetch metadata to a
loopback origin that they omit for a named plaintext origin, so every route
runs with both.

Each browser gets these proxy settings, recorded with the launch:

- Chromium drops `--no-proxy-server` from `CHROMIUM_FLAGS`, because it
  overrides `--proxy-server`. It receives `--disable-field-trial-config`,
  `--host-resolver-rules` for both test names, `--proxy-server`, and
  `--proxy-bypass-list=<-loopback>`. For the TLS proxy it also receives the
  certificate's `--ignore-certificate-errors-spki-list` value.
- Firefox uses `network.proxy.type=1` with `network.proxy.http` and
  `network.proxy.http_port` for the plaintext proxy. Its manual settings
  cannot name a TLS proxy, so for that route it uses
  `network.proxy.type=2` with a `data:` PAC URL that returns
  `HTTPS proxy.phantom.test:<port>`, and a `cert_override.txt` in its
  temporary profile. Both routes set
  `network.proxy.allow_hijacking_localhost=true` and an empty
  `network.proxy.no_proxies_on`.

For each run the fixture keeps:

- every connection with its listener, ALPN offer, SNI, and negotiated
  protocol;
- every HTTP/1.1 request line and header line in hex, with its form
  (`origin`, `absolute`, or `authority`) and the tunnel it arrived in;
- for HTTP/2 connections, every frame in both directions and each client
  HPACK block with its representations and decoded fields in order.

Browser background traffic also reaches the proxy. A request whose authority
is neither test origin is recorded as `kind:background` with its method and
authority only; its tunnel bytes are discarded, and its HPACK block is marked
`background=true` without fields. The tool refuses to write `cookie`,
`authorization`, or `proxy-authorization`.

## Next

- [Validation](../../docs/explanation/validation.md#browser-recipes): record
  what a new capture shows and how the browser was launched.
- [Add a browser recipe](../../docs/internals/browser-recipes.md): turn
  retained captures into recipe functions and replay tests.
