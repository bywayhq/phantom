# Capture tools

Record what a real browser sends to a loopback server and keep it as a
fixture under [`fixtures/`](../../fixtures/). For a new browser version,
start with a [quick fingerprint snapshot](#quick-fingerprint-snapshot), then
see [Which tool to run](#which-tool-to-run).

Keep the browser build, platform, launch settings and reproduction commands
with each fixture.
Run every command from the repository root; the Python tools need Python
3.10 or later. Windows SSE captures over HTTP/3 require CPython 3.12.3 or
later. Every listener refuses a non-loopback address.

## Quick fingerprint snapshot

`snapshot.py` records a desktop browser's TLS and HTTP startup from one
headless launch on a fresh profile, and `snapshot_compare.py` compares it
with the browser's retained fixtures:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.snapshot --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.97 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --repeat 3 --output-dir <scratch-directory>/chrome
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.snapshot_compare --browser chrome \
  <scratch-directory>/chrome/snapshot-1.txt
```

Snapshot capture restores your event-loop error handler when it finishes,
including failures and cancellation. Unrelated callback errors reach your
handler while capture is running.
Use a finite positive `--run-timeout` and a finite nonnegative `--observation`.
Keep `--client-version`, `--operating-system` and rendered metadata on one
line of printable ASCII.

Before writing, the tool collects registered connections and their callback
outcomes within a ten-second cooperative cleanup deadline. Callback failures
and incomplete cleanup prevent writing, including with `--allow-partial`.
Completion requires one exact run token in an origin-form request target.

Split captures exceeding 128 runs or 8 MiB of recorded data per run. Each
transport permits 128 lifetime connections and 32 active connections. Each
QUIC connection permits 128 streams. HTTP/1 request headers, including their
terminator, have a 64 KiB limit.

`--browser` takes `chrome`, `edge`, `brave`, `opera`, or `firefox`, or an
[Android browser](#snapshots-on-android);
[`run_matrix.py`](#run-captures-from-a-manifest) runs it as the `snapshot`
tool for several desktop browsers at once. One run
serves `server.phantom.test` over TLS/TCP (ALPN `h2` and `http/1.1`) and QUIC
(`h3`) on one port number of 127.0.0.1, and plaintext HTTP/1.1 on another:

1. The browser opens `/`. The response carries `Accept-CH` and `Critical-CH`
   for every user-agent client hint, so Chromium repeats the navigation with
   them.
2. The page fetches `/fetch`. The response carries `Alt-Svc: h3=":<port>"`,
   and the server then sends GOAWAY.
3. The page navigates to `/next` on a new connection, which takes `h3`, and
   fetches `/fetch` again. A `/next` served over TCP, which Firefox can do
   while it validates the alternative, loads `/next` once more.
4. The page navigates to `/plain` on the plaintext port, which fetches
   `/done`.

Chromium gets the launch switches of [Alt-Svc racing](#alt-svc-racing), with
the certificate's SPKI and a resolver rule that leaves 127.0.0.1 alone.
Firefox gets the HTTP/3 preferences of the other QUIC tools and a
`cert_override.txt`. The TLS server issues no session tickets.

Run `n` writes `snapshot-<n>.txt` (`format=phantom-snapshot-v1`) with every
connection, every request's fields in wire order as
[`cookie_crumbs.py`](#cookie-crumbs) writes them, the client hints as
`hint_<n>` lines of `phantom-client-hints-v2`, and these sections:

| Prefix | Holds | Drop-in fixture |
| --- | --- | --- |
| `tls.` | The first TCP ClientHello | Yes: `phantom-client-hello-v2`, written by `--split` as `client-hello.txt` |
| `quic_client_hello.` | The first QUIC ClientHello | Yes: `phantom-quic-client-hello-v1`, written by `--split` as `quic-client-hello.txt` |
| `h2.` | The frames before the first HEADERS, `initial_settings`, `connection_window_update`, and every client frame | No: the `phantom-http2-tls-v2` fields of those names, without the ALPS and limit fields |
| `h3.` | Transport parameters, SETTINGS, and the first HTTP/3 request | No: the fields of `phantom-http3-client-startup-v2`, but its request is the script navigation to `/next`, not a first navigation |

Each QUIC connection also records up to eight of the client's Initial
datagrams in arrival order, one
`quic_connection_<i>_initial_datagram_<n>=size:<bytes>,version:<hex>,destination_cid_length:<n>,source_cid_length:<n>`
line each, after `quic_connection_<i>_initial_datagram_count`. A datagram
counts when its first packet is a version 1 or version 2 Initial. `--split`
and `snapshot_compare.py` also read older snapshots without these lines.

`--split <snapshot> --output-dir <directory>` writes the two drop-in
fixtures. The tool exits 1 when a run timed out, did not use HTTP/3, or has
an `*_error` line (a part it could not parse); `--allow-partial` keeps it at
0.

`snapshot_compare.py` reads, for each layer, the newest retained fixture of
the browser recorded on the snapshot's operating system, and prints
`compared <path>` and one `differs ...` line per difference. It compares:

- the TCP and QUIC ClientHellos: legacy version, cipher suites, extension
  order, and every extension body, QUIC transport parameters included;
- the HTTP/2 frames before the first HEADERS, against `http2/`;
- the first HTTP/2 navigation's field order, HEADERS flags, and priority,
  against the first navigation of the WebSocket `accept.txt`;
- HTTP/3 SETTINGS;
- the client hints.

GREASE values, key shares, the ECH config ID, enc, and payload, the QUIC
connection ID, and reserved versions are normalized first. For Chromium
browsers an extension or transport parameter list that differs only in order
is not a difference, because Chromium permutes both per connection. Firefox
shuffles its QUIC ClientHello extensions per connection but keeps
`quic_transport_parameters`, `encrypted_client_hello`, and, when resuming,
`pre_shared_key` last, so for Firefox only the extensions before that tail
may change order; its TCP extensions and transport parameters must match in
order. Firefox also draws its ECH GREASE AEAD per connection, so that AEAD is
not compared. A layer missing from the snapshot, or with no retained
fixture, is a difference. Malformed normalized extension lengths, duplicate
extensions and missing declared entries fail comparison. Counts are limited
to 16,384 TLS records, 16,384 HTTP/2 frames and 1,024 hints; input file size
is unrestricted. Request-field comparison covers the first HTTP/2
navigation only.

Take a snapshot first for every new browser version. The other tools record
a changed layer for a recipe, and they are the only way to record behavior
across connections: resumption and 0-RTT, Alt-Svc racing, retries, broken
alternatives, EventSource reconnects, proxies, WebSocket openings, cookie
crumbs, and ECH.

### Snapshots on Android

`--browser` also takes `chrome-android`, `edge-android`, `brave-android`,
`opera-android`, and `firefox-android`, with adb as `--browser-path` and
the device in `ANDROID_SERIAL`, as under [Android browsers](#android-browsers):

```sh
ANDROID_SERIAL=emulator-5556 uv run --no-project --python 3.10   --with-requirements scripts/requirements.txt   python -m scripts.capture.snapshot --browser chrome-android   --browser-path "$ANDROID_SDK_ROOT/platform-tools/adb"   --client-version 154.0.8037.57   --operating-system "Android 17 (API 37) x86_64 emulator reporting Pixel 7 CP3A.260905.009"   --repeat 3 --output-dir <scratch-directory>/chrome-android
```

The launcher opens the page URL with a `VIEW` intent
(`launch_mode=android-intent`) and types nothing; the page's own script makes
every later request. The
resolver rule maps `server.phantom.test` to `10.0.2.2`, the emulator's route
to host loopback, which carries the TLS and QUIC legs. `/plain` names the
device's own 127.0.0.1, so the launch adds `adb reverse` for the plaintext
port and for the TLS port.

What each browser yields:

- Chrome, Brave, and Edge: every layer, as on the desktop. An intent carries
  no user activation, so the first navigation has no `sec-fetch-user`, and
  `snapshot_compare.py` reports that against a typed `accept.txt`.
- Opera: the TCP ClientHello only. Opera for Android reads no command-line
  file, so it gets no resolver rule and no certificate switch. It opens
  `https://localhost:<port>/` through `adb reverse`, sends one ClientHello
  with `server_name` `localhost`, and stops at the certificate error. A
  cleared profile first steps through Opera's first-run screens, which take
  most of the run.
- Firefox: the TCP ClientHello only. GeckoView reads preferences but no
  profile files, so there is no `cert_override.txt`. Firefox resolves
  `server.phantom.test` to the device's 127.0.0.1 with
  `network.dns.localDomains`, reaches the listener through `adb reverse`,
  and every handshake fails at the certificate: three or four connections a
  run, each with a complete ClientHello. No HTTP/2 frame, request, QUIC
  connection, or client hint arrives.

For Opera and Firefox pass `--run-timeout 5 --allow-partial`: nothing arrives
after the certificate error, and every run is partial. Play serves Edge for
Android as an arm64 build only; run it on an arm64 emulator.

## Which tool to run

| To record | Run | Fixture area |
| --- | --- | --- |
| Every layer's fingerprint from one launch, compared with the retained fixtures | [`snapshot.py`](#quick-fingerprint-snapshot) | A scratch directory; `--split` writes `fixtures/tls/` and `fixtures/http3/` ClientHello files |
| A TLS ClientHello over TCP | `cargo run -p phantom-testkit --example capture_client_hello` | `fixtures/tls/` |
| HTTP/2 startup frames | `cargo run -p phantom-net --example capture_http2_tls` | `fixtures/http2/` |
| A QUIC ClientHello and HTTP/3 startup | [`chrome_http3.py`](#http3-startup) | `fixtures/http3/` |
| Any of those three, with the browser launched for you | [`startup_capture.py`](#connection-startup-launches) | `fixtures/tls/`, `fixtures/http2/`, `fixtures/http3/` |
| QUIC session resumption and 0-RTT requests | [`quic_resumption.py`](#quic-resumption-and-0-rtt) | `fixtures/http3/` |
| TLS 1.3 session resumption over TCP, and TCP early data | [`tls_resumption.py`](#tls-resumption-over-tcp) | `fixtures/tls/` |
| Firefox's TCP or QUIC ClientHellos to `127.0.0.1` or `[::1]`, with an optional ECH GREASE size | [`ip_literal_client_hello.py`](#clienthellos-to-ip-literals) | `fixtures/tls/firefox/` |
| Client hints, default and after `Accept-CH` | [`client_hints.py`](#client-hints) | `fixtures/client-hints/` |
| WebSocket openings over HTTP/2 and HTTP/1.1 | [`http2_websocket.py`](#websocket-openings) | `fixtures/websocket/` |
| EventSource reconnects over HTTP/1.1, HTTP/2 or HTTP/3 | [`sse_reconnect.py`](#eventsource-reconnects) | `fixtures/sse/` |
| Safari HTTP/H2 EventSource reconnects on hosted macOS | [Safari capture](SAFARI.md) | Reviewed workflow artifacts |
| Headed Chrome HTTP reconnects on arm64 and Intel Macs | [macOS capture](MACOS.md) | Installed identity and request bytes |
| Decrypted `wss://` openings through HTTP, HTTPS or SOCKS5 proxies | [`tunnelled_websocket.py`](#tunnelled-websocket-openings) | `fixtures/tunnelled-websocket/` |
| Alt-Svc racing between QUIC and TCP | [`alt_svc_race.py`](#alt-svc-racing) | `fixtures/alt-svc/` |
| Plaintext requests and `ws://` openings through HTTP proxies | [`proxy_route.py`](#proxy-routes) | `fixtures/proxy/` |
| ClientHellos with Encrypted Client Hello from an HTTPS record | [`chrome_ech.py`](#encrypted-client-hello) | `fixtures/tls/` |
| Several cookies on one request over HTTP/1.1, HTTP/2, and HTTP/3 | [`cookie_crumbs.py`](#cookie-crumbs) | `fixtures/cookies/` |
| The PING a Chromium browser sends when it reuses an idle HTTP/2 connection | [`http2_preface_ping.py`](#http2-preface-ping) | `fixtures/http2/` |
| How each connection ends (TLS `close_notify` or not), idle and unanswered PINGs, revalidation, and upload fields | [`http_lifecycle.py`](#connection-lifecycle) | `fixtures/lifecycle/` |
| Whether a Chromium navigation starts again for an ALPS `ACCEPT_CH` hint, and where the hint goes | [`alps_accept_ch.py`](#alps-accept_ch-restart) | `fixtures/client-hints/` |
| Socket options, connection attempts, and host lookups inside a Chromium browser on Windows | [`socket_hooks.py`](#socket-hooks) | `fixtures/socket-hooks/` |
| The same for Firefox on Windows, with keepalive over each connection's life and Firefox's MOZ_LOG | [`firefox_socket_hooks.py`](#firefox-socket-hooks) | `fixtures/socket-hooks/firefox/` |
| Several of these tools for several desktop browsers in one command | [`run_matrix.py`](#run-captures-from-a-manifest) | The manifest's `output_dir` |

The two Cargo examples are Rust programs, not scripts in this directory.
`quic_packet_diff.py` and `compare_quic_flights.py` compare QUIC captures.

## Run captures from a manifest

`run_matrix.py` runs a list of captures for desktop browsers from one JSON
manifest, several at a time, and writes a summary and a results file. Each job
is one run of a capture tool's own command line for one tool, browser, and
scenario, with that scenario's `--repeat` count. The tool writes its fixture
itself, so a fixture has the same format and naming as one written by hand.

Run it from the repository root with the capture requirements installed. Jobs
start under the runner's Python interpreter:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.run_matrix captures.json
```

| Option | Effect |
| --- | --- |
| `--jobs N` | Run at most `N` jobs at once. The default is a quarter of the logical CPUs, at most 8 |
| `--retries N` | Run a failed job up to `N` more times (default 1) |
| `--force` | Also run jobs that the work directory records as complete |
| `--only PREFIX` | Run only jobs whose id starts with `PREFIX`; repeat it for more |
| `--dry-run` | Print each job's id and command line, then stop |
| `--work-dir DIR` | Where completion records, attempt logs, temporary directories, and NetLogs go (default `<temp>/phantom-run-matrix-<manifest name>`) |
| `--results PATH` | Where to write the results file (default `<work-dir>/results.json`) |

The runner exits with status 1 if any job failed, and with status 130 after
Ctrl+C.

### Manifest

```json
{
  "operating_system": "Windows 11 Home 10.0.26200 x64",
  "repeat": 3,
  "browsers": {
    "chrome": {
      "path": "C:/Program Files/Google/Chrome/Application/chrome.exe",
      "version": "154.0.8037.58"
    },
    "opera": {
      "path": "%LOCALAPPDATA%/Programs/Opera/135.0.5973.92/opera.exe",
      "version": "135.0.5973.92"
    }
  },
  "captures": [
    {
      "tool": "tls_resumption",
      "browsers": ["chrome", "opera"],
      "scenarios": ["sequential", "methods"],
      "output_dir": "fixtures/tls/{browser}/{version}/windows-11-26200"
    },
    {
      "tool": "client_hints",
      "browsers": ["chrome"],
      "repeat": 5,
      "output_dir": "fixtures/client-hints/{browser}/{version}/windows-11-26200"
    }
  ]
}
```

| Key | Meaning |
| --- | --- |
| `operating_system` | Passed to every tool as `--operating-system` |
| `repeat` | Default `--repeat` for every capture (default 3) |
| `browsers` | Each desktop browser a capture may name (`chrome`, `edge`, `brave`, `opera`, or `firefox`), with its executable `path` and the `version` passed as `--client-version`. Environment variables in `path` are expanded |
| `captures[].tool` | A tool from the table below |
| `captures[].browsers` | Browsers from `browsers` to capture |
| `captures[].scenarios` | Scenario names, or `"all"` for every scenario the tool defines. Omit it for `client_hints` and `snapshot`. For `startup_capture` the names are layers |
| `captures[].repeat` | `--repeat` for this capture |
| `captures[].output_dir` | Directory for the fixtures. `{browser}`, `{version}`, `{tool}`, and `{scenario}` are replaced; a relative path is relative to the repository root |
| `captures[].args` | More arguments for the tool, such as `["--navigate", "devtools"]`. The runner refuses the arguments it sets itself |
| `captures[].exclusive` | `true` runs each job of the capture with no other job. `false` lets a tool whose evidence depends on timing share the host; see [Parallel safety](#parallel-safety) |
| `captures[].timeout` | Seconds before an attempt is stopped. The default is twice the tool's run budget times `repeat`, plus 60. A Firefox job that shares the host also gets `repeat` times `--jobs` times 15 seconds for launch turns |

The runner refuses a manifest with an unknown key, a browser a tool does not
support, an unknown scenario, or two jobs that would write the same file.

| Tool | Files per job | Browsers | Runs alone |
| --- | --- | --- | --- |
| `client_hints` | `navigation.txt` | All five | No |
| `tls_resumption` | `resumption-<scenario>.txt` | All five | By default: the fixtures keep connection counts, ticket order, and which requests arrive in early data |
| `quic_resumption` | `<prefix>-<scenario>.txt`, where `--fixture-prefix` sets `<prefix>` (default `resumption`) | All five | By default: the fixtures keep connection counts and which requests travel in 0-RTT |
| `cookie_crumbs` | `crumbs-<scenario>.txt` | All five | By default: the fixtures keep connections and the order of QPACK encoder-stream inserts |
| `http2_websocket` | `<scenario>.txt` | All five | By default: the fixtures keep retries, connection counts, and frame order |
| `proxy_route` | `<scenario>.txt` | All five | By default: the fixtures keep connection and tunnel counts, and browsers retry failed tunnels |
| `sse_reconnect` | `<scenario>.txt`; use separate output directories for each `--protocol` | All five | By default: the fixtures keep reconnect delays |
| `tunnelled_websocket` | `<proxy>-<origin-alpn>-<scenario>.txt` | All five | By default: the fixtures keep tunnel counts, retries, and frame order |
| `alt_svc_race` | `<scenario>.txt` | Chrome, Edge | Always: it binds UDP and TCP ports drawn from the fixed range 20000-39999, and the fixtures keep race delays |
| `startup_capture` | For run `n`: `client-hello-<n>.txt` (`tls`), `client-startup-<n>.txt` (`http2`), or `client-startup-<n>.txt` and `quic-client-hello-<n>.txt` (`http3`) | Chromium browsers | No |
| `snapshot` | `snapshot-<n>.txt` for run `n`; omit `scenarios` | All five | No |
| `chrome_ech` | `ech-<scenario>.txt`, or `ech-quic-<scenario>.txt` with `--quic`; `repeat` must be 1 | Chromium browsers | Always: the origin listens on `127.0.0.1:443`, and `--dns-from-policy` needs a machine-wide Edge policy |

`startup_capture` at the `tls` and `http2` layers and `chrome_ech` run Cargo
examples, which must be built first; pass `--capture-binary` in `args`.
`alt_svc_race` gets a NetLog directory of its own inside the work directory.
It picks its port from 20000-39999 rather than from port 0, because Windows
excludes UDP and TCP ranges separately; two runs could draw the same number,
so it never shares the host.
Android browsers and `manual` are not supported; see
[Android browsers](#android-browsers).

### Resume and retry

The work directory keeps a completion record for each job that passed: the
job's parameters (tool, browser, executable path, `--client-version`,
`--operating-system`, scenario, `repeat`, extra arguments, and output paths),
whether it shared the host, the concurrency, and the SHA-256 of each file it
wrote. The runner skips a job only when its record matches the manifest and
every file still has the recorded digest. The record is removed when the job
starts and written only when an attempt passes, so a fixture from a failed
attempt, from other parameters, or written by hand is captured again and
overwritten. Resuming needs the same `--work-dir`.

An attempt passes when the tool exits with status 0 and rewrites every file
after the attempt starts, and each file ends with a newline and has no
`run_<n>_timed_out=true` line. Several tools record a run that timed out in the
fixture instead of failing, and no retained fixture holds one.

A failed attempt is run again at once. Each attempt's standard output and
standard error go to `<work-dir>/logs/<job>.<attempt>.log`. Its temporary
directory, which holds the browser profile, is
`<work-dir>/tmp/<digest>.<attempt>`, where the digest is the first eight hex
digits of the SHA-256 of the job ID. Firefox 157 on Windows does not start
from a profile path of 209 or more characters: it never loads the page or
publishes its remote protocol endpoint, so the attempt times out. On Windows
the runner therefore refuses a work directory deep enough for a profile path
to pass 208 characters when the manifest's jobs, after `--only`, include
Firefox. The limit was measured only for Firefox, so a work directory for
other browsers is not checked.

A direct launch shows the limit without the runner. In PowerShell, this
starts Firefox headless on an empty profile whose path is 208 characters,
then 209, and checks for the remote protocol endpoint file after ten seconds:

```powershell
foreach ($length in 208, 209) {
  $base = "$env:LOCALAPPDATA\Temp\pfl$length"
  $path = "$base\" + ("p" * ($length - "$base\".Length))
  New-Item -ItemType Directory -Force $path | Out-Null
  $firefox = Start-Process -PassThru "C:\Program Files\Mozilla Firefox\firefox.exe" `
    -ArgumentList "--headless", "--no-remote", "--profile", "`"$path`"",
    "--remote-debugging-port", "0", "about:blank"
  Start-Sleep -Seconds 10
  "$($path.Length): $(Test-Path "$path\WebDriverBiDiServer.json")"
  taskkill /PID $firefox.Id /T /F | Out-Null
}
```

On the Windows 11 capture host, with Firefox 157.0, it prints `208: True`
and `209: False`. The 208-character profile holds 53 entries after ten
seconds; at 209 characters Firefox has already exited, leaving two, so
`taskkill` reports that it found no such process. Delete the two `pfl`
directories afterwards.

On Windows a trusted CPython bootstrap waits until it belongs to a kill-on-close
Job Object before starting the tool. It uses the actual interpreter rather than
a virtual environment's redirector; the tool keeps its original interpreter and
environment. Assignment failure stops the attempt before
the tool runs. The tool and its ordinary descendants belong to that job;
external brokers and device processes have separate cleanup. On other systems
a private custodian leads the process group and reports the tool's exit status.
It stays alive until group cleanup, so the group identifier cannot be reused
after the tool exits. This requires normal child reaping and no competing
process reaper. If the parent goes away, the custodian kills its group.

When an attempt ends or reaches its timeout, cleanup ends the owned group
or job and sweeps processes whose command lines contain its temporary
directory as a whole path component. It then removes that directory.
Cleanup failures retain the original causes and owners that can be retried.
Invalid Windows handles are retired with their diagnostic. Before Windows
assignment, parent EOF stops the bootstrap without starting the tool.

Windows cleanup collects up to 4,096 original member handles before termination
and waits for them under one twenty-second budget. Failed waits keep their
handles for another cleanup attempt. Processes already exiting and absent
before collection are outside this completion guarantee. Native calls can
exceed the wait budget.

Direct `ProcessContainer` callers use `wait(timeout=...)`, `poll()` and `pid`
instead of `.process`. Wait timeouts must be finite and nonnegative. Closing
before collecting the tool's exit status reports `ProcessContainerStopped`.
The container owns process reaping.

Ctrl+C starts no more jobs or retries, ends every running attempt the same
way, prints the summary, and writes the results file. A job that was running
is reported as `stopped`, and one that had not started as `not-run`. Failed
launches, cleanup and progress reporting produce failed job results.

At the end the runner prints one line per job (status, attempts, seconds, and
the last failure) and a total, then writes the results file: the concurrency,
whether it was interrupted, the wall-clock seconds, and each job's tool,
browser, scenario, whether it shared the host, outputs, and attempts with
their seconds, failure, and log path. Keep it with the capture's notes: the
fixture formats have no field for the concurrency a capture ran under.

### Parallel safety

Jobs that run at the same time share nothing the runner or the tools write:

- Each attempt gets its own directory as `TMP`, `TEMP`, and `TMPDIR`, so
  browser profiles and certificate files from `tempfile` land there.
- Every listener binds loopback port 0, except `alt_svc_race`, which runs
  alone. `startup_capture` picks the HTTP/3 port by binding port 0 and
  releasing it; if another process takes the port first, the attempt fails
  and is retried.
- Output files cannot overlap: the manifest check refuses it.
- Desktop Firefox launches take turns while other jobs run, as
  [Browser launcher](#browser-launcher) describes.
- A tool that uses machine-wide state always runs with no other job:
  `chrome_ech` and `alt_svc_race`.

A job runs alone by default when host load can change its connection counts,
request order or timing. Only `client_hints` and `startup_capture` share the
host by default. Set `"exclusive": false` for captures of ClientHello or header
values, and keep timing-sensitive jobs exclusive.

On the capture host (16 cores, 32 threads), 15 jobs of `client_hints` and
`tls_resumption` for Chrome 154, Edge 154, Brave 154, Opera 135, and
Firefox 156, 45 browser runs, took 127 seconds with `--jobs 1` and 111 seconds
with the default `--jobs 8`, where the `tls_resumption` jobs ran alone. With
`"exclusive": false` for `tls_resumption` they took 26 seconds at `--jobs 8`,
and each job took about 25% longer than alone. The number of resumed
ClientHellos, and in `methods-http1` whether a run had 7 or 8 connections,
differed even between runs made alone. At 16 jobs each took about 70% longer
than alone. Measured September 2026.

### Add a tool to the runner

A tool can run under the runner when it:

1. takes `--browser`, `--browser-path`, `--client-version`,
   `--operating-system`, and `--repeat`, and either `--scenario` with
   `--output-dir` or a single `--output`;
2. binds its listeners to loopback port 0, or declares the fixed port as
   machine-wide state;
3. creates temporary files through `tempfile` and launches browsers through
   `browser_launch.py`;
4. writes each fixture with `write_text_fixture`, and either exits with a
   nonzero status when a run fails or records it as
   `run_<n>_timed_out=true`;
5. launches browsers from a coroutine through `BrowserDriver` or
   `enter_browser`, so a Firefox launch waiting its turn does not stop the
   tool's event loop.

Then add a `Tool` entry to `TOOLS` in `run_matrix.py` with the module, the
browsers it supports, the files a job writes, a run budget in seconds, and
`global_state` if it uses machine-wide state, or `timing` if its evidence
includes counts, order, or delays. Add a manifest test for its file names to
`tests/test_run_matrix.py`.

## Browser launcher

The Python tools start browsers through `browser_launch.py`. Each run gets a
new temporary profile, which the launcher removes with the browser's process
tree afterwards. Fixtures record the exact launch arguments, with the profile
path replaced by `<temporary-profile>`.

| `--browser` | How it starts |
| --- | --- |
| `chrome`, `edge`, `brave`, `opera` | `--headless=new` unless `--headful`, `--user-data-dir`, the flags in `CHROMIUM_FLAGS`, then the page URL |
| `firefox` | `--headless` unless `--headful`, `--wait-for-browser`, `--no-remote --profile`, then the page URL |
| `chrome-android`, `edge-android`, `brave-android`, `opera-android`, `firefox-android` | On an Android device through adb; see [Android browsers](#android-browsers) |
| `manual` | Starts no process. Each run prints its URL on standard error for a person to open. Use it for Safari and any browser that cannot be launched from the command line |

Every tool that takes `--browser chrome` also takes `brave` and `opera`. On
the capture host their executables are
`C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe` and
`%LOCALAPPDATA%/Programs/Opera/<version>/opera.exe`. Use Opera's versioned
executable rather than the `opera.exe` launcher beside the version
directories, so the version under test is the one that runs.

`CHROMIUM_FLAGS` suppresses background requests from a fresh profile: first
run and default-browser checks, background networking, component updates,
default apps, proxies, phishing detection, background extensions, domain
reliability, sync, pings, and the `MediaRouter` and `OptimizationHints`
features. Firefox has no matching switches, so the launcher writes a `user.js`
that turns off the same classes of traffic, including updates, captive-portal
and connectivity checks, telemetry, Safe Browsing, DNS over HTTPS, and
proxies.

When `run_matrix.py` runs a job beside others, it sets
`PHANTOM_CAPTURE_LOCK_DIR` for that job, and desktop Firefox launches then
take turns. Each holds a lock file in that directory until
`sessionCheckpoints.json` in its profile records
`sessionstore-windows-restored`, which Firefox writes at about the moment it
requests the page, until the process exits, or for at most 15 seconds. The
wait runs in a worker thread, so the tool's server answers the page while
Firefox starts. Standalone tools and `--jobs 1` launch at once. On the capture
host, Firefox 156 loaded its page in 5 of 9 launches in groups of three,
versus 12 of 12 in groups of four with the lock. Chromium loaded 8 of 8
in groups of four.

`client_hints.py` and `http2_websocket.py` take `--browser-switch=<switch>`,
repeatable, for a Chromium browser. The switch is appended to the launch
arguments and recorded with them. On macOS, Edge takes `Accept-Language`
from the system's language list and ignores `--lang`, so its captures pass
`--browser-switch=--accept-lang=en-US`.

On macOS a Chromium launch also receives `--use-mock-keychain`. Without it,
a fresh profile reads and writes the browser's "Safe Storage" item in the
login keychain, which the person's own browser profile uses. The switch is
recorded with the other launch arguments. `startup_capture.py` adds it in
the same position.

After a run the launcher ends the browser's process group, then kills any
process whose command line still names the run's temporary profile. A
process that names another profile, such as the person's own browser, is
never touched. On macOS, set `TMPDIR` to keep the temporary profiles in a
directory of your choice.

Fixtures record `launch_mode` (`headless`, `headful`, `manual`,
`android-typed`, or `android-intent`). Captures made in different modes are
compared, never assumed equal. A coding agent needs the human's approval before it launches a
local browser.

## Android browsers

Android captures run on the `phantom-pixel7` emulator on the Windows capture
host: the Android 17 (API 37) Google Play x86_64 system image, build
`CE2A.260420.019`. The emulator is rooted with Magisk v30.7 through a patched
copy of its ramdisk, and a Magisk module sets the build properties of a
Pixel 7: model `Pixel 7`, fingerprint
`google/panther/panther:17/CP3A.260905.009/16091614:user/release-keys`, and
security patch 2026-09-05. A capture therefore reports the model
`"Pixel 7"`. Gboard's stylus handwriting is turned off. The browsers come
from the Play Store, signed in with a throwaway account, so each is the build
Play serves to that device, which can trail the version Google's release API
lists.

[Android capture emulators](android/README.md) describes how both
emulators are built: the system images, rooting, the Magisk module, the guest
settings, and the `onboarded` snapshot. Set `ANDROID_SDK_ROOT` to the Android
SDK directory and start an emulator from Git Bash with
[`start-capture.sh`](android/start-capture.sh), which loads `onboarded`
without saving over it and clears the proxy variables:

```sh
scripts/capture/android/start-capture.sh -r <patched-ramdisk.img> \
  -- -no-window -no-audio > emulator.log 2>&1 &
```

The device's serial is `emulator-5556`.

Play serves Edge for Android only as an arm64 build, which cannot start on
the x86_64 emulator. Edge runs on `phantom-pixel7-arm`, an emulator on an
Apple silicon Mac with the same Android 17 build as an arm64-v8a image and
the same Magisk module. That emulator reaches the Mac's loopback at
`10.0.2.2`. A listener that runs on the Windows host, such as the TLS and
HTTP/2 startup examples, is reached through an `ssh -R` forward of the
Mac's loopback port to it; the forward passes the TCP stream bytes
unchanged.

Chromium sends `initial_rtt_us` on a fresh QUIC connection when a cellular
network is the default, which the recipes do not model. Both emulators use
Wi-Fi only: turn mobile data off before a capture and check that Wi-Fi is
connected:

```sh
adb -s emulator-5556 shell svc data disable
adb -s emulator-5556 shell cmd wifi status
```

If Wi-Fi drops and `dumpsys connectivity` reports no default network,
`svc wifi disable` followed by `svc wifi enable` restores it.

Never pass `-wipe-data`: it signs the Play account out, removes the
browsers, and discards the rooted `onboarded` state. If adb lists the device
as `unauthorized`, create the host's public key with
`adb pubkey ~/.android/adbkey > ~/.android/adbkey.pub` and restart the
emulator.

Every run stops the browsers in the table below, ends cached apps, and
clears the tested browser's app data, which on a personal phone erases its
tabs, history, and sign-ins. The launcher therefore refuses a device that does
not report `ro.kernel.qemu` or `ro.boot.qemu` as `1`, which every emulator
does. To run on a phone set aside for captures, set
`PHANTOM_ANDROID_ALLOW_PHYSICAL_DEVICE=1`, or pass `--allow-physical-device` to
`android_run.py`.

The launcher also refuses an emulator that cold-booted instead of loading
the `onboarded` snapshot. It tells them apart by the `debug.phantom.snapshot`
property, which is set in guest memory before the snapshot is saved; see
[The `onboarded` snapshot](android/README.md#the-onboarded-snapshot).
`PHANTOM_ANDROID_ALLOW_COLD_BOOT=1` or `--allow-cold-boot` overrides it.
The flag applies only to that launch and leaves the environment unchanged.

`startup_capture.py` and `chrome_ech.py` take desktop browsers only, and
`proxy_route.py` refuses the authentication scenarios for an Android
browser.

Pass `--browser <name>-android`, the adb executable as `--browser-path`, and
the device serial in `ANDROID_SERIAL`:

```sh
ANDROID_SERIAL=emulator-5556 uv run --no-project --python 3.10 \
  python -m scripts.capture.client_hints \
  --browser chrome-android \
  --browser-path "$ANDROID_SDK_ROOT/platform-tools/adb" \
  --client-version 154.0.8037.57 \
  --operating-system "Android 17 (API 37) x86_64 emulator reporting Pixel 7 CP3A.260905.009" \
  --repeat 3 \
  --output fixtures/client-hints/chrome-android/154.0.8037.57/android-17-pixel7-emulator/navigation.txt
```

For Edge on the arm64 emulator, pass `--operating-system "Android 17 (API
37) arm64 emulator reporting Pixel 7 CP3A.260905.009"`; the fixture
directory is still `android-17-pixel7-emulator`.

Each run, through `android_device.py`:

1. stops every browser in the table below, so none holds a socket or sends
   background traffic, then clears the browser's app data with `pm clear`,
   which is the Android equivalent of a fresh profile;
2. writes the browser's debug configuration and makes the package the
   device's debug app (`am set-debug-app --persistent`), which a release
   build requires before it reads that file;
3. adds `adb reverse` for each port that a URL or switch names on
   `127.0.0.1` or `localhost`;
4. opens `about:blank` with a `VIEW` intent aimed at the package, focuses the
   address bar with Ctrl+L, and types the page URL with
   `adb shell input text`, six characters at a time. After each chunk a
   `uiautomator dump` reads the focused field; the launcher retypes whatever
   did not arrive and presses Enter only when the field holds the exact URL;
5. afterwards stops the browser, removes the reverse ports and the debug
   configuration, and clears the debug app.

Failed setup also cleans up the actions the session started. Cleanup tries
the remaining actions after an error and reports failures with the original
error. A refused launch leaves the device alone. Calling cleanup again
retries only actions that failed. A rejected cleanup command is reported as
an error and remains available for retry. Direct `AndroidLaunch` callers
must set `typing_attempts` to a positive count.

A failed emulator or snapshot query stops setup before changing the device.
An absent property from a successful query still follows the refusal rules.

A failed focus query, screen dump or screen read stops navigation. Its output
cannot authorize an onboarding tap or Enter in the address bar.

Async capture drivers run Android commands and browser cleanup in workers.
The capture server keeps responding during those waits. Cancelling the caller
leaves cleanup running and reports a later failure through the loop's error
handler. Another cleanup call waits for that worker while it is running.

The page load is therefore a typed address-bar navigation, and fixtures
record `launch_mode=android-typed`. A page that another app opens through a
`VIEW` intent has no user activation, and Chrome then leaves out
`Sec-Fetch-User` and sends `Sec-Fetch-Site: cross-site`. A `LaunchPlan`
with `android_entry="intent"` opens the page
that way instead and records `android-intent`; the TLS, HTTP/2 startup, and
QUIC captures use it, because those layers do not depend on how the page was
opened and the intent needs no typing. `quic_resumption.py`,
`http2_websocket.py`, and `proxy_route.py` take `--android-entry intent` for
the same launch. Use it when the fixture's evidence is what the page's script
sends, such as resumed connections or WebSocket openings, and keep the typed
default when a page-load request is compared with a template. An intent run
of these tools takes 5 to 7 seconds on the capture host.

A loaded device drops injected keys while the address bar fetches
suggestions, and the address bar appends a selected inline completion to what
was typed. Checking the field after each chunk handles both. An "isn't
responding" dialog, which a busy emulator shows for System UI, takes the
focus; the launcher taps its Wait button and refocuses the address bar.
With 2.5 GB of RAM the guest's system server died during long capture
sessions; `phantom-pixel7` runs with 8 GB. On the capture
host a typed entry takes about 90 seconds while other builds run, so the
Android runs use run timeouts of 240 seconds.

| `--browser` | Package | Debug configuration |
| --- | --- | --- |
| `chrome-android` | `com.android.chrome` | `/data/local/tmp/chrome-command-line` |
| `edge-android` | `com.microsoft.emmx` | `/data/local/tmp/chrome-command-line` |
| `brave-android` | `com.brave.browser` | `/data/local/tmp/chrome-command-line` |
| `opera-android` | `com.opera.browser` | None; the launch refuses switches |
| `firefox-android` | `org.mozilla.firefox` | `/data/local/tmp/org.mozilla.firefox-geckoview-config.yaml`, preferences only |

A typed entry does not work with Firefox for Android: the launcher opens
`about:blank` by `VIEW` intent first, and Firefox does not resolve that
intent. Firefox captures use `--entry intent`.

Opera for Android reads no command-line file, so the launcher refuses
switches for it: a tool can capture it only on the device's own loopback
without a certificate, as `client_hints.py` and `proxy_route.py --scenario
direct-loopback` do. A cleared Opera profile opens first-run screens that no
switch skips. The launcher steps through them from `uiautomator` dumps while
Opera's `WelcomeActivity` has the focus: Next, Skip, Customize rather than
Allow on the data-collection screen, every checked box unchecked before
Confirm, and Start browsing. The dumps of these screens can be empty for a
while or list pages not yet shown, so this can stall; the launch then fails
rather than type into the wrong screen.

A Chromium command-line file holds `--disable-fre`, `CHROMIUM_FLAGS`, and
the tool's switches. Android has no headless mode and no `--user-data-dir`.
The GeckoView file holds the Firefox baseline preferences and the tool's
preferences; a tool that needs files in the Firefox profile, such as
`cert_override.txt`, cannot run there.

The TLS and HTTP/2 startup examples only listen. Start one on a free
loopback port, then open its URL on the device with `android_run.py`, which
runs one launch as above and stops the browser after `--hold` seconds:

The hold defaults to eight seconds. It must be finite and nonnegative;
zero stops the browser immediately after opening the page.

```sh
ANDROID_SERIAL=emulator-5556 uv run --no-project --python 3.10 \
  python -m scripts.capture.android_run \
  --browser chrome-android \
  --adb "$ANDROID_SDK_ROOT/platform-tools/adb" \
  --entry intent \
  --switch=--disable-quic \
  "--switch=--host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost" \
  --switch=--ignore-certificate-errors \
  --url https://server.phantom.test:<port>/
```

Add `--print-arguments` to print the fixture's `launch_arguments` value
without launching; pass it to the example as its launch-arguments argument.
The examples wait 30 seconds for a connection, so use `--entry intent` with
them.

The emulator reaches host loopback at `10.0.2.2` over both TCP and UDP. The
launcher rewrites `MAP <name> 127.0.0.1` in `--host-resolver-rules` to that
address, so a test name reaches a host listener, QUIC included; `adb reverse`
forwards TCP only.

Limits:

- The emulator's network terminates the guest's TCP connections and opens
  new ones from the host, so the listener sees the host's SYN, window, and
  socket options, never the device's. No TCP-layer setting can be captured
  this way.
- Chromium's AES hardware check sees an x86_64 CPU on `phantom-pixel7`.
  `phantom-pixel7-arm` runs on a Mac. The Magisk module changes reported
  identity fields.

## EventSource reconnects

`sse_reconnect.py` records how a browser's `EventSource` reconnects after a
server-sent events stream ends. Its default `--protocol h1` serves plaintext
HTTP/1.1 to one `new EventSource(...)` page per run and writes one
`format=phantom-sse-reconnect-v1` fixture per scenario.

Desktop browsers also accept `--protocol h2` or `--protocol h3` with the
packages pinned in `scripts/requirements.txt`. These modes serve HTTPS and
require the requested protocol on every recorded connection. Their
`phantom-sse-reconnect-v2` fixtures retain ordered decoded headers and stream
identities, resets and closes. They do not retain compressed HPACK or QPACK
representations. Ending a stream replaces the H1 FIN stimulus; resetting a
stream replaces the H1 reset stimulus.

On Windows, HTTP/3 requires CPython 3.12.3 or later. The tool rejects older
runtimes, whose asynchronous ICMP completion can stop the receive loop.
The pinned runtime can still report a synchronous receive reset after a peer
closes. After the run completes, cleanup records that reset
and replaces the stopped listener within the original cleanup deadline.
Active-run errors still fail the capture.
Use the same pinned interpreter as the Windows capture tests:

```sh
uv run --no-project \
  --python "$(cat scripts/capture/windows-python-version.txt)" \
  --with-requirements scripts/requirements.txt \
  python -m scripts.capture.sse_reconnect --protocol h3 <browser-options>
```

Pass `args: ["--protocol", "h3"]` in a `sse_reconnect` manifest entry. The
runner appends the protocol to its job ID. Files still use `<scenario>.txt`,
so give each protocol a separate output directory. Use fresh work and output
directories for new experiments.

Use finite positive run timeouts and single-line printable ASCII metadata.
Cleanup attempts to collect accepted response workers within a five-second
cooperative deadline. A response or cleanup failure prevents publishing its
fixture.

The macOS headed Chrome workflow runs `macos_headful_capture.py` for one
`reconnect-204` attempt. Its artifact retains command output, source and
browser hashes, observed User-Agent bytes, and the last phase on failure.
Source or browser changes, missing terminal observations, and failed capture
commands prevent success, even when a fixture exists.

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

Split larger experiments into separate runs. The shared server allows 32
runs, 32 active connections, 128 connections per run, 1,024 requests, 256
WebSockets and 128 page results per run. It records at most 64 MiB per run
and 16 MiB per direction on one connection. Request heads, ClientHellos and
decoded HTTP/2 header blocks are limited to 64 KiB. A WebSocket message may
contain at most 16 MiB of decoded data, with 32 MiB across one stream.
Exceeding a limit fails the capture before its fixture is written.

Run timeouts must be finite and positive. Observation times must be finite
and nonnegative. Android requires IPv4 loopback. Desktop captures support
either loopback family. Shutdown attempts every owned connection and
listener, and reports serving or cleanup failures. Cleanup that exceeds its
deadline fails; some owners may still be running.

Offline frame and header analysis lives in `http2_analysis.py`. Import its
analysis types and helpers there; `http2_session.py` owns the live recorder.

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
  `network.dns.disableIPv6` matching the selected listener family, and
  `network.http.http3.enable=false`
  preferences, plus a `cert_override.txt` in its temporary profile.
  `--firefox-skip-tls-trust` omits the override.

## Client hints

`client_hints.py` records which user-agent client hints a browser sends by
default and which it adds after a server asks for them with `Accept-CH`. It
serves two plaintext HTTP/1.1 navigations on a loopback origin per run and
writes one `format=phantom-client-hints-v2` fixture. Chromium treats loopback
HTTP origins as potentially trustworthy, so it sends hints to them.

`--accept-ch` takes lowercase HTTP field names without `|`, the fixture
separator. `--run-timeout` must be finite and positive. For IPv6 loopback,
use `--listen '[::1]:0'`.

Use single-line printable ASCII metadata. The tool rejects malformed HTTP
field names. Valid names keep their original case and order.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.client_hints \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.97 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --repeat 3 \
  --output fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/navigation.txt
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

Before another run or fixture publication, the tool collects registered
connections and their callback outcomes. A callback failure stops the capture.
A run fails above 64 retained connections. Cleanup has a five-second
cooperative deadline; incomplete cleanup prevents fixture publication.
Protocol setup failures retain and retire the accepted socket.

## HTTP/2 preface PING

`http2_preface_ping.py` records the client frames of one HTTP/2 connection
that a Chromium browser reuses after idle periods. The page fetches `/a`,
waits `--idle` seconds (11.5 by default), fetches `/b`, waits `--short`
seconds (9), fetches `/c`, waits `--idle` seconds again, and sends a 100-byte
`POST /p` before `/done`. A run takes about 35 seconds.

Use single-line printable ASCII metadata. Invalid metadata fails before
resource acquisition, and the renderer checks derived launch values before
publication. Protocol setup failures retain and retire the accepted socket.

```sh
uv run --no-project --python 3.10 --with h2==4.4.1 --with hpack==4.2.0 \
  --with cryptography==50.0.1 python -m scripts.capture.http2_preface_ping \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --output-dir fixtures/http2/chrome/154.0.8037.58/windows-11-26200
```

It writes one `format=phantom-http2-preface-ping-v1` fixture,
`preface-ping.txt`. Each `frame_<n>` line is one client frame of the
connection that carried the page, after the connection preface: its time
since the listener started, type, flags, stream, and length, the request path
of a HEADERS frame without its query, and the payload of a PING. No other
payload is written.

Only `/done` with the run's exact token on the page's connection completes
the capture. Before writing, the tool collects registered connections and
their callback outcomes within a five-second cooperative cleanup deadline.
A callback error or incomplete cleanup prevents fixture publication.

Use finite positive waits within the page timer limit (2,147,483.647 seconds).
The tool limits a run to 32 retained connections and 64 MiB of recorded
decrypted input and output. Each connection permits 200 frames, with an
inbound frame payload limit of 16 KiB.

## Connection lifecycle

`http_lifecycle.py` serves a scripted page over TLS on loopback to Chrome,
Edge, Brave, Opera, or Firefox, and writes one
`format=phantom-http-lifecycle-v1` fixture, `<scenario>.txt`, per run. The
server reads TLS through memory BIOs, so for every connection the browser
opens it records whether a `close_notify` arrived before the TCP end, or a
reset. It also keeps each connection's HTTP/2 client frames other than DATA,
with PING payloads and `GOAWAY` fields, and each request's field names in
wire order, with the values of the validator, `Expect`, and body fields.

Each run collects its registered listeners and connections before writing.
Capture and cleanup failures retain their original causes and prevent writes.
Cleanup has a five-second cooperative deadline. Local cleanup does not count
as a browser close event.

A run allows 32 connections, 256 requests and 64 MiB of encrypted input and
output. Each connection allows 64 active HTTP/2 streams, 65,536 input frames
including DATA, and 2,000 recorded frames. HTTP/2 frame payloads are limited
to the advertised 16 KiB. Completed HTTP/1 heads have a 64 KiB limit and
request bodies have an 8 MiB limit. Methods and header names must be ASCII
HTTP tokens. Targets must contain visible ASCII. Paths containing commas
and header names containing pipes fail before recording.

`--idle` must be finite and positive, up to 2,147,483.647 seconds.
Completion requires one exact run token on the page's selected connection.
Resource captures may finish on another owned connection to the same origin.
Firefox accepts only `--listen 127.0.0.1` or `--listen ::1`, checked before
acquiring a certificate or listener. IPv4 disables IPv6. IPv6 prefers IPv6
without excluding IPv4. Chromium brackets IPv6 resolver addresses.

| Scenario | ALPN | What the page does |
| --- | --- | --- |
| `revalidate` | `h2` | Fetches four cacheable resources twice each; a matching `If-None-Match` or an `If-Modified-Since` gets `304` |
| `upload-h1`, `upload-h2` | `http/1.1`, `h2` | POSTs 100 bytes, 1 MiB string and `Blob` bodies, a 1 MiB multipart `FormData`, and a form with a 1 MiB file |
| `idle-ping` | `h2` | Fetches, leaves the connection idle for `--idle` seconds (75), fetches again |
| `ping-unanswered` | `h2` | Fetches, waits 11.5 s, fetches again; from that request on the server writes nothing on the connection |
| `close` | `h2` and `http/1.1` | Fetches over HTTP/2, aborts an HTTP/1.1 response at a second origin, fetches there again, then the tool closes the browser over CDP or WebDriver BiDi |
| `resources` | `h2` or explicit `http/1.1` or `h3` | Loads one local script, stylesheet, image and licensed Ahem font |

`resources` defaults to HTTP/2 and retains each request's initial HEADERS
priority. Add `--resource-protocol h1` to observe HTTPS over HTTP/1.1 instead.
H1 retains raw request lines and headers, including case, order and duplicates.
Use `--resource-protocol h3` with desktop Chromium for HTTP/3. It retains client
stream bytes, ordered fields and QPACK state for independent request decoding.
All modes retain at most 512 KiB of plaintext peer bytes. They accept only six
owned paths with the exact run token and reject credentials or unrelated
headers. The page verifies script execution, image decoding and font loading
before reporting success. Both asset values and raw bytes require review before
publication. This scenario uses no NetLog and creates no profile or template.
Select `http_lifecycle` with `scenarios: ["resources"]` and `repeat: 1` in a
matrix manifest. Use a separate output directory for each protocol; each writes
`resources.txt`. H1 and H3 output identify their selected protocol.

Capture Chrome and Firefox on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.http_lifecycle --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.97 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario close \
  --output-dir fixtures/lifecycle/chrome/154.0.8037.97/windows-11-26200
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.http_lifecycle --browser firefox \
  --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe" \
  --client-version 157.0 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario idle-ping \
  --output-dir fixtures/lifecycle/firefox/157.0/windows-11-26200
```

Chromium browsers map `server.phantom.test` with `--host-resolver-rules`
and trust the throwaway certificate with
`--ignore-certificate-errors-spki-list`; Firefox gets
`network.dns.localDomains` and a `cert_override.txt` for both listener
ports. The `close` and `resources` scenarios add `--remote-debugging-port`.
A run takes 1 to 5 seconds, except `ping-unanswered` (about 23) and
`idle-ping` (about 81). The page's own results go to the `page_result` line.

## ALPS `ACCEPT_CH` restart

`alps_accept_ch.py` runs the `capture_alps_accept_ch` example, which serves
`server.phantom.test` over TLS 1.3 and HTTP/2 from BoringSSL with an ALPS
`ACCEPT_CH` frame naming `--accept-ch` for its own origin, and launches a
Chromium browser at it with a NetLog. The page fetches `/fetch` and then
`/done`. The `format=phantom-alps-accept-ch-v1` fixture keeps each
connection and request the server saw, with field names in the order it
decoded them and the hints beyond Chromium's three defaults, and from the
NetLog the origin's `ACCEPT_CH` frames and each URL request to the origin:
whether `URL_REQUEST_DELEGATE_CONNECTED` ended with an error, and the field
names it sent. A navigation that started again shows as a request that
sent nothing, followed by another for the same path.

```sh
cargo build -p phantom-net --example capture_alps_accept_ch
uv run --no-project --python 3.10 python -m scripts.capture.alps_accept_ch \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.97 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --capture-binary target/debug/examples/capture_alps_accept_ch.exe \
  --output fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/alps-accept-ch.txt
```

`alps-accept-ch-reordered.txt` used
`--accept-ch "Sec-CH-UA-Platform-Version, Sec-CH-UA-Model, Sec-CH-UA-Arch"`.
Every name but the origin's fails to resolve (`MAP * ~NOTFOUND`), so the
fresh profile's background connections stay off the network. The NetLog is
removed after the run unless `--netlog` names a path for it.

## HTTP/3 startup

`chrome_http3.py` records one browser HTTP/3 connection against an aioquic
server, through the first request.
Pass `--client-hello <path>` to also write the QUIC
ClientHello.

With `--listen 127.0.0.1:0` the server binds a port the operating system
chooses, reports it on its `listening on` line, and records it in
`listen_address` and in place of each `<port>` in `--launch-arguments`.
On Windows it retries a bind that fails with os error 10055 at a reserved
port block.

Pass `--output <path>` to write the startup fixture; the tool then writes it
with LF line endings. Without `--output` the fixture goes to standard output,
which Python opens in text mode, so on Windows it carries CRLF.
`fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt` was
written that way and is the one CRLF file under `fixtures/`. Its bytes and the
SHA-256 that `scripts/capture/tests/test_chrome_http3.py` pins are stable in
the repository, because `.gitattributes` marks `fixtures/**` as `-text`, and
every parser strips the carriage return. Do not rewrite its line endings.

The tool serves only the first QUIC connection it receives.
[`startup_capture.py`](#connection-startup-launches) launches the browser for
it and handles a browser that abandons its startup connections.

## Connection-startup launches

`startup_capture.py` runs one of the three single-connection listeners (the
`capture_client_hello` and `capture_http2_tls` examples, or
`chrome_http3.py`) and launches a fresh Chromium browser against it, once per
`--repeat`. The browser gets the launch arguments of the retained Chrome 154
fixture for the layer, and the fixture records them with the profile path and
certificate hash replaced by placeholders.

`--navigate command-line` (the default) puts the page URL on the command
line, as the Chrome, Edge, and Brave fixtures were taken. `--navigate
devtools` starts the browser on `about:blank` with `--remote-debugging-port=0`,
waits `--settle` seconds (default 5), and navigates its first page with
`Page.navigate` over DevTools. The fixture's `launch_mode` is then
`devtools-navigate`. Use it for a browser such as Opera 135, which opens a
preconnect at startup and abandons it when its certificate verifier changes;
the listener would otherwise record that connection and never see the
request.

Build the examples, then capture Opera's HTTP/2 and HTTP/3 startups:

```sh
cargo build -p phantom-testkit --example capture_client_hello
cargo build -p phantom-net --example capture_http2_tls
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt   python -m scripts.capture.startup_capture   --browser opera   --browser-path "$LOCALAPPDATA/Programs/Opera/135.0.5973.92/opera.exe"   --client-version 135.0.5973.92   --operating-system "Windows 11 Home 10.0.26200 x64"   --layer http2 --navigate devtools --repeat 3   --output-dir <scratch-directory>/opera-http2
```

Use `--layer http3` for the QUIC ClientHello and HTTP/3 startup, and
`--layer tls` for the TCP ClientHello. Run `n` writes `client-hello-<n>.txt`
for TLS, `client-startup-<n>.txt` for HTTP/2, and `client-startup-<n>.txt`
with `quic-client-hello-<n>.txt` for HTTP/3.
Each listener prints a line starting with `listening on <address>` on
standard error once it has bound, and the tool launches the browser when it
reads that line. It gives up after `--server-start` seconds (default 30).

`--timeout` and `--server-start` must be finite and positive. `--repeat`
must be positive, and `--settle` must be finite and nonnegative. The capture
wait starts after the page is opened. TCP waits for `--timeout` seconds;
HTTP/3 allows ten more seconds for its listener to finish.

Remote browser TCP connection and WebSocket upgrade share a five-second
setup deadline. Cleanup can take additional time after setup fails.

The tool accepts at most 1 MiB of listener output and 64 KiB of diagnostics.
These limits apply to file snapshots, rather than temporary disk use between
polls. Cleanup stops owned processes and removes their temporary files.
Failures retain the initiating error and independent cleanup errors.

## QUIC resumption and 0-RTT

`quic_resumption.py` records what a browser sends when it resumes a QUIC
session: the resumed ClientHello, whether it offers early data, and which
requests travel in 0-RTT packets. It writes one
`format=phantom-quic-resumption-v1` fixture per scenario, named
`resumption-<scenario>.txt`.

Chromium brackets IPv6 resolver addresses. Firefox accepts only
`--listen 127.0.0.1` or `--listen ::1`, checked before acquiring a certificate
or listener. IPv4 disables IPv6. IPv6 prefers IPv6 without excluding IPv4.

Use finite positive run timeouts and single-line printable ASCII metadata.
The command permits at most 128 scenario runs in total. Shutdown collects
protocols, timers and the UDP listener within a five-second cooperative
deadline. Callback failures and incomplete cleanup prevent publication.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt   python -m scripts.capture.quic_resumption   --browser chrome   --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe"   --client-version 154.0.8037.58   --operating-system "Windows 11 Home 10.0.26200 x64"   --scenario accept --repeat 5   --output-dir fixtures/http3/chrome/154.0.8037.58/windows-11-26200
```

The retained `accept-delayed` and `reject` fixtures used `--repeat 3`.
The `resumption-streams-accept.txt` and `resumption-streams-reject.txt`
fixtures, the first to record unidirectional stream types, were written with
`--scenario accept reject --repeat 3 --fixture-prefix resumption-streams`
for Chrome and Edge. For
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
- the packet-number spaces each client stream arrived in;
- for each client unidirectional stream, in the order its first byte
  arrived: its stream type, and the packet-number space, length, and arrival
  time of the STREAM frame that carried its first byte.

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

## TLS resumption over TCP

`tls_resumption.py` records how a browser resumes TLS 1.3 sessions over TCP:
the resumed ClientHello, which ticket each connection presents, whether it
offers and sends early data, and which requests arrive in early data. It
writes one `format=phantom-tls-resumption-v2` fixture per scenario, named
`resumption-<scenario>.txt`.

Use finite positive run timeouts and single-line printable ASCII metadata.
Shutdown collects accepted peers and response tasks within a ten-second
cooperative deadline. Unexpected serving and cleanup failures prevent writing.
ClientHello and HTTP/1 headers each have a 32 KiB limit. Bodies have a 64 KiB
limit. Expected disconnects preserve independent cleanup errors.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt   python -m scripts.capture.tls_resumption   --browser chrome   --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe"   --client-version 154.0.8037.58   --operating-system "Windows 11 Home 10.0.26200 x64"   --scenario all --repeat 3   --output-dir fixtures/tls/chrome/154.0.8037.58/windows-11-26200
```

Use the other browsers' paths from [Browser launcher](#browser-launcher) and
[QUIC resumption and 0-RTT](#quic-resumption-and-0-rtt). The tool refuses an
aioquic version other than 1.3.0.

The server is aioquic's TLS 1.3 handshake with a TLS record layer in the
tool, on two loopback TCP listeners bound to port 0 (`a` and `b`). It serves
`server.phantom.test` and `top.partition.test`, each with its own
self-signed certificate, so a browser cannot pool one name's connection for
the other. After each handshake the server sends its own NewSessionTickets,
each with a 64-byte random identity and, unless the scenario says otherwise,
`max_early_data_size` 0xffffffff. It accepts early data whenever a client
offers it with a known ticket. It closes a connection after answering
`/retire` or `/done`, after a slow response, or after an HTTP/2 `GOAWAY`.
Each page step waits 300 ms before the next, so every step starts on a new
connection.

In the `websocket` scenarios the page retires its connection, then opens a
WebSocket to `wss://server.phantom.test:<port>/socket`, closes it once it
opens, and requests `/done`. The server answers an HTTP/1.1 Upgrade with
`101` and, over HTTP/2, sends `SETTINGS_ENABLE_CONNECT_PROTOCOL` in its first
SETTINGS and answers an extended CONNECT with `200`. It answers the client's
first WebSocket frame, its Close, with a Close. Only Firefox offers early
data over TCP, so only Firefox fixtures of these scenarios are retained.

| Scenario | ALPN | Tickets | Question |
| --- | --- | --- | --- |
| `sequential` | `h2` | 2 per connection | Resumed ClientHello, early data, and which of two tickets a new connection uses |
| `sequential-http1` | `http/1.1` | 2 per connection | The same with HTTP/1.1 |
| `no-early-data` | `h2` | 2 per connection, without early data | Resumed ClientHello when the ticket does not permit early data |
| `issue-once` | `h2` | 8 on the first connection to complete a handshake | How many tickets a browser keeps for one origin, in which order it uses them, and whether it reuses one |
| `parallel` | `http/1.1` | 2 per connection | Tickets used by six connections opened at once for six slow requests |
| `origins` | `h2` | 2 per connection | Whether a ticket learned on listener `a` is offered to listener `b`, the same host on another port |
| `methods` | `h2` | 2 per connection | Which of `GET`, `HEAD`, `OPTIONS`, `POST`, `PUT`, and `DELETE`, issued together, travel in early data; then a lone `POST` |
| `methods-http1` | `http/1.1` | 2 per connection | The same with HTTP/1.1 |
| `partition` | `h2` | 2 per connection | Whether a ticket learned while `server.phantom.test` is the top-level site is offered when a `top.partition.test` page fetches it, and after returning |
| `websocket` | `h2` | 2 per connection | Whether a resumed connection that opens a `wss://` WebSocket offers early data, and what travels in it |
| `websocket-http1` | `http/1.1` | 2 per connection | The same with HTTP/1.1 |

For each connection the fixture keeps:

- the listener, server name, offered and selected ALPN, and timings;
- the tickets the ClientHello offered, named `connection_<n>.ticket_<i>` after
  the connection that issued them, and whether the server resumed one;
- whether early data was offered and accepted, how many early-data bytes
  arrived, the HTTP/2 events, by `h2` class name, that early data produced
  (only in `v2` fixtures; `v1` fixtures also lack `server_websocket`),
  and the tickets the connection was issued;
- the extension order, key-share groups, PSK modes, PSK identity and binder
  lengths, the `session_ticket` extension length, and how the ClientHello
  differs from the run's first one.

For each request it keeps the connection, method, host, path, body length,
and whether it arrived in early data. Run 0 also keeps each raw ClientHello
and each request's field names in order. Summary lines count ClientHellos
that offered a PSK, resumed, and offered or sent early data, and any ticket a
browser offered twice.

Traffic keys stay in memory; no TLS secret or key log is written.

Chromium receives `--host-resolver-rules` that map both names to the
listener address and every other name to `~NOTFOUND`, both certificates'
`--ignore-certificate-errors-spki-list`, `--disable-quic`, and
`--disable-field-trial-config`. `--netlog-dir` adds `--log-net-log` for
diagnosis; NetLogs are not fixture inputs. Firefox receives
`network.dns.localDomains` naming both hosts, `network.dns.disableIPv6=true`,
`network.http.http3.enable=false`, and a `cert_override.txt` covering both
names on both ports.

## ClientHellos to IP literals

`ip_literal_client_hello.py` records the ClientHellos headless Firefox sends to
`https://127.0.0.1:<port>/` or `https://[::1]:<port>/`, which carry no
`server_name`. `--grease-size` sets `security.tls.ech.grease_size`, the
`maximum_name_length` Firefox pads its TCP ECH GREASE payload for, so a sweep
of sizes shows which host length Firefox pads by.

Capture one TCP run and one QUIC run on Windows:

```sh
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m scripts.capture.ip_literal_client_hello \
  --firefox-path "C:/Program Files/Mozilla Firefox/firefox.exe" \
  --transport tcp --family ipv4 --grease-size 93 \
  --output fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/tcp-ipv4-grease-size-93.txt
uv run --no-project --python 3.10 --with aioquic==1.3.0 \
  python -m scripts.capture.ip_literal_client_hello \
  --firefox-path "C:/Program Files/Mozilla Firefox/firefox.exe" \
  --transport quic --family ipv4 \
  --output fixtures/tls/firefox/157.0/windows-11-26200/ip-literal/quic-ipv4.txt
```

For a sweep, repeat the TCP command with `--family ipv4` and `--family ipv6`
and each `--grease-size` in a range, such as 85 to 94.

Over TCP a listener reads each ClientHello and closes the connection; Firefox
retries, so one run keeps several ClientHellos, and the later ones drop
`compress_certificate`. Over QUIC, `network.http.http3.alt-svc-mapping-for-testing`
points Firefox at `h3` on the page's port, where UDP and TCP share one port
chosen from 20000 to 32767. A UDP socket keeps the client's datagrams, and the
first connection's ClientHello is read from its Initial packets with the
Initial keys. Nothing answers a handshake. On Windows, Firefox 157.0 sent no
QUIC datagram to `[::1]`.

`--timeout` must be finite and positive. It limits recording after the browser
starts. The version probe has a five-second deadline. TCP reads have an
absolute five-second deadline, including partial input. A run keeps at most
128 connections, 64 TCP ClientHellos or 256 UDP datagrams, and 1 MiB of
recorded bytes. TLS input allows 128 records and 128 KiB per connection.
Each ClientHello or reconstructed CRYPTO stream is limited to 64 KiB.
QUIC analysis allows 1,024 packets per run, 4,096 frames per packet and
128 ACK ranges per ACK. Oversized input and malformed packet or frame
encodings fail the run. An incomplete ClientHello can remain absent when
the recording deadline ends.

QUIC reconstruction selects the first authenticated Initial connection.
Matching CRYPTO overlaps preserve all bytes; conflicting overlaps fail.
The tool stops parsing a packet at an unsupported frame. Initial keys are
public.

Worker and socket failures remain errors even after a ClientHello arrives.
Cleanup waits up to five seconds for cooperative worker completion.
An unfinished worker stays attached to the reported failure. These deadlines
do not preempt a blocking native operation or bound shared browser startup.
The version probe buffers process output during its finite wait.

The fixture keeps `client_version`, `url`, a `prefs=` line naming every
preference the run set, `datagrams=` for QUIC, and `client_hello_<n>_hex`
lines. The `tcp-*-sweep-<label>.txt` fixtures come from an earlier version of
the script that recorded neither the preference nor its value.

## Alt-Svc racing

`alt_svc_race.py` records how Chromium races a learned `h3` alternative
(advertised in an `Alt-Svc` response field) against a new TCP connection to
the origin. It writes one `format=phantom-alt-svc-race-v1` fixture per
scenario.

Each run allows 32 lifetime connections, 32 UDP peers, 512 requests and
512 page results. Request targets are limited to 64 KiB. A limit failure
stops the run before it writes a fixture. Split larger experiments into
separate runs.

Use a positive `--repeat` count. Zero and negative counts fail before creating
output directories or replacing fixtures.

`--timeout` adds seconds to the scripted page waits; its default is 60.
Use a finite value. Zero and finite negative margins are accepted. This budget
covers the wait for the page to finish, rather than browser startup or cleanup.

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
by a killed browser. It keeps complete events before an unfinished final event
or document suffix. Malformed records fail the capture instead of being skipped.

The page drives these server paths:

- `/learn` sends `Alt-Svc: h3=":<port>"; ma=86400`.
- `/learn-retire` does the same and also sends `GOAWAY` on its connection, so
  the next request needs a new connection.
- `/retire` retires every open connection.
- `/hold` is an image that keeps the load event pending until `/done`. As a
  result headless `--dump-dom` exits cleanly, and the NetLog ends with `polledData`,
  whose Alt-Svc mappings give each broken alternative's expiry.

Headful runs request browser shutdown over its fresh loopback remote endpoint
after `/done`. They fail unless the process exits and the NetLog is complete.
Forced cleanup still runs on failure. Headless runs keep their existing exit path.

With `--observe-images`, fixtures retain `/hold` HTTP/2 fields in wire order,
including duplicates, fetch metadata and the `priority` header. They also record
the stream and initial HEADERS priority. `none` means that HEADERS carried no
priority, not that the stream received no later priority updates. Credentials
are rejected; the known authority and page referrer use `<port>` in place of
the listener's ephemeral port. HPACK encoding and HTTP/3 image fields are not
retained. Other race fields are unchanged.

| Scenario | QUIC listener | Question |
| --- | --- | --- |
| `race-after-learning` | serves H3 | First new connection after learning on a fresh profile |
| `race-after-quic-worked` | serves H3 | Main-job delay once QUIC has worked and its sessions closed |
| `udp-blackhole` | drops datagrams | When TCP starts; brokenness of a blackholed alternative |
| `quic-bad-certificate` | untrusted certificate | Whether a QUIC certificate failure marks the alternative broken |
| `quic-bad-alpn` | no common ALPN | Whether a QUIC ALPN failure marks the alternative broken |
| `existing-h2-session` | serves H3 | Requests while an H2 session exists when h3 is learned |
| `broken-backoff` | drops datagrams | Brokenness expiry and the period after a second failure (about 5.5 minutes per run) |
| `two-alternatives` | serves H3, after a second serving alternative | Which of two listed alternatives a new connection uses |
| `first-alternative-blackholed` | serves H3, after an alternative that drops datagrams | Whether a broken first alternative leads to the second |

The last two scenarios list a QUIC-only listener on a port of its own before
the origin's own port: `Alt-Svc: h3=":<earlier-0-port>"; ma=86400,
h3=":<port>"; ma=86400`. That listener binds loopback port 0 through
`reserved_ports.py`. The fixture records each run's datagrams and requests
per listener in `run_<n>_udp_listeners`, and the server-side transport of a
request to it as `h3-earlier-0`. The retained Chrome 154.0.8037.97 fixtures
used `--scenario two-alternatives first-alternative-blackholed --repeat 3`.

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

An HTTP/2 retirement write error stays on the connection being retired.
Expected disconnects retain their record tag. Other ordinary errors fail the
capture after cleanup. These errors do not stop retirement of the remaining
connections.

Loopback adds no latency, so delays that depend on round-trip time appear
only as the values Chrome logged.

## Tunnelled WebSocket openings

`tunnelled_websocket.py` records decrypted `wss://` openings through an
explicit loopback proxy. Select `--proxy http`, `https` or `socks5` and
`--origin-alpn h1` or `negotiate` (the default). The HTTPS proxy offers H1
only; the origin negotiates separately. SOCKS5 uses no authentication.

The tool uses the secure scenarios and five echo messages of
[WebSocket openings](#websocket-openings). It records the CONNECT or SOCKS
exchange separately from the origin's TLS and ordered WebSocket headers.
The `phantom-tunnelled-websocket-v1` fixture includes the actual origin ALPN,
response, echo results and cleanup outcomes. It rejects credentials and
cookies before publication. Inspect decoded origin events for the selected
WebSocket protocol.

For desktop captures, save a new manifest such as this one. Replace the
browser path, installed version and scratch paths for the capture host:

```json
{
  "operating_system": "Windows 11 Home 10.0.26200 x64",
  "repeat": 1,
  "browsers": {
    "chrome": {
      "path": "C:/Program Files/Google/Chrome/Application/chrome.exe",
      "version": "<installed-version>"
    }
  },
  "captures": [
    {
      "tool": "tunnelled_websocket",
      "browsers": ["chrome"],
      "scenarios": ["accept"],
      "args": ["--proxy", "https", "--origin-alpn", "negotiate"],
      "output_dir": "<scratch-directory>/tunnel-https-negotiate"
    }
  ]
}
```

Use full, unique `--proxy` and `--origin-alpn` option names. The runner adds
both values to the job ID and writes `<proxy>-<origin-alpn>-<scenario>.txt`.
Check the manifest first, then remove `--dry-run` to capture:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.run_matrix <new-manifest>.json --dry-run \
  --jobs 1 --retries 0 --work-dir <scratch-directory>/work \
  --results <scratch-directory>/results.json
```

Each run uses a fresh browser profile. The tool supports desktop Chromium
browsers and Firefox; it adds no Android, proxy authentication, H3 WebSocket
or MASQUE mode. Keep failed attempts and cleanup diagnostics with the results.

## Proxy routes

`proxy_route.py` records what a browser sends for a plaintext `http://` page
and its `ws://` opening, directly and through an HTTP proxy. It writes one
`format=phantom-proxy-route-v1` fixture per scenario.

Each run accepts at most 32 connections and records at most 512 requests,
page results, and remote events each. Exceeding a limit fails the run without
writing its fixture. Split larger experiments into separate runs.

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

The default listener is `127.0.0.1`, as shown in the table below. Desktop
captures can select IPv6 loopback with `--listen ::1`; URLs and proxy
addresses use brackets around that address. Android captures require IPv4
loopback.

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
| `http-proxy-auth-loopback` | plaintext HTTP proxy, Basic auth | `127.0.0.1` |
| `http-proxy-auth-hostname` | plaintext HTTP proxy, Basic auth | `origin.phantom.test` |
| `https-proxy-auth-loopback` | TLS proxy offering `h2`, Basic auth | `127.0.0.1` |
| `https-proxy-auth-hostname` | TLS proxy offering `h2`, Basic auth | `origin.phantom.test` |
| `http-proxy-secure-hostname` | plaintext HTTP proxy | `origin.phantom.test`, then `https://` and `wss://` tunnels |
| `https-proxy-secure-hostname` | TLS proxy offering `h2` | `origin.phantom.test`, then `https://` and `wss://` tunnels |
| `http-proxy-auth-secure-hostname` | plaintext HTTP proxy, Basic auth on CONNECT | `origin.phantom.test`, then `https://` and `wss://` tunnels |
| `https-proxy-auth-secure-hostname` | TLS proxy offering `h2`, Basic auth on CONNECT | `origin.phantom.test`, then `https://` and `wss://` tunnels |
| `http-proxy-auth-remembered-hostname` | plaintext HTTP proxy, Basic auth on `/probe` | `origin.phantom.test`, navigated twice |
| `https-proxy-auth-remembered-hostname` | TLS proxy offering `h2`, Basic auth on `/probe` | `origin.phantom.test`, navigated twice |
| `http-proxy-auth-nostore-hostname` | plaintext HTTP proxy, Basic auth on `/probe` | `origin.phantom.test`, no-store `fetch()` twice |
| `https-proxy-auth-nostore-hostname` | TLS proxy offering `h2`, Basic auth on `/probe` | `origin.phantom.test`, no-store `fetch()` twice |
| `http-proxy-auth-nostore-loopback` | plaintext HTTP proxy, Basic auth on `/probe` | `127.0.0.1`, no-store `fetch()` twice |
| `https-proxy-auth-nostore-loopback` | TLS proxy offering `h2`, Basic auth on `/probe` | `127.0.0.1`, no-store `fetch()` twice |

The four `-auth-` scenarios show when a browser sends `Proxy-Authorization`
after its first 407. Both proxy listeners require the throwaway credential
`phantom-user` / `phantom-pass`. A test-origin request that lacks the exact
`Proxy-Authorization: Basic <base64>` value gets
`407 Proxy Authentication Required` with
`Proxy-Authenticate: Basic realm="phantom-capture"` and `Content-Length: 0`.
That covers an HTTP/1.1 CONNECT, an absolute-form request, an HTTP/2 CONNECT
stream, and a forwarded HTTP/2 stream. The connection stays open, and on
HTTP/2 the 407 HEADERS frame ends the stream. Requests inside an established
tunnel and background traffic are not challenged. The page opens two `ws://`
connections one after the other and then reports both outcomes to `/done`, so
each run has a page request, two CONNECT tunnels, and a `/done` request after
the first challenge.

Browsers send `Accept-Encoding`, client hints, and fetch metadata to a
loopback origin that they omit for a named plaintext origin, so every route
runs with both.

The ten scenarios added for CONNECT and credential placement change the
page:

- A `-secure-` page fetches `https://origin.phantom.test:443/tls` and then
  opens `wss://origin.phantom.test:8443/tls`, each through a CONNECT tunnel.
  The proxy records each CONNECT head, answers `200`, and closes the tunnel
  (on HTTP/2, the `200` HEADERS frame ends the stream), so no origin TLS
  completes and the page reports the failures to `/done`. The port tells the
  two tunnels apart: the fixture records kind `https-connect` for 443 and
  `wss-connect` for 8443. Browsers retry the failed tunnel, so a run holds
  more than one of each. In the auth variant only CONNECT requests are
  challenged: the page loads without credentials, the first `https://`
  CONNECT gets the 407, and the later ones carry the remembered credential.
  Firefox's manual proxy settings cover `http://` and `ws://` only, so the
  `-secure-` plaintext-proxy launch also sets `network.proxy.ssl` and
  `network.proxy.ssl_port` to the same proxy.
- A `-remembered-` page fetches `/probe`, the only request the proxy
  challenges, and then `/ready`. When `/ready` arrives, the tool navigates
  the page again over the remote protocol (`Page.navigate` or
  `browsingContext.navigate`) to `/page?...&step=2`, which reports to
  `/done`. The run holds a challenged `fetch()`, its replay, and a
  navigation that carries the remembered credential.
- A `-nostore-` page fetches `/probe` and then `/done`, both with
  `{cache: "no-store"}`. The proxy challenges only `/probe`, so the run holds
  a challenged no-store `fetch()`, its replay, and a no-store `fetch()` that
  carries the remembered credential.

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

An auth scenario starts the browser on `about:blank` with a remote debugging
port and supplies the credential over the browser's remote protocol before it
loads the page. The client for both protocols is in `browser_remote.py`.

- Chromium receives `--remote-debugging-port=0`, and the tool reads the port
  from `DevToolsActivePort` in the profile. Over the DevTools protocol it
  attaches to the page target, enables `Fetch` with `handleAuthRequests` and
  the pattern `*`, and continues every paused request unchanged. It answers
  `Fetch.authRequired` with `ProvideCredentials` when the challenge source is
  `Proxy` and cancels any other challenge. It then calls `Page.navigate`.
  `Fetch` does not see WebSocket handshakes, so a 407 on a `ws://` CONNECT
  would reach no handler; the page would report the outcome.
- Firefox receives `--remote-debugging-port 0` and
  `remote.prefs.recommended=false`, which stops the remote agent from
  applying its automation preferences. The tool reads the port from
  `WebDriverBiDiServer.json` in the profile. Over WebDriver BiDi it opens a
  session, subscribes to `network.authRequired`, adds an intercept for the
  `authRequired` phase, and answers a blocked 407 challenge with
  `network.continueWithAuth` and `provideCredentials`. It then calls
  `browsingContext.navigate`.

The fixture records the method as `credential_supply` and each challenge the
remote protocol reported as `run_<n>_remote_event_<i>`, with its source or
status, scheme, realm, and URL path.

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
`background=true` without fields. The tool refuses to write `cookie` or
`authorization`.

The tool never writes a `Proxy-Authorization` value. It keeps the field's
name and position and replaces the value with `redacted:capture-credential`
when it matched the test credential, or `redacted:other` when it did not. An
HTTP/1.1 header line becomes the hex of `Proxy-Authorization: <marker>`. An
HPACK field keeps its representation and index, gives the marker as
`value_hex`, and adds `redacted:true`. In an auth scenario each request
record also carries `proxy_authorization:none`, `capture-credential`, or
`other`; its `status` is 407 when the proxy challenged it.

## Encrypted Client Hello

`chrome_ech.py` records the ClientHellos a Chromium browser or Firefox sends
when the origin's HTTPS record carries `ech`, and writes one
`format=phantom-ech-client-hello-v2` fixture per run. Version 2 adds the
`dns_https_alpn` line and the `quic_connection_*` lines to version 1; TCP-only
runs record `quic_connection_count=0`. It runs the
`capture_ech_client_hello` example, which serves `https://server.phantom.test/`
on `127.0.0.1:443` from a BoringSSL origin that decrypts ECH, and a loopback
DNS-over-HTTPS server that answers the origin's `A` query and its `HTTPS`
query with one record whose `ech` names `public.phantom.test`. Every other
name gets NXDOMAIN.

The capture has a 180-second deadline from server launch, including readiness.
It rejects fixtures over 16 MiB, diagnostics over 1 MiB and lines over 16 KiB.
Process-tree cleanup runs on success and failure. Reporting and decoding
failures reach the caller. Output files can exceed the limit between polls;
the limits bound accepted recordings, rather than temporary disk use.
Blocking callbacks and native operations remain outside deadline preemption.

The browser learns the DNS-over-HTTPS server from the
`dns_over_https.mode` and `dns_over_https.templates` preferences, which the
tool writes into the disposable profile's `Local State` file. Nothing outside
that profile changes. `--host-resolver-rules` is not used: it cannot produce
an HTTPS record.

Edge 153 ignores those preferences and sent no DNS-over-HTTPS query with
them. For Edge, pass `--dns-from-policy` and `--doh-port`: the tool writes no
preferences, the DNS-over-HTTPS server listens on the given loopback port,
and the browser must already have the `DnsOverHttpsMode` and
`DnsOverHttpsTemplates` machine policies naming that port. Before it starts
anything, the tool reads `HKLM\SOFTWARE\Policies\Microsoft\Edge` with
`reg query` and stops if either value is missing or different. It never
writes the registry. Setting the policy needs an administrator shell, and while
it is set every Edge window on the machine sends its lookups to the capture
server, so remove it as soon as the captures finish:

```sh
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsMode /t REG_SZ /d secure /f /reg:64
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsTemplates /t REG_SZ /d https://127.0.0.1:65355/dns-query /f /reg:64
# capture, then:
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsMode /f /reg:64
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsTemplates /f /reg:64
```

The DNS-over-HTTPS server uses the origin's self-signed certificate.
`--ignore-certificate-errors` covers it: Chromium applies the switch to the
network context's HTTP session, and DNS-over-HTTPS requests go through that
session. An Edge window started without the switch fails those handshakes,
and the example logs each failed connection on standard error.

For Firefox TCP captures, supply a CA-signed PEM leaf and key, and an NSS
SQL `cert9.db` containing that CA. The leaf must cover `server.phantom.test`,
`public.phantom.test` and IP `127.0.0.1`. Hashes bind the PEM certificate and
database. The tool stages the key in its temporary peer directory and copies the
database into its disposable profile, enables TRR-only DoH to its loopback
listener and disables HTTP/3. It uses normal certificate verification.
`--quic` and `--dns-from-policy` are unavailable with Firefox.

```sh
uv run --no-project --python 3.10 python -m scripts.capture.chrome_ech \
  --browser firefox --browser-path '<firefox>' --client-version 158.0.1 \
  --operating-system '<host OS>' --headful --scenario accept \
  --origin 127.0.0.1:0 --capture-binary '<capture_ech_client_hello>' \
  --certificate '<leaf.pem>' --certificate-sha256 '<PEM SHA-256>' \
  --private-key '<key.pem>' --cert9-db '<cert9.db>' \
  --cert9-sha256 '<database SHA-256>' --output '<ech-accept.txt>'
```

The peer records the certificate DER hash, ECH acceptance and each TCP
handshake. Repeat with `--scenario reject` to observe its retry configuration.
Add `--resumption early-accept`, `--resumption early-reject` or
`--resumption ech-retry` to the Firefox `accept` command for one seed page
and one same-origin GET on fresh TCP. The peer closes the seed connection,
keeps its ticket context, and either accepts early data, disables it on new
connections after the seed, or rotates the ECH key after flushing the seed
response. Browser early-data preferences remain unchanged.

Output links offered PSK hashes to tickets issued on the actual seed request,
records decrypted bytes read before Finished, native final completion and
served probe GETs. Rejected early plaintext is discarded by the TLS backend;
the rejected offer and the later served request are recorded separately.
Speculative connections and a run with no early-data offer keep their actual
results. `tls_resumption.py` also provides broader TCP resumption sequences.

Build the example, then capture both scenarios:

```sh
cargo build -p phantom-net --example capture_ech_client_hello
uv run --no-project --python 3.10 python -m scripts.capture.chrome_ech \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario accept \
  --capture-binary target/debug/examples/capture_ech_client_hello.exe \
  --output fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-accept.txt
uv run --no-project --python 3.10 python -m scripts.capture.chrome_ech   --browser edge   --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"   --client-version 153.0.4234.48   --operating-system "Windows 11 Home 10.0.26200 x64"   --scenario accept   --doh-port 65355 --dns-from-policy   --capture-binary target/debug/examples/capture_ech_client_hello.exe   --output fixtures/tls/edge/153.0.4234.48/windows-11-26200/ech-accept.txt
```

| Scenario | Question |
| --- | --- |
| `accept` | Outer server name and `encrypted_client_hello` fields when the origin holds the published key |
| `reject` | What follows a rejection whose server offers a retry configuration |

With `--quic`, the record lists `h3` and `h2`, and the origin also serves
HTTP/3 on the same UDP port from a BoringSSL QUIC server that holds the same
key, through the `phantom-quic-btls` `server` feature. The browser runs with
`--enable-quic` and trusts the origin's key through
`--ignore-certificate-errors-spki-list`; Chromium's QUIC client accepts a
certificate from an unknown root only for a host named in
`--origin-to-force-quic-on`, so the origin's host is named there with port 9,
which is never requested. The example prints the key's hash on its ready line
and the fixture records it as `<certificate-spki>`. Each QUIC connection
records the ClientHello the server read from the Initial packets, the same
outer fields as a TCP connection, the inner server name, and how the
handshake ended, including the close code the browser sent:

```sh
uv run --no-project --python 3.10 python -m scripts.capture.chrome_ech \
  --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario reject --quic \
  --capture-binary target/debug/examples/capture_ech_client_hello.exe \
  --output fixtures/tls/chrome/154.0.8037.58/windows-11-26200/ech-quic-reject.txt
```

Edge 153.0.4234.48 read the `Local State` preferences in the `--quic` runs, so
they need no policy.

Each connection records its ClientHello records, extension order, outer
server name, the outer extension's fields, whether the origin decrypted the
inner ClientHello, and the inner server name. Queries for names other than
the origin are counted, not listed; they are the fresh profile's background
requests. Opera 135 sent no DNS-over-HTTPS query with these preferences.
Opera 136 overrides them at startup with its own, so for `--browser opera`
the tool also writes `dns_over_https.opera.doh_mode` as `custom` and
`dns_over_https.opera.custom_servers` as the template into the same
`Local State` file, and records them in `dns_configuration`. Use Opera's
versioned executable,
`%LOCALAPPDATA%/Programs/Opera/136.0.6008.52/opera.exe`.

## Cookie crumbs

`cookie_crumbs.py` records how a browser sends several cookies on one request:
whether it splits the cookie field into one field per cookie, the position of
those fields, and how each is encoded. It writes one
`format=phantom-cookie-crumbs-v1` fixture per scenario, named
`crumbs-<scenario>.txt`.

Each run collects its registered TCP or QUIC owners before fixture publication.
Capture and cleanup failures preserve their original causes and prevent writes.
Cleanup attempts have a ten-second cooperative deadline.

Metadata must contain only printable ASCII on one line. HTTP/3 analysis
retains each request's decoder history so later table updates do not change
its recorded entry references.

Run timeouts must be finite and positive. Observation delays may be zero.
Their sum must be finite. The command allows 128 scenario runs in total.
Each run allows 32 active and 128 lifetime connections, 128 QUIC streams
per connection, and 8 MiB of recorded channel data.

Completed HTTP/1 heads have a 64 KiB limit. Completion requires one exact
run token in the original origin-form target: a path beginning with one
slash, without raw spaces, controls or a fragment.

Chromium brackets IPv6 resolver addresses. Firefox accepts only
`--listen 127.0.0.1` or `--listen ::1`, checked before acquiring a certificate
or listener. IPv4 disables IPv6. IPv6 prefers IPv6 without excluding IPv4.

Capture Chrome on Windows:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt   python -m scripts.capture.cookie_crumbs   --browser chrome   --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe"   --client-version 154.0.8037.58   --operating-system "Windows 11 Home 10.0.26200 x64"   --scenario all --repeat 3   --output-dir fixtures/cookies/chrome/154.0.8037.58/windows-11-26200
```

For Edge, use
`--browser edge --browser-path "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`,
and for Firefox,
`--browser firefox --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe"`.
The tool refuses `h2`, `hpack`, and `aioquic` versions other than 4.4.1,
4.2.0, and 1.3.0.

Each run loads `/start`, whose response sets five probe cookies with
`Path=/`, and navigates to `/page`, which fetches `/fetch` and then `/done`
with `{cache: "no-store"}`. The three requests after `/start` carry the
cookies, so each run has a navigation and two `fetch()` requests with cookies
on one connection. The probes are `pa=1`, `phantom_b=12345`,
`pc=0123456789abcdef` (19 bytes), `pd=0123456789abcdefg` (20 bytes), and a
53-byte `phantom_long`; the 19- and 20-byte pair straddles Firefox's rule for
indexing a crumb.

| Scenario | Listener | Question |
| --- | --- | --- |
| `h1` | Plaintext HTTP/1.1 on the loopback address | `Cookie` line spelling, position, and joining |
| `h2` | TLS for `server.phantom.test`, ALPN `h2` | Crumbs, their HPACK representations, and their position |
| `h3` | aioquic HTTP/3 for `server.phantom.test` on a UDP port bound to 0 | Crumbs, their QPACK field lines and encoder-stream inserts, and their position |

For each request the fixture keeps its kind (`start`, `page`, `fetch`, or
`done`) and its fields in order:

- for HTTP/1.1, the request line and header lines in hex;
- for HTTP/2, the HPACK block in hex, with each representation, its index,
  its Huffman flags, and the decoded field, as the WebSocket tool records;
- for HTTP/3, the field section in hex, its Required Insert Count and Base,
  and each field line's representation, table, index, absolute dynamic
  index, `N` bit, Huffman flags, and decoded field.

For each HTTP/3 connection it also keeps the QPACK encoder stream in hex and
parsed into instructions. The HTTP/3 server advertises aioquic's QPACK limits:
a table capacity of 4,096 bytes and 16 blocked streams.

The tool refuses to write any cookie other than the probes, whether in a
field or inserted into the QPACK table, and any `authorization` or
`proxy-authorization` field. Browsers launch as for the WebSocket tool for
`h1` and `h2`, and as for the QUIC resumption tool for `h3`.

## Socket hooks

Pass extra browser switches as `--browser-switch=--name` or
`--browser-switch=--name=value`. The tool owns the temporary profile and
page URL. It rejects `--user-data-dir`, `--single-argument`, positional
URLs and argument terminators before creating resources or output.

The hooks require Windows x64, with `ws2_32.dll` and `dnsapi.dll` already
loaded in the network service. The network-service child resumes after
it acknowledges configuration and hook installation. A hook failure stops
the run.
Each run admits at most 64 children and retains 100,000 hook reports.
The origin permits 32 unfinished connections, 128 connection records and
512 requests. Split larger experiments into separate runs.

`socket_hooks.py` records what no wire capture shows: the socket options a
Chromium browser sets, the order and timing of its connection attempts, and
its host lookups, including the ones its cache answers without a query. It
spawns the browser under [Frida](https://frida.re/) with child gating, loads
the agent in `socket_hooks.js` into the network service process (the
utility process started with
`--utility-sub-type=network.mojom.NetworkService`) before that process runs,
and lets every other child run unhooked. A loopback HTTP/1.1 origin serves
the page and records the connections it accepts, so each log carries wire
evidence beside the hook evidence. It writes one
`format=phantom-socket-hooks-v1` fixture per scenario, named
`hooks-<scenario>.txt`. Windows only: the agent hooks `ws2_32.dll` and
`dnsapi.dll`.

The browser runs headless by default. Add `--headful` to show its window;
the fixture records the selected mode in `launch_mode`.

Capture Opera on Windows:

```sh
uv run --no-project --python 3.10 \
  --with-requirements scripts/requirements.txt \
  --with-requirements scripts/capture/hooks-requirements.txt \
  python -m scripts.capture.socket_hooks --browser opera \
  --browser-path "$LOCALAPPDATA/Programs/Opera/136.0.6008.52/opera.exe" \
  --client-version 136.0.6008.52 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario all \
  --output-dir fixtures/socket-hooks/opera/136.0.6008.52/windows-11-26200
```

Frida is pinned in `scripts/capture/hooks-requirements.txt` rather than in
`scripts/requirements.txt`, because no other tool needs it; each retained
log names the version it was taken with in `hook_tool`. `--raw-dir` also
writes each run's undecoded agent reports, for diagnosis; they are not
fixture inputs.

| Scenario | Page | Question |
| --- | --- | --- |
| `single` | Fetches `/done` | The options on each TCP socket to the origin |
| `parallel` | Fetches `/slow` ten times at once; each response takes 1.5 s | How many connections one origin gets at once |
| `idle` | Fetches `/fast`, again 290 s later, and again 600 s after the start | Whether a used connection idle 290 s is reused and one idle 310 s is replaced |
| `lookups` | Fetches `http://127.0.0.1.nip.io:<port>/close` every 10 s, 13 times; the origin closes each connection | How often the browser looks the name up |
| `lookups-system` | The same, with `AsyncDns` added to `--disable-features` | The same through the system resolver |
| `happy-eyeballs` | Loads `http://localhost:<port>/`; only `127.0.0.1` listens | The order of attempts to `[::1]` and `127.0.0.1` |
| `happy-eyeballs-slow` | The same, with the agent failing `SIO_TCP_INITIAL_RTO` on IPv6 sockets | The delay before the IPv4 attempt while the `[::1]` attempt is still pending |

`127.0.0.1.nip.io` is a public name whose DNS answer is `127.0.0.1`, so a
lookup leaves the host while the connection stays on loopback. Chromium
154 fails a refused loopback connect at once on Windows, where Windows
would otherwise retransmit the SYN for about two seconds;
`happy-eyeballs-slow` undoes that for IPv6 sockets only, so the browser's
fallback timer can fire. Chromium 152, which Opera 136 builds on, does not
fail it early, so Opera's unmodified `happy-eyeballs` run already shows the
timer.
The fixture names the change in `hook_intervention`.

Each fixture starts with its provenance: `evidence=hook`, the browser and
build, the operating system, the Frida version, the agent's path and SHA-256
(`hook_agent_sha256`), the tool's SHA-256, the launch arguments, and the
network service's command line with handles and the profile path replaced.
Each run then has summary lines and every event in call order, one compact
JSON object per `run_<n>_event_<i>` line:

| Line | Holds |
| --- | --- |
| `origin_tcp_option_set_<i>` | How many sockets to the origin set each list of options, in call order: `setsockopt` options and `SIO_KEEPALIVE_VALS` (`onoff/time_ms/interval_ms`) and `SIO_TCP_INITIAL_RTO` (`rtt_ms/max_syn_retransmissions`) |
| `origin_tcp_option_callers` | The modules that made those calls |
| `origin_connect_attempts` | Each `connect` to the origin port, as `ms:address` |
| `origin_ipv4_after_ipv6_ms` | Milliseconds from an IPv6 attempt to the IPv4 attempt that followed it |
| `lookups` | Each lookup of `127.0.0.1.nip.io` or a name under it: a resolver call or a DNS query the browser sent itself |
| `server_connection_<i>` | Each connection the origin accepted: when, when it closed, how long it sat idle before closing, and its requests |

Events name sockets `s0`, `s1`, and so on from creation to close, give times
in milliseconds from the first report, and replace every address other than
loopback and unspecified ones with `<external>`, so a log names no DNS
server or remote host by address. Host names the browser looked up for its
own background requests stay in the DNS query events.

`test_socket_hooks.py` checks the decoding, the summaries, and the origin,
and the retained logs' source hashes from revision `15b1603e`. Archived logs
keep those historical identities when the tool changes. Fresh header tests
check the current agent and tool hashes separately.

## Firefox socket hooks

### Hosted native DNS

The manual `Windows native DNS capture` workflow runs one headed Firefox 157
lookup on a disposable Windows Server 2025 runner. It stages a pinned portable
browser, then routes only `127.0.0.1.nip.io` to a loopback DNS peer with NRPT.
A separate watchdog and an always-run workflow step restore that rule before
artifacts upload. The controller refuses desktop execution.

The page starts on a numeric loopback address and waits for hook attachment.
Success requires a later A query at the DNS peer and a complete HTTP response
body. Raw DNS packets, hooks, origin records, MOZ_LOG and restoration results
stay in `target/windows-native-dns-capture/`. The fresh profile disables TRR
(`network.trr.mode=5`); no host cache flush or preliminary lookup runs.
An absent HTTPS query stays absent. This is a native routing check, not a
Windows 11 observation or a DNS TTL/cache measurement.

### Local captures

`firefox_socket_hooks.py` records the same calls as
[`socket_hooks.py`](#socket-hooks) inside Firefox, which opens its HTTP
connections in its parent process and changes their keepalive while they
live. It loads `socket_hooks.js` unchanged and `firefox_socket_hooks.js`
after it, as one Frida script. The extension adds `shutdown`, the
`SO_ERROR` read that tells how a connect failed, the hints of each
`getaddrinfo` call, and each `DnsQuery_A` call with the TTLs it returned.

Firefox's launcher process marks itself failed in the registry when it starts
under Frida, and Firefox then runs without it for 45 days
(`toolkit/xre/LauncherRegistryInfo.cpp:17-21` at tag `FIREFOX_157_0_RELEASE`).
Without the launcher, Firefox also ignored the page URL on the command line.
If that ever happens, delete the `<path to firefox.exe>|Launcher`,
`|Browser`, and `|LauncherCrashTime` values under
`HKCU\Software\Mozilla\Firefox\Launcher`; the next ordinary launch writes
new timestamps, with `|Launcher` lower than `|Browser`.

The tool therefore launches Firefox the way `browser_launch.py` always
does, waits for the page request, and finds the parent using the temporary
profile, exact executable and confirmed launch PID. Selection failures report
the process identities without their full command lines.
With `--raw-dir`, failed runs keep partial hooks, peer records, MOZ_LOG and
error details in a `*-failed.json` file, limited to 64 MiB.
The page waits on `/go` until the hooks report ready, and only then reaches
the measured origin on a second
loopback port as `127.0.0.1.nip.io`. Firefox's own MOZ_LOG
(`nsSocketTransport:5,nsHttp:5,nsHostResolver:5,GetAddrInfo:5`) runs beside
the hooks; the log keeps the lines about the measured origin.

Capture Firefox 157 on Windows. The retained set ran `h2` and `websocket`
twice, `backup` five times, and the other three scenarios once:

```sh
run() {
  uv run --no-project --python 3.10 \
    --with-requirements scripts/requirements.txt \
    --with-requirements scripts/capture/hooks-requirements.txt \
    python -m scripts.capture.firefox_socket_hooks \
    --browser-path "C:/Program Files/Mozilla Firefox/firefox.exe" \
    --client-version 157.0 \
    --operating-system "Windows 11 Home 10.0.26200 x64" \
    --output-dir fixtures/socket-hooks/firefox/157.0/windows-11-26200 \
    "$@"
}
run --scenario h2 websocket --repeat 2
run --scenario backup --repeat 5
run --scenario http1-long http1-idle dns-cache
```

The tool refuses to start when `application.ini` beside the executable names
another version, and fails when the version changed during the capture.

Use single-line printable ASCII metadata and finite positive scenario waits.
The run keeps at most 128 connections, 512 requests and 100,000 hook reports.
It limits request heads and WebSocket frames to 64 KiB, hook messages to
16 KiB after Frida parses them, and parent MOZ_LOG input to 64 MiB across
64 files.

Cleanup waits up to 200 seconds for the native worker and normal teardown.
After timeout or interruption, it separately attempts to collect local peers
within five seconds. Blocking native calls can outlive those waits.
Failed or interrupted runs retire local peers separately and retain unfinished
cleanup for collection through the reported owner. Healthy runs detach hooks
and close the browser before retiring origins. Serving, hook, lookup and
cleanup failures prevent fixture publication.

| Scenario | Measured origin | Question |
| --- | --- | --- |
| `http1-idle` | HTTP/1.1; `/fast` at once and 90 s later, then idle | Keepalive on a pooled connection past the short-lived period, and when Firefox closes it |
| `http1-long` | HTTP/1.1; `/trickle` sends one chunk every 5 s for 85 s | When an active connection switches to long-lived keepalive |
| `h2` | TLS with ALPN `h2` only; `/fast` twice | Keepalive before and after HTTP/2 is negotiated |
| `h2-backup` | TLS with ALPN `h2` only; two sequential requests, origin close, then reconnect | Dual-stack fallback, reuse and the family of a later connection |
| `websocket` | `ws://`; the origin sends a frame every 5 s; the page closes after 20 s | Keepalive after the 101 response |
| `websocket-backup` | Two `ws://` upgrades, then two HTTP requests | Address selection while a WebSocket remains active and after both close |
| `wss-backup` | Two `wss://` upgrades over HTTP/1.1, then two HTTPS requests | TLS completion and closure of an unused backup connection |
| `backup` | HTTP/1.1; `/fast`, then three concurrent `/slow` (3 s each), then `/fast` after the origin closed every connection | Connection attempts when the name resolves to `[::1]` then `127.0.0.1` and only `127.0.0.1` listens, and the family of later connections |
| `dns-cache` | HTTP/1.1; `/close` at 0, 30, 65, and 95 s | How long Firefox keeps the name's answer |

The `backup`, `h2-backup`, `websocket-backup` and `wss-backup` scenarios make
`getaddrinfo` resolve
`localhost` in place of `127.0.0.1.nip.io` and drop the answer's canonical
name, so Firefox's TTL
lookup still names `127.0.0.1.nip.io`; the fixture names the change in
`hook_intervention`. A refused loopback connect takes about two seconds on
Windows, which keeps the `[::1]` attempt pending past Firefox's backup timer.
The page uses `127.0.0.1` itself, and the TLS origin's throwaway certificate
is trusted through `cert_override.txt` in the run's profile.

Run `h2-backup` separately with `run --scenario h2-backup --repeat 1 --headful`.
Omit `--headful` for the default headless mode. Its requests read each response
body before continuing; a failed response cannot signal completion.
Its `/drop` probe aborts the origin transport to force a new connection; it
does not measure graceful TLS or HTTP/2 shutdown.
Use an isolated Firefox 157 executable if your installed browser has updated.

Run the WebSocket backup scenarios separately with
`run --scenario websocket-backup --headful` or
`run --scenario wss-backup --headful`.

The header adds to the Chromium tool's: `browser_build_id`, the extension and
its SHA-256 (`hook_agent_extension_sha256`), `decoder_sha256` for
`socket_hooks.py`, whose decoders the tool reuses, and `moz_log`. Each run
then has these lines besides the events:

| Line | Holds |
| --- | --- |
| `launcher_process` | `true` when the hooked parent process is a child of Firefox's launcher process, `false` when Firefox started without the launcher |
| `origin_socket_<i>` | One socket that connected to the measured port: its address, when it connected, the error NSPR read if the connect failed, the options set before `connect`, and each later option, keepalive change, and `shutdown` as `+ms` after the connect |
| `lookup_calls` | Each `getaddrinfo` call for the name with its flags and family, its answers, and each `DnsQuery_A` with the answer TTLs |
| `server_connection_<i>` | Each connection the origin accepted: address family, when it opened and closed, how it closed (`fin` from the client, `server`, `reset`, or `websocket`), and its requests |
| `moz_log_<i>` | A retained MOZ_LOG line: milliseconds from the first hook report, the module, and the message, with object addresses renamed `p<n>` |

`test_firefox_socket_hooks.py` checks the decoding, the summaries, the MOZ_LOG
filter, and the origin. Retained hashes identify the shared sources at
`15b1603e` and the Firefox extension and tool at `71885a75`. Archived logs
keep all four hashes. Fresh header tests check the current sources separately.

## Next

- [Contributing](../../CONTRIBUTING.md#tests-and-evidence): tests and retained evidence.
