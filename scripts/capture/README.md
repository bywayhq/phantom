# Capture tools

Record what a real browser sends to a loopback server and keep it as a
fixture under [`fixtures/`](../../fixtures/). For a new browser version,
start with a [quick fingerprint snapshot](#quick-fingerprint-snapshot), then
see [Which tool to run](#which-tool-to-run).

> For contributors recording browser evidence. Read
> [Add a browser recipe](../../docs/internals/browser-recipes.md) first when
> the capture is for a new recipe.

A fixture is raw evidence recorded on the capture machine, not a report from a
third-party fingerprinting service. Why each retained capture exists, and what
it proves, belongs in [Validation](../../docs/explanation/validation.md).
Run every command from the repository root; the Python tools need Python
3.10. Every listener refuses a non-loopback address.

## Quick fingerprint snapshot

`snapshot.py` records a desktop browser's fingerprint at every layer from one
headless launch on a fresh profile, and `snapshot_compare.py` compares it
with the browser's retained fixtures:

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.snapshot --browser chrome \
  --browser-path "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  --client-version 154.0.8037.58 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --repeat 3 --output-dir <scratch-directory>/chrome
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.snapshot_compare --browser chrome \
  <scratch-directory>/chrome/snapshot-1.txt
```

`--browser` takes `chrome`, `edge`, `brave`, `opera`, or `firefox`;
[`run_matrix.py`](#run-captures-from-a-manifest) runs it as the `snapshot`
tool for several browsers at once. One run
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
is not a difference, because Chromium permutes both per connection. A layer
missing from the snapshot, or with no retained fixture, is a difference. It
does not compare HTTP/3 request fields, HTTP/2 fields other than the first
navigation's, or HTTP/1.1.

Take a snapshot first for every new browser version. The other tools record
a changed layer for a recipe, and they are the only way to record behavior
across connections: resumption and 0-RTT, Alt-Svc racing, retries, broken
alternatives, EventSource reconnects, proxies, WebSocket openings, cookie
crumbs, and ECH. [Fingerprint snapshot evidence](../../docs/explanation/validation.md#fingerprint-snapshot-evidence)
has the runs that checked the tool against the retained fixtures.

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
| Client hints, default and after `Accept-CH` | [`client_hints.py`](#client-hints) | `fixtures/client-hints/` |
| WebSocket openings over HTTP/2 and HTTP/1.1 | [`http2_websocket.py`](#websocket-openings) | `fixtures/websocket/` |
| EventSource reconnects | [`sse_reconnect.py`](#eventsource-reconnects) | `fixtures/sse/` |
| Alt-Svc racing between QUIC and TCP | [`alt_svc_race.py`](#alt-svc-racing) | `fixtures/alt-svc/` |
| Plaintext requests and `ws://` openings through HTTP proxies | [`proxy_route.py`](#proxy-routes) | `fixtures/proxy/` |
| ClientHellos with Encrypted Client Hello from an HTTPS record | [`chrome_ech.py`](#encrypted-client-hello) | `fixtures/tls/` |
| Several cookies on one request over HTTP/1.1, HTTP/2, and HTTP/3 | [`cookie_crumbs.py`](#cookie-crumbs) | `fixtures/cookies/` |
| Several of these tools for several desktop browsers in one command | [`run_matrix.py`](#run-captures-from-a-manifest) | The manifest's `output_dir` |

The two Cargo examples are Rust programs, not scripts in this directory.
[Capture commands and launches](../../docs/explanation/validation.md#capture-commands-and-launches)
has their arguments and the browser launch flags used with them.
`quic_packet_diff.py` and `compare_quic_flights.py` compare QUIC captures; see
[HTTP/3 internals](../../docs/internals/http3.md#capture-workflow).

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
| `sse_reconnect` | `<scenario>.txt` | All five | By default: the fixtures keep reconnect delays |
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
standard error go to `<work-dir>/logs/<job>.<attempt>.log`.

On Windows each attempt's processes, the browsers included, belong to a Job
Object that ends them when it closes. On other systems the tool leads a new
process group. When an attempt ends, passes, fails, or reaches its timeout,
the runner closes its job, ends every process whose command line names the
attempt's temporary directory as a whole path component, and removes that
directory. The match is the launcher's profile sweep, so a browser whose
profile path only starts with the same text keeps running. If the runner
itself exits, Windows closes the jobs and ends their processes.

Ctrl+C starts no more jobs or retries, ends every running attempt the same
way, prints the summary, and writes the results file. A job that was running
is reported as `stopped`, and one that had not started as `not-run`.

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

A job runs alone by default when its tool's fixtures keep connection counts,
connection or request order, or delays, because load on the host can change
them. Only `client_hints` and `startup_capture` share the host by default.
Use `--jobs 1`, or keep the default, for a capture whose evidence is a count,
an order, or a timing. Set `"exclusive": false` only for a capture whose
evidence is the content of what the browser sent, such as a ClientHello or
field values.

On the capture host (16 cores, 32 threads), 15 jobs of `client_hints` and
`tls_resumption` for Chrome 154, Edge 154, Brave 154, Opera 135, and
Firefox 156, 45 browser runs, took 127 seconds with `--jobs 1` and 111 seconds
with the default `--jobs 8`, where the `tls_resumption` jobs ran alone. With
`"exclusive": false` for `tls_resumption` they took 26 seconds at `--jobs 8`,
and each job took about 25% longer than alone. The number of resumed
ClientHellos, and in `methods-http1` whether a run had 7 or 8 connections,
differed between these three passes, including between runs made alone, so
the passes do not show whether sharing the host changes them. The runner has
been run with up to 16 jobs; at 16 each job took about 70% longer than
alone. Measured September 2026.

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
Firefox starts. Jobs that run alone, and every job under `--jobs 1`, do not
get the variable. On the capture
host, Firefox 156 processes started three at a time at the same moment loaded
their page in 5 of 9 launches; with the lock, 12 of 12 loaded in groups of
four. Chromium browsers started four at a time loaded 8 of 8 and do not take
turns. A tool run on its own does not see the variable and launches at once.

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

Android captures run on the `phantom-api35-play` emulator on the Windows
capture host: a Pixel 7 device profile on the Android 15 (API 35) Google Play
x86_64 system image, build `AE3A.240806.036`. The browsers come from the Play
Store, signed in with a throwaway account, so each is the build Play serves to
that device, which can trail the version Google's release API lists.

Set `ANDROID_SDK_ROOT` to the Android SDK directory; on the capture host it
is `C:/code/tools/android-sdk`. Start the emulator from Git Bash with the
proxy variables cleared. The emulator otherwise routes the guest's TCP
through the host's `HTTP_PROXY`:

```sh
env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
  "$ANDROID_SDK_ROOT/emulator/emulator" -avd phantom-api35-play \
  -memory 4096 -no-snapshot -no-boot-anim -no-metrics
```

The emulator offers Wi-Fi and a cellular network. Chromium sends
`initial_rtt_us` on a fresh QUIC connection when the cellular one is the
default, which the recipes do not model, so turn mobile data off inside the
emulator before a capture and check that Wi-Fi is connected:

```sh
adb -s emulator-5554 shell svc data disable
adb -s emulator-5554 shell cmd wifi status
```

If Wi-Fi drops and `dumpsys connectivity` reports no default network,
`svc wifi disable` followed by `svc wifi enable` restores it.

Add `-no-window -no-audio` to run it without a window. Never pass
`-wipe-data`: it signs the Play account out and removes the browsers. If adb
lists the device as `unauthorized`, create the host's public key with
`adb pubkey ~/.android/adbkey > ~/.android/adbkey.pub` and restart the
emulator.

Every run stops the browsers in the table below, ends cached apps, and
clears the tested browser's app data, which on a personal phone erases its
tabs, history, and sign-ins. The launcher therefore refuses a device that does
not report `ro.kernel.qemu` or `ro.boot.qemu` as `1`, which every emulator
does. To run on a phone set aside for captures, set
`PHANTOM_ANDROID_ALLOW_PHYSICAL_DEVICE=1`, or pass `--allow-physical-device` to
`android_run.py`. `startup_capture.py` and `chrome_ech.py` take desktop
browsers only, and `proxy_route.py` refuses the authentication scenarios for
an Android browser.

Pass `--browser <name>-android`, the adb executable as `--browser-path`, and
the device serial in `ANDROID_SERIAL`:

```sh
ANDROID_SERIAL=emulator-5554 uv run --no-project --python 3.10 \
  python -m scripts.capture.client_hints \
  --browser chrome-android \
  --browser-path "$ANDROID_SDK_ROOT/platform-tools/adb" \
  --client-version 153.0.8010.52 \
  --operating-system "Android 15 (API 35) sdk_gphone64_x86_64 emulator AE3A.240806.036" \
  --repeat 3 \
  --output fixtures/client-hints/chrome-android/153.0.8010.52/android-35-emulator/navigation.txt
```

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

The page load is therefore a typed address-bar navigation, and fixtures
record `launch_mode=android-typed`. A page that another app opens through a
`VIEW` intent has no user activation, and Chrome then leaves out
`Sec-Fetch-User`. A `LaunchPlan` with `android_entry="intent"` opens the page
that way instead and records `android-intent`; the TLS, HTTP/2 startup, and
QUIC captures use it, because those layers do not depend on how the page was
opened and the intent needs no typing.

A loaded device drops injected keys while the address bar fetches
suggestions, and the address bar appends a selected inline completion to what
was typed. Checking the field after each chunk handles both. An "isn't
responding" dialog, which a busy emulator shows for System UI, takes the
focus; the launcher taps its Wait button and refocuses the address bar.
With 2.5 GB of RAM the guest's system server died during long capture
sessions, so start the emulator with 4 GB. On the capture
host a typed entry takes about 90 seconds while other builds run, so the
Android runs use run timeouts of 240 seconds.

| `--browser` | Package | Debug configuration |
| --- | --- | --- |
| `chrome-android` | `com.android.chrome` | `/data/local/tmp/chrome-command-line` |
| `edge-android` | `com.microsoft.emmx` | `/data/local/tmp/chrome-command-line` |
| `brave-android` | `com.brave.browser` | `/data/local/tmp/chrome-command-line` |
| `opera-android` | `com.opera.browser` | None; the launch refuses switches |
| `firefox-android` | `org.mozilla.firefox` | `/data/local/tmp/org.mozilla.firefox-geckoview-config.yaml`, preferences only |

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

```sh
ANDROID_SERIAL=emulator-5554 uv run --no-project --python 3.10 \
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
- An emulator is not a phone. `sec-ch-ua-model` in a capture carries the
  emulator's model, `sdk_gphone64_x86_64`, which the recipes leave to the
  caller, and the CPU is x86_64 rather than a phone's ARM core, which
  Chromium's AES hardware check reads.

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
with `quic-client-hello-<n>.txt` for HTTP/3; retain a run under the names in
[Validation](../../docs/explanation/validation.md#brave-154-and-opera-135-recipes).
Each listener prints a line starting with `listening on <address>` on
standard error once it has bound, and the tool launches the browser when it
reads that line. It gives up after `--server-start` seconds (default 30).

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
writes one `format=phantom-tls-resumption-v1` fixture per scenario, named
`resumption-<scenario>.txt`.

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

For each connection the fixture keeps:

- the listener, server name, offered and selected ALPN, and timings;
- the tickets the ClientHello offered, named `connection_<n>.ticket_<i>` after
  the connection that issued them, and whether the server resumed one;
- whether early data was offered and accepted, how many early-data bytes
  arrived, and the tickets the connection was issued;
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

`chrome_ech.py` records the ClientHellos a Chromium browser sends when the
origin's HTTPS record carries `ech`, and writes one
`format=phantom-ech-client-hello-v2` fixture per run. Version 2 adds the
`dns_https_alpn` line and the `quic_connection_*` lines to version 1; TCP-only
runs record `quic_connection_count=0`. It runs the
`capture_ech_client_hello` example, which serves `https://server.phantom.test/`
on `127.0.0.1:443` from a BoringSSL origin that decrypts ECH, and a loopback
DNS-over-HTTPS server that answers the origin's `A` query and its `HTTPS`
query with one record whose `ech` names `public.phantom.test`. Every other
name gets NXDOMAIN.

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
requests. Opera 135 sent no DNS-over-HTTPS query with these
preferences, so it has no fixture.

## Cookie crumbs

`cookie_crumbs.py` records how a browser sends several cookies on one request:
whether it splits the cookie field into one field per cookie, the position of
those fields, and how each is encoded. It writes one
`format=phantom-cookie-crumbs-v1` fixture per scenario, named
`crumbs-<scenario>.txt`.

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

## Next

- [Validation](../../docs/explanation/validation.md#browser-recipes): record
  what a new capture shows and how the browser was launched.
- [Add a browser recipe](../../docs/internals/browser-recipes.md): turn
  retained captures into recipe functions and replay tests.
