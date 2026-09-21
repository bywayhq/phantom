# Capture tools

These tools record browser behavior against loopback servers so fixtures under
[`fixtures/`](../../fixtures/) are local raw evidence, not observer reports.
Rationale for each retained capture belongs in
[Validation](../../docs/validation.md); this page covers how to run the tools.

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

## HTTP/3 startup

`chrome_http3.py` records one browser HTTP/3 startup against an aioquic
server. [Validation](../../docs/validation.md) lists its retained fixtures and
the launch commands used for them.
