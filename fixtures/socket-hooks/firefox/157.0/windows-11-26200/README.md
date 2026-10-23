# Firefox 157 Windows HTTP/2 reconnect

`hooks-h2-backup.txt` records one headed Firefox 157.0 run on Windows 11
10.0.26200 x64. Build ID: `20260924084938`; Mozilla source revision:
`8eb25af4acf031ab1e06abf1a912275083c820ed`.

Two requests reused one HTTP/2 session. After the origin's forced transport
disconnect, the third used a new session and IPv4 connection. The pending
IPv6 attempts closed when the first HTTP/2 connection became ready.
All response bodies completed, with no hook, serving or cleanup errors.

The tool rewrote `getaddrinfo` for `127.0.0.1.nip.io` to `localhost`, returning
IPv6 before IPv4. A disposable profile held the loopback certificate override.
The origin abort tests reconnect behavior, not graceful TLS shutdown. This
single run does not establish timing thresholds, proxy behavior or ECH policy.
The last hook snapshot precedes browser teardown; afterward the browser,
profile and server owners were removed.

Capture source: `bdc0847f969b468d5afb287949e11c0204242b93`, with Python 3.12.10
and Frida 17.23.3. The executable's Mozilla signature was valid and its bytes
were unchanged before and after the run.

Reproduce with that Firefox build:

```sh
uv run --no-project --python 3.12.10 \
  --with-requirements scripts/requirements.txt \
  --with-requirements scripts/capture/hooks-requirements.txt \
  python -m scripts.capture.firefox_socket_hooks \
  --browser-path PATH_TO_FIREFOX --client-version 157.0 \
  --scenario h2-backup --repeat 1 --headful \
  --output-dir OUTPUT --raw-dir RAW
```

SHA256:

- `hooks-h2-backup.txt`: `3ac475709d8681a0c0dfd2a2d8a780555506dadf4e203d1e0bcf2e1868f936fd`
- `firefox.exe`: `6a6175344a8cb4215d3c5202f718531adc0c13828e36f47a13a934cee61c0c7b`
- `application.ini`: `e066925e0b377c6842f11f98f2f50da16ca4f6a48da70503e69f52094181c7d2`

## Direct WebSocket connections

`hooks-websocket-backup.txt` uses the same Firefox build and Windows host.
The first WebSocket tried IPv6, then connected over IPv4. A second opening
used the same connection entry's IPv4 preference. Both closed cleanly. Two
following HTTP requests shared a new connection; their separate connection
entry tried IPv6 again before IPv4. One extra accepted socket carried no
request.

This cleartext run uses the lookup rewrite described above, with no TLS
trust override. It covers neither secure WebSockets nor proxies.

Capture source: `17dd80673c148bcc78df18bd17541a6f240e3ca7`, Python 3.12.10
and Frida 17.24.3. Reproduce with the command above, replacing the scenario
with `--scenario websocket-backup`. The signed executable was unchanged,
and the disposable browser, profile and listeners were removed.

Fixture SHA256: `b17aa6c4fe19a4e90e8ef2f50892b5a9d17b032e336e6f97b4542f12b7496006`.
