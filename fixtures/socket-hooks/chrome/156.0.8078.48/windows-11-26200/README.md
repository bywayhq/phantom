# Chrome 156 Windows sockets and HTTP/1.1

`hooks-single.txt` records Chrome 156.0.8078.48 on Windows 11 Home
10.0.26200 x64. The headless browser ran with Frida 17.23.3 and Python 3.12.10
against one loopback HTTP origin on an assigned port.

Four origin connections set `TCP_NODELAY`, 45-second keepalive idle and
interval, and port randomization. The shared Chromium TCP component supplies
these settings. The 300 ms address-racing default and Windows build 22621
threshold follow [the pinned Chromium source][source], rather than this
IPv4-only run. Loopback SYN retry settings use the system default in Phantom.

Capture source: `dde964d60a5332fbae1da0502ddad00c1dd77074`. The run completed
without hook errors and removed its owned browser and profile. UDP entries
are background traffic, separate from the controlled TCP origin.
Both headed and headless runs record `SO_RANDOMIZE_PORT=1` on UDP sockets.
The shared UDP component requests this option, as does [Chromium 156][udp-source].

`hooks-parallel.txt` records ten slow requests using six connections.
`hooks-idle.txt` records reuse after 290 seconds and replacement on a request
after 310 seconds. Both ran headful against plain loopback HTTP, without hook
errors or cleanup failures. Their capture sources are
`13f20d82f5bd36016e07d691e7df6cc534d8c9ec` and
`0cef515ce453ae48bbe6062af22bbfb49cf110dc`, respectively.

The shared HTTP/1.1 component uses six connections and a 300-second used-idle
limit, checked when a request arrives. [The pinned source][idle-source] sets
that exact limit; the observations bracket it. Phantom applies it per origin
and route, without Chromium's pool-wide limits or unused preconnect sockets.

Reproduce with the matching Chrome binary:

```sh
uv run --no-project --python 3.12.10 \
  --with-requirements scripts/requirements.txt \
  --with-requirements scripts/capture/hooks-requirements.txt \
  python -m scripts.capture.socket_hooks --browser chrome \
  --browser-path PATH_TO_CHROME --client-version 156.0.8078.48 \
  --operating-system "Windows 11 Home 10.0.26200 x64" \
  --scenario single --repeat 1 --output-dir OUTPUT --raw-dir RAW
```

For the headful connection-policy scenarios, use the same command with
`--headful --scenario parallel idle` in place of `--scenario single`.
The idle scenario takes about ten minutes.

SHA256:

- `hooks-single.txt`: `693cd220495ce859adff86a3d926599cbb78aa0ba58dc5a0245678caf86180db`
- `hooks-parallel.txt`: `7385f2ca5f8995ba1d877e6f29ac10f14ef47a5ba44c9f5af97c8209affec9e0`
- `hooks-idle.txt`: `98248087d01bcf0adba8d999926c9704470ae9788ae6dcbc63f938c3e204c1cd`
- `chrome.exe`: `480f275b63d1ea39113cbc8344ac395578acc25b432bd39af5fbc77005179aca`
- `chrome.dll`: `e23d982e66959f3d738154ba68dd2638c9c7473a7e0f362eaee2b1dad5e20f57`
- `chrome_elf.dll`: `752655e7e186e11e8976b81d5a6156e690b5c761f3dafcc480d2c2fcfc648f83`

[source]: https://chromium.googlesource.com/chromium/src/+/d0c02bfad08ec92a6ffcf989e53cd995e6381a4c/
[idle-source]: https://chromium.googlesource.com/chromium/src/+/d0c02bfad08ec92a6ffcf989e53cd995e6381a4c/net/socket/client_socket_pool.cc

[udp-source]: https://chromium.googlesource.com/chromium/src/+/d0c02bfad08ec92a6ffcf989e53cd995e6381a4c/net/socket/udp_socket_win.cc
