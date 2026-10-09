# HTTP/1 request fixtures

Use these retained requests to test exact request-line and header bytes.
The files include all three runs from their original capture documents.

## Provenance

These files are byte-identical copies of repository assets. The capture tool
is `scripts/capture/http2_websocket.py`, documented under
[WebSocket openings](https://github.com/bywayhq/phantom/blob/main/scripts/capture/README.md#websocket-openings).
It records request and header lines before parsing them. It refuses to retain
Cookie, Authorization, or Proxy-Authorization headers.

| Package asset | Original repository asset | SHA-256 |
| --- | --- | --- |
| `chrome-154-windows-h1-accept.txt` | `fixtures/websocket/chrome/154.0.8037.58/windows-11-26200/h1-accept.txt` | `0a10349caf479b72631725c12a5ef495f12411e0f832e1f0c3f3e284c40849ce` |
| `firefox-157-windows-h1-accept.txt` | `fixtures/websocket/firefox/157.0/windows-11-26200/h1-accept.txt` | `41ee523a20a8cc6cc1416877395eba53ae498216955086cb743f09e254561dbb` |

| Browser | Exact build | Platform | Launch mode | Captured at (Unix seconds) |
| --- | --- | --- | --- | --- |
| Google Chrome | 154.0.8037.58 | Windows 11 Home 10.0.26200 x64 | headless | 1790242984 |
| Mozilla Firefox | 157.0 | Windows 11 Home 10.0.26200 x64 | headless | 1790926384 |

The `h1-accept` scenario serves a plaintext WebSocket page. Each run records
the page request, WebSocket opening, and result-report fetch as `page`,
`websocket`, and `done`. The capture documents retain launch settings,
listener addresses, request indexes, and timing observations.

The requests use temporary loopback ports and per-run tokens. Tests must
declare any target, Host, or User-Agent adjustments. The expected bytes do
not come from a Phantom profile or request generator.

## Next

- [Phantom testkit](https://github.com/bywayhq/phantom/tree/main/crates/phantom-testkit): capture and comparison examples.
