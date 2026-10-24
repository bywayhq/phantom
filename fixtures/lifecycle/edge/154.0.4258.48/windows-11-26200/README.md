# Edge 154 revalidation

`revalidate.txt` records Edge 154.0.4258.48 on Windows 11 build 26200.
Run `scripts/capture/http_lifecycle.py --browser edge --scenario revalidate`
with that build and a fresh profile.

HTTP/2 validators follow `accept-language`, before `priority`. ETag precedes
the modification date when both apply. All eight fetches read their bodies.
The second heuristic-cache fetch needs no wire request.

Capture source: `a9eb5759d90e087c8655ede0310a4f8051aaf874`, Python 3.12.10,
Windows Selector event loop.
