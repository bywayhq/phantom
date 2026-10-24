# Chrome 156 revalidation

`revalidate.txt` records Chrome 156.0.8078.48 on macOS 15.5, build 24F74,
arm64. Run `scripts/capture/http_lifecycle.py --browser chrome
--scenario revalidate` with that build and a fresh profile.

HTTP/2 validators follow `accept-language`, before `priority`. ETag precedes
the modification date when both apply. All eight fetches read their bodies.
The second heuristic-cache fetch needs no wire request.

Capture source: `1ede7db2fe5fe82d0fc28ca9b1d0216c1cf5d413`, Python 3.10.18.
