# Opera 136 revalidation

`revalidate.txt` records Opera 136.0.6008.52 on Windows 11 build 26200.
The official build uses Chromium 152.0.7977.130.

Run `scripts/capture/http_lifecycle.py --browser opera --scenario revalidate`
with that build and a fresh profile. HTTP/2 validators follow
`accept-language`, before `priority`. ETag precedes the modification date
when both apply. All eight fetches read their bodies.
