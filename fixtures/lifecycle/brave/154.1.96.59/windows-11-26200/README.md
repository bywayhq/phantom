# Brave 154 revalidation

`revalidate.txt` records Brave 154.1.96.59 on Windows 11 build 26200.
The official v1.96.59 portable build uses Chromium 154.0.8037.58.

Run `scripts/capture/http_lifecycle.py --browser brave --scenario revalidate`
with that build and a fresh profile. The capture records HTTP/2 validator
fields after `accept-language` and before `priority`, with ETag before the
modification date when both apply. All eight fetches read their bodies.
