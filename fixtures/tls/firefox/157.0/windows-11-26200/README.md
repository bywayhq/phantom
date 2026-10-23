# Firefox 157 ECH

Firefox 157.0, build `20260924084938`, on Windows 25H2 build 26200.9457.
Recorded October 23, 2026 with fresh headful profiles, TRR mode 3, HTTP/3
disabled and a profile-local capture CA. Certificate verification stays enabled.

`ech-accept.txt` accepts ECH config 1. `ech-no-https-record.txt` returns HTTPS
NODATA and retains ECH GREASE. Each run serves one HTTP/1.1 response.

Use the Firefox command in the
[ECH capture instructions](../../../../../scripts/capture/README.md), with
`--scenario accept` or `--scenario no-https-record`. Peer and driver source:
`1bd257c4b32302e2ab7c6e494408f2d99e9a1a30`.

`ech-early-accept.txt` resumes a seed ticket, accepts 465 early request bytes
and serves the probe once after completing TLS. The peer retires idle setup
connections before releasing the seed page. Source: `3365b4021`.

`ech-early-reject.txt` resumes a seed ticket but sends its GET after TLS
rejects early data. `ech-retry.txt` replaces ECH config 1 with config 2 and
completes a full handshake. Use `--resumption early-reject` or
`--resumption ech-retry`. Peer source: `d73130dce`.
