# Firefox 157 on Windows

`snapshot-port-443-diagnostic.txt` uses Firefox 157.0 on Windows build
26200.9457, with TLS and QUIC on loopback port 443. Snapshot source:
`48b69e947b59a37b2aa729ddc2dcc183995a1689`.

The first HTTP/3 request omits `Alt-Used`. The reused connection sends
`server.phantom.test`, without `:443`.

This capture used a Python cleanup diagnostic, a disposable certificate
override and local hostname mapping. HTTP/2 GOAWAY triggered the move to
HTTP/3. The page and original process handles completed cleanup. The
retained QPACK prefix covers the first request; the second request's
fields come from the capture's runtime decoder.
