# How servers recognize a client

Learn how a server tells which program made a request without reading its
`User-Agent`, and why copying a browser's headers is not enough.

> For evaluators and builders who are new to request fingerprinting.

## The short version

Every HTTP client makes many small choices before it sends a request: which
TLS cipher suites to offer and in what order, how large an HTTP/2
flow-control window to ask for, which order to write header fields in.
Browsers make these choices in their own code, and one browser build makes
them the same way every time, apart from a few values it randomizes per
connection. A server that records them gets a **fingerprint**: a description
of the program, independent of what the program says about itself.

Think of the TLS fingerprint as a `User-Agent` the client cannot edit. The
`User-Agent` field is one line of text that any library can set to anything.
The handshake is produced by the TLS library itself, so changing it means
changing the library.

A request passes through several layers, and each one leaves its own
fingerprint:

| Layer | Sent | What the server can see | Section |
| --- | --- | --- | --- |
| TCP | When the connection opens | Socket options such as `TCP_NODELAY`; the SYN packet comes from the operating system | (not covered here) |
| TLS | First message on every HTTPS connection | Versions, cipher suites, extensions and their contents, ALPN | [TLS](#tls) |
| HTTP/2 | Right after TLS | SETTINGS values and order, the first window update, stream priority | [HTTP/2](#http2) |
| HTTP/3 over QUIC | Instead of TCP, TLS, and HTTP/2 | QUIC transport parameters, HTTP/3 SETTINGS | [HTTP/3](#http3) |
| Request fields | With each request | Header names, spelling, order, and pseudo-header order | [Header order](#header-order) |
| Client hints | With each request, and after the server asks | `sec-ch-ua` brand lists and which hints appear when | [Client hints](#client-hints) |

## TLS

An HTTPS connection starts with the client's ClientHello message. It lists
the TLS versions, cipher suites, key-exchange groups, and signature
algorithms the client supports, plus a set of extensions such as the server
name and ALPN (the list of HTTP versions the client can speak). Chrome,
Firefox, curl, and Rust's `rustls` all send different lists.

Hashes such as JA3 and JA4 condense a ClientHello into one short string that
a server can log and compare. Chrome shuffles its extension order on every
connection, so newer hashes such as JA4 sort the extensions before hashing.
The contents still identify the program: a shuffled Chrome ClientHello still
carries Chrome's cipher suites, groups, and extension payloads.

Phantom's TLS [recipes](reference/glossary.md#recipe) come from ClientHellos
recorded from real browsers, for example
`fixtures/tls/chrome/154.0.8037.58/windows-11-26200/client-hello.txt`.

## HTTP/2

After the TLS handshake, an HTTP/2 client must send a SETTINGS frame, and
browsers follow it with a WINDOW_UPDATE frame. The protocol fixes the frame
format; the values, and which settings to send in which order, are the
client's choice.

Here are the first two frames Chrome 154 sent on Windows 11, from
`fixtures/http2/chrome/154.0.8037.58/windows-11-26200/client-startup.txt`:

```text
000018 04 00 00000000     SETTINGS frame, 24-byte payload, stream 0
  0001 00010000           HEADER_TABLE_SIZE      = 65536
  0002 00000000           ENABLE_PUSH            = 0
  0004 00600000           INITIAL_WINDOW_SIZE    = 6291456 (6 MiB)
  0006 00040000           MAX_HEADER_LIST_SIZE   = 262144
000004 08 00 00000000     WINDOW_UPDATE frame, stream 0
  00ef0001                increment              = 15663105
```

Firefox 156 on the same machine sent a different set of settings and values
(from `fixtures/websocket/firefox/156.0/windows-11-26200/accept.txt`):

| | Chrome 154 | Firefox 156 |
| --- | --- | --- |
| Settings sent, in order | 1, 2, 4, 6 | 1, 2, 4, 5 |
| `INITIAL_WINDOW_SIZE` | 6291456 | 131072 |
| `MAX_HEADER_LIST_SIZE` (6) | 262144 | not sent |
| `MAX_FRAME_SIZE` (5) | not sent | 16384 |
| Connection window update | 15663105 | 12517377 |

Chrome's increment raises the connection window from the protocol's default
of 65535 bytes to exactly 15 MiB; Firefox's raises it to 12 MiB. A server
reads these few numbers before any request arrives. A client library with its
own defaults sends its own numbers, whatever its `User-Agent` says.

## Header order

HTTP says the order of most header fields does not change their meaning, so
libraries often sort them, group them, or store them in a hash map. Browsers
write them in a fixed order. Chrome 154's first navigation over HTTP/1.1,
from `fixtures/client-hints/chrome/154.0.8037.58/windows-11-26200/navigation.txt`,
sent its fields in this order:

```text
Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site,
Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding,
Accept-Language
```

HTTP/2 and HTTP/3 add pseudo-header fields (`:method`, `:authority`,
`:scheme`, `:path`) before the others, and their order differs too. Chrome
sends `:method`, `:authority`, `:scheme`, `:path`; Firefox 156 sends
`:method`, `:path`, `:authority`, `:scheme`.

This is why copying a browser's headers into another client is not enough.
The names and values can match while the order, the pseudo-header order, the
SETTINGS frame, and the ClientHello all still describe the other client.

## HTTP/3

HTTP/3 runs over QUIC, which runs over UDP instead of TCP. QUIC has its own
handshake, and in it the client sends transport parameters: limits such as
the idle timeout and flow-control windows, each with an ID, a value, and a
position. Chrome 154 sent 13 of them, including an idle timeout of 30000 ms
and a Google-specific connection option `ORIG`
(`fixtures/http3/chrome/154.0.8037.58/windows-11-26200/client-startup.txt`).
HTTP/3 then sends its own SETTINGS, which differ between clients in the same
way HTTP/2 SETTINGS do.

A client that supports only HTTP/2 does not match a browser that would have
used HTTP/3, and a client that quietly retries over HTTP/2 when HTTP/3 fails
changes its fingerprint in the middle of a session.

## Client hints

Chromium-based browsers send user-agent client hints: fields such as
`sec-ch-ua`, which lists brands and versions in a set order. Chrome 154 sends:

```text
sec-ch-ua: "Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"
```

A server can ask for more hints with an `Accept-CH` response field. In the
same capture, Chrome sent 3 hints on its first request and 11 on the next one,
after the server asked for them. Which hints appear, in which position, and
on which request is part of the fingerprint. Firefox sends no client hints
at all, so a `sec-ch-ua` field next to a Firefox handshake is a mismatch.

## Consistency

Each layer is checked against the others. A Chrome ClientHello followed by
an HTTP/2 SETTINGS frame from a Go or Python library describes two different
programs on one connection. So does a `User-Agent` for Chrome 154 with a
`sec-ch-ua` for Chrome 153, or a Firefox `User-Agent` with Chrome's header
order.

A server does not need to know every browser's fingerprint to notice this. It
needs only to see that the layers disagree. For that reason Phantom treats a
[profile](reference/glossary.md#profile) as one browser build at every layer
it covers, and refuses to send a request whose `User-Agent` or `sec-ch-ua`
names another browser than its request template.

## What this page does not cover

Fingerprinting also happens inside the page, where JavaScript can read
canvas and WebGL output, installed fonts, screen size, WebRTC addresses, and
timing. The IP address and its history are a separate signal. Phantom does
none of this: it does not run JavaScript, render pages, or choose your IP
address. It shapes the network traffic of the layers listed above and nothing
else.

## See your own fingerprint

These public services are run by third parties, not by Phantom. Each one
echoes back what it observed about your connection:

- [tls.peet.ws](https://tls.peet.ws/) shows the ClientHello, its JA3 and JA4
  hashes, and an HTTP/2 fingerprint built from the SETTINGS and header
  frames it received.
- [BrowserLeaks TLS](https://browserleaks.com/tls) shows the ClientHello
  fields and hashes.

Open one in your browser, then request the same URL with `curl` or your
usual HTTP library, and compare the two results. Phantom's own evidence does
not rely on these services; it comes from browser
[captures](reference/glossary.md#capture) recorded against a local listener.

## Next

- [Why Phantom](why-phantom.md): when Phantom fits and how it compares with
  other clients.
- [Getting started](getting-started.md): build Phantom and send a request
  with Chrome 154's fingerprint.
- [Validation](explanation/validation.md): the captures and tests behind each
  layer.
