# How servers recognize a client

A server can tell which program made a request without reading its
`User-Agent`. This page shows how, and why copying a browser's headers
doesn't change what the server sees.

## The short version

Every HTTP client makes many small choices before it sends a request: which
encryption methods to offer and in what order, how much data to let the
server send before waiting, and what order to write its headers in. Each
browser makes these choices in its own code, and a given browser version
makes them the same way, apart from values it randomizes. A server that
records them gets a **fingerprint**: a description of the program that doesn't depend on what
the program says about itself.

Think of it as a `User-Agent` the client can't edit. The `User-Agent` header
is one line of text that any library can set to anything. The TLS handshake
comes from the TLS library itself, so changing it means changing the
library.

A request passes through several layers, and each one leaves its own
fingerprint:

| Layer | When it's sent | What the server can see |
| --- | --- | --- |
| [TLS](#tls) | First message on every HTTPS connection | Versions, cipher suites, extensions, ALPN |
| [HTTP/2](#http2) | Right after TLS | Settings and their order, window size, priority |
| [HTTP/3](#http3) | Instead of TCP and HTTP/2 | QUIC transport parameters, HTTP/3 settings |
| [Headers](#header-order) | With each request | Header names, spelling, and order |
| [Client hints](#client-hints) | With each request | Browser brand lists, and which hints appear when |

TCP leaves a few traces too, such as socket options, but this page doesn't
cover them.

## TLS

An HTTPS connection starts with a message from the client called the
ClientHello. It says hello to the server and lists what the client can do:
the TLS versions, the cipher suites (encryption methods), the key-exchange
groups, and the signature algorithms it supports. It also carries
extensions, such as the server name and ALPN, the list of HTTP versions the
client speaks. Chrome, Firefox, curl, and Rust's `rustls` all send different
lists.

Hashes such as JA3 and JA4 boil a ClientHello down to one short string that
a server can log and compare. Chrome shuffles the order of its extensions on
every connection, so JA4 sorts them before hashing. The contents still give
the program away: a shuffled Chrome ClientHello still carries Chrome's
cipher suites, groups, and extension data.

Phantom sends the ClientHello of the browser you pick. Each set of browser
settings Phantom carries is called a [recipe](reference/glossary.md#recipe).

## HTTP/2

After the TLS handshake, an HTTP/2 client sends a SETTINGS frame, and
browsers follow it with a WINDOW_UPDATE frame. The protocol fixes the frame
format. The values, and which settings to send in which order, are up to the
client.

Here are the first two frames Chrome 154 sends on Windows 11:

```text
000018 04 00 00000000     SETTINGS frame, 24-byte payload, stream 0
  0001 00010000           HEADER_TABLE_SIZE      = 65536
  0002 00000000           ENABLE_PUSH            = 0
  0004 00600000           INITIAL_WINDOW_SIZE    = 6291456 (6 MiB)
  0006 00040000           MAX_HEADER_LIST_SIZE   = 262144
000004 08 00 00000000     WINDOW_UPDATE frame, stream 0
  00ef0001                increment              = 15663105
```

Firefox 157 on the same machine sends different settings and values:

| | Chrome 154 | Firefox 157 |
| --- | --- | --- |
| Settings sent, in order | 1, 2, 4, 6 | 1, 2, 4, 5 |
| `INITIAL_WINDOW_SIZE` | 6291456 | 131072 |
| `MAX_HEADER_LIST_SIZE` (6) | 262144 | not sent |
| `MAX_FRAME_SIZE` (5) | not sent | 16384 |
| Connection window update | 15663105 | 12517377 |

Chrome's window update raises the connection window from the default of
65535 bytes to exactly 15 MiB. Firefox's raises it to 12 MiB. The server
reads these few numbers before any request arrives. A library with its own
defaults sends its own numbers, whatever its `User-Agent` says.

## Header order

HTTP says the order of most headers doesn't change their meaning, so
libraries often sort them, group them, or keep them in a hash map. Browsers
write them in a fixed order. When Chrome 154 loads a page over HTTP/1.1, it
sends its headers in this order:

```text
Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-Site,
Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest, Accept-Encoding,
Accept-Language
```

HTTP/2 and HTTP/3 put pseudo-headers (`:method`, `:authority`, `:scheme`,
`:path`) before the others, and browsers order those differently too. Chrome
sends `:method`, `:authority`, `:scheme`, `:path`. Firefox 157 sends
`:method`, `:path`, `:authority`, `:scheme` on HTTP/2 and
`:method`, `:scheme`, `:authority`, `:path` on HTTP/3.

This is why copying a browser's headers into another client isn't enough.
The names and values can match while the header order, the pseudo-header
order, the SETTINGS frame, and the ClientHello still describe the other
client.

## HTTP/3

HTTP/3 runs over QUIC, which runs over UDP instead of TCP. QUIC has its own
handshake, and in it the client sends transport parameters. These are limits
such as the idle timeout and flow-control windows, each with an ID, a value,
and a position. Chrome 154 sends 13 of them, including an idle timeout of
30000 ms and a Google-specific connection option, `ORIG`. HTTP/3 then sends
its own SETTINGS, which differ between clients the same way HTTP/2 SETTINGS
do.

A client that only speaks HTTP/2 doesn't look like a browser that would have
used HTTP/3. A client that quietly retries over HTTP/2 when HTTP/3 fails
changes its fingerprint partway through a session.

## Client hints

Chromium-based browsers send user-agent client hints. These are headers such
as `sec-ch-ua`, which lists brands and versions in a set order. Chrome 154
sends:

```text
sec-ch-ua: "Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"
```

A server can ask for more hints with an `Accept-CH` response header. On a
first visit Chrome sends 3 hints. After a server asked for more, Chrome sent
11 on the next request. Which hints appear, where, and on which request is
part of the fingerprint. Firefox sends no client hints at all, so a
`sec-ch-ua` header next to a Firefox handshake doesn't add up.

## Consistency

A server can compare the layers with each other. A Chrome ClientHello
followed by the HTTP/2 settings of a Go or Python library describes two
different programs on one connection. So does a `User-Agent` for Chrome 154
with a `sec-ch-ua` for Chrome 153, or a Firefox `User-Agent` with Chrome's
header order.

The server doesn't need to know every browser's fingerprint to spot this. It
only needs to see that the layers disagree. That's why a Phantom
[profile](reference/glossary.md#profile) describes one browser version at
every layer it covers. Phantom doesn't compare the `User-Agent` or
`sec-ch-ua` you send with the rest of the profile, so keep them from the
same browser and version.

## What this page does not cover

Pages also fingerprint you from JavaScript, by reading canvas and WebGL
output, installed fonts, screen size, WebRTC addresses, and timing. Your IP
address and its history are another signal. Phantom doesn't run JavaScript
or choose your IP address. It shapes the network traffic described above.

## See your own fingerprint

These third-party services show what they saw of your connection:

- [tls.peet.ws](https://tls.peet.ws/) shows the ClientHello, its JA3 and JA4
  hashes, and an HTTP/2 fingerprint.
- [BrowserLeaks TLS](https://browserleaks.com/tls) shows the ClientHello and
  its hashes.

Open one in your browser, then request the same URL with `curl` or your
usual HTTP library, and compare the two.

## Next

- [Why Phantom](why-phantom.md): when Phantom fits and how it compares with
  other clients.
- [Getting started](getting-started.md): send a request with Chrome 154's
  fingerprint.
- [Validation](explanation/validation.md): how each layer is tested against
  the real browser.
