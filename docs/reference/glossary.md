# Glossary

Each term the documentation uses has one definition here, with a link to the
page that covers it.

> For anyone who meets an unfamiliar term on another page.

Terms are in alphabetical order. Phantom's documentation says "field" for a
header or trailer line, as RFC 9110 does.

## Accept-CH

A response field in which an HTTPS origin asks for more
[client hints](#client-hints) on later requests. Phantom keeps bounded
`Accept-CH` state per exact [origin](#origin). An H2 or H3 server can make the
same request for a whole connection with an `ACCEPT_CH` setting sent through
[ALPS](#alps). See [Client hints](../guides/profiles.md#send-client-hints).

## ALPN

Application-Layer Protocol Negotiation: the TLS extension in which the client
offers application protocols, such as `h2` and `http/1.1`, and the server
selects one. The offer and its order are part of the [ClientHello](#clienthello).
See [Negotiated protocol](#negotiated-protocol).

## ALPS

Application-Layer Protocol Settings: a TLS extension that lets each side send
application settings during the handshake. Chromium offers it for H2 and H3.
Phantom sends the recipe's ALPS offer and reads the peer's settings from it.

## Alt-Svc

A response field (RFC 7838), or an H2 `ALTSVC` frame, in which an origin
advertises that the same service is also available elsewhere. Phantom acts
only on `h3` alternatives, only when the caller enables the store, and keys
each advertisement by origin and [route](#route). See
[HTTP/3 and Alt-Svc](../guides/http3.md).

## Alt-Used

A request field naming the [Alt-Svc](#alt-svc) alternative a request uses.
Phantom adds it only on H3 attempts it makes through the Alt-Svc store, and
rejects a caller-supplied `Alt-Used` before any I/O.

## Browser source

A browser's source code at a release tag, used as evidence where a
[capture](#capture) cannot see a behavior, such as TCP socket options. See
[TCP socket option evidence](../explanation/validation.md#tcp-socket-option-evidence).

## Capture

A recording of a named browser build's traffic against a loopback listener.
Captures are retained under `fixtures/` as [fixtures](#fixture), and tests
compare [recipes](#recipe) with them. See
[Validation](../explanation/validation.md).

## Client hints

Request fields, such as `sec-ch-ua`, that describe the browser and platform.
A browser sends some by default, and a server can ask for more with
[Accept-CH](#accept-ch). Firefox sends no user-agent client hints. See
[Client hints](../guides/profiles.md#send-client-hints).

## ClientHello

The first TLS handshake message a client sends. It lists versions, cipher
suites, groups, and extensions in an order each browser fixes or permutes in
its own way, which makes it one of the most visible parts of a fingerprint.
See [TLS](../fingerprinting.md#tls).

## CONNECT-UDP

The RFC 9298 proxy method that carries UDP through an HTTP proxy; it is part
of MASQUE. Phantom sends exact H3 through it, over an H3 proxy leg by default
or over an explicitly selected H2 extended CONNECT or H1 Upgrade leg. See the
[route matrix](route-matrix.md).

## Connection-setup retry

A new connection attempt after a typed setup failure, before any request byte
is sent. It is opt-in and draws on one bounded budget per request. See
[Retries and replays](../explanation/design.md#retries-and-replays).

## Critical-CH

A response field naming [client hints](#client-hints) the server needs.
Phantom makes one bounded retry of a safe-method request in response to it.

## Differential

A test that compares what Phantom sends with a retained [capture](#capture),
after [normalization](#normalization), at the level of bytes, frames,
packets, or qlog events.

## Exact protocol

A request mode in which the request uses the protocol you chose (H1, H2, or
H3) or fails. It never falls back to another protocol. Compare
[negotiated protocol](#negotiated-protocol).

## Extended CONNECT

A CONNECT request with a `:protocol` pseudo-header field (RFC 8441 for H2,
RFC 9220 for H3). Phantom uses it to open a WebSocket on an H2 stream, and
only after the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. See
[WebSocket](../guides/websocket.md).

## Fingerprint

A description of a client program built from the choices it makes on the
network, such as its TLS offer, HTTP/2 settings, and field order, independent
of what its `User-Agent` says. Each layer leaves its own fingerprint, and a
[profile](#profile) sets the layers Phantom reproduces. See
[How servers recognize a client](../fingerprinting.md#the-short-version).

## Fixture

A retained file under `fixtures/` that holds a [capture](#capture) together
with the client, version, platform, and launch conditions needed to reproduce
it.

## GOAWAY

The H2 or H3 frame in which a server stops accepting new streams. Its
identifier tells the client which requests the server did not process.

## GREASE

Reserved values that a client places among cipher suites, extensions,
settings, and QUIC transport parameters so that peers stay tolerant of
unknown values. The values change per connection. ECH GREASE is a placeholder
Encrypted Client Hello extension of the same kind.

## H1, H2, H3

HTTP/1.1, HTTP/2, and HTTP/3.

## Happy Eyeballs

Connecting to IPv6 and IPv4 addresses in a staggered race. Phantom's
`TcpAddressRacing` reproduces Chromium's Happy Eyeballs v2. See
[TCP](coverage.md#tcp).

## Headless

A browser launched without a visible window. Most captures are headless; the
runs marked headful used a visible window.

## HPACK

The H2 field compression (RFC 7541). A server can see which representation,
name index, and Huffman choice the client picked for each field.

## JA3, JA4

Hash summaries of a TLS ClientHello used to label clients. See
[How servers recognize a client](../fingerprinting.md#tls).

## Negotiated protocol

A request mode with one TLS handshake in which the server picks H1 or H2
through [ALPN](#alpn). With the Alt-Svc store enabled, a later negotiated
request can use a learned H3 alternative. Compare
[exact protocol](#exact-protocol).

## Normalization

Removing from a comparison only the values that must vary per connection,
such as random bytes, key material, connection IDs, and GREASE values. See
[Fixtures and normalization](../explanation/validation.md#fixtures-and-normalization).

## Origin

The scheme, host, and port of a URL. Phantom keys cookies, client hints,
Alt-Svc, and pools by exact origin, with the host in its canonical Unicode
form.

## Pool key

The [origin](#origin) plus the complete [route](#route). Connections,
admission, and learned state are never shared across pool keys. See
[Defaults and limits](limits.md#connection-pools).

## Profile

The fixed description of what the client puts on the wire: the TLS
ClientHello, TCP options, H2 and H3 settings, QUIC transport parameters, and
client hints. A `ClientProfile` is immutable and is built from
[recipes](#recipe) or custom settings. See
[Browser profiles](../guides/profiles.md).

## Pseudo-header fields

The `:method`, `:scheme`, `:authority`, and `:path` fields (and `:protocol`
for [extended CONNECT](#extended-connect)) that open an H2 or H3 request.
Their order differs between browsers.

## QPACK

The H3 field compression (RFC 9204). Chrome advertises a nonzero inbound
dynamic table, and Phantom's QPACK stream bytes match its captures.

## QUIC

The UDP transport under H3 (RFC 9000), with TLS 1.3 inside. Phantom's QUIC is
Quinn with a BoringSSL TLS backend. See [QUIC](coverage.md#quic).

## Recipe

A built-in profile component, such as `chromium::v154_tls()`. Most come from
browser [captures](#capture); TCP recipes come from
[browser source](#browser-source). A recipe's name records the browser, build,
and layer. See [Browser profiles](coverage.md#browser-profiles).

## Replay

Sending a request again when some of it may have reached the server. Phantom
has a built-in replay for a bodyless GET after a graceful H2 `GOAWAY`, and
opt-in replays for a reused connection that closed and for requests the peer
did not process. See
[Retries and replays](../explanation/design.md#retries-and-replays).

## Request template

A `RequestTemplate`: for one kind of browser request, the captured field
order and values for each protocol, slots for caller fields and client hints,
and the captured H2 priority. See
[Request templates](../guides/profiles.md#apply-a-captured-request-template).

## Route

How the client reaches the server: directly, or through an HTTP, SOCKS5, or
[CONNECT-UDP](#connect-udp) proxy. A route is chosen before connection setup
and never changes as a fallback. See the [route matrix](route-matrix.md).

## SETTINGS

The H2 or H3 frame each side sends at connection start with its parameters,
such as table sizes and window sizes. Values and their order differ between
browsers. See [HTTP/2](../fingerprinting.md#http2).

## SNI

Server Name Indication: the host name a client names in its ClientHello. An
Alt-Svc upgrade keeps the origin's SNI, and a CONNECT-UDP proxy has its own.

## SOCKS5

The RFC 1928 proxy protocol. `socks5://` resolves the origin locally and
`socks5h://` lets the proxy resolve it. H3 runs over its UDP ASSOCIATE
command. See [Routes and proxies](../guides/routes-and-proxies.md).

## Trailers

Fields sent after the body. Phantom sends request trailers on H1, H2, and H3,
either static or produced by a declared streaming body.

## Transport parameters

The QUIC values a client sends in its handshake, such as idle timeout and
flow-control limits. Chrome sends them in an order that changes per
connection, with a GREASE parameter.

## Trust anchor IDs

A TLS extension that lists identifiers of the trust anchors a client holds.
Chrome 154 sends 28 in ascending order; Edge 153 omits the extension.

## Next

- [Coverage](coverage.md): what Phantom supports, layer by layer.
- [How servers recognize a client](../fingerprinting.md): the terms in
  context.
