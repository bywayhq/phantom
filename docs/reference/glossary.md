# Glossary

Look up an unfamiliar term and follow its link for details.
Terms are in alphabetical order. "Field" means a header or trailer line.

## Accept-CH

A response field in which a
[potentially trustworthy](#potentially-trustworthy) origin asks for more
[client hints](#client-hints) on later requests. Phantom keeps bounded
`Accept-CH` state per exact [origin](#origin). An H2 or H3 server can make
the same request for a whole connection with an `ACCEPT_CH` setting sent
through [ALPS](#alps); a navigation that lacks a hint it names restarts with
it. See [Client hints](../guides/request-templates.md#send-client-hints).

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
Phantom adds it only when the profile's `Http3RequestSettings::alt_used` is
`Append`, as in the Firefox 157 recipe, and only on H3 attempts it makes
through the Alt-Svc store or to an alternative the caller pins. The Chromium
recipes never send it, as Chrome 154 does not. Phantom rejects a
caller-supplied `Alt-Used` before any I/O.

## Browser source

A browser's source code at a release tag, used as evidence where a
[capture](#capture) cannot see a behavior, such as TCP socket options.

## Capture

A recording of a named browser build's traffic against a loopback listener.
Captures are retained under `fixtures/` as [fixtures](#fixture), and tests
compare [recipes](#recipe) with them.

## Client hints

Request fields, such as `sec-ch-ua`, that describe the browser and platform.
A browser sends some by default, and a server can ask for more with
[Accept-CH](#accept-ch). Firefox sends no user-agent client hints. See
[Client hints](../guides/request-templates.md#send-client-hints).

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

## Connection bound

The most H1 connections a client keeps open to one [pool key](#pool-key),
idle ones included. Browsers cap it per host, and Phantom takes it from the
profile's `Http1Settings`. See
[HTTP/1.1 connections](profiles.md#http11-connections).

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
H3) or fails. It never falls back to another protocol, except an H3 request
whose retry policy opts into the HTTP/2 fallback. Compare
[negotiated protocol](#negotiated-protocol).

## Extended CONNECT

A CONNECT request with a `:protocol` pseudo-header field (RFC 8441 for H2,
RFC 9220 for H3). Phantom uses it to open a WebSocket on an H2 or H3
stream, and only after the peer advertises
`SETTINGS_ENABLE_CONNECT_PROTOCOL`. See
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
`TcpAddressRacing` reproduces Chromium's Happy Eyeballs v2.
`TcpBackupConnection` opens the IPv4 backup attempt of Firefox's release
builds and, on direct HTTP/1.1 and negotiated requests, keeps the slower
attempt's connection, as Firefox does. Elsewhere it closes it.

## Headless

A browser launched without a visible window. Most captures are headless; the
runs marked headful used a visible window.

## Hook log

A record of the calls a named browser build made into the operating
system's socket and resolver interfaces, taken with Frida from inside the
process that opens its connections: a Chromium browser's network service,
or Firefox's parent process. It shows socket options, failed connection
attempts, and lookups answered from a cache, which a
[capture](#capture) cannot.

## HPACK

The H2 field compression (RFC 7541). A server can see which representation,
name index, and Huffman choice the client picked for each field. A profile
states those choices in `Http2Settings::hpack`.

## HTTPS record

A DNS resource record (RFC 9460, type 65) through which an origin advertises
how to connect to it, such as the ALPN protocols it supports, before the
client has contacted it. With the `https-records` feature, an HTTPS record
that lists `h3` lets a negotiated request use H3. See [Find HTTP/3 through
HTTPS DNS
records](../guides/http3-discovery.md#find-http3-through-https-dns-records).

## JA3, JA4

Hash summaries of a TLS ClientHello used to label clients. See
[How servers recognize a client](../fingerprinting.md#tls).

## Negotiated protocol

A request mode that lets the server pick H1 or H2 through [ALPN](#alpn).
A direct `http://` request uses H1. Through an HTTPS H2 proxy, it uses H2
forwarding instead. With discovery enabled, a later HTTPS request can use
H3 through Alt-Svc or an HTTPS DNS record. Compare
[exact protocol](#exact-protocol).

## Normalization

Removing from a comparison only the values that must vary per connection,
such as random bytes, key material, connection IDs, and GREASE values.

## Origin

The scheme, canonical host, and effective port of a URL. Phantom uses
ASCII host names when it serializes an origin. Client hints are keyed by
origin. Alt-Svc and connection pools also include the route. Cookies use
name, domain, and path, with separate host-only and partitioned stores.

## Pool key

The [origin](#origin) plus the complete [route](#route). Connections and
request slots are kept separately for each pool key. See
[Defaults and limits](limits.md#connection-pools).

## Potentially trustworthy

An [origin](#origin) that W3C Secure Contexts lets browsers treat as secure:
an `https` or `wss` origin, or an `http` or `ws` origin whose host is a
loopback address (`127.0.0.0/8` or `::1`), `localhost`, or a name under
`.localhost`. Browsers send client hints, `Sec-Fetch-*` fields, and the `br`
and `zstd` codings only to such origins, and allow `Secure` cookies from them.
See [Template assembly](profiles.md#template-assembly).

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

The H3 header compression format (RFC 9204). It replaces repeated names
and values with references to a table shared by the connection.

## QUIC

The UDP transport under H3 (RFC 9000), with TLS 1.3 inside. Phantom's QUIC is
Quinn with a BoringSSL TLS backend.

## Recipe

A built-in profile component, such as `chrome::v154_tcp_tls()`. Its name
records the browser, build, and layer. Some settings describe recorded
traffic; others define policies such as socket options and connection limits.

## Replay

Sending a request again when some of it may have reached the server. Phantom
has a built-in replay for a bodyless GET after a graceful H2 `GOAWAY`, and
opt-in replays for a reused connection that closed and for requests the peer
did not process. See
[Retries and replays](../explanation/design.md#retries-and-replays).

## Request template

A `RequestTemplate`: header order and values for one kind of browser
request, with slots for your headers and client hints. It also sets the
H2 request priority. `PreparedRequestTemplate::new` validates one
for use with `RequestBuilder::template`. See
[Request templates](../guides/request-templates.md#apply-a-captured-request-template).

## Route

How the client reaches the server: directly, or through an HTTP, SOCKS5, or
[CONNECT-UDP](#connect-udp) proxy. A route is chosen before connection setup
and never changes as a fallback. See the [route matrix](route-matrix.md).

## SETTINGS

The H2 or H3 frame each side sends at connection start with its parameters,
such as table sizes and window sizes. Values and their order differ between
browsers. See [HTTP/2](../fingerprinting.md#http2).

## Snapshot

A value holding a client's cookies (`CookieSnapshot`) or learned Alt-Svc
alternatives (`AltSvcSnapshot`), for storage you own. Import revalidates every
entry. See [Snapshots](cookies.md#snapshots) and [Keep Alt-Svc state across
restarts](../guides/http3-discovery.md#keep-alt-svc-state-across-restarts).

## SNI

Server Name Indication: the host name a client names in its ClientHello. An
Alt-Svc upgrade keeps the origin's SNI, and a CONNECT-UDP proxy has its own.

## SOCKS5

The RFC 1928 proxy protocol. `socks5://` resolves the origin locally and
`socks5h://` lets the proxy resolve it. H3 runs over its UDP ASSOCIATE
command. See [SOCKS5 and CONNECT-UDP proxies](../guides/socks-and-connect-udp.md).

## Trailers

Fields sent after the body. Phantom sends request trailers on H1, H2, and H3,
either static or produced by a declared streaming body.

## Transport parameters

The QUIC values a client sends in its handshake, such as idle timeout and
flow-control limits. Chrome sends them in an order that changes per
connection, with a GREASE parameter.

## Trust anchor IDs

A TLS extension that lists identifiers of the trust anchors a client holds.
Chrome 154 sends 28 in ascending order; Opera 136 sends 32 in an order drawn
per process over TCP and per connection over QUIC; Edge 154 omits the
extension.

## Next

- [Validation](../explanation/validation.md): recordings and source references.
- [How servers recognize a client](../fingerprinting.md): the terms in context.
