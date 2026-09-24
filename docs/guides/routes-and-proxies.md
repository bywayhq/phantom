# Routes and proxies

A route says how the client reaches a server: directly, or through an HTTP,
SOCKS5, or CONNECT-UDP proxy. Set a default route with `ClientBuilder::route`,
or override it for one request with `RequestBuilder::route`.

The route you set is the route Phantom uses. If the proxy fails, the request
fails with a typed error. Phantom never connects directly instead, because
that would expose your real address and change what the server sees. Each
pooled connection belongs to one route, so a request through one proxy never
reuses a connection opened through another.

Terms such as H1, H2, H3, exact, and negotiated are defined in
[Key terms](client.md#key-terms).

## Choose a route

| Route | Constructor | Carries |
| --- | --- | --- |
| Direct | `Route::direct()`, the default | Every scheme and protocol |
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTPS origins through CONNECT; `http://` origins through HTTP/1.1 forwarding |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | Exact and negotiated H1/H2 over a TCP tunnel; exact and Alt-Svc H3 over UDP ASSOCIATE |
| CONNECT-UDP | `Route::connect_udp(ConnectUdpProxy)` | Exact H3 only |

The [route matrix](../reference/route-matrix.md) lists every supported and
rejected combination of scheme, protocol, and route. An unsupported
combination fails before any proxy or origin I/O; Phantom does not pick
another route or protocol for it.

## HTTP proxies

An `HttpProxy` is an `http://` or `https://` proxy. The origin's scheme
decides how Phantom uses it:

| Origin | Mode | What happens |
| --- | --- | --- |
| `https://` (exact H1 or H2), `wss://` | CONNECT tunnel | The proxy opens a TCP tunnel, and Phantom runs the origin's TLS inside it |
| `http://`, `ws://` | Absolute-form forwarding | Phantom sends the request to the proxy with the full URL as its target |

The route below works for an HTTPS origin through CONNECT and for an
`http://` origin through exact-H1 forwarding. In both cases Phantom sends the
Basic credentials only after the proxy asks for them.

```rust
use phantom::{HttpProxy, Route};

fn route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = HttpProxy::new("https://proxy.example:8443")?
        .with_basic_auth("proxy-user", "proxy-password")?;
    let route = Route::http_proxy(proxy);
    Ok(route)
}
```

### Forwarding `http://` origins

Forwarding carries only exact HTTP/1.1 requests for `http://` origins. It
never switches to CONNECT, negotiated H1/H2, H2, H3, or a direct route.

With an `https://` proxy, Phantom first opens TLS to the proxy and verifies
its certificate and hostname under the proxy trust settings (see
[Trust roots and verification](#trust-roots-and-verification)). The forwarded
request travels inside that TLS connection, but the origin itself is still
plain HTTP.

### Basic proxy authentication

`HttpProxy::with_basic_auth` stores credentials that Phantom sends only in
answer to a challenge. Each logical request starts without
`Proxy-Authorization`:

- A strict, valid Basic `407` challenge allows exactly one replay, on a fresh
  connection over the same complete route.
- The generated `Proxy-Authorization` field, marked sensitive, goes after all
  caller fields and before generated framing fields.
- Owned bodies and their static trailers are replayed exactly. A one-shot
  streaming body cannot be replayed: after a valid challenge, the request
  returns a typed request-body error before opening the second connection.
- A second `407`, or a malformed or unsupported challenge, returns a typed
  proxy error.
- Phantom keeps no challenge state, so the next logical request starts without
  credentials again.

The same rules apply to CONNECT tunnels and to plaintext WebSocket Upgrade
requests sent through a forward proxy. CONNECT-UDP proxies use a similar
one-replay rule, described in [Proxy legs](#proxy-legs).

Basic credentials sent to an `http://` proxy travel unencrypted. Use an
`https://` proxy when the credentials are sensitive.

### HTTP/2 to the proxy

Phantom speaks HTTP/1.1 to an `https://` proxy by default. For a proxy that
accepts only HTTP/2, add `.with_http2_transport()?` to the `HttpProxy`; that
route then carries HTTPS origins only. An `http://` proxy rejects this option
with a `ProxyConfigError`, because Phantom does not speak cleartext HTTP/2
(h2c).

In both modes, the TLS ClientHello sent to the proxy offers the profile's
ALPN list unchanged. A browser offers the same list to an HTTPS proxy, and a
rewritten list would produce a ClientHello that no measured browser sends.
Phantom then enforces the protocol the proxy selects:

| Mode | Accepts | Rejects |
| --- | --- | --- |
| HTTP/1.1 (default) | `http/1.1` or no ALPN | `h2` |
| HTTP/2 | `h2` | `http/1.1` or no selection |

A mismatch is a typed proxy error; Phantom never switches proxy protocols.
HTTP/2 mode also needs a profile that offers `h2` and carries HTTP/2
settings. If either is missing, the request fails before proxy I/O.

In HTTP/2 mode, each tunnel opens its own proxy connection with the profile's
HTTP/2 SETTINGS, priority, and pseudo-header order. Tunnels never share a
proxy connection, and the proxy connection is not pooled apart from the
origin connection that owns it.

- The CONNECT request follows RFC 9113 section 8.5: only `:method` and
  `:authority` pseudo-headers, then the ordered CONNECT fields with HTTP/2
  lowercase names.
- The authority placeholder supplies `:authority`. Connection-specific fields
  such as `Proxy-Connection` fail before I/O.
- The tunnel is a flow-controlled stream of DATA frames that carries the
  origin's TLS for H1 or H2 origins. Closing the origin connection resets
  only that stream and ends its proxy connection.
- Basic `407` challenges follow the same one-replay rule on a fresh proxy
  connection.
- Plaintext `http://` forwarding requires the HTTP/1.1 proxy mode and fails
  before I/O in HTTP/2 mode.

### CONNECT request fields

These methods set the fields of the CONNECT request. They do not affect
forwarded requests.

| Method | Effect |
| --- | --- |
| `HttpProxy::header` | Appends one field, in order, after the default leading `Host` |
| `HttpProxy::headers` | Replaces the literal fields after the leading `Host` |
| `HttpProxy::connect_headers` | Replaces the whole sequence with `HttpConnectHeader` values, including the `Authority` placeholder that places `Host` |

A literal `Host` or request-framing field is rejected before proxy I/O. Use
the `Authority` placeholder to control where `Host` goes.

`Route::http_connect` is an older name that builds the same
`Route::HttpProxy` as `Route::http_proxy`.

## SOCKS5 proxies

The URI scheme of a `Socks5Proxy` decides where the origin's hostname is
resolved:

| Scheme | Resolves the origin | `Socks5Proxy::dns_mode` |
| --- | --- | --- |
| `socks5://` | Locally | `Socks5DnsMode::Local` |
| `socks5h://` | At the proxy | `Socks5DnsMode::Remote` |

Set credentials with `Socks5Proxy::with_username_password`, which uses
RFC 1929 username and password authentication. Credentials inside the proxy
URI are rejected. H1 and H2 origins, and H1 `ws://` and `wss://` WebSockets,
use a TCP tunnel through the proxy.

```rust
use phantom::{Route, Socks5Proxy};

fn socks_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?
        .with_username_password("user", "password")?;
    Ok(Route::socks5(proxy))
}
```

### Negotiated HTTPS over SOCKS5

`get_negotiated` opens one TLS handshake inside an RFC 1928 CONNECT tunnel and
lets ALPN choose H1 or H2. The origin keeps its own certificate verification
and SNI; the proxy only carries the bytes. Negotiated connections are pooled
per origin **and** route, so a direct connection and a proxied one to the same
origin never substitute for each other.

With Alt-Svc enabled, such a request can learn an `h3` alternative and a later
request can upgrade to it over the same proxy, using UDP ASSOCIATE. SOCKS5 is
the only proxy route that carries both legs; see
[Routes that carry the upgrade](http3.md#routes-that-carry-the-upgrade).

### HTTP/3 over SOCKS5

Exact H3 asks the proxy for a UDP relay with an RFC 1928 UDP ASSOCIATE
request. The TCP control connection stays open for as long as the
association lives.

- With `socks5://`, Phantom resolves the origin locally and sends to one fixed
  IP address.
- With `socks5h://`, Phantom does no local lookup and puts the canonical
  origin hostname in each SOCKS UDP request.
- H3 connections and their associations stay in the normal route-keyed pool,
  so compatible requests can reuse them.
- Username and password authentication, when configured, uses RFC 1929.

Proxy authentication, negotiation, and rejection failures return typed
errors, and Phantom does not try another address after them. A failed proxy
TCP connect or QUIC setup can be retried only through a fresh association on
the same route, under the
[connection-setup retry](retries.md#connection-setup-retries) policy. No
failure selects another route or protocol. Loopback tests retry a refused
local-DNS proxy connect, and a QUIC handshake refused through an established
association, each through a new association (see
[connection-retry evidence](../explanation/validation.md#connection-retry-evidence)).

The proxy's relay address must meet these rules:

- The reply must carry a nonzero port.
- A concrete IP relay address is used as given. For an unspecified address
  such as `0.0.0.0`, Phantom substitutes the IP of the established TCP proxy
  connection and keeps the returned port. A domain name as relay address is
  rejected.
- With `socks5h://`, a reply may name the target by the exact canonical
  domain or by an IP with the same port. Quinn, the QUIC library, still sees
  one stable peer and authenticates the QUIC connection.

Exact H3 cannot use an HTTP proxy, by forwarding or by CONNECT; that
combination fails before origin I/O. WebSocket over H3 extended CONNECT is
planned, not supported.

## CONNECT-UDP (MASQUE) proxies

`Route::connect_udp` sends exact H3 through an RFC 9298 CONNECT-UDP proxy,
also called MASQUE. The proxy relays the UDP datagrams of the QUIC connection
to the origin, called the inner connection.

- `ConnectUdpProxy::new` takes an `https` URI template. The template must
  contain `{target_host}` and `{target_port}`, and must not contain user
  information or a fragment.
- `ConnectUdpProxy::header` appends ordered fields to the CONNECT-UDP
  request.
- Each inner connection opens its own outer connection to the proxy. The
  outer connection is verified against the proxy trust roots, and the inner
  connection against the origin trust roots.

```rust
use phantom::{ConnectUdpProxy, RequestHeader, Route};

fn masque_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .header(RequestHeader::new("x-client", "phantom"));
    Ok(Route::connect_udp(proxy))
}

fn masque_over_http2_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = ConnectUdpProxy::new(
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
    )?
    .with_http2_transport()
    .with_basic_auth("proxy-user", "proxy-password")?;
    Ok(Route::connect_udp(proxy))
}
```

### Proxy legs

The proxy leg is the outer connection from Phantom to the proxy. HTTP/3 is
the default; the other two legs run over TCP.

| Leg | Select with | Requirements |
| --- | --- | --- |
| HTTP/3 (default) | Default | The outer profile must support HTTP/3 Datagrams large enough for a full 1200-byte QUIC Initial, or the request fails before I/O |
| HTTP/2 | `with_http2_transport` | An extended CONNECT pseudo-header order in the HTTP/2 profile, and a proxy that selects `h2` and enables extended CONNECT |
| HTTP/1.1 | `with_http1_transport` | An `Upgrade: connect-udp` request that must receive 101 |

The HTTP/2 and HTTP/1.1 legs carry datagrams in capsules on the proxy stream
and use the client profile's TLS offer. The leg is part of the route, so
routes that differ only in leg never share connections. An ALPN or
capability mismatch is a typed proxy error; Phantom never switches legs.

`ConnectUdpProxy::with_basic_auth` sends Basic credentials only after a valid
`407` challenge, once, on a fresh proxy connection. A second `407` fails with
an authentication error.

H1, H2, negotiated requests, and WebSocket reject this route before I/O. A
negotiated request needs a TLS stream for ALPN, which a QUIC-only route cannot
provide, so it cannot learn or use an Alt-Svc alternative here either. Only
failures to resolve or connect to the proxy are retryable. When the proxy
rejects the request, the typed error's source exposes the status. See
[HTTP/3 internals](../internals/http3.md#connect-udp-masque) for the full
protocol contract.

## Trust roots and verification

Phantom verifies certificates and hostnames by default. Proxies and origins
have separate trust stores, configured on `ClientBuilder`:

| Method | Applies to |
| --- | --- |
| `add_root_certificate_der` | Origins: adds a private DER root |
| `add_proxy_root_certificate_der` | HTTPS proxies, including a TLS forward proxy and the outer connection of a CONNECT-UDP proxy |
| `server_authentication` | Origins: sets the verification policy |
| `proxy_server_authentication` | Proxies: sets the verification policy |

Both policy methods accept `ServerAuthentication::Disabled`. Use it only for
controlled conformance work. Building the client fails for these
combinations:

- disabled origin verification with additional origin roots, or with a
  profile that supports H3;
- disabled proxy verification with additional proxy roots; and
- disabled proxy verification with a CONNECT-UDP default route, on any leg.

Disabled proxy verification is not supported for any CONNECT-UDP route,
including one set per request.

## Configuration errors

Phantom validates proxy credentials before I/O and keeps them out of
diagnostics. Configuration errors carry stable categories:
`ProxyConfigErrorKind` for HTTP proxies, `Socks5ProxyConfigErrorKind` for
SOCKS5, and `ConnectUdpProxyConfigErrorKind` for CONNECT-UDP.
