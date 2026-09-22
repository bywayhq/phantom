# Routes and proxies

A route says how the client reaches an origin. Set a default route with
`ClientBuilder::route`, or override it for one request with
`RequestBuilder::route`. The complete route is part of pool identity, and a
proxy failure never falls back to a direct connection.

## Choose a route

| Route | Constructor | Carries |
| --- | --- | --- |
| Direct | Default | Every scheme and protocol |
| HTTP proxy | `Route::http_proxy(HttpProxy)` | HTTPS origins through CONNECT; `http://` origins through HTTP/1.1 forwarding |
| SOCKS5 | `Route::socks5(Socks5Proxy)` | H1/H2 over a TCP tunnel; exact H3 over UDP ASSOCIATE |
| CONNECT-UDP | `Route::connect_udp(ConnectUdpProxy)` | Exact H3 only |

The [route matrix](../reference/route-matrix.md) lists every supported and
rejected combination of scheme, protocol, and route. Unsupported combinations
fail before any proxy or origin I/O instead of selecting another route or
protocol.

## HTTP proxies

An `HttpProxy` is an `http://` or `https://` proxy. It supports two modes of
operation, chosen by the origin's scheme:

- **CONNECT tunnel** for `https://` origins (exact H1 or H2) and `wss://`
  WebSockets. The proxy opens a TCP tunnel and Phantom speaks origin TLS
  inside it.
- **Absolute-form forwarding** for `http://` origins and plaintext `ws://`
  WebSockets. The request is sent to the proxy with the full URL as its target.

The credential-bearing route below works for either an HTTPS origin through
CONNECT or an `http://` origin through exact-H1 forwarding. In both cases Basic
credentials are sent only after a valid proxy challenge.

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

Forwarding is limited to exact HTTP/1.1 requests for `http://` origins. An
`https://` proxy endpoint uses the independent proxy authentication policy,
which verifies the proxy certificate and hostname by default, then carries the
absolute-form request inside that TLS connection; the origin itself is still
plain HTTP. Forwarding never changes to CONNECT, negotiated H1/H2, H2, H3, or a
direct route.

### Basic proxy authentication

When Basic credentials are configured, each logical request begins without
`Proxy-Authorization`.

- A strict, valid Basic `407` challenge permits exactly one replay on a fresh
  connection for the same complete route.
- The generated sensitive `Proxy-Authorization` field follows all caller
  fields and precedes generated framing fields.
- Owned bodies and their static trailers are replayed exactly. A one-shot
  streaming body cannot be replayed: after a valid challenge it returns a
  typed request-body error before opening the retry connection.
- A second `407`, or a malformed or unsupported challenge, returns a typed
  proxy error.
- Challenge state is not retained, so the next logical request starts
  anonymously again.

The same lifecycle applies to CONNECT tunnels and to plaintext WebSocket
Upgrade requests sent through a forward proxy. CONNECT-UDP proxies use a
similar one-replay rule, described [below](#proxy-legs).

### HTTP/2 to the proxy

An `https://` proxy speaks HTTP/1.1 by default.
`HttpProxy::with_http2_transport` selects HTTP/2 to the proxy instead; it is
rejected for `http://` proxies because Phantom does not speak cleartext h2c.
For an HTTP/2-only proxy, add `.with_http2_transport()?` to the proxy; that
route then supports HTTPS origins only.

In both modes the proxy-facing TLS ClientHello offers the profile's ALPN list
unchanged, because a browser offers the same list to an HTTPS proxy and a
rewritten list would be a ClientHello no measured client sends. The selected
protocol is then enforced:

- the default mode accepts `http/1.1` or no ALPN and rejects `h2`;
- the HTTP/2 mode requires `h2` and rejects `http/1.1` or no selection.

A mismatch is a typed proxy error; Phantom never switches proxy protocols. The
HTTP/2 mode requires a profile that offers `h2` and carries HTTP/2 settings,
and reports either gap before proxy I/O.

In HTTP/2 mode each tunnel opens one dedicated proxy connection using the
profile's HTTP/2 SETTINGS, priority, and pseudo-header order. Proxy sessions
are not shared between tunnels or pooled separately from the origin connection
that owns them.

- The CONNECT request follows RFC 9113 section 8.5: only `:method` and
  `:authority` pseudo-headers, then the ordered CONNECT fields with HTTP/2
  lowercase names.
- The authority placeholder supplies `:authority`, and connection-specific
  fields such as `Proxy-Connection` fail before I/O.
- The tunnel is a flow-controlled stream of DATA frames carrying origin TLS
  for H1 or H2 origins. Closing the origin connection resets only that stream
  and ends its proxy connection.
- Basic `407` challenges follow the same one-replay rule on a fresh proxy
  connection.
- Plaintext `http://` forwarding requires HTTP/1.1 proxy transport and fails
  before I/O in HTTP/2 mode.

### CONNECT request fields

- `HttpProxy::header` appends an ordered CONNECT field after the default
  leading `Host`, `headers` replaces the literal fields, and
  `connect_headers` replaces the whole sequence with `HttpConnectHeader`
  values, including the `Authority` placeholder that controls `Host`
  placement. These fields apply to CONNECT tunnels, not to forwarded
  requests.
- `Route::http_connect` is an older name that builds the same
  `Route::HttpProxy` as `Route::http_proxy`.

## SOCKS5 proxies

`Socks5Proxy` accepts two URI schemes:

- `socks5://` resolves the origin locally (`Socks5DnsMode::Local`).
- `socks5h://` lets the proxy resolve the origin (`Socks5DnsMode::Remote`).

`Socks5Proxy::dns_mode` reports which one the URI selected.
`Socks5Proxy::with_username_password` configures RFC 1929 credentials;
credentials inside the proxy URI are rejected. H1 and H2 origins, and H1
`ws://` and `wss://` WebSockets, use a TCP tunnel.

```rust
use phantom::{Route, Socks5Proxy};

fn socks_route() -> Result<Route, Box<dyn std::error::Error>> {
    let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?
        .with_username_password("user", "password")?;
    Ok(Route::socks5(proxy))
}
```

### HTTP/3 over SOCKS5

Exact H3 opens an RFC 1928 UDP ASSOCIATE and keeps the TCP control connection
alive for the association lifetime.

- Local-DNS `socks5://` resolves the origin locally and fixes one IP target.
- Remote-DNS `socks5h://` performs no local origin lookup and encodes the
  canonical origin hostname in each SOCKS UDP request.
- H3 connections and associations are retained through the normal route-keyed
  pool, so compatible requests can reuse them.
- Optional username/password authentication uses RFC 1929.

Proxy authentication, negotiation, and rejection failures are typed and are
not address-fallback candidates. Proxy TCP and QUIC connection setup may
advance or retry only through a fresh association on the same configured
route, under the documented exact-H3 [setup retry policy](retries.md); no
failure selects another route or protocol. Loopback tests retry a refused
local-DNS proxy connect and a QUIC handshake refused through an established
association, each through a new association (see
[connection-retry evidence](../explanation/validation.md#connection-retry-evidence)).

Relay addresses follow strict rules:

- The relay reply must provide a nonzero port.
- Phantom uses a concrete IP relay address directly. For an unspecified relay
  address, it substitutes only the established TCP proxy peer IP and retains
  the returned port. Domain relay addresses are rejected.
- Remote-DNS replies may identify the target by the exact canonical domain or
  by a same-port IP, while Quinn sees one stable logical peer and
  authenticates the QUIC connection.

Exact H3 rejects HTTP forwarding and HTTP CONNECT before origin I/O. WebSocket
over H3 extended CONNECT remains planned.

## CONNECT-UDP (MASQUE) proxies

`Route::connect_udp` sends exact H3 through an RFC 9298 CONNECT-UDP proxy
(also called MASQUE). The proxy relays the inner QUIC connection's UDP
datagrams.

- `ConnectUdpProxy::new` takes an `https` URI template that must contain
  `{target_host}` and `{target_port}` and must not contain user information or
  a fragment.
- `.header` appends ordered CONNECT-UDP request fields.
- Each inner connection opens its own outer connection to the proxy,
  authenticated with the proxy trust roots, and the inner connection keeps
  origin trust and identity.

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

The connection to the proxy is called the proxy leg.

| Leg | Select with | Requirements |
| --- | --- | --- |
| HTTP/3 (default) | Default | The outer profile must support HTTP/3 Datagrams large enough for a full 1200-byte QUIC Initial, or the request fails before I/O |
| HTTP/2 | `with_http2_transport` | An extended CONNECT pseudo-header order in the HTTP/2 profile, and a proxy that selects `h2` and enables extended CONNECT |
| HTTP/1.1 | `with_http1_transport` | An `Upgrade: connect-udp` request that must receive 101 |

The HTTP/2 and HTTP/1.1 legs carry datagrams in capsules on the proxy stream
and use the client profile's TLS offer. The leg is part of route identity;
ALPN or capability mismatches are typed proxy errors and never switch legs.

`with_basic_auth` sends Basic credentials only after a valid 407 challenge,
once, on a fresh proxy connection; a second 407 fails with an authentication
error.

HTTP/1.1, HTTP/2, negotiated requests, and WebSocket reject this route before
I/O. Only outer proxy resolution and connection failures are retryable, and a
proxy rejection exposes its status through the typed error source. See
[HTTP/3 internals](../internals/http3.md#connect-udp-masque) for the full
protocol contract.

## Trust roots and verification

Certificate and hostname verification remain enabled by default. The proxy and
origin trust stores are independent.

- `add_root_certificate_der` adds private DER roots for origins.
- `add_proxy_root_certificate_der` adds roots for an HTTPS proxy, including a
  TLS-encrypted forward proxy and the outer connection of a CONNECT-UDP proxy.
- `ClientBuilder::server_authentication` and `proxy_server_authentication`
  accept `ServerAuthentication::Disabled` for controlled conformance work
  only. Origin verification can be disabled for H1/H2 but not combined with
  additional roots or H3. Proxy verification cannot be disabled for a
  CONNECT-UDP route on any leg.

## Configuration errors

Proxy credentials are validated before I/O and excluded from diagnostics.
Proxy, SOCKS5, and CONNECT-UDP configuration errors expose stable
`ProxyConfigErrorKind`, `Socks5ProxyConfigErrorKind`, and
`ConnectUdpProxyConfigErrorKind` categories.
