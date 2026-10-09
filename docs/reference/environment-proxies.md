# Environment proxies

Read proxy settings once and apply them to a client. You can also inject
the same settings without reading the process environment.

## Opt in with a snapshot

`EnvironmentProxies::from_env()` takes an immutable snapshot.
`EnvironmentProxies::from_values` parses injected name/value pairs.
Unknown names are ignored. The last value for each exact name wins.

Pass the result to `ClientBuilder::environment_proxies`. Later environment
changes do not affect the client. Phantom does not read system proxy
settings or certificate environment variables.

## Route precedence

| Order | Selection |
| --- | --- |
| 1 | Explicit request route, including `Route::direct()` |
| 2 | Explicit client route, including `Route::direct()` |
| 3 | Matching `NO_PROXY` rule selects Direct |
| 4 | Proxy for the origin's scheme |
| 5 | `ALL_PROXY` |
| 6 | Direct |

Explicit routes win regardless of builder setter order. Redirects select
again for the new logical origin. WebSocket openings map `ws` to HTTP and
`wss` to HTTPS. SSE requests and reconnects use ordinary request selection.
Proxy failures fail the request. They never trigger a direct connection.

## Variables and precedence

| Lowercase | Uppercase | Applies to |
| --- | --- | --- |
| `http_proxy` | `HTTP_PROXY` | HTTP and `ws` origins |
| `https_proxy` | `HTTPS_PROXY` | HTTPS and `wss` origins |
| `all_proxy` | `ALL_PROXY` | Either scheme without a scheme proxy |
| `no_proxy` | `NO_PROXY` | Intentional direct connections |

A present lowercase value overrides uppercase, even when empty. An empty
scheme value still permits `ALL_PROXY`. An empty `no_proxy` disables the
uppercase bypass list.

A present `REQUEST_METHOD`, even empty, causes Phantom to ignore uppercase
`HTTP_PROXY`. Lowercase `http_proxy` and the other settings remain available.
This is Phantom's CGI policy.

Every selected value is validated, including a proxy hidden by a wildcard
bypass. Shadowed values and CGI-ignored `HTTP_PROXY` are not parsed.

## Proxy URLs and credentials

| URL scheme | Route |
| --- | --- |
| `http` | HTTP proxy over TCP |
| `https` | HTTP proxy over TLS |
| `socks5` | SOCKS5 with local DNS |
| `socks5h` | SOCKS5 with proxy DNS |

Schemes are case-insensitive. Other schemes return a typed configuration
error. Protocol combinations follow the [route matrix](route-matrix.md).
Environment HTTP proxies use HTTP/1.1 to the proxy.

An HTTPS proxy requires `http/1.1` in the profile's TLS ALPN list. A profile
offering only `h2` fails client construction when the snapshot contains an
HTTPS proxy. An environment URL cannot select HTTP/2 proxy transport.
Configure that with an explicit `HttpProxy::with_http2_transport` route
and a profile that meets its connector requirements.
Proxy certificate verification remains on.
Use `add_proxy_root_certificate_der` to trust a private proxy root.

Proxy URLs may contain username and password values. Percent escapes must
decode to valid UTF-8. Literal `+` stays `+`. Malformed escapes, controls,
ambiguous raw `@` characters, and credentials rejected by the existing
HTTP Basic or SOCKS5 validators return errors.

HTTP Basic authentication follows the existing challenge and credential
cache rules. A snapshot does not insert preemptive authorization headers.
Credentials keep the existing pool partitions.

## NO_PROXY grammar

Separate entries with commas. Surrounding spaces and empty entries are
ignored. An optional port matches the origin's effective port.

| Entry | Matches |
| --- | --- |
| `*` | Every origin |
| `example.com` or `.example.com` | Apex and subdomains at a dot boundary |
| `example.com:443` | Those names on port 443 |
| `127.0.0.1` | That literal IPv4 origin |
| `[::1]` or `::1` | That literal IPv6 origin |
| `[::1]:8443` | That literal IPv6 origin on port 8443 |
| `127.0.0.0/8` or `2001:db8::/32` | Literal origin addresses in that CIDR |

Domain matching normalizes case, IDNA, and one trailing root dot. A leading
dot includes the apex. `example.com` does not match `notexample.com`.
Bare IPv6 has no port. CIDR entries are unbracketed, with host bits masked.
They never resolve a domain through DNS.

URLs, other wildcards, empty domain labels, IPv6 zone identifiers, and user
information are rejected. Each selected value is limited to 32 KiB. A bypass
list accepts at most 1024 nonempty entries. Controls are rejected.

## Errors and diagnostics

Parsing errors expose the variable name and a stable error kind through
`EnvironmentProxyError`. Display and Debug omit URLs and credentials.
Its source may be an existing typed proxy configuration error.
Client construction and requests retain their usual typed error categories.

## Next

- [Routes and proxies](../guides/routes-and-proxies.md): apply a snapshot
  and override a route.
- [SOCKS5 and CONNECT-UDP](../guides/socks-and-connect-udp.md): DNS modes
  and HTTP/3 routes.
- [Defaults and limits](limits.md): client and protocol constraints.
