# Proxy routing

Proxy choice is an owned `Route`, not a header convention or an environment
fallback. Set a default route on `ClientBuilder` or override it on one request.
The complete route participates in the session's H1/H2 pool key, so a
connection is never reused across proxy endpoints, DNS modes, or credentials.

```rust,no_run
use phantom::{Client, HttpProtocol, Route, Socks5Proxy};
use phantom::profile::{ClientProfile, chromium};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2());
let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?
    .with_username_password("proxy-user", "proxy-password")?;
let client = Client::builder(profile)
    .route(Route::socks5(proxy))
    .build()?;

let response = client
    .get(HttpProtocol::Http2, "https://example.com/")?
    .send()
    .await?;
println!("{}", response.status());
# Ok(())
# }
```

## Current routes

- `Route::Direct` opens the origin TCP or UDP path directly.
- `Route::HttpConnect` accepts `http://` and `https://` proxy URIs. HTTPS first
  authenticates the proxy with its own roots and hostname, then sends the same
  ordered HTTP/1.1 CONNECT request before the independent origin TLS handshake.
  The profile's TLS recipe is used unchanged for the outer handshake; a proxy
  selecting `h2` is rejected because H2 proxy transport is not implemented.
  Optional HTTP Basic credentials use challenge-response negotiation rather
  than a preemptive field.
- `Route::Socks5` uses `socks5://` for locally resolved origin names and
  `socks5h://` for proxy-resolved origin names. Local DNS sends an ordered IP
  candidate as a SOCKS address; remote DNS sends the original domain. The
  proxy endpoint itself is always resolved locally. Optional RFC 1929
  username/password authentication is configured with
  `Socks5Proxy::with_username_password`; user information in the URI remains
  invalid. Configured credentials add username/password to the offered methods;
  the proxy may still select no-authentication.

HTTPS proxy roots are configured with
`ClientBuilder::add_proxy_root_certificate_der`; they do not extend origin
trust. `ClientBuilder::proxy_server_authentication` controls only the proxy TLS
leg. Plaintext and TLS proxy routes are distinct pool identities, and session
ticket caches for proxy and origin handshakes are isolated.

SOCKS5 remains TCP CONNECT only. Both no-auth and username/password routes
support one-shot H1/H2 requests, session-owned H1/H2 reuse, and H1 WSS. Each
username and password must encode to 1–255 UTF-8 bytes; construction rejects
invalid lengths before DNS or network I/O. Credentials are owned by the route,
included in route and pool identity, and omitted from debug output, errors,
and traces. Wire tests use synthetic marker credentials.

HTTP/2 proxy transport, forwarding, custom resolvers, non-Basic HTTP
authentication, GSSAPI, UDP ASSOCIATE, and H3 proxying are not supported.

## HTTP Basic CONNECT authentication

Configure credentials separately from the proxy URI:

```rust,no_run
use phantom::{HttpProxy, Route};

# fn example() -> Result<Route, Box<dyn std::error::Error>> {
let proxy = HttpProxy::new("https://proxy.example:8443")?
    .with_basic_auth("proxy-user", "proxy-password")?;
let route = Route::http_connect(proxy);
# Ok(route)
# }
```

The initial CONNECT is anonymous. Phantom retries only after a syntactically
valid Basic challenge with a realm, opens a fresh TCP connection, repeats the
proxy TLS handshake when applicable, and sends credentials once. A second 407,
an unsupported or malformed challenge, cancellation, or proxy connection
failure is terminal. This retry occurs before origin TLS and before any origin
request bytes, so it does not replay the application request.

`with_basic_auth` appends a `Proxy-Authorization` placeholder to the default
CONNECT fields. Callers that replace the full sequence with `connect_headers`
can position `HttpConnectHeader::proxy_authorization` explicitly. The
placeholder emits no field on the anonymous attempt and emits the generated
field in place on the authenticated attempt. Literal `Proxy-Authorization`
fields cannot be combined with typed credentials.

Usernames must be nonempty ASCII without a colon or control characters;
passwords must be ASCII without control characters. An empty password is
allowed. Credentials are part of route and pool identity and remain absent
from debug output, errors, and traces.

Basic authentication does not provide transport confidentiality. Credentials
sent to a plaintext `http://` proxy are recoverable by an observer on that
network path; use an `https://` proxy when the credentials are sensitive.

## Failure and observability

Origin request and credential validation finish before proxy I/O. Invalid
configuration, connection failure, authentication failure, negotiation
failure, and proxy rejection are typed and do not cause a direct attempt. An
I/O-disabled Tokio runtime returns a typed runtime error. Tracing records route
and outcome categories but not proxy credentials, request fields, or peer
payloads.

Forced H3 accepts only a direct route today. HTTP CONNECT and SOCKS5 TCP routes
are rejected before any proxy TCP or origin UDP socket is opened. UDP-capable
SOCKS5 and CONNECT-UDP/MASQUE will remain distinct, packet-tested additions.
