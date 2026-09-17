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

HTTP/2 proxy transport, authentication challenges, forwarding, custom
resolvers, GSSAPI, UDP ASSOCIATE, and H3 proxying are not supported.

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
