# Proxy routing

Proxy choice is an owned `Route`, not a header convention or an environment
fallback. Set a default route on `ClientBuilder` or override it on one request.
The complete route participates in the session's HTTP/2 pool key, so a
connection is never reused across proxy identities or DNS modes.

```rust,no_run
use phantom::{Client, HttpProtocol, Route, Socks5Proxy};
use phantom::profile::{ClientProfile, chromium};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let profile = ClientProfile::new(chromium::v152_macos_tls())
    .with_http2(chromium::v152_macos_http2());
let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?;
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
- `Route::HttpConnect` opens a plaintext connection to an HTTP proxy and sends
  an ordered CONNECT request before origin TLS.
- `Route::Socks5` uses `socks5://` for locally resolved origin names and
  `socks5h://` for proxy-resolved origin names. Local DNS sends an ordered IP
  candidate as a SOCKS address; remote DNS sends the original domain. The
  proxy endpoint itself is always resolved locally.

The SOCKS5 slice is no-auth and TCP CONNECT only. It supports H1, H2,
session-owned H1/H2 reuse, and H1 WSS. It does not currently support
credentials, custom resolvers, UDP ASSOCIATE, or H3. DNS ownership is part of
the route value and therefore part of connection-pool identity.

## Failure and observability

Origin request validation finishes before proxy I/O. Invalid configuration,
connection failure, negotiation failure, and proxy rejection are typed and do
not cause a direct attempt. An I/O-disabled Tokio runtime returns a typed
runtime error. Tracing records route and outcome categories but not proxy
credentials, request fields, or peer payloads.

Forced H3 accepts only a direct route today. HTTP CONNECT and SOCKS5 TCP routes
are rejected before any proxy TCP or origin UDP socket is opened. UDP-capable
SOCKS5 and CONNECT-UDP/MASQUE will remain distinct, packet-tested additions.
