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
- `Route::Socks5` accepts only `socks5h://` endpoints. Domain origins are sent
  to the proxy as SOCKS5 `DOMAIN` targets; IP literals use their native address
  form. The proxy endpoint itself is resolved locally.

The SOCKS5 slice is no-auth and TCP CONNECT only. It supports H1, H2,
session-owned H2 reuse, and H1 WSS. It does not currently support local origin
DNS, credentials, UDP ASSOCIATE, or H3. Those are separate route capabilities,
not flags that silently change the meaning of `socks5h`.

## Failure and observability

Origin request validation finishes before proxy I/O. Invalid configuration,
connection failure, negotiation failure, and proxy rejection are typed and do
not cause a direct attempt. An I/O-disabled Tokio runtime returns a typed
runtime error. Tracing records route and outcome categories but not proxy
credentials, request fields, or peer payloads.

Forced H3 accepts only a direct route today. HTTP CONNECT and SOCKS5 TCP routes
are rejected before any proxy TCP or origin UDP socket is opened. UDP-capable
SOCKS5 and CONNECT-UDP/MASQUE will remain distinct, packet-tested additions.
