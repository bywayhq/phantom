# Use a proxy

Set a route when you build a client to send its requests through a proxy.
You need a reachable proxy and its URL; the example below assumes an HTTP
proxy listening on `127.0.0.1:8080`. Proxy support needs no Cargo feature.
For installation and runtime setup, see [Getting started](crate::guide::getting_started).

```no_run
use phantom::profile::browser::chrome;
use phantom::{Client, ContentDecoding, HttpProxy, Route, response_text};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let profile = chrome::v154_windows()
    .with_request_template(chrome::v154_windows_navigation_template());
let proxy = HttpProxy::new("http://127.0.0.1:8080")?;
let client = Client::builder(profile)
    .route(Route::http_proxy(proxy))
    .build()?;

let response = client
    .get_negotiated("https://example.com/")?
    .content_decoding(ContentDecoding::advertised(1 << 20))
    .send()
    .await?;
let response = response_text(response, 1 << 20).await?;
println!("{}\n{}", response.status(), response.body());
# Ok(())
# }
```

Reuse the client. Connections are pooled by route. A proxy failure returns
an error instead of sending the request directly.

## Choose the proxy connection

The proxy URL describes the connection **to the proxy**. Phantom resolves
the proxy's hostname locally. The proxy resolves the destination's hostname.
Profile socket settings apply to your connection to the proxy, not its
connection to the destination. A direct route instead resolves and connects
to the destination locally.

For an `https://` destination, Phantom opens a CONNECT tunnel and performs
the origin's TLS handshake inside it. For an `http://` destination, the
proxy forwards the plaintext request. Use an `https://` proxy URL to encrypt
the connection to the proxy; it does not encrypt the proxy's connection to
a plaintext destination.

An HTTPS proxy uses HTTP/1.1 by default. If your proxy requires HTTP/2 on the
proxy connection, select [`HttpProxy::with_http2_transport`](crate::HttpProxy::with_http2_transport).
This setting controls the proxy connection independently of the protocol
inside a CONNECT tunnel.

A custom [`tcp_connector`](crate::ClientBuilder::tcp_connector) owns DNS and
socket configuration for its streams. Profile TCP settings do not apply.
The connector cannot be combined with proxy routes or HTTP/3.

To override the route for one request, call [`RequestBuilder::route`](crate::RequestBuilder::route):

```no_run
use phantom::{Client, Route};

# async fn example(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let response = client
    .get_negotiated("https://example.com/")?
    .route(Route::direct())
    .send()
    .await?;
let _body = response.into_body().collect_with_limit(1 << 20).await?;
# Ok(())
# }
```

## Authenticate to the proxy

Pass credentials through the proxy configuration. [`HttpProxy::new`](crate::HttpProxy::new)
rejects URLs containing a username or password.

```no_run
use phantom::HttpProxy;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let username = std::env::var("PROXY_USERNAME")?;
let password = std::env::var("PROXY_PASSWORD")?;
let proxy = HttpProxy::new("https://proxy.example:8443")?
    .with_basic_auth(username, password)?;
# drop(proxy);
# Ok(())
# }
```

With ordinary setup, Basic authentication waits for the proxy's `407`
challenge. After credentials succeed, the client can send them on the first
attempt of later requests through that proxy. See
[`preemptive_proxy_authentication`](crate::ClientBuilder::preemptive_proxy_authentication)
to change that behavior, or [`with_digest_auth`](crate::HttpProxy::with_digest_auth)
for Digest authentication.

Keep passwords out of source code, command-line arguments, logs, and origin
headers. Configure proxy authentication on the route rather than adding
`Proxy-Authorization` to a request. Basic credentials sent to an `http://`
proxy are unencrypted on that connection, even when the destination uses
HTTPS; use a trusted HTTPS proxy when credentials need transport protection.

## Choose where SOCKS resolves names

For SOCKS5, choose the DNS behavior in the proxy URL:

- `socks5://127.0.0.1:1080` resolves destination names on your machine.
- `socks5h://127.0.0.1:1080` sends destination names to the proxy to resolve.

```no_run
use phantom::{Route, Socks5Proxy};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let route = Route::socks5(Socks5Proxy::new("socks5h://127.0.0.1:1080")?);
# drop(route);
# Ok(())
# }
```

Pass this route to the same client builder used above. The proxy's own
hostname still needs local resolution. For authentication, use
[`Socks5Proxy::with_username_password`](crate::Socks5Proxy::with_username_password);
the constructor rejects credentials in the URL. SOCKS5 does not encrypt its
username/password exchange. [`Socks4Proxy`](crate::Socks4Proxy) also supports
local DNS or SOCKS4a proxy DNS, but carries only TCP and cannot target IPv6.

For explicit local DNS, use [`ClientBuilder::dns_resolver`](crate::ClientBuilder::dns_resolver)
or [`resolve`](crate::ClientBuilder::resolve) overrides. With `https-records`,
[`DnsOverTls`](crate::dns::DnsOverTls) and [`DnsOverHttps`](crate::dns::DnsOverHttps)
provide encrypted resolvers with explicit bootstrap addresses and endpoint trust.
A local resolver does not replace destination lookups delegated to a proxy.

## Opt in to environment settings

Phantom connects directly by default and does not read operating-system
proxy settings. To read proxy environment variables once for a client:

```no_run
use phantom::profile::browser::chrome;
use phantom::{Client, EnvironmentProxies};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder(chrome::v154_windows())
    .environment_proxies(EnvironmentProxies::from_env()?)
    .build()?;
# drop(client);
# Ok(())
# }
```

The snapshot recognizes `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and
`NO_PROXY`, plus lowercase forms, which take precedence. A matching
`NO_PROXY` rule selects a direct connection; otherwise the destination's
scheme setting wins over `ALL_PROXY`. An explicit client route overrides
the snapshot, and a request route overrides both, regardless of setter order.

Environment URLs may include encoded credentials, unlike the proxy
constructors above. Protect these values as secrets. For exact matching,
validation, and CGI rules, see [`EnvironmentProxies`](crate::EnvironmentProxies).

## Use HTTP/3 through a proxy

An ordinary HTTP CONNECT tunnel carries TCP, so an HTTP proxy cannot carry
HTTP/3. SOCKS5 can carry it when the proxy supports UDP ASSOCIATE. A
[`ConnectUdpProxy`](crate::ConnectUdpProxy) carries exact HTTP/3 requests
through a MASQUE proxy; it rejects negotiated HTTP/1.1-or-HTTP/2 requests.
Use [`Route::connect_udp`](crate::Route::connect_udp) with
[`HttpProtocol::Http3`](crate::HttpProtocol::Http3) and the URI template
provided by your proxy operator. The proxy connection defaults to HTTP/3;
the reference documents explicit HTTP/2 and HTTP/1.1 alternatives.
Local DNS and socket settings govern that outer proxy connection. The
origin's QUIC packets travel inside it. The proxy resolves the origin name.

Proxy and origin certificate trust are separate. For a private proxy CA,
add its DER certificate with
[`add_proxy_root_certificate_der`](crate::ClientBuilder::add_proxy_root_certificate_der).
This also applies to CONNECT-UDP. Origin certificates keep their own trust
checks inside the tunnel. Unsupported route/protocol combinations fail
before network I/O.

To restrict secure proxy keys, set
[`proxy_server_spki_pins`](crate::ClientBuilder::proxy_server_spki_pins).
These pins cover the outer HTTPS or CONNECT-UDP connection and supplement
normal proxy verification. Origin keys use
[`server_spki_pins`](crate::ClientBuilder::server_spki_pins) independently.
With proxy pins configured, selecting a plaintext HTTP or SOCKS proxy fails.
Direct routes remain usable.

Continue with [Requests and responses](crate::guide::requests_and_responses)
for response handling and request policies, or
[Browser profiles](crate::guide::browser_profiles) for profile and header choices.
