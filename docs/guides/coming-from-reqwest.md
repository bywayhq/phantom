# Coming from reqwest

Map what you do in reqwest to Phantom, task by task, and see where the two
clients behave differently.

> For builders who know reqwest and have read [Getting started](../getting-started.md).

The reqwest examples use reqwest 0.13. Phantom asks you to state what reqwest
chooses for you, such as the protocol and the request fields, because a
server can observe each choice
([How servers recognize a client](../fingerprinting.md#the-short-version)).

| reqwest | Phantom |
| --- | --- |
| `Client::new()`, `Client::builder()` | `Client::builder(profile)`; a [profile](../reference/glossary.md#profile) is required |
| ALPN picks HTTP/1.1 or HTTP/2; `http1_only`, `http2_prior_knowledge` | `HttpProtocol` on every request, or `get_negotiated` to let ALPN pick |
| `default_headers`, `user_agent` | No client-level fields; a [request template](../reference/glossary.md#request-template) or ordered `RequestHeader`s per request |
| `json`, `form`, `query` | None; serialize the body yourself and pass bytes to `body` |
| Follows up to 10 redirects | Follows none until you set `RedirectPolicy::limited(n)` |
| `timeout`, `connect_timeout`, `read_timeout` | `RequestTimeouts` with `total`, `connect`, `read_idle`, and two more phases |
| `Proxy::all`; system proxies from `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` | `Route` with `HttpProxy`, `Socks5Proxy`, or `ConnectUdpProxy`; no environment variables are read |
| `cookie_store(true)` (`cookies` feature) | `ClientBuilder::cookies()` (`cookies` feature) |
| `resolve`, `resolve_to_addrs`, `dns_resolver` | `ClientBuilder::resolve(host, ips)` and `dns_resolver(AddressResolver)`; the port always comes from the URL ([Resolve host names](name-resolution.md)) |
| `gzip(true)`, on when the `gzip` feature is on | `ContentDecoding::advertised(max)` per request |
| `Response::text`, `bytes`, `json` | `ResponseBody::collect_with_limit(max)`, which returns `Bytes` |
| `Error::is_timeout`, `is_connect` | [`RequestError::kind()`](responses.md#handle-errors), a non-exhaustive `RequestErrorKind` |

## Send a GET request

Build a client once, then send a request on the protocol you choose.

```rust,ignore
let client = reqwest::Client::new();
let response = client.get("https://example.com/").send().await?;
```

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn get() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    let client = Client::builder(profile).build()?;
    let response = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    println!("{}", response.status());
    Ok(())
}
```

- `get` uses the [exact protocol](../reference/glossary.md#exact-protocol)
  and fails if the server or route cannot carry it. `get_negotiated(uri)`
  lets the TLS handshake choose HTTP/1.1 or HTTP/2
  ([Choose a protocol](client.md#choose-a-protocol-for-a-request)).

## Set request fields in order

Send Chrome's navigation fields in Chrome's order, then one field of your own.

```rust,ignore
let request = client.get("https://example.com/").header("accept-language", "en-US");
```

```rust
use phantom::profile::chromium;
use phantom::{Client, HttpProtocol, PreparedRequestTemplate, RequestBuilder, RequestHeader};

fn fields(client: &Client) -> Result<RequestBuilder, Box<dyn std::error::Error>> {
    // Prepare the template once; reuse it across requests.
    let navigation = PreparedRequestTemplate::new(chromium::v154_windows_navigation_template())?;
    Ok(client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(&navigation)
        .header(RequestHeader::new("x-trace", "1")))
}
```

- reqwest stores fields in a `HeaderMap`, keyed by lowercase name.
  `RequestHeader` keeps position, spelling, and duplicates, because
  [header order](../fingerprinting.md#header-order) is part of the
  fingerprint. Without a template, fields go out in the order you add them.
- Phantom adds no `User-Agent`, `Accept`, or `Sec-Fetch-*` field. A template
  supplies them; use one from the profile's browser
  ([Apply a captured request template](request-templates.md#apply-a-captured-request-template)).

## POST a body

Send a JSON body that you serialized yourself.

```rust,ignore
let request = client.post("https://example.com/api").json(&value); // `json` feature
```

```rust
use phantom::{Client, HttpProtocol, Method, RequestBuilder, RequestHeader};

fn post(client: &Client, json: String) -> Result<RequestBuilder, phantom::RequestError> {
    Ok(client
        .request(HttpProtocol::Http2, Method::POST, "https://example.com/api")?
        .header(RequestHeader::new("content-type", "application/json"))
        .body(json))
}
```

- Phantom has no `json`, `form`, `query`, or `multipart` helpers and sets no
  `Content-Type`. It appends `Content-Length` when you supply none.

## Follow redirects, set timeouts, use a proxy, and keep cookies

Follow at most five redirects, bound each request, send it through an HTTP
proxy with Basic credentials, and keep cookies between requests.

```rust,ignore
let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::limited(5))
    .connect_timeout(Duration::from_secs(10))
    .read_timeout(Duration::from_secs(30))
    .timeout(Duration::from_secs(60))
    .proxy(reqwest::Proxy::all("http://proxy.example:8080")?.basic_auth("user", "password"))
    .cookie_store(true) // `cookies` feature
    .build()?;
```

```rust
use std::{num::NonZeroUsize, time::Duration};

use phantom::profile::ClientProfile;
use phantom::{Client, HttpProxy, RedirectPolicy, RequestTimeouts, Route};

fn build(profile: ClientProfile) -> Result<Client, Box<dyn std::error::Error>> {
    let five = NonZeroUsize::new(5).expect("five is nonzero");
    let timeouts = RequestTimeouts::new()
        .connect(Duration::from_secs(10))
        .read_idle(Duration::from_secs(30))
        .total(Duration::from_secs(60));
    let proxy = HttpProxy::new("http://proxy.example:8080")?.with_basic_auth("user", "password")?;
    Ok(Client::builder(profile)
        .redirect_policy(RedirectPolicy::limited(five))
        .request_timeouts(timeouts)
        .route(Route::http_proxy(proxy))
        .cookies() // `cookies` feature
        .build()?)
}
```

- Without a redirect policy, Phantom returns every redirect response to you.
  With one, it follows `http://` and `https://` targets but never changes the
  request's protocol or route to reach one
  ([Follow redirects](redirects.md#follow-redirects)).
- `RequestBuilder::timeouts` replaces the timeouts for one request. The
  `pool_admission` and `response_head` phases are in
  [Configure the client](client.md#configure-the-client).
- The [route](../reference/glossary.md#route) you set is the only route: a
  proxy failure is an error, never a direct connection. An HTTP proxy route
  carries `get_negotiated` but never upgrades it to H3 through Alt-Svc
  ([SOCKS5 and CONNECT-UDP proxies](socks-and-connect-udp.md)).
- For a browser's cookie position, build the profile with
  `with_cookie_placement(chromium::v154_cookie_placement())`
  ([Place the cookie field](cookies.md#place-the-cookie-field-where-a-browser-does)).

## Read the body

Read the body into memory with a size limit, then decode it yourself.

```rust,ignore
let text = response.text().await?;
```

```rust
use phantom::{Client, HttpProtocol};

async fn text(client: &Client) -> Result<String, Box<dyn std::error::Error>> {
    let response = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    Ok(String::from_utf8(body.to_vec())?)
}
```

- A body over the limit fails with `RequestErrorKind::ResponseBodyLimit`.
  Phantom does no charset or JSON decoding; pass the bytes to your
  deserializer, such as `serde_json::from_slice`.
- A 4xx or 5xx status is not an error; there is no `error_for_status`.

## Behaviors that differ

- Phantom never switches protocol or route after a failure
  ([No silent fallback](../explanation/design.md#no-silent-fallback)).
- Redirects, timeouts, retries, cookies, Alt-Svc, and content decoding are
  off until you enable them ([Off by default](../reference/limits.md#off-by-default)).
- The body arrives as the server sent it, compressed or not
  ([Content decoding](content-decoding.md)).
- Phantom adds no browser fields and keeps the order of yours
  ([Order is part of the fingerprint](../explanation/design.md#order-is-part-of-the-fingerprint)).
- Proxy credentials go out after the proxy's first `407`, then on every later
  request ([Proxy authentication](../explanation/design.md#proxy-authentication)).

## Next

- [Using the client](client.md): every request and response option.
- [Browser profiles](profiles.md): choose the browser the client matches.
- [Why Phantom](../why-phantom.md): when reqwest is the better fit.
