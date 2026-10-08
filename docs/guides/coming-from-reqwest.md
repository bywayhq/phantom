# Coming from reqwest

If you know reqwest, most of Phantom will feel familiar. This page puts the
reqwest code you already have next to the Phantom code that does the same
thing.

> Read [Getting started](../getting-started.md) first. The reqwest examples
> use reqwest 0.13.

## What stays the same

- You build a `Client` once and clone it freely. Clones share connections.
- You build a request, then call `.send().await`.
- The response is an `http::Response`, so `status()` and `headers()` work
  as usual.
- A 4xx or 5xx status is a normal response, not an error.
- The cookie jar sits behind a `cookies` feature.

## What's different

reqwest makes a few choices for you. A server can see each of those
choices, so Phantom asks you to make them
([How servers recognize a client](../fingerprinting.md#the-short-version)).

- You give the client a [profile](../reference/glossary.md#profile): the
  browser it copies on the wire.
- You pick the protocol for each request.
- Redirects, timeouts, cookies, decompression and most retries are off until
  you turn them on ([Off by default](../reference/limits.md#off-by-default)).
- Phantom adds no headers such as `User-Agent`, and sends yours in the
  order you add them.
- There are no `json`, `form` or `query` helpers.
- Phantom reads no proxy settings from the environment.

| reqwest | Phantom |
| --- | --- |
| `Client::new()` | `Client::builder(profile)` |
| ALPN picks the protocol | `HttpProtocol` per request, or `get_negotiated` |
| `default_headers`, `user_agent` | A [request template](request-templates.md), or `RequestHeader`s per request |
| `json`, `form`, `query` | Your own serializer, then `body` |
| Follows 10 redirects | `RedirectPolicy::limited(n)` |
| `timeout`, `connect_timeout`, `read_timeout` | `RequestTimeouts` |
| `Proxy::all` | `Route` with `HttpProxy`, `Socks5Proxy` or `ConnectUdpProxy` |
| `cookie_store(true)` | `ClientBuilder::cookies()` |
| `resolve`, `dns_resolver` | `ClientBuilder::resolve`, `dns_resolver` ([Resolve host names](name-resolution.md)) |
| `gzip(true)` | `ContentDecoding::advertised(max)` per request |
| `text`, `bytes`, `json` | `ResponseBody::collect_with_limit(max)` |
| `is_timeout`, `is_connect` | [`RequestError::kind()`](responses.md#handle-errors) |

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

`get` uses the protocol you name. If the server can't speak it, the request
fails. `get_negotiated` lets the server pick HTTP/1.1 or HTTP/2, as reqwest
does ([Choose a protocol](client.md#choose-a-protocol-for-a-request)).

## Set headers in order

Send Chrome's page-load headers in Chrome's order, then one header of your
own.

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

reqwest keeps headers in a `HeaderMap`, which lowercases names and groups
duplicates. Phantom keeps order, spelling and duplicates, because servers
look at [header order](../fingerprinting.md#header-order). Without a template,
headers go out in the order you add them.

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

Phantom sets no `Content-Type`, so add your own. It adds `Content-Length`
when you don't.

## Follow redirects, set timeouts, use a proxy, and keep cookies

Follow five redirects, set timeouts, use a proxy with a password, and keep
cookies.

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

The route you set is the only one Phantom uses. If the proxy fails, the
request fails. It doesn't fall back to a direct connection
([Routes and proxies](routes-and-proxies.md)).

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

Phantom doesn't decode text or JSON. Pass the bytes to your deserializer,
such as `serde_json::from_slice`.

## Next

- [Using the client](client.md): the rest of the request options.
- [Browser profiles](profiles.md): pick the browser to copy.
- [Why Phantom](../why-phantom.md): when reqwest is the better fit.
