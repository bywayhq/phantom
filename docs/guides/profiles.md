# Browser profiles

Choose a built-in browser profile, change one, apply a captured request
template, and send client hints.

> For builders who have read [Using the client](client.md).

A [profile](../reference/glossary.md#profile) decides what a server can
observe about your client's connections: the TLS ClientHello, HTTP/2 SETTINGS
and pseudo-header order, QUIC transport parameters, HTTP/3 settings, TCP
socket options, HTTP/1.1 connection counts, and
[client hints](../fingerprinting.md#client-hints). You build one from
[recipes](../reference/glossary.md#recipe), most of them taken from browser
[captures](../reference/glossary.md#capture). The fields of each
request, such as `User-Agent`, come from a request template instead.

## Choose a built-in profile

Combine one browser's recipes into a profile.

```rust
use phantom::profile::{chromium, edge, firefox, ClientProfile, Http3ClientSettings};

fn profiles() -> [ClientProfile; 2] {
    // Firefox 156: TLS, HTTP/2, and cookie-field recipes, plus its
    // source-derived TCP options and HTTP/1.1 connection count.
    let firefox = ClientProfile::new(firefox::v156_tls())
        .with_tcp(firefox::v156_tcp())
        .with_http1(firefox::v156_http1())
        .with_http2(firefox::v156_http2())
        .with_cookie_placement(firefox::v156_cookie_placement());

    // Edge 153: its own TLS and client hints; its H2, QUIC, and H3 match the
    // Chromium recipes. It borrows Chromium's HTTP/1.1 connection bound.
    let edge = ClientProfile::new(edge::v153_tls())
        .with_http1(chromium::v154_http1())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v153_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(edge::v153_windows_client_hints());

    [firefox, edge]
}
```

- Phantom carries one version per browser: Chrome 154 (`chromium::v154_*`),
  Edge 153 (`edge::v153_*`), and Firefox 156 (`firefox::v156_*`). The
  [recipe table](../reference/profiles.md#built-in-recipes) lists which
  components each one has; Firefox has no QUIC, HTTP/3, or client-hint
  recipe.
- A request fails before any network I/O if the profile lacks a component it
  needs, such as HTTP/3 settings for an H3 request.
- `with_http1` sets how many H1 connections the client keeps to each origin
  and route. `chromium::v154_http1` and `firefox::v156_http1` allow 6, from
  browser source; without `with_http1` the client keeps one
  ([HTTP/1.1 connections](../reference/profiles.md#http11-connections)).
- A `windows` in a recipe name records where it was captured. The runtime
  never branches on the host OS or the browser name
  ([Recipe names and platforms](../reference/profiles.md#recipe-names-and-platforms)).

## Build a custom profile

Start from a recipe, change its public fields, and build the profile from
the result.

```rust
use phantom::profile::{chromium, ClientProfile, CookiePlacement};

fn chrome_on_macos() -> ClientProfile {
    // Chromium on macOS sets only the keepalive idle time.
    let mut tcp = chromium::v154_tcp();
    if let Some(keepalive) = tcp.keepalive.as_mut() {
        keepalive.interval = None;
    }

    ClientProfile::new(chromium::v154_tls())
        .with_tcp(tcp)
        .with_http2(chromium::v154_http2())
        .with_cookie_placement(CookiePlacement::before_fields(["priority"]))
}
```

- Built-in and custom profiles use the same types. Phantom validates each
  setting, and a conflict fails before any I/O instead of being ignored.
- Settings the host cannot apply fail `ClientBuilder::build` with
  `BuildErrorKind::InvalidProfile`. Windows, for example, requires a
  keepalive interval, so the profile above fails to build there.
- A custom profile is not evidence of browser behavior. Only retained
  captures back a named recipe.

## Apply a captured request template

Send the fields a browser sends for one kind of request, in its order, with
`RequestBuilder::template`.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol, RequestHeader};

async fn navigate_then_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    let page = client
        .get(HttpProtocol::Http2, "https://example.com/")?
        .template(chromium::v154_windows_navigation_template())
        .send()
        .await?;
    page.into_body().collect_with_limit(1 << 20).await?;

    // `Referer` is a caller slot: its value is the page URL.
    let data = client
        .get(HttpProtocol::Http2, "https://example.com/data.json")?
        .template(chromium::v154_windows_fetch_no_store_template())
        .header(RequestHeader::new("referer", "https://example.com/"))
        .send()
        .await?;
    println!("{}", data.status());
    Ok(())
}
```

- Each browser has two templates: an address-bar navigation and a
  same-origin `fetch(url, {cache: "no-store"})` GET
  ([template table](../reference/profiles.md#request-templates)).
- A field you add whose name matches a template entry takes that entry's
  position and keeps your value. Other fields follow the template's last
  field. A caller slot, such as `Referer` or Edge's `User-Agent`, sends
  nothing until you fill it
  ([assembly rules](../reference/profiles.md#template-assembly)).
- The Edge templates require your `User-Agent`; a request without one fails
  with `RequestErrorKind::RequestTemplate` before any I/O. Phantom does not
  compare your `User-Agent` or `sec-ch-ua` with the template, so use the
  template, client hints, and `User-Agent` of one browser and version
  ([required caller fields](../reference/profiles.md#required-caller-fields)).

## Send client hints

Send the client hints a browser sends by default, and the ones a server asks
for.

```rust
use phantom::profile::{chromium, ClientProfile};
use phantom::{Client, HttpProtocol};

async fn with_hints() -> Result<(), Box<dyn std::error::Error>> {
    let profile = ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_client_hints(chromium::v154_windows_client_hints());
    let client = Client::builder(profile).build()?;

    // Sends the default hints. An `Accept-CH` response adds to what the
    // next request to this origin sends.
    let first = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
    drop(first);

    // Forget every origin's requested hints.
    client.clear_client_hints();
    Ok(())
}
```

- `ClientHintSettings` fixes the hint names, their order, their values, and
  whether each is sent by default or only on request.
- An HTTPS response's `Accept-CH` sets the hints requested for its exact
  origin. On H2 and H3, a server can also request hints during the TLS
  handshake with ALPS `ACCEPT_CH`, for that connection only.
- If a `Critical-CH` response names a missing supported hint and the method
  is safe, Phantom retries once, on the same protocol and route. A streaming
  body cannot be retried and fails with `RequestErrorKind::RequestBody`.
- Clones of a client share learned hints; separately built clients do not.
  Rules for each case are in the
  [client-hint reference](../reference/profiles.md#client-hints).

## Limits

- A profile shapes network behavior only
  ([Coverage](../reference/coverage.md#at-a-glance)).
- The TCP SYN (window, MSS, options, TTL) comes from the host OS. Run on the
  platform the profile presents if that layer matters.
- There is no Edge TCP recipe, and Firefox's keepalive schedule and address
  selection are not modeled
  ([TCP socket options](../reference/profiles.md#tcp-socket-options)).
- There is no Edge HTTP/1.1 connection recipe: no source or capture shows
  Edge 153's value. Negotiated requests keep one connection per origin
  whatever the profile says
  ([HTTP/1.1 connections](../reference/profiles.md#http11-connections)).
- Templates cover only address-bar navigations and same-origin no-store
  `fetch` GETs. Firefox templates have no HTTP/3 list and no hint slots
  ([template limits](../reference/profiles.md#template-limits)).
- A `fetch` or Firefox template refuses to send hints an origin requested,
  because no capture shows where they go
  ([Client hints in templates](../reference/profiles.md#client-hints-in-templates)).
- The client-hint model covers top-level requests from a standalone client
  ([model limits](../reference/profiles.md#client-hint-model-limits)).

## Next

- [Profile reference](../reference/profiles.md): recipe, template, and
  client-hint tables.
- [Coverage](../reference/coverage.md#browser-profiles): the exact builds
  behind each recipe.
- [Connections, redirects, and cookies](connections-and-state.md): where the
  cookie field goes.
