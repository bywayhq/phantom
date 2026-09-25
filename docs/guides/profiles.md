# Browser profiles

Choose a built-in browser profile, or change one to build your own.

> For builders who have read [Using the client](client.md).

A [profile](../reference/glossary.md#profile) decides what a server can
observe about your client's connections: the TLS ClientHello, HTTP/2 SETTINGS
and pseudo-header order, QUIC transport parameters, HTTP/3 settings, TCP
socket options, HTTP/1.1 connection counts, and
[client hints](../fingerprinting.md#client-hints). You build one from
[recipes](../reference/glossary.md#recipe), most of them taken from browser
[captures](../reference/glossary.md#capture). The fields of each
request, such as `User-Agent`, come from a
[request template](request-templates.md) instead.

## Choose a built-in profile

Combine one browser's recipes into a profile.

```rust
use phantom::profile::{
    brave, chromium, edge, firefox, opera, ClientProfile, Http3ClientSettings,
};

fn profiles() -> [ClientProfile; 4] {
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

    // Brave 154 and Opera 135 follow the same pattern with their own TLS,
    // H3 TLS, and client hints.
    let brave = ClientProfile::new(brave::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            brave::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(brave::v154_windows_client_hints());
    let opera = ClientProfile::new(opera::v135_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            opera::v135_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(opera::v135_windows_client_hints());

    [firefox, edge, brave, opera]
}
```

- Phantom carries one version per browser: Chrome 154 (`chromium::v154_*`),
  Edge 153 (`edge::v153_*`), Brave 154 (`brave::v154_*`), Opera 135
  (`opera::v135_*`), and Firefox 156 (`firefox::v156_*`). The
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

## Limits

- A profile shapes network behavior only
  ([Coverage](../reference/coverage.md#at-a-glance)).
- The TCP SYN (window, MSS, options, TTL) comes from the host OS. Run on the
  platform the profile presents if that layer matters.
- There is no Edge, Brave, or Opera TCP recipe, and Firefox's keepalive
  schedule and address selection are not modeled
  ([TCP socket options](../reference/profiles.md#tcp-socket-options)).
- There is no Edge, Brave, or Opera HTTP/1.1 connection recipe: no source
  or capture shows their values
  ([HTTP/1.1 connections](../reference/profiles.md#http11-connections)).

## Next

- [Request templates and client hints](request-templates.md): send a
  browser's request fields in its order.
- [Profile reference](../reference/profiles.md): recipe, template, and
  client-hint tables.
- [Coverage](../reference/coverage.md#browser-profiles): the exact builds
  behind each recipe.
