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
    brave, chrome_android, chromium, edge, firefox, opera, ClientProfile, Http3ClientSettings,
};

fn profiles() -> [ClientProfile; 5] {
    // Firefox 156: TLS, HTTP/2, and cookie-field recipes, plus its
    // source-derived TCP options and HTTP/1.1 connection count.
    let firefox = ClientProfile::new(firefox::v156_tls())
        .with_tcp(firefox::v156_tcp())
        .with_http1(firefox::v156_http1())
        .with_http2(firefox::v156_http2())
        .with_cookie_placement(firefox::v156_cookie_placement());

    // Edge 154: its own TLS and client hints; Chromium TCP, HTTP/1.1,
    // address cache, H2, QUIC, and H3 recipes.
    let edge = ClientProfile::new(edge::v154_tls())
        .with_tcp(chromium::v154_tcp())
        .with_http1(chromium::v154_http1())
        .with_dns_cache(chromium::v154_dns_cache())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(edge::v154_windows_client_hints());

    // Brave 154 and Opera 136 follow the same pattern with their own TLS,
    // H3 TLS, and client hints, and both place cookies as Chromium does.
    let brave = ClientProfile::new(brave::v154_tls())
        .with_tcp(chromium::v154_tcp())
        .with_http1(chromium::v154_http1())
        .with_dns_cache(chromium::v154_dns_cache())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            brave::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(brave::v154_windows_client_hints())
        .with_cookie_placement(chromium::v154_cookie_placement());
    let opera = ClientProfile::new(opera::v136_tls())
        .with_tcp(chromium::v154_tcp())
        .with_http1(chromium::v154_http1())
        .with_dns_cache(chromium::v154_dns_cache())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            opera::v136_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
        .with_client_hints(opera::v136_windows_client_hints())
        .with_cookie_placement(chromium::v154_cookie_placement());

    // Chrome 154 for Android: the Chromium TLS recipes without ECH from
    // HTTPS records, Android client hints, and the Chromium H2, QUIC, and H3.
    let android = ClientProfile::new(chrome_android::v154_tls())
        .with_http2(chrome_android::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome_android::v154_http3_tls(),
            chrome_android::v154_quic(),
            chrome_android::v154_http3(),
            chrome_android::v154_http3_request(),
        ))
        // The captured Pixel 7; `v154_android_client_hints_for_model` sends another model.
        .with_client_hints(chrome_android::v154_android_client_hints());

    [firefox, edge, brave, opera, android]
}
```

- Phantom carries one version per browser, in a desktop module such as
  `chromium` and an Android module such as `chrome_android`. The
  [recipe table](../reference/profiles.md#built-in-recipes) names each
  module's browser version and lists which components it has; not every
  module has every component.
- A request fails before any network I/O if the profile lacks a component it
  needs, such as HTTP/3 settings for an H3 request.
- `with_http1` sets how many H1 connections the client keeps to each origin
  and route. `chromium::v154_http1` and `firefox::v156_http1` allow 6, from
  browser source, and the Chromium one also serves Brave; without
  `with_http1` the client keeps one
  ([HTTP/1.1 connections](../reference/profiles.md#http11-connections)).
- A `windows` or `android` in a recipe name records where it was captured. The runtime
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
- Firefox's keepalive schedule and address selection are not modeled
  ([TCP socket options](../reference/profiles.md#tcp-socket-options)).
  Brave, Edge, and Opera use `chromium::v154_tcp`, which leaves out the
  Windows port randomization all three browsers turn on.

## Next

- [Request templates and client hints](request-templates.md): send a
  browser's request fields in its order.
- [Profile reference](../reference/profiles.md): recipe, template, and
  client-hint tables.
- [Coverage](../reference/coverage.md#browser-profiles): the exact builds
  behind each recipe.
