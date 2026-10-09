# Browser profiles

Pick the browser your client copies, or change a built-in one to make your
own.

> Read [Using the client](client.md) first.

A [profile](../reference/glossary.md#profile) is everything about your
connections that a server can see: the TLS
handshake, the HTTP/2 and HTTP/3 settings, TCP options and
[client hints](../fingerprinting.md#client-hints). You build it from
[recipes](../reference/glossary.md#recipe), which are one browser's
settings for one layer. Headers such as `User-Agent` come from a
[request template](request-templates.md) instead.

## Choose a built-in profile

Combine one browser's recipes into a profile.

```rust
use phantom::profile::{
    ClientProfile, Http3ClientSettings,
    browser::{brave, chrome, edge, firefox, opera},
};

fn profiles() -> [ClientProfile; 5] {
    // Firefox 157: its TLS, TCP, HTTP/1.1 and HTTP/2 settings, and where
    // it puts the cookie header.
    let firefox = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_cookie_placement(firefox::v157_cookie_placement());

    // Edge 154: its own TLS and client hints, plus Chromium's other
    // settings.
    let edge = ClientProfile::new(edge::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_http1(chrome::v154_http1())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(edge::v154_windows_client_hints());

    // Brave 154 and Opera 136 follow the same pattern, with their own TLS
    // and client hints.
    let brave = ClientProfile::new(brave::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_http1(chrome::v154_http1())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            brave::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(brave::v154_windows_client_hints())
        .with_cookie_placement(chrome::v154_cookie_placement());
    let opera = ClientProfile::new(opera::v136_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_http1(chrome::v154_http1())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            opera::v136_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(opera::v136_windows_client_hints())
        .with_cookie_placement(chrome::v154_cookie_placement());

    // Chrome 154 for Android, with Android client hints.
    let android = ClientProfile::new(chrome::v154_android_tcp_tls())
        .with_http2(chrome::v154_android_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_android_quic_tls(),
            chrome::v154_android_quic(),
            chrome::v154_android_http3(),
            chrome::v154_android_http3_request(),
        ))
        // A Pixel 7. `v154_android_client_hints_for_model` sends another model.
        .with_client_hints(chrome::v154_android_client_hints());

    [firefox, edge, brave, opera, android]
}
```

Each brand has one module under `phantom::profile::browser`, such as
`chrome`. Android recipe names include `_android_`. Not every version has
every recipe.
The [recipe table](../reference/profiles.md#built-in-recipes) lists them.

A request fails if the profile lacks a part it needs. An HTTP/3 request,
for example, needs `with_http3`.

`with_http1` sets how many HTTP/1.1 connections the client opens to one
server at once. The Chromium and Firefox recipes allow 6. Without
`with_http1`, the client opens one
([HTTP/1.1 connections](../reference/profiles.md#http11-connections)).

`windows` or `android` in a recipe name says which platform the recipe
copies. Phantom sends it the same way on any host
([Recipe names and platforms](../reference/profiles.md#recipe-names-and-platforms)).

## Build a custom profile

Start from a recipe, change its public fields, and build the profile from
the result.

```rust
use phantom::profile::{ClientProfile, CookiePlacement, TcpKeepalivePolicy, browser::chrome};

fn chrome_on_macos() -> ClientProfile {
    // Chromium on macOS sets only the keepalive idle time.
    let mut tcp = chrome::v154_tcp();
    if let TcpKeepalivePolicy::Fixed(keepalive) = &mut tcp.keepalive {
        keepalive.interval = None;
    }

    ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(tcp)
        .with_http2(chrome::v154_http2())
        .with_cookie_placement(CookiePlacement::before_fields(["priority"]))
}
```

Built-in and custom profiles use the same types. A setting that conflicts
with another fails instead of being ignored.

A setting the host can't apply makes `ClientBuilder::build` fail. Windows,
for example, needs a keepalive interval, so the profile above fails to
build there.

## Limits

- The first TCP packet (window size, TTL and similar) comes from the host
  OS. Run on the platform the profile copies if that matters to you.
- Some TCP and UDP behavior differs by OS version, such as random local
  ports on Windows. [TCP socket options](../reference/profiles.md#tcp-socket-options)
  has the details.

## Next

- [Request templates and client hints](request-templates.md): send a
  browser's headers in its order.
- [Profile reference](../reference/profiles.md): every recipe and setting.
- [Coverage](../reference/coverage.md#browser-profiles): the browser builds
  behind each recipe.
