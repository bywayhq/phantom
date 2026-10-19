# phantom-profile

Choose browser recipes and typed connection settings for Phantom. You can
change TLS, HTTP, QUIC, socket, WebSocket, and proxy CONNECT settings in one
profile.

Recipes are grouped under `browser::{chrome, edge, brave, opera, firefox}`.
Use a platform factory, such as `chrome::v154_windows()` or
`chrome::v154_macos()`. Factories compose available connection layers and leave
request headers without a template. Set one with
`ClientProfile::with_request_template`.

Windows factories include TCP, TLS, HTTP/1.1, HTTP/2, HTTP/3, WebSocket, proxy
CONNECT, and cookie-placement settings. Client hints apply to Chromium browsers;
Firefox sends none. macOS and Android factories cover fewer layers. Each
constructor documents its included settings and generic defaults.

Component functions keep custom layering available. `*_tcp_tls` supplies TLS
for HTTP/1.1 and HTTP/2. `*_quic_tls` supplies TLS for QUIC and HTTP/3.
The `catalog` module lists exact browser builds, platforms, and layer coverage.

Brave's version labels use the Chromium major. `v154_windows` describes
Brave 1.96.59, and `v153_android` describes Brave 1.95.104.

This crate defines the settings. `phantom-net` applies them to connections,
and `phantom-http` provides the client API.

## Change settings

Public fields let you combine recipe components and change individual values.
After editing a settings value, call its `validate` method when it has one.
Validation checks the value's structure. A transport can still reject settings
that its backend or your operating system cannot apply.

Adding or removing required public fields is a breaking API change. Before
version 1.0, it requires a minor release. Policy enums marked `non_exhaustive`
require a catch-all match arm. Reject an unknown policy when applying settings.

Equality compares stored values, including list order. Equal settings do not
promise equal bytes across connections with random draws or different peers.
Settings and validation errors provide Clone, Debug, Eq, Send, and Sync where
those traits appear on the type. Network errors may retain runtime or backend
sources and are outside this contract. Defaults, builders, and Hash apply only
to types that provide them.

## Next

- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  send requests with the client.
