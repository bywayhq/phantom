# phantom-profile

Choose browser recipes and typed connection settings for Phantom. You can
change TLS, HTTP, QUIC, socket, WebSocket, and proxy CONNECT settings in one
profile.

Recipes are grouped under `browser::{chrome, edge, brave, opera, firefox}`.
Use an explicit Windows or Android factory, such as `chrome::v154_windows()`.
Factories compose the available connection layers and leave request headers
without a template. You can set one with `ClientProfile::with_request_template`.

Component functions keep custom layering available. `*_tcp_tls` supplies TLS
for HTTP/1.1 and HTTP/2. `*_quic_tls` supplies TLS for QUIC and HTTP/3.
Android factories include only the layers with recipes. Opera has TLS and
client hints. Firefox has TLS only. There are no composed macOS factories.

Brave's version labels use the Chromium major. `v154_windows` describes
Brave 1.96.59, and `v153_android` describes Brave 1.95.104.

This crate defines the settings. `phantom-net` applies them to connections,
and `phantom-http` provides the client API.

## Next

- [Profiles guide](https://github.com/bywayhq/phantom/blob/main/docs/guides/profiles.md):
  choose and change a profile.
- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  send requests with the client.
