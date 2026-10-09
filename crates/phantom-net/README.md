# phantom-net

Build Phantom connections over HTTP/1.1, HTTP/2, or HTTP/3. You can use its
protocol transports with TLS profiles, HTTP proxies, SOCKS5, and CONNECT-UDP.

This internal crate supplies the transports used by `phantom-http`. Use the
client crate for origin connection pools, redirects, cookies, and retries.

## API boundary

The public API uses `bytes` buffers, `http` request and response types,
`http-body` streams, and Tokio I/O traits. `phantom-profile` supplies wire
settings, and `phantom-quic-btls` supplies QUIC configuration and optional
key-log handles.

HTTP engine errors are private implementation details. Operations return
Phantom's typed errors. `std::error::Error::source` retains their underlying
causes for diagnostics. `Http1ProtocolError` is an opaque payload; you do
not need to depend on the HTTP engine to inspect a failure.

## Next

- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  use the client API.
- [Design](https://github.com/bywayhq/phantom/blob/main/docs/explanation/design.md):
  see how the crates fit together.
