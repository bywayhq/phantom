# phantom-net

Build Phantom connections over HTTP/1.1, HTTP/2, or HTTP/3. You can use its
protocol transports with TLS profiles, HTTP proxies, SOCKS4/5, and CONNECT-UDP.

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

## Ticket transactions

`SessionTicketCacheOwner::capture_stores` captures TCP TLS and QUIC stores
without consuming their tickets. Authenticate the complete manifest and each
source witness when sealing a snapshot. Treat records and keys as secrets.

Prepare native-authorized replacements before calling `replace_stores`.
It validates every destination before swapping any store. Prepare accompanying
client registry changes first, then apply them after replacement succeeds.
Release registry locks before finishing the returned retirement handle.

For application code, use `Client::export_session_tickets` and
`Client::import_session_tickets`. They support TCP TLS and QUIC with matching
profile, trust, peer, and route settings. Custom TCP connectors cannot transfer
tickets because callbacks have no persistent route identity.

## Next

- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  use the client API.
