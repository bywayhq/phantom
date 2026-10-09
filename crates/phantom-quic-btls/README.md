# phantom-quic-btls

Connect Phantom's QUIC transport to BoringSSL for TLS 1.3 handshakes and
packet protection. You can configure it with Phantom's typed TLS profiles.

This internal crate supplies Quinn's cryptography provider for Phantom. Its
`server` feature adds a provider for loopback tests and capture tools.

## API boundary

Use `QuicClientConfig` with your BoringSSL context and Phantom's TLS and QUIC
settings. Handshake metadata, certificates, ECH, session state, reset keys,
and typed errors remain public. The `keylog` feature adds bounded key-log
queues. Packet keys, key derivation, version helpers, and Retry helpers are
private; Quinn receives them through its crypto traits.

The public API intentionally uses `btls` context types, `quinn-proto` config
types and crypto traits, and `phantom-profile` settings. These are part of
the provider interface. BoringSSL FFI and its supporting libraries stay
private.

## Next

- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  use HTTP/3 through the client.
- [HTTP/3 internals](https://github.com/bywayhq/phantom/blob/main/docs/internals/http3.md):
  work on the QUIC transport.
