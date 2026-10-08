# phantom-quic-btls

Connect Phantom's QUIC transport to BoringSSL for TLS 1.3 handshakes and
packet protection. You can configure it with Phantom's typed TLS profiles.

This internal crate supplies Quinn's cryptography provider for Phantom. Its
`server` feature adds a provider for loopback tests and capture tools.

## Next

- [Phantom README](../../README.md): use HTTP/3 through the client.
- [HTTP/3 internals](../../docs/internals/http3.md): work on the QUIC
  transport.
