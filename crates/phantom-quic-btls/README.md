# phantom-quic-btls

Connect Phantom's QUIC transport to BoringSSL for TLS 1.3 handshakes and
packet protection. You can configure it with Phantom's typed TLS profiles.

This internal crate supplies Quinn's cryptography provider for Phantom. Its
`server` feature adds a provider for loopback tests and capture tools.
Early data is disabled by default. `QuicServerConfig::with_early_data`
enables it with an application context, combined with the remembered QUIC
transport settings. The application must handle replayable requests safely.

## API boundary

Use `QuicClientConfig` with your BoringSSL context and Phantom's TLS and QUIC
settings. Handshake metadata, certificates, ECH, session state, reset keys,
and typed errors remain public. The `keylog` feature adds bounded key-log
queues. Packet keys, key derivation, version helpers, and Retry helpers are
private; Quinn receives them through its crypto traits.

Ticket transfer uses the cache owner's prepared capture and replacement
types. Capture keeps source tickets available and seals records after the
store and native guards drop. Import requires native-authenticated permits
for the destination's installed policy. Validate every replacement while all
transaction guards are held, commit them, then release the guards before
finishing retired stores. Treat exported records and their keys as secrets.

The records retain the receiving connection's QUIC version, remembered server
parameters, application state and RTT. Parameter parsing does not validate
HTTP/3 application state. The consumer must check that state before import.
Applications can use `Client::export_session_tickets` and
`Client::import_session_tickets` for TCP TLS and QUIC. Import checks the complete
snapshot against the receiving client's profile, trust, peer, and route.

The public API intentionally uses `btls` context types, `quinn-proto` config
types and crypto traits, and `phantom-profile` settings. With `keylog`,
`NssKeyLogLine` also implements `zeroize::Zeroize`. BoringSSL FFI remains
private.

## Next

- [Phantom README](https://github.com/bywayhq/phantom/blob/main/README.md):
  use HTTP/3 through the client.
