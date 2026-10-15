# Import complete custom profiles

You can load your own connection settings and request fields from JSON.
Enable the `fingerprint-import` feature, which is also included in `full`.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let bytes = std::fs::read("profile.json")?;
let profile = phantom::fingerprint::import_profile_json(&bytes)?;
let client = phantom::Client::builder(profile).build()?;
# let _ = client;
# Ok(())
# }
```

Import only parses and validates settings. Building a client checks backend
and host support. Imported settings have no catalog identity or browser
validation claim.

## Document

The envelope has exactly `format`, `version`, and `profile`. This complete
example configures TLS 1.2 and leaves every optional layer absent:

```json
{
  "format": "phantom.custom-profile",
  "version": 1,
  "profile": {
    "tls": {
      "versions": { "min": "Tls12", "max": "Tls12" },
      "cipher_suites": ["EcdheRsaAes128GcmSha256"],
      "groups": ["X25519"],
      "key_shares": [],
      "signature_schemes": ["RsaPssRsaeSha256"],
      "delegated_credential_schemes": [],
      "alpn_protocols": [[104, 116, 116, 112, 47, 49, 46, 49]],
      "alps": null,
      "certificate_compression": [],
      "session_tickets": { "enabled": false, "tcp_per_origin": null },
      "session_ticket_order": "NewestFirst",
      "session_ticket_extension_when_resuming": false,
      "tcp_early_data": false,
      "record_size_limit": null,
      "tls12_extensions_in_tls13_client_hello": false,
      "requested_trust_anchor_ids": null,
      "grease": false,
      "grease_signature_algorithms": false,
      "extension_order": { "kind": "BackendDefault", "extensions": [] },
      "ech": { "kind": "Disabled", "settings": null },
      "request_ocsp_staple": false,
      "request_signed_certificate_timestamps": false,
      "aes_hardware": true,
      "close_notify": true
    },
    "tcp": null,
    "udp": null,
    "dns_cache": null,
    "http1": null,
    "http2": null,
    "http3": null,
    "client_hints": null,
    "websocket": null,
    "proxy_connect": null,
    "cookie_placement": { "before": [] },
    "request_template": null
  }
}
```

All twelve profile fields are required. `tls` and `cookie_placement` cannot
be null. Every present settings record requires every field, including
nullable fields. Unknown or duplicate keys fail. There are no references,
inheritance, recipe defaults, or inferred settings.

## Values

| Value | JSON representation |
| --- | --- |
| Bytes | Ordered array of integers in `0..=255` |
| String | JSON string, checked by the owning settings validator |
| Enum without data | Exact Rust variant name as a string |
| Duration | `{"seconds": 7, "nanoseconds": 3}` |
| Optional value | Exact value or `null` |
| Ordered list | JSON array, including meaningful duplicate candidate slots |

Numbers must be unsigned whole integers. Floats, exponent notation and
negative numbers fail. Duration nanoseconds must be below one billion.
Host-sized limits use the caller's native `usize` range.

Field names follow the public profile types. The tables below specify
records whose Rust representation needs an explicit JSON tag.

## TLS policies

| Field | Record or value |
| --- | --- |
| `versions` | `min`, `max`; `Tls10`, `Tls11`, `Tls12`, or `Tls13` |
| `alps` | `protocol` bytes, `settings` bytes, `use_new_codepoint` boolean |
| `session_tickets` | `enabled` boolean, `tcp_per_origin` integer or null |
| `requested_trust_anchor_ids` | `kind`: `Fixed`, `PerClient`, or `PerConnection`; `orders`: array of ordered byte-string lists |
| `extension_order` | `kind`: `BackendDefault`, `Permuted`, `Fixed`, or `PermutedWithTail`; `extensions`: variant-name array |
| `ech` | `kind`: `Disabled`, `Grease`, or `HttpsRecords`; `settings`: null or GREASE record |
| GREASE record | `payload_length` record, `aeads` variant-name array |
| `payload_length` | `kind`: `BackendDefault`, `Exact`, or `FromClientHello`; `value`: null, length, or maximum name length respectively |

Disabled tickets require a null limit. Disabled ECH requires null settings.
Backend-default payload length requires null `value`. Backend-default and
permuted extension order require an empty `extensions` list. Fixed trust
anchors require exactly one order. Drawn anchors retain candidate order and
repeated slots. Import does not sample those policies.

## TCP, DNS and HTTP/1

| Record | Fields |
| --- | --- |
| `tcp` | `nodelay`, `send_buffer_size`, `keepalive`, `address_selection`, `port_randomization` |
| Fixed keepalive | `kind`: `Fixed`; `idle`, `interval` durations |
| Scheduled keepalive | `kind`: `Schedule`; `short_lived_idle`, `long_lived_idle`, `minimum_interval`, `short_lived_time` durations; `probe_count`; `set_interval`, `set_probe_count` booleans |
| Unchanged keepalive | `kind`: `Unchanged` |
| Sequential addresses | `kind`: `Sequential`; `advance`: `AfterAnyFailure` or `AfterRefusalOrTimeout` |
| Racing addresses | `kind`: `Racing`; `fallback_delay` duration |
| Backup addresses | `kind`: `Backup`; `delay` duration, nullable `known_family_backup_timeout` |
| TCP port randomization | Null or `minimum_windows_build` |
| `udp` | `port_randomization` boolean |
| `dns_cache` | `max_entries`, `ttl`, `min_record_ttl`, nullable `negative_ttl`, `system_ttl` (`Ignore` or `FirefoxWindows`) |
| `http1` | `max_connections_per_origin`, `idle_timeout` |
| HTTP/1 idle timeout | `kind`: `Unlimited`, or `CheckedOnRequest` / `ClosedOnTimer` with `duration` |

## HTTP/2 and HTTP/3

HTTP/2 includes every public `Http2Settings` field. `hpack`, `streams`, and
priority values contain all fields of their corresponding public types.
Each initial setting is `{"kind": "InitialWindowSize", "value": 65535}`.
Boolean settings use boolean values. HTTP/2 idle timeout always has `kind`
and `duration`; `Unlimited` requires null, `ClosedOnTimer` requires a duration.

HTTP/3 is null or one complete group: `tls`, `quic_transport`, `http3`, and
`request`. These contain every field of the corresponding native settings.
HTTP/3 initial settings use `kind` and `value`. `RandomizedGrease` requires
null. QUIC parameter order and width names retain their native spelling.

Each QUIC wire parameter has `kind`, `id_width`, and `length_width`. Its
`kind` is a record with its own `kind` discriminator:

| Parameter kind | Additional fields |
| --- | --- |
| Scalar transport parameter | `value_width` |
| `InitialSourceConnectionId` | `length` |
| `VersionInformation` | `available_version_count`, `grease` |
| `MinAckDelay` | `draft`, `value_width` |
| `GoogleConnectionOptions` | `options` |
| `Grease` | `minimum_payload_length`, `maximum_payload_length` |
| `ResetStreamAt`, `InitialRtt` | None |

Destination connection-ID length is null, `{"kind":"Fixed","length":8}`,
or `{"kind":"MaskedRandom","minimum":8,"base":5}`.

## Hints and ordered fields

`client_hints` contains `hints`, an ordered list of `name`, byte-array `value`,
and `delivery` (`Default` or `AcceptCh`). Values are already resolved bytes,
including any quoted model. Empty bytes and quoted empty bytes differ.
`cookie_placement` contains the ordered `before` string list.

Request-template fields use `variant`; WebSocket and CONNECT fields use
`kind`. Each tagged record carries the fields of its corresponding native
variant. Request-template proxy authorization uses `attempt`: `Every`,
`Preemptive`, or `Replay`. No credentials are stored in these placeholders.

WebSocket deflate parameters use `kind`. `ServerMaxWindowBits` requires
`bits`; `ClientMaxWindowBits` requires nullable `bits`. The two context
takeover flags have no other fields.

## Errors and limits

`FingerprintImportError::kind()` gives a recovery category. `field()` gives
a known field path. Display and Debug omit supplied values. Native policy
failures retain a typed source. Compact JA3/JA4 descriptions cannot restore
missing order or policy; an explicit compact format gets `LossyDescription`.
Bare hashes are not JSON documents.

| Resource | Maximum |
| --- | --- |
| Input bytes | 16 MiB |
| Nested value depth | 16 below the root |
| Decoded string bytes, including keys | 64 KiB |
| Fields in one object | 64 |
| Values in one array | 65,535 |
| Aggregate JSON values | 1,048,576 |

Native validators apply their own policy limits after parsing. Import
performs no network I/O, client construction or task spawning.

## Next

- [Profiles](profiles.md) : built-in recipes and custom settings.
- [Limits](limits.md) : transport support and validation boundaries.
