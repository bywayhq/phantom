# TLS 1.3 SHA-384 fixture provenance

The SHA-384 fixtures in `src/key_schedule/tests.rs` use the 48-byte traffic
secret `00..2f`. They implement RFC 8446 `HKDF-Expand-Label` with an empty
context. The following commands reproduced the checked-in values with OpenSSL
3.6.2; they require only OpenSSL 3's `kdf` command.

```sh
phantom_sha384_secret=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f

openssl kdf -keylen 32 -kdfopt digest:SHA384 -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:${phantom_sha384_secret}" -kdfopt hexinfo:00200e746c7331332071756963206b657900 HKDF
openssl kdf -keylen 12 -kdfopt digest:SHA384 -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:${phantom_sha384_secret}" -kdfopt hexinfo:000c0d746c733133207175696320697600 HKDF
openssl kdf -keylen 32 -kdfopt digest:SHA384 -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:${phantom_sha384_secret}" -kdfopt hexinfo:00200d746c733133207175696320687000 HKDF
openssl kdf -keylen 48 -kdfopt digest:SHA384 -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:${phantom_sha384_secret}" -kdfopt hexinfo:00300d746c7331332071756963206b7500 HKDF

phantom_sha384_first_update=d21f524277390ba96b86484d9c687f850f1e4d1f997033bba06051129179a762a94067d065f3f715e83d65a7bf8c79b9
openssl kdf -keylen 48 -kdfopt digest:SHA384 -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:${phantom_sha384_first_update}" -kdfopt hexinfo:00300d746c7331332071756963206b7500 HKDF
```

In order, the commands emit the `quic key`, `quic iv`, `quic hp`, first
`quic ku`, and second `quic ku` fixtures. OpenSSL formats output as uppercase
colon-separated bytes; the tests store the same bytes as lowercase hex.
