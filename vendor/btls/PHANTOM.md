# Phantom patch notes

This directory is the `btls` wrapper package from the exact upstream commit
recorded below plus the canonical wrapper patches recorded here. It deliberately
does not vendor the `btls-sys` package or BoringSSL submodule. Those resolve from
the reviewed dependency-fork commit, which retains the upstream wrapper base and
the exact BoringSSL submodule revision while applying the native ECH, record
size limit, and delegated-credential patches.

- Upstream commit: `129887582a538b8f4dcf371d15c953335312ca37`
- Upstream repository: <https://github.com/0x676e67/btls>
- Source archive: <https://codeload.github.com/0x676e67/btls/tar.gz/129887582a538b8f4dcf371d15c953335312ca37>
- Complete source archive SHA-256:
  `e77c9cafe8158b8c6e8f7979a461e122e06379285a9f0ab4d68797293dfd9767`
- Reviewed dependency fork: <https://github.com/0xARYA/btls>
- Reviewed dependency commit: `78b8c24a3388973d1d33c523995d311d766a1026`
- BoringSSL submodule commit: `f1f2556a5dfa59e147d9d47279cc3f7f8a18b433`
- Upstream package license remains in `LICENSE`.

## Why this patch exists

The upstream safe wrapper can enable ALPS only with an empty application
settings value, although its pinned BoringSSL C API accepts distinct protocol
and settings byte strings. It also does not expose the peer settings query.

The upstream ECH GREASE API enables the extension but leaves its payload length
to BoringSSL's randomized policy. Firefox 154 on macOS 15.5 was captured with a
239-byte GREASE payload, producing an `encrypted_client_hello` extension body of
281 bytes. The dependency fork adds an exact per-connection payload-length API;
omitting it preserves BoringSSL's randomized policy.

The upstream record-size-limit patch advertised RFC 8449 without enforcing it.
The dependency fork negotiates directional limits, applies them to the traffic-
key epoch that produced each protected record, fragments outgoing handshake and
application data, and rejects oversized incoming records. TLS 1.3 first-flight
handling defers the decision until EncryptedExtensions establishes whether the
extension was negotiated, preserving the legal non-echo path.

The upstream delegated-credential patch advertised extension 34 but did not
verify a credential received from a TLS 1.3 server. It also inherited a test-
runner field-order bug that could make two non-standard implementations agree.
The dependency fork implements RFC 9345 client verification after ordinary
certificate and hostname verification, checks certificate authorization and
lifetime, keeps the issuer and delegated signature-scheme namespaces separate,
uses the delegated key for CertificateVerify, and clamps session lifetime to
the credential expiry. A fixed-byte oracle independently proves the RFC signing
order.

The patches are additive:

- `SslRef::add_application_settings_with_payload` passes both byte strings to
  `SSL_add_application_settings`.
- `SslRef::peer_application_settings` combines
  `SSL_has_application_settings` and `SSL_get0_peer_application_settings` into
  `Option<&[u8]>`, preserving the difference between no negotiation and a
  negotiated empty value.
- `src/ssl/test/alps.rs` proves absent, negotiated-empty, and nonempty
  bidirectional values over TLS 1.3 with ALPN `h2`.
- `SslRef::set_ech_grease_payload_length` exposes the fork's checked native
  setter without enabling ECH GREASE implicitly. The API and its tests are
  excluded from FIPS builds because that build does not apply the native patch.
- `src/ssl/test/ech.rs` proves 239 payload bytes produce a 281-byte extension
  body, the unset path retains BoringSSL's allowed randomized sizes, and an
  empty or oversized payload is rejected with a populated error stack.
- `SslContextBuilder::set_record_size_limit` and
  `SslRef::set_record_size_limit` expose checked, fallible RFC 8449 controls.
- `src/ssl/test/patches.rs` proves range validation and bidirectional
  fragmentation for TLS 1.2 and TLS 1.3.
- `SslContextBuilder::set_delegated_credentials` preserves the ordered wire
  advertisement, including Firefox's legacy ECDSA-SHA1 entry, while received
  credentials remain subject to the stricter TLS 1.3 algorithm check. RSAE
  schemes are rejected.
- Native runner tests prove positive and adversarial RFC 9345 client
  verification; wrapper tests preserve exact extension bytes and invalid-
  algorithm rejection.

The canonical machine-applicable wrapper changes are
`patches/alps-settings.patch`, `patches/ech-grease-payload-length.patch`, and
`patches/record-size-limit.patch`, and `patches/delegated-credentials.patch`.
They contain only wrapper APIs, documentation, and upstream-style tests;
packaging changes remain separate. The dependency commit stores the native
BoringSSL changes in the numbered, non-FIPS `btls-sys` patch series: patch 0005
implements RFC 8449, patch 0006 implements RFC 9345 client verification, and
patch 0011 controls the ECH GREASE payload length.

The existing one-argument `add_application_settings` remains compatible and
delegates to the new method with an empty payload.

`Cargo.toml` materializes the upstream workspace-inherited package fields and
dependencies so this package can be used independently. `README.md` materializes
the exact repository-level file targeted by upstream's package symlink. The
standalone `btls-sys` dependency is pinned to the reviewed fork commit.
That commit must be published before Cargo can resolve this source on another
machine.

## Refreshing the vendor copy

1. Download the reviewed upstream commit into an isolated directory and verify
   its complete archive before extracting it:

   ```sh
   btls_revision=129887582a538b8f4dcf371d15c953335312ca37
   expected_checksum=e77c9cafe8158b8c6e8f7979a461e122e06379285a9f0ab4d68797293dfd9767
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-btls.XXXXXX")
   archive="$refresh_dir/btls-$btls_revision.tar.gz"

   curl --fail --location --output "$archive" \
     "https://codeload.github.com/0x676e67/btls/tar.gz/$btls_revision"
   actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   test "$actual_checksum" = "$expected_checksum"
   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/btls-$btls_revision/btls"
   ```

   On Linux, use `sha256sum` when `shasum` is unavailable.

2. Compare `candidate` with `vendor/btls`. Expected differences are
   the four files under `patches/`, the standalone manifest values, the
   materialized `README.md`, and this file. The checked-in wrapper sources and
   tests should exactly equal the candidate plus all four canonical patches.

   The scheduled candidate probe performs this staging from an exact detached
   git revision. It copies only the upstream `btls` wrapper, materializes the
   workspace-inherited manifest fields, replaces the wrapper README symlink
   with its repository target, and pins the standalone `btls-sys` dependency
   to the reviewed dependency-fork revision. These packaging adaptations are
   separate from the canonical wrapper patches; failure to apply any patch
   is reported as source drift requiring review.

3. Replace the wrapper package only, reapply those reviewed changes, and update
   the upstream revision and checksums here. Rebase the dependency-fork commit
   separately, regenerate the affected canonical wrapper and native patches
   without whitespace normalization, and update its pin in this file and the
   manifests. Do not copy the BoringSSL submodule into this directory.

4. Prove Cargo selected one wrapper and that `btls-sys` and `tokio-btls` resolve
   to the reviewed dependency-fork revision:

   ```sh
   cargo tree -i btls --locked
   cargo tree -i btls-sys --locked
   cargo tree -i tokio-btls --locked
   ```

## Required checks

```sh
cargo fmt --manifest-path vendor/btls/Cargo.toml --all --check
cargo clippy --manifest-path vendor/btls/Cargo.toml --all-targets --features prefix-symbols -- -D warnings
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols ssl::test::alps
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols ssl::test::ech
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols record_size_limit
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols delegated_credentials
cargo +1.85.0 check --manifest-path vendor/btls/Cargo.toml --all-targets --features prefix-symbols
```

Do not replace the feature selection with `--all-features`: upstream declares
`fips` and `rpk` mutually exclusive. `prefix-symbols` is the configuration used
by Phantom on Linux. Omit it on Apple platforms, matching Phantom's
target-specific dependency selection; upstream currently skips the archive
rewrite needed to link prefixed symbols there. The scheduled probe runs on
Linux and therefore uses `prefix-symbols`.

On macOS and Windows, use the corresponding omission variant:

```sh
cargo clippy --manifest-path vendor/btls/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::alps
cargo test --manifest-path vendor/btls/Cargo.toml ssl::test::ech
cargo test --manifest-path vendor/btls/Cargo.toml record_size_limit
cargo test --manifest-path vendor/btls/Cargo.toml delegated_credentials
cargo +1.85.0 check --manifest-path vendor/btls/Cargo.toml --all-targets
```
