# Phantom vendor notes: btls

**Audience:** maintainers auditing or refreshing Phantom's TLS dependency.
This file records provenance, the reason for each local deviation, the refresh
procedure, and required checks. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored wrapper.

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
- Reviewed dependency fork: <https://github.com/bywayhq/btls>
- Reviewed dependency commit: `f478ea16a4b2f6ebbd221ce7cafdec10a32028eb`
  (`feat(boringssl): size ECH GREASE payloads from the ClientHello`, which
  adds native patch 0017). It is four commits on the earlier reviewed commit
  `c4596bc5ee7facb860ef91c184ac50b5b863b733`, and they add native patches
  0014 to 0017 and their wrapper methods. That commit added native patch 0013
  on `126eca11538e79814ffef527a68080fe6dbbb21b`
  (`fix(btls-sys): leave the C allocator out of the bindings`), which keeps
  `malloc`, `calloc`, `realloc`, and `free` out of the generated bindings,
  whose `extern` declarations of them Rust 1.99.0 denies, and is itself
  one commit on the earlier reviewed commit `c48fddb13539e06fadedfac6039570598ff89864`.
- BoringSSL submodule commit: `f1f2556a5dfa59e147d9d47279cc3f7f8a18b433`
- Upstream package license remains in `LICENSE`.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`btls` becomes `phantom-btls` at `0.5.6-phantom.6`), keeps
the upstream library name so source, tests, and examples are unchanged, and
points the repository metadata at Phantom. It removes the upstream
documentation link, keeps Cargo's reserved archive files out of the packaged
crate, and records the upstream package, version, and source archive under
`[package.metadata.phantom]`. The `btls-sys` dependency still resolves from the
reviewed fork revision by git; publishing it under a Phantom name, with its own
`links` key, is a later release step. It changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Why this patch exists

The upstream safe wrapper can enable ALPS only with an empty application
settings value, although its pinned BoringSSL C API accepts distinct protocol
and settings byte strings. It also does not expose the peer settings query.

The upstream AEAD wrapper requires exclusive access for every operation because
it also accepts stateful TLS-specific algorithms. The pinned BoringSSL contract
allows concurrent seal/open calls for generic AEAD contexts, so QUIC needs a
separate safe wrapper that cannot be constructed with a TLS AEAD.

The pinned BoringSSL API supports TLS 1.3 KeyUpdate and authenticated protocol
message observation, but the upstream wrapper exposes neither. Phantom uses a
small safe wrapper for deterministic post-handshake interoperability tests;
runtime client configuration remains unchanged.

The upstream client-session API requires an unsafe `SSL_set_session` call whose
peer, context, and pre-handshake invariants otherwise escape into Phantom.
The scoped-session wrapper binds an owned session to its exact verified
hostname, `SSL_CTX`, and opaque application scope, removes early-data
capability, and exposes one safe pre-handshake attachment method that rejects
any identity mismatch. Session construction remains private to the real
new-session callback pair.

Firefox 157 sends early data over TCP when it resumes with a ticket that
permits it. The upstream wrapper exposes none of BoringSSL's client early-data
calls, and the scoped-session wrapper strips the capability from every
session. The early-data patch lets a connector opt in to keeping that
capability, still per connector and scope, and wraps the pinned BoringSSL
calls a client needs: enabling early data on one connection, observing the
early-data state and the server's answer, and resetting after a rejection.
`SSL_reset_early_data_reject` aborts the process when the handshake is not
waiting on a rejection, so the safe wrapper calls it only when
`SSL_in_early_data` and `SSL_get_error` together prove that wait, and returns
`false` otherwise. Native patch 0013, described below, lets a client that
sends `record_size_limit` offer early data at all.

The upstream ECH GREASE API enables the extension but leaves its payload length
to BoringSSL's randomized policy. Firefox 154 on macOS 15.5 was captured with a
239-byte GREASE payload, producing an `encrypted_client_hello` extension body of
281 bytes. The dependency fork adds an exact per-connection payload-length API;
omitting it preserves BoringSSL's randomized policy.

BoringSSL also fixes the ECH GREASE AEAD by host capability: AES-128-GCM when
AES hardware is reported and ChaCha20-Poly1305 otherwise. Firefox 154 draws
AES-128-GCM or ChaCha20-Poly1305 per connection with equal probability (359
and 337 of 696 observed connections). The dependency fork adds a
per-connection list of allowed HPKE AEADs; each handshake draws one uniformly
with `RAND_bytes`, and a HelloRetryRequest reuses the first ClientHello's
extension. An empty list preserves BoringSSL's hardware-based choice.

The upstream wrapper exposes `SslContextBuilder::set_ech_keys` but keeps the
`SslEchKeys` type it takes, and `SslEchKeysBuilder`, in a private module, so
no caller outside the crate can build server ECH keys. Phantom's tests run a
loopback server that decrypts ECH to prove the client's real ECH path from
HTTPS records, and its capture server uses the same keys.

The upstream record-size-limit patch advertised RFC 8449 without enforcing it.
The dependency fork negotiates directional limits, applies them to the traffic-
key epoch that produced each protected record, fragments outgoing handshake and
application data, and rejects oversized incoming records. TLS 1.3 first-flight
handling defers the decision until EncryptedExtensions establishes whether the
extension was negotiated, preserving the legal non-echo path.

Patch 0005 also disabled TLS 1.3 early data whenever a limit was configured
or negotiated, which kept the Firefox recipe, whose ClientHello always
carries `record_size_limit`, from ever offering it. RFC 8449 section 4
subjects records to the limits of the handshake that produced their keys,
and a client writes 0-RTT records before EncryptedExtensions carries the
server's limit. Patch 0013 therefore lets such a client offer early data and
keeps the early-data capability of tickets from connections that negotiated
a limit. As in NSS, the whole 0-RTT write epoch, `EndOfEarlyData` included,
uses the protocol maximum of 2^14+1 bytes of TLSInnerPlaintext; the server's
limit applies from the handshake write keys. A server that negotiated a
limit below 16385 cannot accept such records, so it issues no early-data
tickets and declines early data; a server at the maximum accepts it.

Three parts of Firefox 157's QUIC ClientHello cannot be expressed through the
upstream wrapper. Firefox shuffles its built-in extensions and appends the
rest, so every QUIC ClientHello ends with `quic_transport_parameters` and then
`encrypted_client_hello`, followed by `pre_shared_key` when it resumes;
BoringSSL can fix a prefix and shuffle the remainder, but cannot fix a tail.
Native patch 0014 adds a fixed tail written after the shuffled middle, and
`extension-order-tail.patch` wraps it. BoringSSL refuses `record_size_limit` on
a QUIC connection, which Firefox sends with 16385; native patch 0015 negotiates
it there without applying a limit, since QUIC carries no TLS records, and
`record-size-limit-quic.patch` corrects the wrapper documentation that said
QUIC was unsupported. NSS also sends an empty `extended_master_secret` and a
`renegotiation_info` of one zero byte in a ClientHello whose minimum version is
TLS 1.3, which BoringSSL omits; native patch 0016 adds a switch for both, and
`tls13-legacy-extensions.patch` wraps it on the context and the connection.

NSS sizes its ECH GREASE payload as if it encrypted the ClientHello it
actually sends, so the payload grows with a session ticket: Firefox 157 sent
240 bytes in a fresh ClientHello and 368 in a resumed one, and 208 over QUIC
to an IP literal. A fixed length set with `set_ech_grease_payload_length`
matches only one of them. Native patch 0017 builds the EncodedClientHelloInner
that NSS 3.128 would encrypt for the built ClientHello and pads it as NSS does
for an ECHConfig with a given `maximum_name_length`, by the length of the URL
host, which is the server name except for an IP literal, where NSS sends no
server name but still pads by the host text.
`ech-grease-payload-from-client-hello.patch` wraps it.

The upstream delegated-credential patch advertised extension 34 but could not
accept a credential. BoringSSL's `tls13_process_certificate` rejects the
unknown CertificateEntry extension with a fatal `unsupported_extension` alert,
so a TLS 1.3 server that sends a credential fails the handshake; no
unverified credential is used. It also inherited a test-runner field-order bug
that could make two non-standard implementations agree.
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
- `SslRef::set_ech_grease_aeads` exposes the fork's `SSL_set1_ech_grease_aeads`
  without enabling ECH GREASE implicitly. It accepts HPKE AEAD identifiers
  `0x0001`, `0x0002`, and `0x0003`, each at most once, and is excluded from
  FIPS builds like the payload-length setter.
- `src/ssl/test/ech.rs` proves each single configured AEAD reaches the wire,
  32 connections configured with AES-128-GCM and ChaCha20-Poly1305 produce
  both, and oversized, unknown, and repeated lists are rejected with a
  populated error stack.
- `ech-server-keys.patch` re-exports `SslEchKeys` and `SslEchKeysBuilder`
  from `btls::ssl` and documents the builder's existing unsafe pointer
  constructor. It adds no unsafe code. `src/ssl/test/ech.rs` imports
  `SslEchKeys` through the public path.
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
- `ConcurrentAeadCtx` exposes shared detached-tag operations only for
  AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. Its tests prove the type is
  `Send + Sync` and exercise concurrent seal/open calls with distinct nonces
  and buffers.
- `SslRef::key_update` queues a typed TLS 1.3 KeyUpdate request, while
  `SslContextBuilder::set_msg_callback` exposes borrowed, typed message
  observations without leaking raw FFI into Phantom.
- `src/ssl/test/key_update.rs` proves a requested update is emitted, answered
  with a non-requested update, and followed by application traffic.
- `message-callback-tests.patch` adds an actual SNI context-switch exchange
  and a runtime ClientHello canary for compact and pretty Debug output.
- `message-callback-context.patch` retrieves the message callback from the
  original context retained by `Ssl::new`. Changing the active context during
  SNI does not change the native callback. `SslMessage` Debug keeps metadata
  and byte length while omitting the message bytes.
- `SslSessionScope`, `ScopedSslSession`,
  `SslConnectorBuilder::enable_scoped_client_sessions`, and
  `ConnectConfiguration::into_ssl_with_scoped_session` keep session
  construction and unsafe attachment inside this wrapper, reject cross-host,
  cross-scope, and cross-context reuse, and disable 0-RTT before a session
  enters an external cache.
- `src/ssl/test/session_resumption.rs` proves matching scoped resumption,
  mismatch refusal, and early-data stripping.
- `SslConnectorBuilder::enable_scoped_client_sessions_with_early_data` keeps
  the early-data capability of new scoped sessions;
  `ScopedSslSession::early_data_capable`, `SslRef::set_early_data_enabled`,
  `SslRef::in_early_data`, `SslRef::early_data_accepted`,
  `SslRef::reset_early_data_reject`, and `ErrorCode::EARLY_DATA_REJECTED`
  expose the client early-data calls. Sessions of a connector that does not
  opt in are still stripped, and an attached session sends no early data
  unless the connection enables it.
- `src/ssl/test/session_resumption.rs` proves accepted early data, a
  rejection followed by a reset and a resend on the same connection, a guarded
  reset that refuses to run twice, and a capable session that offers nothing
  when its connection does not enable early data.
- `SslContextBuilder::set_extension_order_tail` exposes
  `SSL_CTX_set_extension_order_tail`; `set_extension_permutation` documents
  that it rejects a type the tail lists. `src/ssl/test/patches.rs` proves
  that eight shuffled ClientHellos end with the tail, before padding, and that
  a type cannot be in both the order and the tail.
- `SslContextBuilder::set_record_size_limit` documents that a QUIC
  connection negotiates the extension with no limit applied. It adds no code.
- `SslContextBuilder::set_tls12_extensions_in_tls13_client_hello` and
  `SslRef::set_tls12_extensions_in_tls13_client_hello` expose the native
  switch. `src/ssl/test/patches.rs` proves the context default, the
  connection override in both directions, and the exact empty and one-byte
  bodies.
- `SslRef::set_ech_grease_payload_from_client_hello` takes the maximum name
  length and an optional host, and replaces a length set by
  `set_ech_grease_payload_length`, as a later call to that method replaces
  it. Both are excluded from FIPS builds. `src/ssl/test/ech.rs` proves the
  padding step of 32 bytes, padding by the given host, the last call winning,
  and the DTLS rejection.

The canonical machine-applicable wrapper changes are listed in
`patches/series`; the order is part of the reviewed source transformation.
They contain only wrapper APIs, documentation, and upstream-style tests;
packaging changes remain separate. The dependency commit stores the native
BoringSSL changes in the numbered, non-FIPS `btls-sys` patch series: patch 0005
implements RFC 8449, patch 0006 implements RFC 9345 client verification,
patch 0011 controls the ECH GREASE payload length, patch 0012 selects the
ECH GREASE AEAD from a configured list, patch 0013 allows early data
beside RFC 8449 limits, patch 0014 writes a fixed extension tail after the
shuffled middle, patch 0015 negotiates RFC 8449 over QUIC, patch 0016 sends
`extended_master_secret` and `renegotiation_info` in a TLS 1.3-only
ClientHello on request, and patch 0017 sizes the ECH GREASE payload from the
built ClientHello. Patch 0012 carries BoringSSL `ssl_test` coverage for
the selection, the rejected inputs, and reuse of the choice across a
HelloRetryRequest; patch 0013 carries coverage for 0-RTT with configured and
negotiated limits on both sides; patches 0014 to 0017 carry `ssl_test`
coverage of the tail order across a HelloRetryRequest, the QUIC negotiation,
the outer-only legacy extensions, and payload sizes for fresh, resumed, and
IP-literal ClientHellos. Every native patch owns the
generated prefix-symbol entries for the APIs it introduces. The dependency CI
replays the complete patch order and rejects stale BoringSSL pregenerated files.

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
   the files under `patches/`, the standalone manifest values, the
   materialized `README.md`, and this file. The checked-in wrapper sources and
   tests should exactly equal the candidate plus every patch listed in the
   canonical series.

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

4. Prove Cargo selected one local `phantom-btls` wrapper and one local
   `phantom-tokio-btls` adapter. Their versions must match the current fork
   pins. Only `btls-sys` resolves to the reviewed dependency-fork revision:

   ```sh
   cargo tree -i phantom-btls --locked
   cargo tree -i btls-sys --locked
   cargo tree -i phantom-tokio-btls --locked
   ```

## Required checks

`Cargo.lock` pins the standalone vendor checks. Refresh it only with a reviewed
dependency update.

```sh
cargo fmt --manifest-path vendor/btls/Cargo.toml --package phantom-btls --check
cargo clippy --manifest-path vendor/btls/Cargo.toml --all-targets --features prefix-symbols --locked -- -D warnings
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked ssl::test::alps
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked ssl::test::key_update
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked scoped_client_session
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked ssl::test::ech
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked record_size_limit
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked delegated_credentials
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked boringssl_patch_extension_order_tail
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked boringssl_patch_tls13_client_hello
cargo test --manifest-path vendor/btls/Cargo.toml --features prefix-symbols --locked aead::tests::shared_generic_context_seals_and_opens_concurrently
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
cargo clippy --manifest-path vendor/btls/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path vendor/btls/Cargo.toml --locked ssl::test::alps
cargo test --manifest-path vendor/btls/Cargo.toml --locked ssl::test::key_update
cargo test --manifest-path vendor/btls/Cargo.toml --locked scoped_client_session
cargo test --manifest-path vendor/btls/Cargo.toml --locked ssl::test::ech
cargo test --manifest-path vendor/btls/Cargo.toml --locked record_size_limit
cargo test --manifest-path vendor/btls/Cargo.toml --locked delegated_credentials
cargo test --manifest-path vendor/btls/Cargo.toml --locked boringssl_patch_extension_order_tail
cargo test --manifest-path vendor/btls/Cargo.toml --locked boringssl_patch_tls13_client_hello
cargo test --manifest-path vendor/btls/Cargo.toml --locked aead::tests::shared_generic_context_seals_and_opens_concurrently
cargo +1.85.0 check --manifest-path vendor/btls/Cargo.toml --all-targets
```
