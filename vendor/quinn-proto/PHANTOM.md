# Phantom vendor notes: quinn-proto

**Audience:** maintainers auditing or refreshing Phantom's QUIC dependency.
This file records provenance, local behavior changes, the refresh procedure,
and focused checks. It is not integration documentation.

The files listed in `patches/series` are the canonical local changes, in
application order. Change those patches and replay them; do not make an
unrecorded edit to the vendored crate.

This directory is the complete crates.io source for `quinn-proto` version
`0.11.18`.

- Crates.io archive SHA-256:
  `a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc`
- Crates.io archive:
  <https://static.crates.io/crates/quinn-proto/quinn-proto-0.11.18.crate>
- Upstream repository: <https://github.com/quinn-rs/quinn>
- Upstream crate licenses remain in `LICENSE-APACHE` and `LICENSE-MIT`.

## Publish identity

`publish-identity.patch` is always the last entry in `patches/series`. It
renames the package (`quinn-proto` becomes `phantom-quinn-proto` at
`0.11.18-phantom.2`), keeps the upstream library name so source, tests, and
examples are unchanged, and points the repository metadata at Phantom. It
removes the upstream documentation link, keeps Cargo's reserved archive files
out of the packaged crate, and records the upstream package, version, and
source archive under `[package.metadata.phantom]`. The standalone `Cargo.lock`
is packaging metadata outside the patches and follows the renamed package. It
changes no Rust source.

Phantom depends on this package only through the renamed package with an exact
version and a path, so the stock package cannot be selected in its place and no
root `[patch]` table is required. When refreshing, regenerate this patch after
the source patches. Increase the `-phantom.N` suffix whenever the fork's
content changes without an upstream version change, and update the exact pins
in the root `Cargo.toml` and in every renamed dependent.

## Why these patches exist

Two Quinn session key boundaries could not represent every provider failure.
`crypto::Session::next_1rtt_keys` was infallible apart from an `Option`, and
`crypto::Session::initial_keys` was fully infallible. A provider whose key
derivation can fail could not report either failure without panicking or
silently substituting different behavior.

The patch changes that method to return
`Result<Option<KeyPair<Box<dyn PacketKey>>>, TransportError>`. The stock rustls
provider retains its prior behavior inside `Ok`. Quinn treats provider errors
and an unexpected `Ok(None)` as `INTERNAL_ERROR`.

Initial 1-RTT installation and explicit, automatic, and peer-triggered key
updates all derive the replacement pair before changing current keys or the key
phase. An automatic failure aborts packet construction. Timestamped paths send
a transport close with the existing keys. The timestamp-free public
`force_key_update` path terminates locally and reports the same error to the
application.

The second patch changes `Session::initial_keys` to return
`Result<Keys, CryptoError>`. The stock rustls provider retains its prior
behavior inside `Ok`. Client construction derives keys before inserting the
connection and reports the bounded `ConnectError::InitialCrypto` variant on
failure. Server construction returns an `INTERNAL_ERROR` close without
inserting the connection. Retry derives replacement Initial keys before
changing connection IDs, packet spaces, the retry token, or retransmission
state, and closes with `INTERNAL_ERROR` if derivation fails.

Focused tests inject deterministic failures at initial client construction,
Retry re-derivation, the first 1-RTT derivation, each update path, and an
automatic update after an acknowledged rotation. They verify bounded connection
errors, `INTERNAL_ERROR`, unchanged key state, and no automatic-update packet
emission. The patches do not add a BoringSSL Session implementation.

The third patch adds two provider-facing transport-profile seams. It allows an
explicit DATAGRAM frame-size advertisement when it fits the configured receive
buffer, preserving Quinn's existing clamped behavior by default. It also adds
bounded connection errors for invalid local parameters and provider-side
encoding failure before any network I/O.

The next four patches let a transport profile reproduce Firefox's QUIC
client, whose stack is neqo. Each one is off or unchanged by default, so a
connection that does not configure it sends and accepts what upstream does.

`patches/profiled-transport-limits.patch` adds local limits that upstream
fixes:

- `TransportConfig::max_ack_delay` sets the advertised `max_ack_delay` and
  the delay the endpoint itself uses before acknowledging. Upstream always
  uses 25 ms, the protocol default, which is never advertised.
- `TransportConfig::active_connection_id_limit` advertises 2 through 8 and
  stores that many of the peer's connection IDs. Upstream advertises 5 and
  stores 5; the queue now holds up to 8 and enforces the advertised limit.
- `TransportConfig::bidi_remote_stream_receive_window` and
  `uni_stream_receive_window` give streams the peer opens their own receive
  windows, advertised as `initial_max_stream_data_bidi_remote` and
  `initial_max_stream_data_uni`. Upstream uses `stream_receive_window` for
  every class. A pooled receive state takes the window of the stream that
  reuses it.
- `TransportConfig::min_initial_datagram_size` pads each client datagram
  that carries an Initial packet to that size, bounded by the space left in
  the datagram. Upstream pads to 1200 bytes.

Tests show the values in the parameters Quinn hands the crypto provider, a
server limited by a client's smaller unidirectional window, a queue that
accepts eight connection IDs, and 1252-byte Initial datagrams.

`patches/reset-stream-at.patch` adds `TransportConfig::reset_stream_at`.
When set, the endpoint advertises the empty `reset_stream_at` parameter
(`0x1d`, the identifier neqo uses) and accepts `RESET_STREAM_AT` frames
(`0x24`, draft-ietf-quic-reliable-stream-reset). A frame whose Reliable Size
is zero, or already read, resets the stream as `RESET_STREAM` does.
Otherwise the final size becomes known, reads deliver bytes up to the
Reliable Size and then report the reset, and flow-control credit for the
discarded bytes is released when the reset completes or the stream stops. A
Reliable Size larger than the final size is a `FRAME_ENCODING_ERROR`. When
support was not advertised, the frame type is unknown: in any packet, the
connection closes with `FRAME_ENCODING_ERROR` and the reason "invalid frame
ID" before the frame's body is read, as upstream does. A stream read with
unordered reads cannot keep the reliable bytes in order, so the frame resets
it at once, and an unordered read that starts while a reliable reset waits
ends the wait with the reset. A peer's `reset_stream_at` parameter is skipped
as unknown. The endpoint never sends the frame.

`patches/ack-frequency-draft-02.patch` adds
`TransportConfig::ack_frequency_draft`. With `AckFrequencyDraft::Draft02`
the local `min_ack_delay` is advertised under draft 02's `0xff02de1a`
instead of draft 07's `0xff04de1b`, and a received `ACK_FREQUENCY` frame is
read with draft 02's fields: a packet tolerance N becomes an ack-eliciting
threshold of N - 1, and an Ignore Order byte of 1 or 0 becomes a reordering
threshold of 0 or 1. A tolerance of 0 or another Ignore Order value is a
`FRAME_ENCODING_ERROR`. A peer's draft 02 parameter is skipped as unknown, so
without the default draft 07 parameter the peer is not sent `ACK_FREQUENCY` or
`IMMEDIATE_ACK` frames.

`patches/quic-v2.patch` implements QUIC version 2 (RFC 9369) and compatible
version negotiation (RFC 9368) for clients:

- Long header packet types follow the version: in v2, Initial is `0b01`,
  0-RTT `0b10`, Handshake `0b11`, and Retry `0b00`.
- The rustls provider accepts `0x6b3343cf`, with the v2 Retry integrity key
  and nonce.
- `EndpointConfig::compatible_versions` lists the versions a server may move
  a client to. Until the server's first flight yields handshake keys, the
  client accepts an Initial in such a version. It derives that version's
  Initial keys with the new `Session::initial_keys_for_version`, from the
  first Initial's Destination Connection ID or a Retry's Source Connection
  ID, and decrypts the packet with them on a copy. Only a packet that
  authenticates moves the connection to the new version, through the new
  `Session::switch_version`; any other is dropped and the client stays in
  its version. A switch discards the 0-RTT keys, and the handshake treats
  early data as rejected: Quinn resets the streams that carried it, and the
  application may send the data again once the connection is established. A
  server may first acknowledge the client in the original version; aioquic
  does. The default methods refuse, so a provider that cannot switch drops
  the packet.
- An endpoint with compatible versions writes its own `version_information`
  (`0x11`), listing its version and then its compatible versions, and checks
  the peer's. A malformed parameter closes the connection with
  `TRANSPORT_PARAMETER_ERROR`: a zero Chosen or Available Version, or a
  client whose Available Versions omit its Chosen Version. A server's
  Available Versions may be empty. A client closes with the new
  `VERSION_NEGOTIATION_ERROR` (`0x11`) when the server's Chosen Version
  differs from the version in use, or when a client that switched gets no
  `version_information`. An endpoint without compatible versions skips the
  peer's parameter as unknown, as upstream does.
- Only the client side of compatible version negotiation is implemented. A
  server never switches a client, and does not check a client's
  `version_information` against the version it received.

Tests cover the packet-type bits in both versions, a connection and a Retry
in v2, a client moved from v1 to v2, a switched client that gets no
`version_information`, a server that lists no Available Versions, a v2
Initial that fails authentication and leaves the client in v1, a switch
with 0-RTT data outstanding, and a client that stays in v1. Default clients
and servers ignore a malformed or mismatched `version_information`, while a
client with compatible versions closes for it. The move is shown with
a rustls session that handshakes in v2 and protects its first flight with
v1 Initial keys, because a rustls session cannot change version; the test
re-protects that flight as v2 for a v2-only server. Phantom's BoringSSL
provider, which can switch, is checked in the workspace test
`firefox_157_client_follows_a_server_to_version_2` of `phantom-net`, where
a relay re-protects its v1 Initials for a v2-only Quinn server, and against
aioquic on loopback.

The ordered canonical source and test deltas are stored in
`patches/fallible-key-updates.patch`, `patches/fallible-initial-keys.patch`,
`patches/profiled-transport-parameters.patch`,
`patches/profiled-transport-limits.patch`, `patches/reset-stream-at.patch`,
`patches/ack-frequency-draft-02.patch`, and `patches/quic-v2.patch`. Apply
them in that order. `PHANTOM.md` and the patch files are packaging metadata
and are not part of the patches.

## Refreshing the vendor copy

1. Download and verify the reviewed crate archive in an isolated directory:

   ```sh
   quinn_proto_version=0.11.18
   expected_checksum=a9746dbde176634f4f2f1faf2404e30a31b2bc1e9cafb5329c95d8177a18c9fc
   refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantom-quinn-proto.XXXXXX")
   archive="$refresh_dir/quinn-proto-$quinn_proto_version.crate"

   curl --fail --location --output "$archive" \
     "https://static.crates.io/crates/quinn-proto/quinn-proto-$quinn_proto_version.crate"

   if command -v shasum >/dev/null 2>&1; then
     actual_checksum=$(shasum -a 256 "$archive" | awk '{print $1}')
   else
     actual_checksum=$(sha256sum "$archive" | awk '{print $1}')
   fi
   test "$actual_checksum" = "$expected_checksum"

   tar -xzf "$archive" -C "$refresh_dir"
   candidate="$refresh_dir/quinn-proto-$quinn_proto_version"
   ```

2. Dry-apply and apply all canonical patches in order. A failed dry
   application requires review and patch regeneration; do not accept fuzz or
   rejected hunks.

   ```sh
   while IFS= read -r patch; do
     git -C "$candidate" apply --check \
       "$PWD/vendor/quinn-proto/patches/$patch"
     git -C "$candidate" apply \
       "$PWD/vendor/quinn-proto/patches/$patch"
   done < "$PWD/vendor/quinn-proto/patches/series"
   ```

3. Copy the patched candidate to `vendor/quinn-proto.next`, then copy this file
   and all canonical patches into it. Keep the current directory as a
   rollback copy until all checks pass. Update the version, archive URL,
   checksum, and patches when refreshing.

4. Refresh and inspect the workspace selection:

   ```sh
   cargo metadata --format-version 1 >/dev/null
   cargo tree -i phantom-quinn-proto --locked
   ```

   The tree must select `quinn-proto v$quinn_proto_version` from
   `vendor/quinn-proto`. The lockfile diff should only remove the registry
   source and checksum from that package entry.

## Focused checks

```sh
rustfmt --check --edition 2021 vendor/quinn-proto/src/tests/initial_keys.rs
rustfmt --check --edition 2021 vendor/quinn-proto/src/tests/key_update.rs
rustfmt --check --edition 2024 --config skip_children=true vendor/quinn-proto/src/tests/transport_limits.rs vendor/quinn-proto/src/tests/quic_v2.rs
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked tests::initial_keys
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked tests::key_update
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked datagram_frame_size
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked tests::transport_limits
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked reset_at
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked reset_stream_at
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked draft02
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked tests::quic_v2
cargo clippy --manifest-path vendor/quinn-proto/Cargo.toml --all-targets --locked -- -D warnings
cargo check --manifest-path vendor/quinn-proto/Cargo.toml --no-default-features --locked
cargo check -p phantom-quic-btls --all-targets --locked
```

The integration checkout owns workspace-wide gates.
