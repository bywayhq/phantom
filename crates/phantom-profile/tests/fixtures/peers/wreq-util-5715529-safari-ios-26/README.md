# Safari iOS 26 preset

The catalog adapts wreq-util's `SafariIos26` TLS, HTTP/2 and navigation preset.
These files record the peer's execution. The iOS build is unknown; other
connection layers and request contexts are absent.

The Apache-2.0 preset comes from [wreq-util at 5715529](https://github.com/0x676e67/wreq-util/tree/5715529002738f46eea86a7271f918f9374d3582).
`LICENSE` retains its terms. Unchanged source files are in `upstream/`;
the declaration adapts their settings to Phantom's types. Other `LICENSE_*`
files retain the resolved native and HTTP implementation notices.

## Execution

Three fresh Linux processes each sent two sequential GETs through the existing
loopback `CaptureServer` with default `ServerPolicy`. The first returned 200
and 13 bytes; `/done` returned 204. Each exited 0 and reused one connection
for streams 1 and 3. No browser ran. No private key is retained.

`consumer/` holds the exact source, manifest and lockfile. Build with
`cargo build --manifest-path consumer/Cargo.toml --locked --jobs 2` on Linux.
The recorded build used Rust 1.99.1, the dev profile without debug information
or incremental compilation, and the native BoringSSL source in the lockfile's
pinned fork. `build-linux.log` retains the original build output.

The consumer enables `emulation`, `emulation-compression` and `tokio-rt`,
selects `SafariIos26`, verifies each throwaway certificate and hostname, and
resolves the capture host explicitly to loopback. It disables proxies, keeps
the preset's ALPN, and checks that both responses use HTTP/2. Connect, request,
combined-work and process limits were 5, 15, 35 and 40 seconds.
Per-run commands, public certificates, completion metadata, response bodies,
raw ClientHello, decrypted streams and HPACK blocks are retained.

## Observations

All three ClientHellos match the retained Safari macOS preset after masking
only random/session-ID bytes, GREASE values and key-exchange bytes. Group and
key widths, extension bodies and ordering remain compared. The two presets
share a TLS component.

SETTINGS are ordered `2=0;3=100;4=2097152;9=1`, followed by a 10420225 connection
window increment. The resolved wreq-proto 0.2.5 builder omits frame/header size
settings despite its `Default` having values. Both request blocks omit HEADERS
priority. ACK of server SETTINGS follows the first HEADERS in runs 1 and 3,
and precedes the connection-window update in run 2.

The eight navigation fields preserve their observed order and values. The
first block inserts ordinary fields; the second reuses their dynamic entries.
Both encode the path without indexing. Literal values use Huffman encoding.
Neither block sends a table-size update for the unchanged server value 4096.
Whole-cookie handling and other HPACK input classes are source-derived and
not exercised here.

`observations.json` keeps the decoded projection. Only the assigned authority
port is normalized in headers; raw HPACK bytes retain it. `provenance.json`
names source, build and executable identities; `sha256.json` covers every
retained file. [Public-client comparison](phantom/README.md) retains Phantom
emission at the recorded integration checkout and localizes its differences.

## Next

Select `catalog::profile("safari-26-ios")` and require the layers you need.
