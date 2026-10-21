# curl-impersonate Safari2601

These are executions of curl-impersonate, not captures of a Safari browser.
The catalog ports its Safari 26.0.1 preset for TLS and HTTP/2, with its specific
navigation headers. It does not establish a macOS build, TCP recipe, HTTP/3,
HTTP/1 header casing, resumption, or other request contexts.

The MIT-licensed preset comes from [curl-impersonate 2.2.3](https://github.com/lexiforest/curl-impersonate/tree/6e8f87760a4dd96771e96fc9d55440dcd8845243).
`LICENSE` preserves its notice. `upstream-preset.patch.txt` is the unchanged
Safari2601 initializer from that commit's `patches/curl.patch`.
`upstream-signature.yaml` is its independent upstream signature.
`provenance.json` records exact source, executable and archive identities.

## Capture

Three fresh official Linux executable processes ran in Ubuntu-24.04 under WSL.
Each sent two sequential requests to the existing loopback `CaptureServer` in
`scripts/capture/http2_session.py`, with default `ServerPolicy`. The first URL
returned 200 and 13 bytes; `/done` returned 204. Each process exited 0 and reused
one connection for streams 1 and 3. `capture-environment.json` records the
server dependencies and source hashes. No browser was run.

`run-N/command.json` retains each exact command. It selects `safari2601`,
HTTP/2 and compression, disables proxies and verifies a throwaway certificate
with `--cacert`. The target resolves explicitly to 127.0.0.1 on an assigned
port. Connect, transfer and process timeouts were 5, 15 and 20 seconds.
The capture owner closed every server and awaited the process before exit.

Each run retains the raw ClientHello handshake, both decrypted HTTP/2 streams,
curl trace, frame and HPACK analysis, command and completion metadata.
`summary.json` keeps ordered values in readable form. No private key is
included. `sha256.json` protects retained bytes from accidental text conversion.

## Comparison

The three normalized ClientHellos agree, including the duplicate signature
scheme 2053. Settings are ordered `2=0;3=100;4=2097152;9=1`; the window increment
is 10420225. Both request HEADERS omit priority fields. The second block emits
a table-size update to 4096 after the server states the default size.
The upstream signature's ACK precedes HEADERS; these executions send the first
HEADERS before ACK. Do not require that scheduling order across directions.

Profile tests check numeric TLS values against the raw ClientHellos, the
HTTP/2 preface and navigation template. `phantom/` retains three public-client
runs, their source/build identities and raw streams. TLS shapes, ordered settings
and request fields match the peer. SETTINGS processing occurred earlier, moving
the 4096 table-size update to the first request. Shutdown GOAWAY also differs.
These runs do not establish identical frame scheduling or connection shutdown.
Cookie splitting and other HPACK input classes remain source-derived.

## Next

Use `catalog::profile("curl-safari-26-macos")` and require the layers you need.
