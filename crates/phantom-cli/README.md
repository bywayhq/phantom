# Phantom CLI

Send requests with an explicit browser profile and protocol. Stream files without
collecting the request or response body in memory.

```console
phantom profiles list
phantom request https://example.com/ --profile chrome-154-windows --protocol negotiated --context navigation
phantom request https://example.com/upload --profile chrome-154-windows --protocol h2 --method PUT --upload input.bin --output response.bin --timeout-ms 30000
```

Build from this repository with `cargo build -p phantom-cli --release --locked`.
The executable is `target/release/phantom` (`phantom.exe` on Windows). Building
requires Phantom's [native build tools](../phantom/src/docs/getting-started.md#install-the-build-tools).

The [CLI artifact workflow](../../scripts/release/README.md#cli-archives) also
prepares checked ZIP/tar archives for Windows x64, Linux x64 and macOS arm64.
Download a successful workflow artifact, check `SHA256SUMS`, then extract its
platform archive and put `phantom` on your path. Keep the included notices.
Each receipt names the tested runtime and native dependencies; older systems
are not yet verified. These workflow candidates are separate from published
releases.

Windows archives require Microsoft's
[x64 Visual C++ v14 runtime](https://aka.ms/vc14/vc_redist.x64.exe), at least as
recent as the archive's MSVC build tools. The runtime DLLs are not bundled.

## Requests

Choose `--profile NAME`, `--profile-file FILE`, or a pinned bundle entry. Built-in
selectors name a fixed recipe. Full identifiers also work; no latest-version or
platform substitution occurs. Choose
`--protocol h1`, `h2`, `h3`, or `negotiated`. Negotiation uses the library's
HTTP/2 and HTTP/1.1 policy. The CLI does not enable HTTP/3 fallback or retries.

Catalog requests have no request template unless you select `--context navigation`
or `--context fetch`. A custom profile file keeps its configured template.
Missing templates and unsupported protocol/route combinations return errors.

Use `--method METHOD` to replace GET. Repeat `--header 'Name: value'` to preserve
field order, spelling and duplicates subject to the chosen protocol's rules.
The selected template still controls generated fields and their placement.

The default route is direct. `--proxy URI` accepts `http`, `https`, `socks4`,
`socks4a`, `socks5` and `socks5h` proxy URIs. Proxy environment variables are not
read. Credentials in proxy URIs, proxy authentication flags and CONNECT-UDP
configuration are not supported by this CLI slice.

`--upload FILE` streams the opened file in 8 KiB chunks. It does not change the
method. Uploads are one-shot: a policy requiring a body resend returns the
library's replay error. There is no hidden buffering or file reopening.

The response body goes to stdout, or to `--output FILE`. File outputs refuse
existing paths. A failed or interrupted download can leave a partial file.
The CLI writes received content bytes without automatic content decoding.
Response trailers are consumed but not printed. Use a pipe for binary stdout.

`--timeout-ms N` bounds send and download, including waits writing output.
`--attempts N` caps origin HTTP attempt admissions, including the initial request
and internal resends. Zero rejects the initial attempt. Admission does not prove
bytes were sent. DNS, TCP/TLS setup and proxy negotiation are separate work.

Control-C drops the pending request or body and starts bounded client shutdown.
Output or diagnostics failures also return an error. Exit codes are 0 for success,
1 for operation/I/O failure, 2 for argument errors and 130 for Control-C.
HTTP error responses succeed unless you pass `--fail`, which exits 22 for 4xx/5xx
after downloading the response body.

## Profiles

```console
phantom profiles describe chrome-154-windows
phantom profiles export chrome-154-windows --output profile.json
phantom profiles import edited.json --output checked.json
phantom request https://example.com/ --profile-file checked.json --protocol h2
```

`list` prints short selectors. `describe` includes the selector, full identifier,
browser build, platform release and recipe revision.

Export produces editable `phantom.custom-profile` JSON. Import validates the
complete document and exports its supported settings with ordering preserved.
Input is limited to 16 MiB. Neither operation creates browser evidence or saves
an installed profile registry. Profile documents include configured literal
header values, so inspect them before sharing.

## Offline bundles

A bundle groups complete custom-profile documents with exact names. Inspect
publisher references before installing a file into your own existing directory:

```console
phantom profiles bundle inspect browsers.json
phantom profiles bundle install browsers.json --store ./profiles
phantom request https://example.com/ --bundle <sha256> --bundle-profile custom/chrome --bundle-store ./profiles --protocol h2
```

Install prints the bundle's lowercase SHA-256. Use that exact digest, not its
publisher label or revision, to pin requests. Installing another revision keeps
older files. To roll back, select an older digest. Requests use only the selected
file and name; there is no catalog fallback or network lookup. `--context` is
unavailable for bundle entries: each document contains its chosen template.

The JSON envelope uses `format: "phantom.profile-bundle"`, `version: 1`, an `id`,
a positive integer `revision`, and `profiles`. Each profile has `name`, `document`
(the complete exported custom-profile object), and `provenance`. References are
objects with `source` and `revision` strings; an empty provenance list is allowed.
Publisher references are retained, not verified or fetched. A digest identifies
bytes, not a trusted publisher. Bundles may contain literal header secrets.

Bundles are limited to 16 MiB and 64 entries. Installation validates every entry
before exclusive file creation. Reinstalling identical bytes succeeds; conflicting
or incomplete files are never overwritten. Ordinary write errors attempt removal
and report cleanup failures. Installation is not crash-atomic: interruption can
leave an incomplete digest file, and concurrent readers can see a partial write.
Requests verify the digest before use. Remove an incomplete file deliberately
before retrying. Keep the store under your control, without untrusted writers.
There is no `profiles update` command or automatic version selection.

## Diagnostics

Add `--diagnostics report.json` to retain a bounded measured timeline after the
operation. This file is separate from stdout and must not already exist.
The JSON records at most 256 events, counts omitted events, and separates the
response head from response-body completion or abandonment.

Missing times and connection facts are `null` or explicit unavailable states.
Overlapping phases are not additive. Events retain redirect hops, admitted
attempt numbers, connection reuse and observed TLS resumption. Endpoints can
identify a proxy. Available certificate chains are leaf-first DER hexadecimal;
they are not a reconstructed trust chain. URLs, request headers and proxy
credentials are absent from the report.

## Next

Run `phantom --help` or read the [library guides](../phantom/src/docs/overview.md).
