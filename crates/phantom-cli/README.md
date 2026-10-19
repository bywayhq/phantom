# Phantom CLI

Send requests with an explicit browser profile and protocol. Stream files without
collecting the request or response body in memory.

```console
phantom profiles list
phantom request https://example.com/ --profile chrome/154.0.8037.97/windows-11-26200/r1 --protocol negotiated --context navigation
phantom request https://example.com/upload --profile chrome/154.0.8037.97/windows-11-26200/r1 --protocol h2 --method PUT --upload input.bin --output response.bin --timeout-ms 30000
```

Build from this repository with `cargo build -p phantom-cli --release --locked`.
The executable is `target/release/phantom` (`phantom.exe` on Windows). Building
requires Phantom's [native build tools](../phantom/src/docs/getting-started.md#install-the-build-tools).

## Requests

Choose exactly one `--profile ID` or `--profile-file FILE`. Built-in identifiers
are exact: no latest-version alias or platform substitution occurs. Choose
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
phantom profiles describe chrome/154.0.8037.97/windows-11-26200/r1
phantom profiles export chrome/154.0.8037.97/windows-11-26200/r1 --output profile.json
phantom profiles import edited.json --output checked.json
phantom request https://example.com/ --profile-file checked.json --protocol h2
```

Export produces editable `phantom.custom-profile` JSON. Import validates the
complete document and exports its supported settings with ordering preserved.
Input is limited to 16 MiB. Neither operation creates browser evidence or saves
an installed profile registry. Profile documents include configured literal
header values, so inspect them before sharing.

The catalog ships with the binary. Independent bundle updates, downloads,
installation and rollback are separate work; there is no `profiles update` command.

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
