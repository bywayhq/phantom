# Chrome 156 Linux requests

Google Chrome stable 156.0.8078.47, Ubuntu 24.04.4 x86_64 on WSL2
(kernel 6.6.114.1-microsoft-standard-WSL2), WSLg 1.0.73. Each headed run
used a fresh profile under `nobody`, the browser sandbox, and zero retries.
The tools supplied loopback hostname mapping and a certificate SPKI exception.

| File | Observation |
| --- | --- |
| [snapshot](../../../../client-hints/chrome/156.0.8078.47/ubuntu-24.04.4-wsl2/snapshot-1.txt) | TCP/QUIC ClientHello, HTTP/2 and HTTP/3 startup, navigation and client hints |
| [resources-h1.txt](resources-h1.txt) | HTTP/1.1 resource fields over TLS |
| [resources-h2.txt](resources-h2.txt) | HTTP/2 fields and initial priorities |
| [resources-h3.txt](resources-h3.txt) | HTTP/3 fields, control and QPACK streams |

All resource pages completed six requests and `resources:ok`, including script
execution, stylesheet effects, image decoding and font loading. Connections
closed after each attempt. These observations supply application and TLS
settings; WSL2's kernel is separate from a native Linux host's TCP/IP behavior.
The [Ahem font and license](../../../../resources/assets/ahem/README.md) are
retained separately.

Snapshot and H1/H2 source: `edfe24398fb9c5bf6cc7fe42c8820176ef3033b4`.
H3 source: `e3bc997ee8486ce59eeb7f35911830389c49c40c`.
Runtime: Python 3.10.21, h2 4.4.1, hpack 4.2.0, aioquic 1.3.0,
pylsqpack 0.3.24. The ordinary Linux package is `156.0.8078.47-1`.

Reproduce a resource cell with the existing capture runner and short paths:

```json
{"operating_system":"Ubuntu24.04.4 WSL2 x86_64 kernel6.6.114.1-microsoft-standard-WSL2 WSLg1.0.73",
 "repeat":1,"browsers":{"chrome":{"version":"156.0.8078.47","path":"/path/to/google-chrome"}},
 "captures":[{"tool":"http_lifecycle","browsers":["chrome"],"scenarios":["resources"],
 "output_dir":"/tmp/pc/out","exclusive":true,"args":["--headful","--resource-protocol","h3"]}]}
```

```sh
uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt \
  python -m scripts.capture.run_matrix <manifest>.json --jobs 1 --retries 0 \
  --work-dir /tmp/pc/w --results /tmp/pc/results.json --dry-run
```

Inspect the plan, then omit `--dry-run` for one attempt. For H1 or H2, change
`--resource-protocol` and use fresh output/work paths. For the snapshot, use
`"tool":"snapshot"`, omit `scenarios`, and pass `"args":["--headful"]`.
Run as an unprivileged user with access to the headed display. Short `TMPDIR`
and work paths keep Chrome's Unix-domain singleton socket within its path limit.

| File | SHA256 |
| --- | --- |
| snapshot-1.txt | 6401c4422c29083d31cb8b89e634295a45c4eea80530e426414ab4c4d036e263 |
| resources-h1.txt | 887d23f51b7516d81e95b4436d4c8f1ab90c36d43fac7701fb2cfce6bd441112 |
| resources-h2.txt | 1dd2a0bab57183d01d41c8356dac8ec671a99318b79c985c0e6bd4a4f45bad86 |
| resources-h3.txt | 8c17790ab189d487176d5380f2a6abf7c07a40ad0d8519926c1bc6b2efcfead0 |
