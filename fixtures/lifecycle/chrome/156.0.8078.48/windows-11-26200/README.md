# Chrome 156 resource requests

Google Chrome stable 156.0.8078.48 on Windows 11 Home 10.0.26200 x64.
Each file is one successful attempt using a fresh profile, with the sandbox
enabled and no retries or NetLog.

| File | Protocol | Mode |
| --- | --- | --- |
| resources.txt | HTTP/2 | headful |
| resources-headless.txt | HTTP/2 | headless |
| resources-h1.txt | HTTP/1.1 over TLS | headful |
| resources-h3.txt | HTTP/3 | headful |

HTTP/2 source: `65ecdd0c6d2fe7a33d90d6c22088431e7ceef781`.
H1/H3 source: `401ebe31a3aa19c8c809f01b37ca200282f8abb6`.
Runtime: Python 3.12.10, h2 4.4.1, hpack 4.2.0;
HTTP/3 also uses aioquic 1.3.0 and pylsqpack 0.3.24.
The local [Ahem asset and license](../../../../resources/assets/ahem/README.md)
are retained separately.

All runs completed six requests and the native page checks for script execution,
stylesheet effects, image decoding and font loading. All connections ended.
H1 retains raw request lines, ordered headers and response bodies. H2 retains
raw peer bytes and initial HEADERS priorities. Its headful/headless fields,
hints and priorities agree except the HeadlessChrome user agent.
H3 retains client request, control and QPACK streams; response completion comes
from the page checks rather than raw server DATA replay.


Reproduce with a manifest, substituting the exact executable and fresh paths:

```json
{"operating_system":"Windows 11 Home 10.0.26200 x64","repeat":1,
 "browsers":{"chrome":{"version":"156.0.8078.48","path":"<chrome.exe>"}},
 "captures":[{"tool":"http_lifecycle","browsers":["chrome"],"scenarios":["resources"],
 "output_dir":"<fresh-output>","exclusive":true,"timeout":120,"args":["--headful"]}]}
```

Run `uv run --no-project --python 3.12.10 --with-requirements scripts/requirements.txt python -m scripts.capture.run_matrix <manifest>.json --jobs 1 --retries 0 --work-dir <fresh-work>`.
For headless, omit `args` and use new output/work paths. Check `--dry-run` first.
For headful H1 or H3, set `args` to
`["--headful", "--resource-protocol", "h1"]` or
`["--headful", "--resource-protocol", "h3"]`, with separate fresh paths.

| File | SHA256 |
| --- | --- |
| resources.txt | bfbb1f60e64accf282d66c0ed1d4734e31c0ab96763e1ece45a5af26918d70fe |
| resources-headless.txt | 138c4aee12ab2aceafe5799ed441a9671437ffb9764625013981442242e9cec2 |
| resources-h1.txt | ccc25154cb1b77315b4021356043a8ca127569bfcbdd171f51cba85a27d5b628 |
| resources-h3.txt | e3b30199daa19fe8c795b7a29d8d3f34841cb160fd8fb36523489c279b94cbbd |
