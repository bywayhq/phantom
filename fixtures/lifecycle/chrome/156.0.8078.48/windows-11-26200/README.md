# Chrome 156 resource requests

Google Chrome stable 156.0.8078.48 on Windows 11 Home 10.0.26200 x64.
`resources.txt` is headful; `resources-headless.txt` is headless. Each is
one successful attempt, without retries or NetLog, using a fresh profile.
Capture source: `65ecdd0c6d2fe7a33d90d6c22088431e7ceef781`.
Runtime: Python 3.12.10, h2 4.4.1, hpack 4.2.0.
The local [Ahem asset and license](../../../../resources/assets/ahem/README.md)
are retained separately.

Both runs record ordered HTTP/2 stylesheet, script, image and font headers,
raw peer bytes and initial HEADERS priorities. All six requests completed.
The ordered fields, hints and priorities agree, except the headless UA names
HeadlessChrome. Headful accepted three connections, headless two; all ended.
These observations do not establish other protocols or a complete profile.

Reproduce with a manifest, substituting the exact executable and fresh paths:

```json
{"operating_system":"Windows 11 Home 10.0.26200 x64","repeat":1,
 "browsers":{"chrome":{"version":"156.0.8078.48","path":"<chrome.exe>"}},
 "captures":[{"tool":"http_lifecycle","browsers":["chrome"],"scenarios":["resources"],
 "output_dir":"<fresh-output>","exclusive":true,"timeout":120,"args":["--headful"]}]}
```

Run `uv run --no-project --python 3.12.10 --with-requirements scripts/requirements.txt python -m scripts.capture.run_matrix <manifest>.json --jobs 1 --retries 0 --work-dir <fresh-work>`.
For headless, omit `args` and use new output/work paths. Check `--dry-run` first.

SHA256 `resources.txt`: `bfbb1f60e64accf282d66c0ed1d4734e31c0ab96763e1ece45a5af26918d70fe`.
SHA256 `resources-headless.txt`: `138c4aee12ab2aceafe5799ed441a9671437ffb9764625013981442242e9cec2`.
