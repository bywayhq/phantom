# Chrome 156 snapshot observations

Google Chrome stable 156.0.8078.48; Windows 11 Home 10.0.26200 x64.
Source: `83a2aaec0d53abf1f9abd5daa31478ef35277944`.
Runtime: Python 3.12.10, h2 4.4.1, hpack 4.2.0, aioquic 1.3.0.
Executable SHA256: `480f275b63d1ea39113cbc8344ac395578acc25b432bd39af5fbc77005179aca`.

`snapshot-1/2/3.txt` are one normal headful batch, without retries.
`snapshot-headless-1/2/3.txt` are a cleanup diagnostic using the same source
and deadlines. Both batches use fresh profiles and the browser sandbox.
The observer wraps `_windows_open_process`, `_windows_terminate_job` and
`_windows_wait_process`. All 27 owned waits completed within 20 seconds.
Observer SHA256: `2cc36ba0a24625b16c2ec9457b20d89e824d1742d500e1eceeabfaf9008d3821`.
An earlier normal headless batch stopped after one snapshot on an owned-member
cleanup timeout. Its private logs are retained; the cause remains unresolved.

Normalized TCP/QUIC TLS, exact H2 startup, ordered H2/first-H3 fields, H3
SETTINGS and 11 hints agree across these modes. Only the decoded User-Agent
value differs after owned authority-port/run-token normalization: Chrome versus
HeadlessChrome. Headless 1 records a TLS ConnectionError before successful H2/H3.
TLS comparison removes GREASE/random keys/ECH payloads and Chromium shuffle;
QUIC also normalizes connection IDs/reserved versions. Against retained 154,
transport structure agrees; three version/GREASE-brand hint values differ.
Raw replay covers three H2 HPACK blocks and the first QPACK request.

Reproduce the normal batch with exact browser and fresh output/work paths:
```json
{"operating_system":"Windows 11 Home 10.0.26200 x64","repeat":3,"browsers":{"chrome":{"version":"156.0.8078.48","path":"<chrome.exe>"}},"captures":[{"tool":"snapshot","browsers":["chrome"],"output_dir":"<fresh-output>","exclusive":true,"timeout":120,"args":["--run-timeout","20","--observation","0.3","--headful"]}]}
```
Run `uv run --no-project --python 3.12.10 --with-requirements scripts/requirements.txt python -m scripts.capture.run_matrix <manifest>.json --jobs 1 --retries 0 --work-dir <fresh-work>`; check `--dry-run` first.
For headless, omit `--headful`; reproducing the diagnostic also needs the
observer wraps above before `snapshot.main`. No full diagnostic argv was saved.

| File | SHA256 |
| --- | --- |
| snapshot-1.txt | 17861ed1dff54619617d1767310838fc7f87609199fa4a5fc24b21b1e616fe6f |
| snapshot-2.txt | bb297e39a72f27c4e00eef20ccd4e432eedec09f6a72b51037f7577db3ef3145 |
| snapshot-3.txt | 764df41215f0d6cbd6f8f9753f55ef521002500633a7eb7f6c1d9eaf687c6e60 |
| snapshot-headless-1.txt | 4fffe492ffcd96a1ad5a738c1a446a347aaf93162bdb81e1b08672eb427da23a |
| snapshot-headless-2.txt | cb15c5f3c20130e08d93166080259f7b05a105a484d5a9b09cb3eba45feddc82 |
| snapshot-headless-3.txt | 95bad2e0a9392d53da7ac1ed4f1dd17bf80228f1d2cd7c710dccb18fadcf4a72 |
