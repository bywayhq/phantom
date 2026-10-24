# Configured native DNS

`native-configured.json` records Firefox 157.0, build 20260924084938,
on macOS 15.5 arm64 with Python 3.10.18.

The fresh profile uses direct connections and disables TRR (`mode=5`).
A scoped resolver answers a native A lookup for a random test domain.
The page reads a complete HTTP body before signalling completion.
The resolver is removed and the original DNS configuration is restored.

Capture source: `b89b88ff`. Staged sources use CRLF; their hashes are in JSON.
Fixture SHA256:
`7600e3fc759ae36ea78eaec68c3246a156461ba0986fb2660fe7be3c4c82e9d4`

Repeat from the repository root as your ordinary user:

```sh
sudo -v
uv run --no-project --python 3.10 \
  --with-requirements scripts/requirements.txt \
  python -m scripts.capture.mac_native_dns_capture \
  --firefox /Applications/Firefox.app/Contents/MacOS/firefox \
  --output target/mac-native-dns
```

Use an unused output directory. See the [capture instructions][capture].
This run does not measure default DNS policy, TTL caching or retries.

## One unanswered A question

`native-retry.json` uses the same Firefox build and host. The peer leaves
the first A question unanswered. A repeated question arrives about one second
later and receives a reply. The page reads its body and completes.

Capture source: `28ded616`. Repeat with `--drop-first-udp-a` and a new
output directory. The record covers recovery in the configured Mac resolver.

[capture]: ../../../../../scripts/capture/README.md#macos-native-dns
