# Capture headed Chrome on hosted Macs

Run one HTTP EventSource reconnect capture on each hosted Mac architecture.
The workflow retains the installed browser identity and the actual request
headers, including the headed browser's `User-Agent` bytes.

## Select the attempts

Dispatch **macOS headed Chrome capture** at a reviewed source ref. It creates
two independent jobs with a ten minute limit each:

| Runner label | Required architecture | Attempt |
| --- | --- | --- |
| `macos-latest` | arm64 | HTTP `reconnect-204` |
| `macos-15-intel` | x86_64 | HTTP `reconnect-204` |

Both labels appear in the [runner image catalog at the reviewed revision](https://github.com/actions/runner-images/blob/e3fa5414d230773024d4a669a8402b50cd28f036/README.md#available-images).
The runner label does not pin a browser or OS build. Each job checks its
actual architecture before attempting the capture. A failed job leaves the
other attempt running. Neither job retries the capture.

The workflow uses the existing capture command with the installed version:

```sh
python -m scripts.capture.sse_reconnect \
  --browser chrome \
  --browser-path '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  --headful --protocol h1 --scenario reconnect-204 \
  --repeat 1 --run-timeout 120 --listen 127.0.0.1:0 \
  --client chrome --client-version '<installed full version>' \
  --output-dir target/macos-headful-capture/fixtures
```

The tool creates a disposable profile and cleans up its browser and loopback
peer. Launch flags appear in the fixture.

## Inspect the attempt

Download the artifact even when the job fails. `provenance.json` records the
command and exit code, full browser version and bundle build, launcher and
bundle metadata hashes, OS, architecture, runner image and source hashes.
Separate files preserve the capture command's complete stdout and stderr.

When emitted, `reconnect-204.txt` holds ordered request bytes and timings.
The workflow checks the page request, initial SSE request and reconnect,
with the terminal observation period complete. It copies observed
`User-Agent` field values into provenance as hex bytes, preserving whitespace
after the colon. It never overrides them.
An early capture failure can leave no fixture; its logs and provenance
remain part of the failed attempt. Cleanup failures remain failures.

Compare captures by their recorded Chrome build and runner image.

## Next

- [Capture tools](README.md): other scenarios and fixture formats.
