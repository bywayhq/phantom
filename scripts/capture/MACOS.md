# Capture headed Chrome on hosted Macs

Record headed Chrome on each hosted Mac architecture. Choose an EventSource
reconnect or Chrome 156 startup and resource requests.

## Select the attempts

Dispatch **macOS headed Chrome capture** at a reviewed source ref. It creates
two independent jobs with a fifteen minute limit each:

| Runner label | Required architecture |
| --- | --- |
| `macos-latest` | arm64 |
| `macos-15-intel` | x86_64 |

Both labels appear in the [runner image catalog at the reviewed revision](https://github.com/actions/runner-images/blob/e3fa5414d230773024d4a669a8402b50cd28f036/README.md#available-images).
The runner label does not pin a browser or OS build. Each job checks its
actual architecture before attempting the capture. A failed job leaves the
other attempt running. Neither job retries the capture.

The default `sse` mode uses installed Chrome for one HTTP `reconnect-204`:

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

Choose `profile` for ordinary Google Chrome **156.0.8078.48**. This mode
downloads Google's stable universal DMG, stages an owned copy, and checks its
signature, system policy, full version and native architectures before use.
Signature and system-policy checks each allow up to 120 seconds. Staging
omits resource forks and general extended attributes while preserving
quarantine information and ACLs. Each hosted job checks this copy behavior
before using Chrome.
The existing installed browser stays in place. A different download build
fails explicitly.

Four existing capture jobs run in sequence: one fingerprint snapshot, then
script, stylesheet, image and font requests over H1, H2 and H3. Each uses a
fresh profile and runs once, without retries. The tools use their existing
per-launch SPKI exceptions and resolver flags.

## Inspect the attempt

Download the artifact even when the job fails. `provenance.json` records the
command and exit code, full browser version and bundle build, launcher and
bundle metadata hashes, OS, architecture, runner image and source hashes.
Separate files preserve the capture command's complete stdout and stderr.

Profile mode also retains the DMG URL/hash, signature checks, each matrix
manifest, result, logs and output hashes. Download the artifacts from failed
jobs too. A failed cell leaves the other protocols eligible to run; the whole
attempt still fails. Cleanup failures retain their owned staging path for
inspection on the disposable runner.

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
