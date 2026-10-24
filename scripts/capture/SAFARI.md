# Capture Safari on a hosted Mac

Run Safari EventSource reconnect captures on a disposable macOS runner.
The workflow records the installed browser, ordered requests and cleanup.

## Run the capture

Select the **Safari loopback capture** workflow and its reviewed source ref.
Choose `h1`, `h2` or the default `both`. It runs independent HTTP and TLS/H2
jobs on `macos-latest`. Each job opens
one headed automation session and attempts `reconnect-204` once. There are
no capture retries. Each job has a ten minute limit and installs the pinned
capture requirements.

For the same capture on an approved disposable Mac:

```sh
python3.10 -m scripts.capture.safari_webdriver \
  --output-dir target/safari-capture
```

HTTP remains the default. For the separate TLS/H2 attempt:

```sh
python3.10 -m pip install --require-hashes -r scripts/requirements.txt
python3.10 -m scripts.capture.safari_webdriver --protocol h2 \
  --output-dir target/safari-h2-capture
```

Use a fresh output path for each attempt. Both modes use only `127.0.0.1`.
TLS/H2 uses the existing H2 peer with a generated self-signed certificate.
It requests `acceptInsecureCerts=true` for that WebDriver session and
requires the returned capability to confirm it. HTTP requests and confirms
`false`. Missing, rejected or different capabilities fail before navigation.

Safari Remote Automation must already be enabled. The hosted image enables
it during provisioning. Missing Safari, disabled automation, an unavailable
GUI session or a non-loopback REST listener fails the attempt explicitly.
The adapter does not change permissions, system trust stores or host settings.

The artifact retains the command log and exit status, `result.json` and,
when a page was attempted, `reconnect-204.txt`. TLS/H2 also retains its public
certificate as `peer-certificate.der`. Inspect failures too. Source hashes,
Safari and driver versions, Safari build, OS, architecture, runner image,
returned capabilities and automation mode identify the attempt.
Command timeouts also retain the exchange stage, received byte count and
response framing, excluding response bodies and session identifiers. Framed
REST replies complete without waiting for the driver to close its connection.

## Interpret the result

Success requires a page request, the initial EventSource request and its
reconnect, followed by the terminal observation period. The loopback SSE
peer records request order and timing. TLS/H2 also requires verified H2
ALPN and decoded ordered request fields with stream identities.
It also retains the client preface and startup frames through the first
request, including ordered SETTINGS and connection window updates.

The adapter deletes its WebDriver session, stops and joins its driver, and
retains launch and cleanup failures separately. It records the listener on
its chosen port and requires the launched driver to remain alive. That
listener can belong to Safari's XPC service, which is outside driver cleanup.

TLS/H2 uses an IP target with session certificate bypass. The certificate
names `server.phantom.test`, not the IP. Domain SNI and ClientHello are not
recorded. Compare results by their recorded browser build,
architecture and hosted VM image.

## Implementation references

- [Apple's WebDriver setup](https://developer.apple.com/documentation/webkit/testing-with-webdriver-in-safari)
- [Safari automation isolation](https://developer.apple.com/documentation/webkit/about-webdriver-for-safari)
- [Safari's supported REST commands](https://developer.apple.com/documentation/webkit/macos-webdriver-commands-for-safari-12-and-later)
- [Safari Technology Preview 135](https://developer.apple.com/documentation/safari-technology-preview-release-notes/stp-release-135):
  WebDriver certificate capability support.
- [Selenium's native Safari service arguments](https://github.com/SeleniumHQ/selenium/blob/trunk/py/selenium/webdriver/safari/service.py)

## Next

- [Capture tools](README.md): other peers and fixture formats.
