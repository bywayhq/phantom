# Capture Safari on a hosted Mac

Run Safari EventSource reconnect captures on a disposable macOS runner.
The workflow records the installed browser, ordered requests and cleanup.

## Run the capture

Select the **Safari loopback capture** workflow and its reviewed source ref.
It runs independent HTTP and TLS/H2 jobs on `macos-latest`. Each job opens
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
returned capabilities and automation mode identify the attempt. The runner
label alone does not pin a browser build.

## Interpret the result

Success requires a real page request, the initial EventSource request and
its reconnect, followed by the existing terminal observation period. Request
order and timing come from the existing loopback SSE peer. Driver creation
alone does not establish capture success. TLS/H2 also requires the peer's
verified H2 ALPN and decoded ordered request fields with stream identities.
An HTTP/1.1 connection cannot satisfy that check.

The adapter deletes its exact WebDriver session, stops and joins its driver,
and retains launch and cleanup failures separately. It does not kill other
Safari processes. Session deletion acknowledgement does not establish that
every system XPC process has exited. Safari's REST listener can belong to its
XPC service rather than the launched driver PID. The adapter records that
one port's listener and requires the launched driver to remain alive. This
is a disposable runner capture, not isolation from hostile local processes.

The HTTP attempt establishes no TLS behavior. The TLS/H2 attempt uses an IP
target and explicit session certificate bypass. The certificate names
`server.phantom.test`, not the IP. This captures neither domain SNI nor a
ClientHello fingerprint, and establishes no ordinary Safari trust behavior.
The peer does not retain the client's SETTINGS frame inventory.
Neither mode establishes H3, a whole Safari profile or equivalence to
interactive browsing. Hosted arm64 and Intel VMs are separate environments.
An arm64 run does not establish Intel or physical Mac results.

## Implementation references

- [Apple's WebDriver setup](https://developer.apple.com/documentation/webkit/testing-with-webdriver-in-safari)
- [Safari automation isolation](https://developer.apple.com/documentation/webkit/about-webdriver-for-safari)
- [Safari's supported REST commands](https://developer.apple.com/documentation/webkit/macos-webdriver-commands-for-safari-12-and-later)
- [Safari Technology Preview 135](https://developer.apple.com/documentation/safari-technology-preview-release-notes/stp-release-135):
  WebDriver certificate capability support.
- [Selenium's native Safari service arguments](https://github.com/SeleniumHQ/selenium/blob/trunk/py/selenium/webdriver/safari/service.py)

## Next

- [Capture tools](README.md): other peers and fixture formats.
- [Validation](../../docs/explanation/validation.md): retained browser evidence.
