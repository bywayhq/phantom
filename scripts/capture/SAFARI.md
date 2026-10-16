# Capture Safari on a hosted Mac

Run one Safari HTTP EventSource reconnect capture on a disposable macOS
runner. The workflow records the installed browser, ordered requests and
cleanup results.

## Run the capture

Select the **Safari loopback capture** workflow and its reviewed source ref.
It runs one headed automation session on `macos-latest`. It attempts
`reconnect-204` once, with no capture retries and a ten minute job limit.
The Python adapter uses only the standard library.

For the same capture on an approved disposable Mac:

```sh
python3.10 -m scripts.capture.safari_webdriver \
  --output-dir target/safari-capture
```

Safari Remote Automation must already be enabled. The hosted image enables
it during provisioning. Missing Safari, disabled automation, an unavailable
GUI session or a non-loopback REST listener fails the attempt explicitly.
The adapter does not change permissions, certificates or host settings.

The artifact contains `result.json` and, when a page was attempted,
`reconnect-204.txt`. Inspect both even when the workflow fails. Source hashes,
Safari and driver versions, Safari build, OS, architecture, runner image,
returned capabilities and automation mode identify the attempt. The runner
label alone does not pin a browser build.

## Interpret the result

Success requires a real page request, the initial EventSource request and
its reconnect, followed by the existing terminal observation period. Request
order and timing come from the existing loopback SSE peer. Driver creation
alone does not establish capture success.

The adapter deletes its exact WebDriver session, stops and joins its driver,
and retains launch and cleanup failures separately. It does not kill other
Safari processes. Session deletion acknowledgement does not establish that
every system XPC process has exited. Safari's REST listener can belong to its
XPC service rather than the launched driver PID. The adapter records that
one port's listener and requires the launched driver to remain alive. This
is a disposable runner capture, not isolation from hostile local processes.

This HTTP capture establishes neither TLS/H2/H3 behavior nor equivalence to
ordinary interactive browsing. Hosted arm64 and Intel VMs are separate
environments. An arm64 run does not establish Intel or physical Mac results.

## Implementation references

- [Apple's WebDriver setup](https://developer.apple.com/documentation/webkit/testing-with-webdriver-in-safari)
- [Safari automation isolation](https://developer.apple.com/documentation/webkit/about-webdriver-for-safari)
- [Safari's supported REST commands](https://developer.apple.com/documentation/webkit/macos-webdriver-commands-for-safari-12-and-later)
- [Selenium's native Safari service arguments](https://github.com/SeleniumHQ/selenium/blob/trunk/py/selenium/webdriver/safari/service.py)

## Next

- [Capture tools](README.md): other peers and fixture formats.
- [Validation](../../docs/explanation/validation.md): retained browser evidence.
