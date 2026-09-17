# External conformance and interoperability

External suites complement Phantom's packet and hostile-peer differentials.
They do not prove browser wire parity, and a server-oriented suite is not
reported as client conformance.

## Suite selection

| Suite | Phantom use | Planned execution tier |
| --- | --- | --- |
| [Autobahn Testsuite](https://github.com/crossbario/autobahn-testsuite) | Drive the public WebSocket client against the fuzzing server. Retain the machine-readable case result and convert every failure into a focused Rust regression. | Bounded smoke set on pull requests after the adapter lands; full pinned container on a schedule and before releases. |
| [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) | Package a thin Phantom client endpoint and declare only supported QUIC/H3 cases. Exercise Phantom against independent server implementations and the runner's network scenarios. | Scheduled Linux container job; selected release gate. |
| [Web Platform Tests](https://github.com/web-platform-tests/wpt) | Import relevant EventSource, Fetch, client-hint, and WebSocket scenarios into Phantom-owned loopback fixtures. Run the original tests against real browsers when gathering browser behavior. | Pinned scenario-sync audit on a schedule; minimized Rust regressions on pull requests. |
| [curl tests](https://curl.se/dev/runtests.html) | Mine mature HTTP, proxy, redirect, authentication, timeout, and connection-reuse scenarios. Re-express applicable cases through Phantom's API and bounded peers. | Curated Rust regressions on pull requests; periodic upstream-delta review. |
| [TLS-Anvil](https://github.com/tls-attacker/TLS-Anvil) | Trigger a fresh Phantom client connection for its TLS 1.2/1.3 client cases. Start with a pinned, bounded profile and expand scheduled coverage after failures have stable classification. | Small pinned profile on pull requests after the adapter lands; fuller combinatorial run on a schedule. |
| [BoringSSL runner](https://boringssl.googlesource.com/boringssl/+/master/ssl/test/) | Validate the pinned TLS engine and patches with its native protocol suite. Phantom continues to test its configuration and callback glue separately. | Pin-update and scheduled vendor job. |
| [h2spec](https://github.com/summerwind/h2spec) and [h3spec](https://github.com/kazu-yamamoto/h3spec) | Use their error cases as inputs to Phantom's client-side hostile peers. Both tools primarily target servers, so they are not direct Phantom pass/fail gates. | Upstream-delta review plus deterministic adapted regressions. |

WPT's normal runner executes JavaScript in a browser. Phantom is a transport
client rather than a browser product, so implementing a fake WebDriver or
JavaScript shell would add machinery without testing the public API. Relevant
cases instead keep an upstream test path and commit pinned beside the adapted
Rust assertion.

The curl harness likewise expects the curl executable and libcurl-specific
diagnostics. Phantom should reuse its scenarios, not impersonate its command
line merely to make the harness start.

## Adapter boundaries

Planned external adapters are test-only binaries or scripts. They may translate a
suite's control protocol into public Phantom calls, but they must not expose
test hooks in production crates or bypass normal request validation.

- The Autobahn adapter performs the suite's case-discovery, case-run, echo,
  close, and report-update sequence through Phantom's WebSocket API.
- The QUIC Interop adapter accepts the runner's environment variables and
  output directory, performs supported downloads through forced H3, and exits
  with the runner's unsupported-case code for everything else.
- WPT and curl imports record the upstream revision and original case path in
  a manifest. Generated protocol data remains separate from handwritten test
  intent.

## Gate policy

Pull-request gates stay deterministic, loopback-only, and bounded. They include
adapted regressions and a short Autobahn subset once its adapter is stable.
Once their adapters land, Docker-heavy matrices, network emulation, full
Autobahn, full TLS-Anvil, the QUIC Interop Runner, and the BoringSSL runner will
execute on a schedule. Live public endpoints remain supplemental because their
behavior and availability are not controlled by this repository.

Every external failure is triaged into one of three outcomes:

1. a Phantom defect, minimized into an ordinary regression;
2. an unsupported capability, reported explicitly without weakening the gate;
3. an upstream suite or engine issue, pinned and documented until resolved.

Reports retain suite revision, Phantom revision, feature set, platform, and
case identifiers. They do not retain credentials, response payloads, TLS key
material, or unbounded packet captures.
