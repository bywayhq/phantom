# External conformance and interoperability

External suites complement Phantom's packet and hostile-peer differentials.
They do not prove browser wire parity, and a server-oriented suite is not
reported as client conformance.

## Suite selection

| Suite | Phantom use | Planned execution tier |
| --- | --- | --- |
| [Autobahn Testsuite](https://github.com/crossbario/autobahn-testsuite) | Drive the public WebSocket client against the fuzzing server. Retain the machine-readable case result and convert every failure into a focused Rust regression. | Eight-case smoke set on relevant pull requests; full supported corpus on a schedule and before releases. |
| [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) | Package a thin Phantom client endpoint and declare only supported QUIC/H3 cases. Exercise Phantom against independent server implementations and the runner's network scenarios. | Scheduled Linux container job; selected release gate. |
| [Web Platform Tests](https://github.com/web-platform-tests/wpt) | Execute selected EventSource resources from a pinned sparse checkout, adapting their assertions through Phantom's public API. Run the original JavaScript tests against real browsers only when gathering browser behavior. | Eleven-case smoke set on relevant pull requests; 29 selected scenarios on a schedule and before releases. |
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

External adapters are test-only binaries or scripts. They may translate a
suite's control protocol into public Phantom calls, but they must not expose
test hooks in production crates or bypass normal request validation.

- The Autobahn adapter performs the suite's case-discovery, case-run, echo,
  close, and report-update sequence through Phantom's WebSocket API. It uses
  WSS with an ephemeral local CA passed through the ordinary additional-root
  API; certificate and hostname verification remain enabled.
- The QUIC Interop adapter accepts the runner's environment variables and
  output directory, performs supported downloads through forced H3, and exits
  with the runner's unsupported-case code for everything else.
- The WPT adapter starts the pinned `wptserve` HTTP/1 server directly on an
  ephemeral loopback port. Its short-lived CA is passed through the ordinary
  additional-root API; it does not alter DNS, OS trust, or production code.
  Original WPT paths remain the case identifiers.
- WPT and curl imports record the upstream revision and original case path.
  Generated protocol data remains separate from handwritten test intent.

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

## Autobahn execution

The runner pins both the suite tag and container digest. Its smoke configuration
covers text and binary framing, Ping/Pong, invalid reserved bits and opcodes,
fragmentation with an interleaved control frame, invalid UTF-8, and Close. The
scheduled configuration runs the supported RFC 6455 corpus while excluding the
performance/limit group and the unsupported compression extension groups.

Run either tier from the repository root:

```console
python3 scripts/conformance/autobahn.py smoke
python3 scripts/conformance/autobahn.py full
```

Strict `OK` and neutral `INFORMATIONAL` results pass. `NON-STRICT`, `WRONG CODE`,
and `FAILED BY CLIENT` are preserved as warnings. Failed, unclean, missing, or
unknown results fail the run. CI retains the suite's bounded index plus a
sanitized summary, metadata, case configuration, and container log; per-case
wire logs and generated TLS keys are not uploaded.

## WPT EventSource execution

The runner fetches the exact pinned WPT commit into a temporary sparse
checkout and executes its original EventSource resource handlers. The Rust
adapter uses `Client`, `Session::event_source`, and `SseStream` without private
test hooks. The smoke set covers streaming data, field parsing, event names,
line endings, BOM handling, UTF-8, MIME validation, and the EventSource request
defaults. The full set adds reconnect state, `Last-Event-ID`, retry timing,
empty-ID transitions, NUL rejection, incomplete final events, and status-code
handling.

Run either tier from the repository root:

```console
python3 scripts/conformance/wpt_eventsource.py smoke
python3 scripts/conformance/wpt_eventsource.py full
```

These are selected native-client adaptations, not a claim that Phantom passes
the browser EventSource API or general Fetch WPT. DOM events, ready state,
workers, CORS, credentials policy, realms, and browser lifecycle behavior are
outside this adapter. It currently uses HTTP/1.1; Phantom's deterministic SSE
integration tests cover the same response-body abstraction over HTTP/2 and
HTTP/3. CI retains only the bounded case manifest, result summary, metadata,
adapter output, and server log. The sparse checkout and generated keys are
discarded.
