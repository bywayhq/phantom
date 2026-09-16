# Async and feature policy

Phantom is async-first and currently targets Tokio. That is a concrete runtime
choice, not a permanent claim that other runtimes are impossible. A runtime
abstraction will be introduced only when a second implementation exists and
can prove the same cancellation, timer, socket, DNS, and driver-lifecycle
semantics.

Libraries enable only the Tokio features they use; Phantom does not enable
Tokio's `full` feature. Library code never creates a process-global runtime or
installs a tracing subscriber. Public client network operations run inside a
compatible runtime. Runtime selection remains out of scope until a second
implementation can prove the same lifecycle contract.

Direct requests require a current Tokio runtime with network I/O enabled. A
missing runtime and a runtime built without I/O are both reported as
`RuntimeUnavailable`. Tokio exposes no stable I/O-driver capability query, so
Phantom contains only Tokio's exact I/O-disabled runtime panic at the network
operation boundary; unrelated panics continue unwinding.

## Operation ownership

One request operation owns its attempts, drivers, response body, deadline, and
cancellation path. The rules are:

- bodies are pull-driven and backpressured through `http_body::Body`;
- bounded channels are used only at ownership boundaries, never as an
  unbounded response buffer;
- dropping a request or body signals protocol cancellation and cannot leave a
  detached driver alive indefinitely;
- locks are not held across `.await` unless the protected value is explicitly
  an asynchronous state machine;
- retry and redirect logic checks body replayability before another attempt;
- timeouts cover named phases and a whole-operation deadline, with one owner
  deciding which expiration wins;
- shutdown is idempotent and deadline-bounded;
- public cancellation and backpressure behavior is documented and tested.

Core response streaming is always present. A future `stream` feature may add a
`futures_core::Stream` adapter; it will not switch the body from buffered to
streaming or change transport semantics.

## Cargo features

The internal transport crates keep ordinary protocol support unconditional for
now. Their first optional capabilities are the concrete diagnostic leaves
`phantom-net/qlog` and `phantom-quic-btls/keylog`. Both are default-off and
still require an explicit bounded runtime sink; enabling either feature alone
does not emit diagnostics or change normal wire behavior. When the public
`Client` facade owns these capabilities, its features will forward to the same
leaves and remain additive so Cargo feature unification cannot disable behavior
selected elsewhere.

The intended vocabulary is:

| Group | Candidate features | Contract |
| --- | --- | --- |
| Protocol engines | `http1`, `http2`, `http3` | Compile support; runtime protocol policy still selects exact, negotiate, or race behavior. |
| Body adapters | `stream` | Adds ecosystem adapters only; core backpressured bodies remain available. |
| Session policy | `cookies` | Adds a cookie store integration; client-hint state stays separately controlled because it has different rules. |
| Content decoding | `gzip`, `brotli`, `deflate`, `zstd` | Response `Content-Encoding`; distinct from TLS certificate compression. |
| Routes | `socks`, later `masque`, possibly `system-proxy` | Compiles a route implementation; never enables proxy discovery or fallback by itself. |
| Higher protocols | `sse`, `websocket` | `sse` adds the bounded pull decoder. `websocket` adds ordered H1 Upgrade plus bounded `Stream`/`Sink` message I/O. |
| Diagnostics | `qlog`, `keylog` | Compiles support; emission still requires an explicit bounded runtime sink. |
| Convenience | `full` | Enables all stable public optional capabilities, excluding tests and unstable experiments. |

There will be no mutually exclusive `runtime-*` or `tls-*` flags without real
coexisting implementations. If a second runtime lands, both runtime features
must be additive, and selecting neither or several must have an explicit
builder contract rather than compile-order behavior.

Every introduced leaf feature is checked by CI with `--no-default-features`,
alone, in the default set, and under `--all-features`; representative pairs
cover meaningful interactions once one crate owns more than one leaf.
Platform jobs cover the native dependency matrix. Documentation labels
compile-time availability separately from the runtime option that activates
it.

This policy follows Cargo's
[additive feature guidance](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification),
[Tokio's recommendation](https://docs.rs/tokio/latest/tokio/#feature-flags)
that libraries enable only the features they need rather than `full`, and the
capability-oriented feature surfaces used by
[Hyper](https://docs.rs/hyper/latest/hyper/#features) and
[Reqwest](https://docs.rs/reqwest/latest/reqwest/#optional-features).

The public `phantom` crate has an empty default set. `cookies` compiles the
bounded cookie jar but does not activate it until
`SessionBuilder::cookies` or `SessionBuilder::cookie_jar` is selected. `sse`
enables the server-sent event response decoder documented in [sse.md](sse.md).
`websocket` enables the ordered H1 opening handshake and bounded message
facade documented in [websocket.md](websocket.md). `full` enables all stable
optional public capabilities. Core response
streaming and session-owned H2 reuse remain unconditional.
