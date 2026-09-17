# HTTP client API ergonomics

This review compares Phantom's public facade with established Rust and
non-Rust HTTP clients. It is an input to API stabilization, not a compatibility
goal: wire fidelity and explicit protocol ownership still take precedence over
familiar convenience.

## Evidence

| Client | Useful precedent | Friction to avoid |
| --- | --- | --- |
| [reqwest](https://docs.rs/reqwest/latest/reqwest/struct.Client.html) and [hyper](https://docs.rs/hyper/latest/hyper/body/) | A cheap cloneable client owns shared pools; bodies are backpressured streams. | One total timeout is not a substitute for read inactivity; upgrades must not select an incompatible ALPN path. |
| [libcurl](https://curl.se/libcurl/c/libcurl.html) | Raw response callbacks and distinct proxy/origin TLS controls. | Sticky flat option bags, implicit environment proxies, and headers retained across redirects obscure ownership. |
| [Go `net/http`](https://pkg.go.dev/net/http) | Reusable concurrency-safe clients/transports, constrained replay, and phase tracing. | Response-body lifecycle affects reuse but has historically been hard to understand; header maps lose wire spelling and global order. |
| [Requests](https://requests.readthedocs.io/en/stable/user/advanced/) and [HTTPX](https://www.python-httpx.org/advanced/clients/) | Session defaults with request overrides, prepared requests, explicit streaming, and phase-specific timeouts. | Prepared flows can bypass session/environment state; manual streams need an obvious close path; mutable hooks can invalidate wire guarantees. |
| [OkHttp](https://github.com/square/okhttp/blob/master/README.md) | One reusable client, single-use cancellable calls, derived clients sharing pools, and dedicated WebSocket/SSE APIs. | Transparent recovery can duplicate an application operation; interceptor ordering becomes part of retry and redirect behavior. |
| [Undici](https://github.com/nodejs/undici/blob/main/docs/docs/api/Dispatcher.md) | A pooled agent over a lower dispatcher seam, raw response headers, and dedicated upgrade APIs. | Unconsumed bodies can exhaust pools; generic errors obscure timeout phases; a long-lived H2 stream must not block siblings. |

## Keep

- Ordered request fields and `OrderedResponseHeaders` remain the fidelity
  surfaces; `HeaderMap` is only the ecosystem-compatible view.
- `ResponseBody` remains an `http_body::Body` with protocol-aware cancellation.
- Redirects, narrow retries, protocol selection, routes, WebSocket, and SSE stay
  explicit and independently testable.
- Proxy and origin TLS policy remain distinct. Environment proxy discovery, if
  added, is an explicit loader rather than ambient behavior.
- HTTP status is not a transport failure. A future status convenience remains
  separate from request execution.

## Resolve before API stabilization

1. Decide whether the reusable pooled object becomes `Client`. Most ecosystems
   use that name for the cheap cloneable pooled handle; Phantom currently calls
   the one-shot configuration `Client` and the pooled state `Session`.
2. Add phase-aware timeout policy with client defaults and request overrides:
   connection/TLS, pool admission, request write inactivity, response head,
   response read inactivity, and an optional whole-operation deadline. SSE and
   WebSocket retain separate long-lived idle policy.
3. Add streaming request bodies only with explicit replay semantics. Owned
   bytes are replayable; a stream is one-shot unless backed by a deliberate
   factory. Redirect, client-hint, and retry paths reject an unavailable replay
   before consuming the body.
4. Add bounded body collection and direct ordered-header/trailer access without
   replacing the streaming response or silently buffering an unlimited body.
5. Record every internal attempt and bounded retry in tracing and response
   metadata without including field values or credentials.
6. Document what unpolled, partially consumed, completed, and dropped bodies do
   to H1 reuse and H2/H3 streams.

## Required lifecycle regression

Run a long-lived SSE response and concurrent bodied requests on the same H2 and
H3 session. Backpressure or cancellation on the SSE stream must not stall,
cancel, or close siblings. This specifically guards the scheduling class seen
in [Undici issue 5524](https://github.com/nodejs/undici/issues/5524).

Generic middleware, custom transport traits, general retry policy, blocking
adapters, caches, and automatic decompression remain deferred until a concrete
use case justifies their ownership and replay semantics.
