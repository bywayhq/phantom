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
- One `HttpProxy` route selects absolute-form forwarding for plaintext HTTP/1
  and CONNECT for HTTPS. Unsupported combinations fail before I/O; callers do
  not choose a wire operation that can contradict the target URI.
- HTTP status is not a transport failure. A future status convenience remains
  separate from request execution.

## Stabilization decisions

1. The reusable pooled object is `Client`. It is cheap to clone, and clones
   share pools and bounded cross-request state. Independently built clients are
   isolated. The former `Session` names remain hidden compatibility aliases
   during migration and are not the API taught to new callers.
2. The first phase-aware timeout policy is landed with client defaults and
   complete request overrides: pool admission, connection setup, response
   head, response read inactivity, and an optional whole-operation deadline.
   Connection setup currently owns DNS, proxy, TLS/QUIC, and protocol startup;
   response-head owns the complete request-body write. A separate write-idle
   clock remains deferred until it can be enforced at every transport, and a
   separate TLS phase waits for lower-layer ownership that can cancel it
   independently. SSE hands established streams to its own idle policy;
   WebSocket retains a separate lifecycle surface.
3. Streaming request bodies are landed with explicit replay semantics. Owned
   bytes are replayable and streams are one-shot. Redirect and client-hint
   paths reject an unavailable second attempt before polling the body again.
   Deliberate replay factories remain a later ergonomics slice.
4. Add bounded body collection and direct ordered-header/trailer access without
   replacing the streaming response or silently buffering an unlimited body.
5. Record every internal attempt and bounded retry in tracing and response
   metadata without including field values or credentials.
6. Document what unpolled, partially consumed, completed, and dropped bodies do
   to H1 reuse and H2/H3 streams.

## Required lifecycle regression

Run a long-lived SSE response and concurrent bodied requests on the same H2 and
H3 client. Backpressure or cancellation on the SSE stream must not stall,
cancel, or close siblings. This specifically guards the scheduling class seen
in [Undici issue 5524](https://github.com/nodejs/undici/issues/5524).

Generic middleware, custom transport traits, general retry policy, blocking
adapters, caches, and automatic decompression remain deferred until a concrete
use case justifies their ownership and replay semantics.
