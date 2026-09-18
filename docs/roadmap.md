# Roadmap

This page is for users and contributors following active direction. Exact
current support lives in [Coverage](coverage.md).

## Now

- Complete the remaining client and proxy-route work without introducing
  direct or cross-protocol fallback.
- Add replay, retry, and streaming-body-produced trailer behavior only with
  explicit ownership and bounded lifecycle rules.
- Finish browser-backed SSE reconnect evidence and the current WebSocket
  hardening slice.

## Next

- Expand cross-platform debug and release gates.
- Broaden fuzzing, sanitizer coverage, lifecycle regressions, and soak tests.
- Keep vendored patches reproducible and review dependency updates in
  isolation.

## Later

- Add browser versions, platforms, and non-browser profiles from fresh capture
  evidence.
- Add H3 upgrade, UDP-capable proxying, and extended CONNECT after their route
  and failure semantics are proven end to end.
- Profile representative cold and warm connections, proxy routes,
  multiplexing, streaming bodies, SSE, and WebSocket workloads before
  optimizing them.

## Completed foundation

The workspace, capture testkit, TLS and ordered H1 path, H2 path, initial
browser-family profiles, forced H3 path, and ordered static request trailers on
exact H1/H2/H3 and negotiated H1/H2 have passed their phase acceptance
criteria. Code, tests, [Design](design.md), and [Validation](validation.md) are
the maintained record of those decisions.
