# Architecture

Phantom separates request intent, session behavior, browser profiles, and wire transport.

```text
public client API
       |
session and browser behavior
       |
validated browser profile
       |
TLS / HTTP / QUIC transport
```

## Current crates

`phantom` is the public facade. It may coordinate requests and session behavior as those capabilities land.

`phantom-profile` owns browser-neutral profile identity and metadata. It must not depend on sockets, an async runtime, or a particular TLS implementation.

`phantom-testkit` owns deterministic, bounded wire observations used by tests. Runtime crates must never depend on it.

## Planned seams

The networking crate will consume validated protocol configuration. It must not branch on browser family. Backend-specific types stay private.

We will add a backend trait only when a second real backend requires interchangeability. Until then, connection construction remains a concrete internal boundary.

## Dependency rules

- Dependencies point from the facade toward profile and networking mechanisms.
- Profiles never contain cookies or other mutable session state.
- Ordered wire fields use ordered representations.
- Public options require an implementation and observable test.
- Unsupported profile capabilities fail explicitly.
