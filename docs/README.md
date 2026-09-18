# Documentation

Use the shortest path that matches your role.

| Audience | Start here | What it conveys |
| --- | --- | --- |
| Evaluating Phantom | [Project README](../README.md) | Value, maturity, current highlights, first request, and key limits |
| New user | [Getting started](getting-started.md) | Source build, minimal setup, protocol choice, and features |
| Downstream integrator | [Downstream integration](downstream.md) | Revision-pinned submodule layout, mandatory root patches, and validation |
| Integrator | [Using the client](client.md) | Profiles, requests, routes, pools, state, timeouts, and responses |
| SSE or WebSocket user | [SSE](sse.md) · [WebSocket](websocket.md) | Feature-specific APIs and lifecycle boundaries |
| Reviewer or maintainer | [Design](design.md) | Architecture, ownership, security, async, and dependency rules |
| Checking support | [Coverage](coverage.md) | Authoritative current, planned, and unsupported behavior |
| Contributor | [Validation](validation.md) | Evidence, fixtures, adversarial tests, external suites, and gates |
| H3 specialist | [HTTP/3 internals](http3.md) | QUIC, QPACK, capture, diagnostics, and vendored seams |
| Following development | [Roadmap](roadmap.md) | Now, next, and later |
| Security reporter | [Security policy](../SECURITY.md) | Private reporting, supported versions, and disclosure expectations |

## Writing contract

- Guides describe behavior that exists today and lead with a usable path.
- Design defines stable invariants, not usage steps.
- Coverage is the single detailed support contract.
- Validation explains how claims are proved, not what the product promises.
- HTTP/3 internals contain specialist detail that would distract most readers.
- Planned work appears in the roadmap or the planned column of coverage.
- Content is linked rather than repeated.

Contributor workflow and commands live in [CONTRIBUTING.md](../CONTRIBUTING.md)
and [AGENTS.md](../AGENTS.md). Reproducible bugs use the repository's
[bug-report form](https://github.com/bywayhq/phantom/issues/new?template=bug_report.yml).
