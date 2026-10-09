# TLS recipe and ALPS test continuation

Read-only baseline df2ae9b7d87567907a2f273068220349dcd4750b. Three complete files, 1,279 lines, leave 24 paths not completed in this agent's additive inventory. JSON records exact Git blob and working bytes separately. No runtime tests or fresh captures were run; no new supported production defect.

## Chromium-family recipe observations

`tls/tests/chrome.rs` lines 1–484: compares actual local connector ClientHellos to frozen desktop and Android recipe fixtures. Ordered cipher/group/version/signature/key-share vectors normalize only GREASE values. Permuted extension identity/count and stable lengths are compared as sorted sets; random ECH payload length is removed from total length. ALPN and host are exact. Trust anchors compare membership except separate Chrome sorting and Opera retained-order tests. Chrome's retained aggregate explicitly requires one order across 60 processes and verifies sorted IDs; Opera tests one order across three connections per connector and a spread across twelve connectors. A per-connection variant checks sixteen draws, and 64 connections per recipe assert the AES-128-GCM GREASE suite.

The assertions have nonzero observation controls, but randomized spread tests remain probabilistic. The main comparison excludes ECH length randomness and does not assert every extension body's bytes or a stable Chromium extension order. A fixture hex parser assumes even known input. These are specific frozen profiles and local generated traffic, not universal browser parity or successful TLS negotiation for all advertised capabilities. Deadline and task ownership reside in the previously reviewed capture helper rather than each test body.

## Firefox fixed order and ECH sizing

`tls/tests/firefox.rs` lines 1–439: desktop and Android fixtures compare complete stable semantic vectors, fixed extension order and layout, single TLS record length/version/type, ALPN and host. Selected delegated credential, record-limit and certificate-compression bodies are literal byte assertions. Android's ticket-order policy is asserted while all other TLS fields are required equal to desktop. Two captured ECH AEAD branches are exact, and 200 local connections allow only those branches with a finite fairness tolerance.

An independent NSS sizing model checks 87 known fresh/resumed TCP/QUIC ClientHellos with explicit counts (41 at 240 payload bytes, 46 at 368). IP literal fixtures require omitted SNI, host-text padding, exact boundary values and nonempty first observations. Earlier preference-less sweeps use their documented label inference rather than claiming recorded absolute preferences. Local IPv4/IPv6-name captures compare the first shape and exact model length. Fixed fixture counts prevent empty oracle passes. Crypto entropy bytes, browser live acceptance and Android resumption order itself are not observed by these fresh ClientHello controls.

## ALPS negotiation and safe diagnostics

`tls/tests/alps.rs` lines 1–356: a connector derived with WebSocket ALPN matches the separately constructed policy ClientHello's stable fields; dropping h2 drops ALPS and Firefox's fixed extension order remains checked. TLS peers round-trip nonempty opaque settings in both directions. Absent ALPS differs from negotiated empty settings. An oversized payload fails connector construction with InvalidConfiguration, safe display and the original InvalidTlsSettings source. A direct tracing helper test records negotiated=true and length=15 with no record_bytes visitation.

The trace subscriber ignores events and arbitrary debug values other than the two expected fields, so its saw_bytes assertion does not prove absence of all possible string/debug/event payload disclosure. The actual production helper was reviewed earlier and records only boolean and length; this is an assertion-scope limit, not an exposure finding. Server tasks are timed when awaited, but handshake/accept and whole-task abort guards are not explicit on early test error. Round-trip bytes establish transport opacity, not HTTP2/HTTP3 application-settings validation.

Existing findings, platform gaps and deferred work keep their prior status.

## Next

- [Coverage](coverage.md): remaining review areas.
- [Findings](findings.md): supported findings and verification.
