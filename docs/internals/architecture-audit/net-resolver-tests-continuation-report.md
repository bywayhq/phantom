# Resolver and address-selection test continuation

Baseline df2ae9b7d87567907a2f273068220349dcd4750b, read-only. Exact SHA256/ranges in matching coverage JSON. Three complete files, 604 lines. No builds, runtime tests or sockets executed. No new supported production finding. This agent's cumulative remaining inventory falls from 64 to 61 paths; this is not team-wide coverage.

host_resolver/tests.rs:1-195 independently checks canonical-name override order, bypass of resolver/cache, replacement and empty overrides, literal IP bypass, uncached calls on each lookup, shared cached lookup/lifetime expiry, selected port rebuilding, error kind/text preservation, and changing resolver after configuring cache. Counting callback records names/calls and returns through a real five-millisecond timer. Cache expiry uses wall-clock sleeps rather than a controlled clock; no cancellation/stalled-runtime/drop assertion lives in this file (separate address-cache tests/remedies own that behavior). Mutex diagnostic recording intentionally skips poisoned recorder state in the test; no production failure-swallowing claim follows.

tcp/address_racing/tests.rs:1-286 scripts each dial outcome and fallback through channels. Assertions distinguish first IPv6 preference, fallback IPv4, family alternation after failure, two-attempt maximum and family preference, success dropping loser futures, single-family racing, last-error preservation and no-address invalid input. CancelGuard records actual dropped pending futures separately from completed ones. The tests wait 16 scheduler yields rather than explicit start acknowledgments, and finish awaits have no overall deadline. These are verification robustness gaps, not source-confirmed race defects. Tests use reserved documentation IP addresses without opening sockets; they are callback-only.

tcp/tests/address_selection.rs:1-123 verifies actual loopback IPv4 fallback after refused IPv6 under sequential/backup/racing profiles. Windows checks the configured 250/300 ms second-attempt range and distinguishes Firefox's all-IPv6 refusal wait from Chromium's early second IPv6 attempt. Listener probes may explicitly skip when IPv6 is unavailable/taken. Refused ports are reserved by a temporary listener and then closed; subsequent refusal remains a host-state assumption, not a permanently owned endpoint. Timing tests allow Windows refusal behavior but lack an enclosing absolute deadline and can skip. No macOS/Linux/Windows execution or measured browser match is claimed.

Earlier full production owners (HostResolver, TCP connection/address selection and racing) remain in prior reports; reading these tests does not reclaim them. The A35 cookie fix handed off separately; its source coverage and root-reported baseline are in a35-cookie-handoff.md. A32/A33 independent source approval is net-contracts-independent-review.md. Capture A30/A31 independent review waits for the authorâ€™s repaired final commit and parent assignment.

## Next

- [Coverage](coverage.md): review boundaries and remaining work.
- [Findings](findings.md): confirmed defects and verification.
