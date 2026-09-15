# Validation model

Successful connectivity is not proof of browser-compatible behavior.

Wire-sensitive changes will be checked at three levels:

1. Deterministic local protocol assertions
2. Normalized packet, frame, or qlog differentials against a pinned fixture
3. Supplemental live checks against services such as Peet and Pingly

Normalization may remove values that are intentionally nondeterministic, such as random bytes, connection identifiers, packet numbers, timestamps, and cryptographic key material. It must not erase ordering, presence, negotiated values, or other behavior the profile claims to control.

Every built-in profile will eventually report one of these evidence levels:

- Experimental: accepted by the implementation but not proven against a browser capture
- Locally verified: covered by deterministic protocol evidence
- Differentially verified: compared against a pinned browser capture

A profile cannot be promoted based only on a successful response or a single summary fingerprint.
