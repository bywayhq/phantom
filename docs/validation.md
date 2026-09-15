# Validation model

Successful connectivity is not proof of browser-compatible behavior.

Wire-sensitive changes will be checked at three levels:

1. Deterministic local protocol assertions
2. Normalized packet, frame, or qlog differentials against a pinned fixture
3. Supplemental live checks against services such as Peet and Pingly

Normalization may remove values that are intentionally nondeterministic, such as random bytes, connection identifiers, packet numbers, timestamps, and cryptographic key material. It must not erase ordering, presence, negotiated values, or other behavior the profile claims to control.

The TLS testkit preserves complete TLS record bytes and the exact reassembled ClientHello handshake. Its strict decoder exposes the ordered semantic fields asserted by the current TLS transport tests. Broader normalization will be added only when a retained browser fixture requires it, so each normalized field has an immediate differential assertion.

Compatibility claims must cite the exact browser capture and differential fixture that supports them. A successful response or summary fingerprint alone is not evidence of parity.
