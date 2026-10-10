# A47 independent production review

Source approved at a678ec76432e583ce9ed52727f019864d3d2609e. No actionable
correctness or scope findings. Full local conformance module and test module
were read; upstream retained raw hashes match their recorded pinned sources.
The exact upstream receive sites are assignment words CLIENT= and SERVER= in
both compliance and ordinary runs before shell=True. The allowlist excludes
substitution, quotes, escapes, operators, controls, whitespace and nonASCII.
IPv6 brackets do not glob in assignment context. Registry mutations follow
validation, and run restores original files in finally.

This is a shell-safe character boundary, not Docker-reference validation.
The accepted-character set preserves primary grammar spellings, including
digest-algorithm plus, without claiming those invented algorithms run in
Docker. Existing fake digest test remains intentionally outside that promise.
No new shell, Docker, network, test or build execution was performed by this
reviewer. Root's retained eight-method Windows result is OK. Exact ranges,
hashes, rejected hypotheses and source limitations are in the companion JSON.

Remaining gates: full integration gate, pinned Ruff check/format, and the
conformance unittest suite. No vendor package changed in A47 itself.

## Next

- [Findings](findings.md): verification and integration state.
