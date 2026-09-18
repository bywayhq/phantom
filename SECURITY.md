# Security policy

Phantom handles untrusted network input across TLS, HTTP, proxy, WebSocket, and
QUIC boundaries. Please report suspected vulnerabilities privately so they can
be investigated before public disclosure.

## Supported versions

Phantom is experimental and has no published releases. Security fixes target
the latest commit on the repository's default branch. Older commits, forks,
and vendored modifications are not maintained as supported release lines.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting from the repository's **Security**
tab, or open a [private security advisory](https://github.com/bywayhq/phantom/security/advisories/new).

Include, when available:

- the affected commit and platform;
- the protocol, route, and feature flags involved;
- a minimal reproduction or malformed input;
- the expected and observed behavior;
- the security impact and required attacker position; and
- whether the report or proof has been shared elsewhere.

Do not include secrets, credentials, private certificates, packet payloads, or
other users' data. Redact captures to the minimum material needed to reproduce
the issue.

If private reporting is unavailable, open a public issue asking maintainers to
establish private contact. Do not include vulnerability details in that issue.

## What to report

Examples include:

- certificate or hostname verification bypass;
- a configured proxy or protocol boundary being bypassed;
- credential, cookie, key-log, or payload disclosure;
- memory-safety issues in native or vendored boundaries;
- remotely triggered panic, unbounded allocation, or resource exhaustion; and
- protocol validation failures with a concrete security consequence.

A fingerprint mismatch without a security consequence belongs in a normal bug
report, preferably with a bounded capture and exact client provenance.

## Disclosure

Please allow maintainers time to reproduce, assess, and prepare a fix before
publishing details. Response time is best-effort; this experimental project
does not currently offer a security service-level agreement. Once remediation
is ready, maintainers may use a GitHub Security Advisory to coordinate credit,
affected commits, and disclosure.
