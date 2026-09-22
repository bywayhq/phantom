# Security policy

Phantom handles untrusted network input across TLS, HTTP, proxy, WebSocket, and
QUIC boundaries. Please report suspected vulnerabilities privately so that
maintainers can investigate and fix them before public disclosure.

## Supported versions

Phantom is pre-1.0 and has no published releases.

| Version | Supported |
| --- | --- |
| Latest commit on the default branch | Yes |
| Older commits | No |
| Forks and locally modified vendored packages | No |

Security fixes land on the default branch. If your project pins a Git
revision, move to a revision that contains the fix.

## Reporting a vulnerability

**Do not report a vulnerability in a public issue, pull request, or
discussion.**

Report it through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**, or go
directly to the
[new advisory form](https://github.com/bywayhq/phantom/security/advisories/new).
Only maintainers can see the report.

If that form is unavailable, open a public issue that asks maintainers to
establish private contact. Do not include any vulnerability details in that
issue.

Include, when available:

- the affected commit and platform;
- the protocol, route, and Cargo features involved;
- a minimal reproduction or malformed input;
- the expected and observed behavior;
- the security impact and the attacker position it requires; and
- whether the report or proof has been shared elsewhere.

Do not include secrets, credentials, private certificates, packet payloads, or
other users' data. Redact captures to the minimum needed to reproduce the
issue.

## What to expect

Phantom is experimental and offers no security service-level agreement;
response times are best-effort. Maintainers aim to:

1. acknowledge the report;
2. reproduce it and assess its impact;
3. keep you informed of progress and ask before sharing your details; and
4. prepare a fix and coordinate disclosure with you.

## Scope

In scope: the `phantom-http` facade and the workspace crates it depends on
(`phantom-net`, `phantom-profile`, `phantom-quic-btls`), and Phantom's patches
to the vendored packages under `vendor/`. Examples:

- certificate or hostname verification bypass;
- a configured proxy, route, or protocol boundary being bypassed, including a
  silent fallback to a direct connection;
- disclosure of credentials, cookies, key-log material, or payloads, including
  through errors, `Debug` output, or tracing;
- memory-safety issues in the native or vendored boundaries;
- a remotely triggered panic, unbounded allocation, or other resource
  exhaustion; and
- protocol validation failures with a concrete security consequence.

Out of scope, as normal bug reports:

- a fingerprint mismatch or detection by a server, without another security
  consequence; please file a bug with a bounded capture and exact client
  provenance;
- behavior that only occurs after explicitly disabling certificate
  verification with `ServerAuthentication::Disabled`; and
- the test kit (`phantom-testkit`), examples, fuzz targets, and the capture
  and conformance scripts under `scripts/`, unless the issue affects library
  users.

Report a vulnerability in upstream code that Phantom has not modified to the
upstream project. If Phantom's pinned or vendored copy then needs an update, a
private report here is welcome too.

## Disclosure

Please allow maintainers time to reproduce, assess, and fix the issue before
publishing details. Once remediation is ready, maintainers may use a GitHub
Security Advisory to coordinate credit, affected and fixed commits, and
disclosure. Reporters are credited unless they prefer to stay anonymous. Once
Phantom is published to crates.io, maintainers intend to submit fixed
vulnerabilities in published versions to the
[RustSec Advisory Database](https://rustsec.org/).
