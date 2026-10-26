# Security policy

Phantom handles untrusted network input across TLS, HTTP, proxy, WebSocket, and
QUIC boundaries. Please report suspected vulnerabilities privately so that
maintainers can investigate and fix them before public disclosure.

## Supported versions

Security fixes target the latest release and the default branch.

| Version | Supported |
| --- | --- |
| Latest published release | Yes |
| Latest commit on the default branch | Yes |
| Older releases and commits | No |
| Forks and locally modified vendored packages | No |

Install the latest patch release for security fixes. If your project pins a
Git revision, move to a revision that contains the fix. Phantom's bundled
dependency patches are included in this support policy.

## Reporting a vulnerability

**Do not report a vulnerability in a public issue, pull request, or
discussion.**

Report it through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**, or go
directly to the
[new advisory form](https://github.com/bywayhq/phantom/security/advisories/new).
Use that private form to share the report with maintainers.

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
  verification with `ServerAuthentication::DangerDisabled`; and
- the test kit (`phantom-testkit`), examples, fuzz targets, and the capture
  and conformance scripts under `scripts/`, unless the issue affects library
  users.

Report a vulnerability in upstream code that Phantom has not modified to the
upstream project. If Phantom's pinned or vendored copy then needs an update, a
private report here is welcome too.

## Automated analysis

CodeQL runs through GitHub's default setup on pull requests, on pushes to the
default branch, and weekly. [`.github/codeql/codeql-config.yml`](.github/codeql/codeql-config.yml)
narrows it to code this repository can act on: it excludes `vendor/`, whose
upstream sources change only through each package's `patches/series`, and test
code, whose published test vectors and fixed test credentials are the point of
the file. An organization owner applies that file with the
`github-codeql-config-file` custom property; the languages, query suite, and
schedule stay in the repository's Advanced Security settings.

[OpenSSF Scorecard](.github/workflows/scorecard.yml) reports supply-chain
posture to the same Security tab. Review each finding against the revision
and configuration that produced it.

For a dependency advisory, compare the affected versions with the workspace
`Cargo.lock` and the resolved build graph. Standalone lockfiles inside vendored
packages describe upstream development dependencies; the workspace excludes
those packages as members. Their metadata can still identify a dependency
that needs investigation. Do not dismiss an advisory solely because its
location is under `vendor/`.

For an unpinned download, check its callers before deciding whether Phantom
executes it. Changes to vendored scripts follow the package's `PHANTOM.md`
and patch workflow.

The `main` ruleset requires signed commits, linear history, up-to-date
branches, and the `CI required` check. It refuses deletion and
non-fast-forward pushes. The ruleset does not require a pull request or a
review approval. The integration process separately requires independent
lane review, passing checks, and a fast-forward merge; see
[CONTRIBUTING.md](CONTRIBUTING.md#continuous-integration).

A dismissed code scanning alert records its reason and a justification. Reopen
one rather than working around it if the justification no longer holds.

## Disclosure

Please allow maintainers time to reproduce, assess, and fix the issue before
publishing details. Once remediation is ready, maintainers may use a GitHub
Security Advisory to coordinate credit, affected and fixed commits, and
disclosure. Reporters are credited unless they prefer to stay anonymous.
Maintainers may submit fixed vulnerabilities affecting published packages to the
[RustSec Advisory Database](https://rustsec.org/).
