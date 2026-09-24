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
posture to the same Security tab and is deliberately left unfiltered. Its
findings are keyed by check rather than by a line of code, so dismissing one
would hide every later instance of the same check. They stay open and are
answered here instead.

- **Vulnerabilities.** The advisories Scorecard reports are not in Phantom's
  dependency graph. Each was checked against the workspace lockfile:
  `rustls` and `serde_with` are at the fixed versions, and the rest do not
  appear at all. They come from the standalone lockfiles inside vendored
  packages, which are upstream development metadata for packages the
  workspace excludes from its build.
- **Pinned dependencies.** The one unpinned download is in an upstream CI
  script inside a vendored package. Phantom never runs it. Removing the
  upstream CI directories would both answer this and reduce what Phantom
  redistributes, but it changes a vendored tree, so it belongs to that
  package's next refresh rather than to a patch of its own.
- **Code review.** Approved changesets require a second person. Every change
  reaches `main` through a pull request whose required check must pass, and
  lane work is reviewed against the working agreement before integration,
  but a solo maintainer cannot approve their own pull request.
- **Branch protection.** The `main` ruleset requires signed commits, linear
  history, up-to-date branches, and the `CI required` check, and refuses
  deletion and non-fast-forward pushes. It does not require a pull request,
  because GitHub cannot sign a rebase merge and a squash merge would discard
  each lane's commits; see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Maintained.** Resolves on its own once the repository is older than
  ninety days.
- **Best practices badge.** Not applied for.

A dismissed code scanning alert records its reason and a justification. Reopen
one rather than working around it if the justification no longer holds.

## Disclosure

Please allow maintainers time to reproduce, assess, and fix the issue before
publishing details. Once remediation is ready, maintainers may use a GitHub
Security Advisory to coordinate credit, affected and fixed commits, and
disclosure. Reporters are credited unless they prefer to stay anonymous. Once
Phantom is published to crates.io, maintainers intend to submit fixed
vulnerabilities in published versions to the
[RustSec Advisory Database](https://rustsec.org/).
