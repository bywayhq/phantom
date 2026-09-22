---
name: browser-capture
description: Record browser wire evidence (TLS, HTTP/2, HTTP/3, WebSocket, SSE, client hints) against loopback servers with scripts/capture and retain it under fixtures/. Use when a profile or recipe needs fresh browser captures or when checking capture provenance.
argument-hint: "<area> <browser>"
---

# Browser captures

`scripts/capture/README.md` documents each capture tool and its exact
commands; `docs/validation.md` records why each retained fixture exists.
Read the relevant sections before capturing.

## Rules

- Launching a local browser needs the human's approval for the session.
- Capture only against the loopback listeners the tools start; they refuse
  non-loopback addresses. Live services may supplement local evidence but
  never replace it.
- Run tools from the repository root with Python 3.10 through `uv`, for
  example `uv run --no-project --python 3.10 python -m scripts.capture.<tool>`.
- Each browser run uses a fresh temporary profile (`browser_launch.py`).
  Headless, headful, and manual captures are compared, never assumed equal.
- Retain fixtures at `fixtures/<area>/<browser>/<exact-version>/<host>/`, for
  example `fixtures/http2/chrome/153.0.8010.48/windows-11-26200/`. Provenance
  is the exact browser version and host OS; a Windows capture never backs a
  macOS recipe.
- Fixtures are machine-focused and byte-exact (`.gitattributes` marks
  `fixtures/**` as `-text`). Put rationale and reproduction commands in
  `docs/validation.md` or the capture README, not in the fixture.
- Never retain credentials, authorization headers, or cookies other than a
  tool's own probe cookie.
- Bind port 0 for loopback listeners. The Windows development host reserves
  UDP ports 49841 to 50959.

## After capturing

Run the capture tests (the `unittest discover -s scripts/capture/tests`
command in `AGENTS.md`), record in `docs/validation.md` what the capture shows
and how it was launched, and only then change profiles or recipes that depend
on it.
