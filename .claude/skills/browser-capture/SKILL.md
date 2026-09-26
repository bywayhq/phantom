---
name: browser-capture
description: Record browser wire evidence (TLS, HTTP/2, HTTP/3, WebSocket, SSE, client hints) against loopback servers with scripts/capture and retain it under fixtures/. Use when a profile or recipe needs fresh browser captures or when checking capture provenance.
argument-hint: "<area> <browser>"
---

# Browser captures

`scripts/capture/README.md` documents each capture tool and its exact
commands; `docs/explanation/validation.md` records why each retained fixture
exists. Read the relevant sections before capturing.

## Rules

- Launching a local browser needs the human's approval for the session.
- Capture only against the loopback listeners the tools start; they refuse
  non-loopback addresses. Live services may supplement local evidence but
  never replace it.
- For desktop browsers, write a JSON manifest and run every capture with
  `run_matrix.py` in one command instead of driving each tool run by run:
  `uv run --no-project --python 3.10 --with-requirements scripts/requirements.txt python -m scripts.capture.run_matrix <manifest>.json`.
  Check the jobs first with `--dry-run`. It runs jobs side by side, runs
  tools whose evidence depends on timing alone, skips jobs its work directory
  recorded as complete, and retries a failed job once. Read the summary table
  and `results.json`, and each failed attempt's log, before retaining
  anything. The manifest format and safety rules are in the capture README
  under "Run captures from a manifest".
- Run a tool directly, from the repository root with Python 3.10 through
  `uv`, for Android browsers, `manual`, a tool the runner does not list, or a
  single diagnostic run: for example
  `uv run --no-project --python 3.10 python -m scripts.capture.<tool>`.
- Each browser run uses a fresh temporary profile (`browser_launch.py`).
  Headless, headful, and manual captures are compared, never assumed equal.
- Retain fixtures at `fixtures/<area>/<browser>/<exact-version>/<host>/`, for
  example `fixtures/http2/chrome/154.0.8037.58/windows-11-26200/`. Provenance
  is the exact browser version and host OS; a Windows capture never backs a
  macOS recipe.
- Fixtures are machine-focused and byte-exact (`.gitattributes` marks
  `fixtures/**` as `-text`). Put rationale and reproduction commands in
  `docs/explanation/validation.md` or the capture README, not in the fixture.
- Never retain credentials, authorization headers, or cookies other than a
  tool's own probe cookie.
- Bind port 0 for loopback listeners. The Windows development host reserves
  UDP ports 49841 to 50959.

## After capturing

1. Run the capture tests: the `unittest discover -s scripts/capture/tests`
   command in `AGENTS.md`.
2. Record in `docs/explanation/validation.md` what the capture shows and how
   the browser was launched.
3. Only then change the profiles or recipes that depend on it.
