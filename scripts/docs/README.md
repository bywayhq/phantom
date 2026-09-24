# Documentation checker

`check_docs.py` checks the Markdown in this repository against
[Writing the documentation](../../docs/internals/documentation.md). CI runs it
on every change.

> For contributors who edit documentation.

## Run the checker

Run it from the repository root with Python 3.10 or later. It needs only the
standard library:

```sh
python scripts/docs/check_docs.py
python scripts/docs/check_docs.py --only links docs/guides/client.md
python -m unittest discover -s scripts/docs/tests -p 'test_*.py'
```

Each finding prints as `path:line: rule: message`. Any error exits with
status 1; a warning does not.

## What it checks

| Group | Files | Rules |
| --- | --- | --- |
| `links` | `README.md`, `CONTRIBUTING.md`, `llms.txt`, `docs/`, `scripts/*/README.md` | `link`: a relative link names a file that exists, with the same letter case. `anchor`: a fragment names a heading slug, a numbered duplicate such as `#limits-1`, or an HTML `id` in the target page. |
| `shape` | `docs/` except `roadmap.md` and `README.md` | `h1`: one H1, first. `heading-level`: no skipped levels. `banner`: a `> For ...` reader line before the first section, within 12 lines. `next`: the last section is `## Next`. `guide-length`: a warning for a guide over 200 lines. |
| `prose` | The link set, except `llms.txt` and `docs/roadmap.md` | `word`: the banned terms in `BANNED_TERMS`. `em-dash`, `emoji`, `exclamation`, `heading-question`, and `link-text` (the text "here", "this", "click here", or "link"). |

Prose rules skip fenced code, inline code, link targets, URLs, and HTML tags.

## Quote a banned term

When a page must quote a banned term, allow it with an HTML comment. The
comment names rules or terms, separated by commas. `allow` covers its own line
and the next one; `allow-begin` covers every line up to `allow-end`:

```markdown
<!-- docs-check: allow robust, em-dash -->
| "A robust client" | Quoted from the upstream README |

<!-- docs-check: allow-begin word -->
- Stock words: delve, robust, seamless.
<!-- docs-check: allow-end -->
```

## Next

- [Writing the documentation](../../docs/internals/documentation.md): the
  rules this tool enforces, and the ones it cannot.
