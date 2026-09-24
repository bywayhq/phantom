---
name: phantom-docs
description: Write, restructure, or review Phantom documentation (README, docs/, llms.txt, CHANGELOG.md, crate rustdoc) to the repository's documentation contract, then prove it with the docs checker and doctests.
argument-hint: "<page or topic>"
---

# Phantom documentation

Target: `$ARGUMENTS`. The authority is
[Writing the documentation](../../../docs/internals/documentation.md). Read it
before you edit; this skill lists the steps and the checks.

## Place the content

1. Name the reader (evaluator, builder, specialist, contributor, or coding
   agent) and their level (new, aware, expert).
2. Pick the one page type that serves them: start, tutorial, guide,
   reference, explanation, or internals. Content of another type goes to the
   page that owns it, with a link back.
3. Fingerprinting is explained only in `docs/fingerprinting.md`, and terms
   only in `docs/reference/glossary.md`. Link to their anchors.

## Write

- Open with a one- or two-sentence lede, then the `> For ...` reader line.
  End with `## Next`.
- A guide section names a task, states the goal in one sentence, and leads
  with a compiling example. Limits go in a final `## Limits`.
- Check every API name and signature in `crates/` before you write it.
- Check every claim about a browser against `docs/explanation/validation.md`
  or a fixture. Date claims about other projects.
- Add a `CHANGELOG.md` entry under `Unreleased` for a user-visible change,
  with a "Migrate:" note for a breaking one.
- Add a new page to `docs/README.md` and `llms.txt`. A new page with Rust
  blocks under `docs/guides/` needs a `#[cfg(doctest)]` include in
  `crates/phantom/src/lib.rs`.

## Check

```sh
python scripts/docs/check_docs.py
scripts/dev/with-cargo-lock.sh cargo test -p phantom-http --all-features --locked --doc
```

For rustdoc changes, also run
`RUSTDOCFLAGS="-D warnings" scripts/dev/with-cargo-lock.sh cargo doc --workspace --all-features --no-deps --locked`.

The checker cannot see reflexive lists of three, bold used for emphasis,
repeated sentence templates across sections, or unsupported claims. Reread
the diff for those before you commit.
