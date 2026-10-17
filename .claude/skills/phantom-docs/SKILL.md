---
name: phantom-docs
description: Write, restructure, or review Phantom documentation (README, llms.txt, CHANGELOG.md, crate rustdoc), then check links and examples.
argument-hint: "<page or topic>"
---

# Phantom documentation

Target: `$ARGUMENTS`. Follow the repository's `AGENTS.md` and the user's
agreed scope.

## Place and write the content

- Keep the README to the introduction, a small example, and onward links.
- Write the docs.rs overview in `crates/phantom/src/docs/overview.md`.
- Use the four guide pages beside it for getting started, browser profiles,
  requests and responses, and proxies. `src/guide.rs` publishes the guides.
- Keep option details in API rustdoc and executable programs in `examples/`.
- Open with the reader's task and lead with a working example. Link to another
  guide or API item instead of repeating its explanation.
- Check signatures, defaults, and feature requirements against the source.
  Check browser claims against retained evidence.
- Link new content from its entry point and compile-check Rust examples.
- Add a changelog entry for user-visible changes, with a migration note for a
  breaking API change.

## Check

```sh
python scripts/docs/check_docs.py
scripts/dev/with-cargo-lock.sh cargo test -p phantom-http --all-features --locked --doc
```

For rustdoc changes, also run
`RUSTDOCFLAGS="-D warnings" scripts/dev/with-cargo-lock.sh cargo doc --workspace --all-features --no-deps --locked`.

The checker cannot verify API claims or readability. Reread the examples and
explanations together before you commit.
