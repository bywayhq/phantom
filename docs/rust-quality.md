# Rust production-quality review

This checklist is the final gate for each public slice and for the production
hardening pass. It supplements compilation and tests; it is not a substitute
for protocol evidence.

## API and ownership

- A module owns one protocol or lifecycle responsibility; there are no
  catch-all `common`, `helpers`, or `utils` modules.
- Public types are concrete until two real implementations prove a trait seam.
- Types prevent contradictory state where practical; validation handles
  cross-field and backend capability constraints before I/O.
- Ordered protocol data never passes through an unordered map.
- Owned configuration cannot mutate the identity of a live pooled connection.
- Public structs use constructors/builders or non-exhaustive evolution where
  direct field construction would freeze accidental implementation details.
- Cloning, `Arc`, boxing, dynamic dispatch, and interior mutability each have a
  lifecycle reason rather than being default choices.

## Async and failure behavior

- No runtime-input `unwrap`, `expect`, `panic`, `todo`, or `unimplemented`.
- Errors preserve the failing layer and source without containing credentials,
  payloads, key material, or arbitrary peer-controlled data.
- Futures and bodies document cancellation, replayability, backpressure,
  timeout, and runtime requirements.
- Tasks have an owner, terminal observation, cancellation signal, and bounded
  shutdown path; queues are bounded.
- No blocking work runs on an async worker, and no ordinary mutex guard is held
  across `.await`.
- Unsafe code is isolated to the smallest backend crate, with a local invariant
  on every block and explicit callback lifetime, aliasing, unwind, and
  `Send`/`Sync` reasoning.

## Naming, comments, and documentation

- Names use protocol terminology and say what a value owns; vague “manager,”
  “processor,” “data,” and “config” names are rejected when a precise name
  exists.
- Comments explain a wire citation, invariant, workaround, ownership decision,
  or surprising constraint. They do not narrate the next line.
- Every public item has useful rustdoc; important operations document errors,
  cancellation, panics if any, and a minimal example at the user-facing seam.
- Captured behavior cites its fixture and provenance. Unsupported claims are
  stated as planned work rather than implied by a type name.
- Files split when ownership changes or independent testing/review becomes
  clearer, not at an arbitrary line count. Tests may live in a sibling module
  so production code remains navigable.

## Verification and maintenance

- `fmt`, Clippy with warnings denied, tests, rustdoc with warnings denied, and
  the declared MSRV pass with the lockfile.
- Feature checks cover no-default, each leaf, defaults, all-features, and
  representative interactions once features exist.
- Native/forked code builds in debug and release on Linux, macOS, and Windows;
  exact revisions, patch provenance, replay, and freshness probes remain
  reproducible.
- Wire-sensitive changes have a local differential and malformed/slow/cancelled
  peer cases. Fuzzing, sanitizers, Miri, and soaks target the boundaries where
  they provide evidence.
- Tracing has static field names and bounded values, installs no subscriber,
  and is tested for terminal outcomes and secret absence.
- Benchmarks isolate the claimed workload. Optimization follows an allocation,
  CPU, contention, or syscall profile and reruns the same packet fixtures.

## AI-smell audit

The closing review searches specifically for:

- speculative traits, providers, extension hooks, and “future-proof” layers;
- browser-family or operating-system branches that should be profile data;
- option bags, boolean soup, opaque byte escape hatches, and dead settings;
- repetitive comments, padded documentation, generic names, and needless
  wrapper types;
- fake status labels, unsupported parity claims, and tests that only restate
  constructors;
- duplicated validation across layers or backend defaults silently overriding
  validated settings;
- giant omniscient modules, or conversely fragmentation into one-function
  files without a separate owner;
- eager buffering, unbounded queues, detached tasks, locks across awaits, and
  `Arc`/clone/box use by reflex;
- platform `cfg` branches used as guesses instead of measured platform
  differences;
- broad forks or patches where a narrow adapter seam is sufficient.

The reviewer records concrete findings and either fixes them or documents why
the design is intentional. A clean checklist is not itself a compatibility
claim; packet and behavior evidence remains authoritative.
