# Writing the documentation

Edit Phantom's documentation, as a human or an agent: who each page is for,
where content belongs, and how the prose reads.

> For contributors who edit the documentation.

## Readers

Five kinds of reader use these pages:

| Reader | Question they bring | Entry point |
| --- | --- | --- |
| Evaluator | Should I use Phantom? | [README](../../README.md), [Why Phantom](../why-phantom.md) |
| Builder | How do I do this task? | [Getting started](../getting-started.md), then the guides |
| Specialist | Is this claim true on the wire? | [Coverage](../reference/coverage.md), [Validation](../explanation/validation.md) |
| Contributor | How do I change Phantom safely? | [CONTRIBUTING.md](../../CONTRIBUTING.md), internals |
| Coding agent | What must I do and never do with this API? | [`llms.txt`](../../llms.txt) |

Readers also differ in what they already know:

- **New**: knows HTTP clients and `User-Agent`, but not that a server can tell
  clients apart without headers. This is the primary reader.
- **Aware**: has heard of TLS fingerprinting or JA3/JA4, but not of HTTP/2
  settings, header order, or QUIC parameters.
- **Expert**: reads ClientHello bytes and knows the captures.

Assume fluent Rust and Tokio everywhere. Do not teach async Rust.

## Explain fingerprinting once

[How servers recognize a client](../fingerprinting.md) is the only page that
explains fingerprinting. Every other page gives at most one sentence and links
to the relevant anchor there. These anchors are stable; link to them freely:

`#the-short-version`, `#tls`, `#http2`, `#header-order`, `#http3`,
`#client-hints`, `#consistency`, `#see-your-own-fingerprint`

Terms have one home too: the [glossary](../reference/glossary.md). Link a term
to its glossary anchor the first time a page uses it. Glossary anchors are the
lowercased term, for example `#profile`, `#recipe`, `#capture`, `#route`,
`#exact-protocol`, `#negotiated-protocol`, `#origin`, and `#alt-svc`.

## Page types

Each page has one type and one reader. Content of another type moves to the
page that owns it and is replaced by a link.

| Type | Reader | Holds | Does not hold |
| --- | --- | --- | --- |
| Start (README, primer, Why Phantom) | Evaluator, new | What Phantom does, what it does not do, one example | API detail, evidence tables |
| Tutorial (Getting started) | Builder, new | One path from build to working request | Options and alternatives |
| Guide (`docs/guides/`) | Builder, aware | Tasks, each led by code | Exhaustive limits, design rationale, evidence |
| Reference (`docs/reference/`) | Anyone looking up a fact | Tables, defaults, limits, the support contract | Narrative |
| Explanation (`docs/explanation/`) | Specialist, curious builder | Why Phantom works this way, and the evidence | Usage steps |
| Internals (`docs/internals/`, CONTRIBUTING) | Contributor | How to change Phantom | User-facing promises |

## Page shape

Every page under `docs/` except reference tables opens like this:

```markdown
# Page title

One or two sentences: what the reader can do or learn here.

> For builders who have read [Getting started](../getting-started.md).
```

The quoted line names the reader and at most one prerequisite. Use the reader
names from the table above.

Every page ends with a `## Next` section of one to three links, each with a
few words on why the reader would go there.

## Guides

A guide is a set of tasks. Each task section:

1. has a heading that names the task, such as "Send a request through a SOCKS5
   proxy", not a feature name such as "SOCKS5";
2. states the goal in one sentence;
3. shows a complete, compiling example;
4. adds at most one short list of what the reader must know to use it
   correctly.

Details that a reader needs only when something goes wrong go in a final
`## Limits` section of the guide, as short bullets. Exhaustive defaults go in
[Defaults and limits](../reference/limits.md). Why Phantom chose a behavior
goes in [Design](../explanation/design.md). Evidence goes in
[Validation](../explanation/validation.md).

Aim for guides under 200 lines. A longer guide usually holds reference or
explanation content that belongs elsewhere.

## Rust examples

- Every Rust block in `README.md`, `getting-started.md`, and `docs/guides/`
  compiles as a doctest. `crates/phantom/src/lib.rs` includes these files; a
  new page with Rust examples needs an entry there.
- Show complete `use` lines. Readers and agents copy examples as they are.
- Use only public API that exists today. Check each signature in the source
  before you write it.
- Prefer a function that takes `&Client` over a full `main`, unless the page
  teaches setup.

## Prose

Write plain, specific sentences. One idea per sentence, active voice, present
tense. Use the same word for the same thing on every page. Give numbers,
names, and conditions instead of adjectives.

Do not write these:

- Stock words: delve, robust, seamless, leverage, powerful, comprehensive,
  crucial, cutting-edge, effortless, unlock, elevate, streamline, navigate
  (except for browsers), landscape, ecosystem (as filler), journey.
- Framing tics: "It's not X, it's Y", "not just X but Y", "whether you're X
  or Y", "in today's world", "let's", "simply", "just", "easily".
- Reflexive lists of three adjectives or clauses.
- Rhetorical questions, including in headings.
- Chains of em-dashes. Use a colon, parentheses, or a new sentence.
- Bold scattered through body text. Bold marks a term on first definition, and
  nothing else.
- Emoji, exclamation marks, and closers such as "In summary" or "That's it".
- Claims that cannot be checked, such as "undetectable", "fast", or "battle-tested".

Say what Phantom does not do as plainly as what it does. A limit stated next
to the feature saves the reader a failed attempt.

## Claims

- Describe only behavior that exists today. Planned work belongs in the
  [roadmap](../roadmap.md) or the planned lists in Coverage.
- Every claim about matching a browser needs evidence in Validation. Do not
  add a claim without it.
- When you move a fact, move it; do not drop it. Removing repetition is fine.
- Link rather than repeat. If two pages state the same limit, one of them
  should link to the other.

## Links and anchors

Use relative links. Anchors follow GitHub's slug rules: lowercase, spaces
become hyphens, punctuation is dropped. When you rename a heading, search the
repository for links to the old anchor and fix them.

## Next

- [CONTRIBUTING.md](../../CONTRIBUTING.md): checks to run before a pull
  request.
- [How servers recognize a client](../fingerprinting.md): the model page for
  new readers.
