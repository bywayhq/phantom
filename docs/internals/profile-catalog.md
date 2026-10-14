# Maintaining the profile catalog

Use the catalog to register an exact recipe and describe each layer's limits.
Keep browser observations separate from recipe implementations.

## Current layout

| File | Responsibility |
| --- | --- |
| `crates/phantom-profile/catalog/profiles.json` | Recipe identities and layer evidence |
| `crates/phantom-profile/src/catalog.rs` | Selection, required layers, and typed recipe bindings |
| `crates/phantom-profile/src/catalog/generated.rs` | Committed generated records |
| `scripts/dev/generate_profiles.py` | Closed-schema validation and offline generation |

Cargo uses the committed registry. It does not run Python or read JSON at
runtime. Discovery and exact lookup borrow static records. Instantiation
calls the selected recipe factory and returns fresh owned settings.

This is the registration foundation. Structured generation of recipe values,
component reuse, and historical-version growth remain in the
[roadmap](../roadmap.md). Request templates currently
use explicit typed bindings; they have no separate catalog evidence records.

## Identity and composition

An identifier names a browser build, capture target, and settings revision.
Lookup accepts only an exact identifier. Unknown versions, platforms, and
revisions fail. A required missing layer also fails, including an intentionally
absent one. An empty required-layer list accepts a partial recipe.

The advertised build does not describe every component. Chrome's Windows
entry names `154.0.8037.97`, while its retained TLS observations describe
`154.0.8037.58`. Each evidence reference records its own build. Unknown host
architecture remains absent; header values do not establish it.

Existing Android factories keep their partial composition. An unavailable
socket or cookie policy may leave the ordinary `ClientProfile` default in
place. That default is not described as browser support. Request templates
must be selected by request kind and added explicitly.

Catalog identifiers are metadata. Transport compatibility, authentication
scope, and connection/session ownership remain transport responsibilities.
Customizing returned settings does not amend or retain a validated identity
on the custom profile. Instantiation does not perform random draws.

Changing settings requires a new revision and a new explicit recipe binding.
Preserve earlier definitions. Changes confined to evidence may retain the
settings identity when the generated settings and draw policies are unchanged.

## Evidence records

Every connection layer has an explicit support state: configured,
intentionally absent, or unavailable. Configured does not mean fully captured.
`verified_fields` describes the observation coverage. `limitations` retains
uncaptured behavior and source-only policies.

| Reference kind | Meaning |
| --- | --- |
| `Capture` | Retained fixture or hook record |
| `Source` | Upstream browser-source HTTPS URL |
| `Reused` | Settings supplied by another recipe |
| `Recipe` | Reviewed implementation and its citations |

A recipe reference is not independent browser evidence. A reused component
needs its own equivalence controls. Observation claims require a retained
capture reference. File existence and schema validation do not prove parity;
review the named replay tests and actual captured fields.

## Update the registry

Edit the JSON records and the closed recipe binding when adding a supported
target. Records cannot contain Rust expressions or arbitrary callable paths.
The binding contract pins the build, target, environment, known architecture,
revision, and configured layers.

```sh
python scripts/dev/generate_profiles.py
python scripts/dev/generate_profiles.py --check
python -m unittest discover -s scripts/dev/tests -p test_generate_profiles.py
```

Generation sorts identifiers and emits layers in a fixed order. The generated
table has `rustfmt::skip` so formatting does not rewrite declaration output.
The generator rejects duplicate JSON keys and identifiers, unknown values,
inconsistent metadata, missing or escaping files, unsupported absence claims,
and observed fields without capture references.

Input limits bound local tooling: 16 MiB of JSON, 4,096 definitions, nesting
depth 16, strings of 4,096 characters, 16 references per layer, and 64 entries
per field or limitation list. These are resource ceilings, not measured corpus
performance targets. The current records still repeat metadata; component
migration and measurement will assess that cost.

The full gate and CI run the generator's tests, which also reject a stale
committed registry. Run profile tests through the Cargo lock helper. Compare
all stored settings and ordering against existing factories, then run the
affected backend replays before integrating a settings migration.

## Next

- [Profile reference](../reference/profiles.md): selecting and composing recipes.
- [Roadmap](../roadmap.md): remaining corpus work.
