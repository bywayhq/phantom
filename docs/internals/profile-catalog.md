# Maintaining the profile catalog

Use the catalog to register an exact recipe and describe each layer's limits.
Keep browser observations separate from recipe implementations.

## Current layout

| File | Responsibility |
| --- | --- |
| `crates/phantom-profile/catalog/profiles.json` | Recipe identities and layer evidence |
| `crates/phantom-profile/catalog/tls-components.json` | Typed TCP and QUIC TLS values |
| `crates/phantom-profile/catalog/http2-components.json` | Typed HTTP/2 settings and field overrides |
| `crates/phantom-profile/catalog/http3-components.json` | Typed HTTP/3 settings and field overrides |
| `crates/phantom-profile/src/catalog.rs` | Selection, required layers, and typed recipe bindings |
| `crates/phantom-profile/src/catalog/generated.rs` | Committed generated records |
| `crates/phantom-profile/src/tls/components.rs` | Committed generated TLS values |
| `crates/phantom-profile/src/catalog/http2_components.rs` | Committed generated HTTP/2 values |
| `crates/phantom-profile/src/catalog/http3_components.rs` | Committed generated HTTP/3 values |
| `scripts/dev/generate_profiles.py` | Closed-schema validation and offline generation |

Cargo uses the committed registry. It does not run Python or read JSON at
runtime. Discovery and exact lookup borrow static records. Instantiation
calls the selected recipe factory and returns fresh owned settings.

Core Chrome and Firefox TLS settings, HTTP/2 settings, and HTTP/3 connection
and request settings use structured components. Other layers and branded or
Android TLS overrides still use handwritten factories. Their migration and
historical-version growth remain in the [roadmap](../roadmap.md). Request
templates use explicit typed bindings; they have no separate evidence records.

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
python -m unittest discover -s scripts/dev/tests -p test_generate_profile_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_http2_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_tls_components.py
```

Generation sorts identifiers and emits fields and layers in fixed orders.
All four generated files use `rustfmt::skip` to preserve their output.
The generator rejects duplicate JSON keys and identifiers, unknown values,
inconsistent metadata, missing or escaping files, unsupported absence claims,
and observed fields without capture references.

Input limits bound local tooling: 16 MiB of JSON, 4,096 definitions, nesting
depth 16, strings of 4,096 characters, 16 references per layer, and 64 entries
per field or limitation list. These are resource ceilings, not measured corpus
performance targets. The current records still repeat metadata; further
component migration and measurement will assess that cost.

The full gate and CI run the generator's tests, which reject any stale
generated file. Run profile tests through the Cargo lock helper. Compare
all stored settings and ordering against existing factories, then run the
affected backend replays before integrating a settings migration.

## Declare TLS components

Chrome 154 and Firefox 157 each have a TCP TLS definition. Their QUIC TLS
definitions inherit only unchanged fields and explicitly replace the others.
Each override replaces a whole typed field, including ordered byte vectors.
The generated module lives under `tls` to preserve private checked types.
It does not introduce public unchecked constructors or runtime panic paths.

Declarations store literal trust-anchor and ALPS bytes, closed algorithm
names, and explicit ECH, extension-order, and ticket policies. Generation
retains candidate positions and duplicate draw slots. It never selects an
order or consumes randomness. Metadata does not authorize ticket rebinding.

Chrome's definition retains 28 trust-anchor identifiers in ascending byte
order. Chrome 154 sorts them when constructing its SSL configuration
(`net/cert/x509_util.cc:708-717` at `154.0.8037.58`, Chromium commit
`942bda4298c1`). All 60 fresh processes in the retained
`trust-anchor-orders.txt` capture and all 132 retained desktop ClientHellos
carry that order. Frozen original controls retain those exact bytes.
Generated assertions check the actual emitted IDs with native recipe bounds.

The generator checks version dependencies, key-share membership, ALPN and
ALPS bounds, trust-anchor vectors and candidate multisets, compression and
extension duplicates, and ECH payload and AEAD choices. Lists have resource
ceilings: 64 algorithms or extension entries, 64 trust-anchor candidates,
4,096 IDs per order, and 256 ALPN protocols. Native encoded-vector limits
still apply. These declarations add no browser observation coverage.

## Declare HTTP/2 components

Each HTTP/2 component supplies a concrete `Http2Settings` value. Chromium 154
and Firefox 157 have separate definitions. Their settings, header orders,
priorities, compression rules, stream limits, and timers differ. Existing
brand and Android factories reuse Chromium's compiled values.

A derived component replaces each field it overrides. HPACK, stream, and
priority records are closed typed fields. Replace the complete record when
overriding one of them. Lists retain their declared order.

Durations store seconds and nanoseconds. Nanoseconds must be below one billion.
The generator checks protocol bounds and timer dependencies. Native profile
validation also checks whether deadlines fit the host's monotonic clock.
The declaration does not promise clock support across hosts.

The migration retains each browser's timer policy and every stored field.
Frozen pre-migration values provide independent comparison controls. They
do not establish additional browser observation coverage.

## Declare HTTP/3 components

Each component names a concrete `Http3Settings` or `Http3RequestSettings`
value. It has an identifier, a kind, an optional base, and explicit values.
A component without a base supplies every field. A derived component inherits
only from the same kind and replaces each field it overrides. Ordered lists
are replaced whole; their items are never merged or sorted.

The current declaration has four components: Chromium 154 and Firefox 157
connection and request settings. Firefox request settings inherit the absent
extended CONNECT order from Chromium. They explicitly replace the ordinary
header order, cookie splitting, and `Alt-Used` policy. Existing Chromium
brand and Android factories continue to reuse Chromium's compiled values.

The generator resolves inheritance offline and emits owned Rust settings.
Public factories keep their signatures. You can customize the returned
values without changing another instance. Runtime policies such as
`RandomizedGrease` remain enum variants; generation and construction perform
no random draws.

Identifiers are bounded Rust names, not callable paths. Field names, enums,
setting kinds, and header kinds come from closed lists. Validation rejects
unknown references, cycles, incompatible kinds, invalid numbers, duplicate
settings, invalid header orders, and unsupported WebTransport. It also checks
the draft datagram dependency. Limits allow 4,096 components, 32 components
per inheritance chain, and 64 initial settings. The JSON byte and nesting
limits also apply to this declaration file.

The source migration keeps independent literal controls from its original
revision. Those tests compare every stored field and ordering, including
draw policies. Existing capture and backend replay tests check wire behavior.
The component declaration supplies implementation values; it adds no browser
observation claim. Layer evidence remains in the registry and factory docs.

## Next

- [Profile reference](../reference/profiles.md): selecting and composing recipes.
- [Roadmap](../roadmap.md): remaining corpus work.
