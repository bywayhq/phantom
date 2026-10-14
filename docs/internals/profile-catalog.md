# Maintaining the profile catalog

Use the catalog to register an exact recipe and describe each layer's limits.
Keep browser observations separate from recipe implementations.

## Current layout

| File | Responsibility |
| --- | --- |
| `crates/phantom-profile/catalog/profiles.json` | Recipe identities, layer references, evidence and template bindings |
| `crates/phantom-profile/catalog/tls-components.json` | Typed TCP and QUIC TLS values |
| `crates/phantom-profile/catalog/quic-components.json` | Typed QUIC transport values and wire policies |
| `crates/phantom-profile/catalog/http1-components.json` | Typed HTTP/1.1 connection limits and timers |
| `crates/phantom-profile/catalog/dns-components.json` | Typed DNS-cache capacity and lifetimes |
| `crates/phantom-profile/catalog/udp-components.json` | Typed UDP socket policy |
| `crates/phantom-profile/catalog/tcp-components.json` | Typed TCP socket and address policies |
| `crates/phantom-profile/catalog/websocket-components.json` | Ordered opening fields and WebSocket policies |
| `crates/phantom-profile/catalog/client-hints-components.json` | Ordered hint names, values, delivery, and model parameters |
| `crates/phantom-profile/catalog/cookie-components.json` | Ordered automatic Cookie placement names |
| `crates/phantom-profile/catalog/proxy-connect-components.json` | Ordered CONNECT fields and proxy connection policies |
| `crates/phantom-profile/catalog/http2-components.json` | Typed HTTP/2 settings and field overrides |
| `crates/phantom-profile/catalog/http3-components.json` | Typed HTTP/3 settings and field overrides |
| `crates/phantom-profile/catalog/request-templates.json` | Complete ordered request-template values |
| `crates/phantom-profile/src/catalog.rs` | Selection and required layers |
| `crates/phantom-profile/src/catalog/generated.rs` | Committed generated records |
| `crates/phantom-profile/src/catalog/connection_profile_definitions.rs` | Immutable typed component references |
| `crates/phantom-profile/src/catalog/connection_profile_values.rs` | Fresh owned connection-profile construction |
| `crates/phantom-profile/src/catalog/request_template_definitions.rs` | Immutable compiled request templates |
| `crates/phantom-profile/src/catalog/request_template_values.rs` | Borrowed values and owned template construction |
| `crates/phantom-profile/src/tls/components.rs` | Committed generated TLS values |
| `crates/phantom-profile/src/catalog/quic_components.rs` | Committed generated QUIC transport values |
| `crates/phantom-profile/src/catalog/http1_components.rs` | Committed generated HTTP/1.1 values |
| `crates/phantom-profile/src/catalog/dns_components.rs` | Committed generated DNS-cache values |
| `crates/phantom-profile/src/catalog/udp_components.rs` | Committed generated UDP values |
| `crates/phantom-profile/src/catalog/tcp_components.rs` | Committed generated TCP values |
| `crates/phantom-profile/src/catalog/websocket_components.rs` | Committed generated WebSocket settings |
| `crates/phantom-profile/src/catalog/client_hints_components.rs` | Committed generated client hints |
| `crates/phantom-profile/src/catalog/cookie_components.rs` | Committed generated Cookie placement |
| `crates/phantom-profile/src/catalog/proxy_connect_components.rs` | Committed generated CONNECT values |
| `crates/phantom-profile/src/catalog/http2_components.rs` | Committed generated HTTP/2 values |
| `crates/phantom-profile/src/catalog/http3_components.rs` | Committed generated HTTP/3 values |
| `scripts/dev/generate_profiles.py` | Offline generator command |
| `scripts/dev/profile_catalog/` | Closed declarations and protocol generation |

The command loads an offline Python package. `declarations.py` bounds JSON
input and shared values. `registry.py` checks identities and evidence.
`components.py` resolves same-kind inheritance and selects closed protocol
validators. Protocol modules validate their typed values. The closed component
emitter calls their Rust encoders where needed.
`rust_literals.py` encodes shared literals, and `cli.py` checks every output
before writing any file. The command also works outside the repository.

Run a focused test module from the repository root:

```sh
python -m unittest scripts.dev.tests.test_generate_profile_cli
```

Cargo uses the committed registry. It does not run Python or read JSON at
runtime. Discovery and exact lookup borrow static records. Connection-profile
instantiation constructs fresh owned settings from immutable component references.
Request-template selection copies immutable values into a fresh owned template.

All existing TLS factories, core QUIC transport, HTTP/1.1, HTTP/2, HTTP/3,
DNS-cache, TCP, UDP, client hints, Cookie placement, CONNECT, and WebSocket
settings use structured components. Complete connection profiles select these
components through typed references. Historical-version growth remains in the
[roadmap](../roadmap.md). Request templates have immutable definitions and exact
kind bindings. Their evidence remains in browser docs and retained fixtures;
they have no separate evidence records.

## Identity and composition

An identifier names a browser build, capture target, and settings revision.
Lookup accepts only an exact identifier. Unknown versions, platforms, and
revisions fail. A required missing layer also fails, including an intentionally
absent one. An empty required-layer list accepts a partial recipe.

The advertised build does not describe every component. Chrome's Windows
entry names `154.0.8037.97`, while its retained TLS observations describe
`154.0.8037.58`. Each evidence reference records its own build. A retained host
architecture does not establish the architecture supported by a composed target.
Leave target architecture absent when that coverage has not been established.

Existing Android factories keep their partial composition. An unavailable
socket or cookie policy may leave the ordinary `ClientProfile` default in
place. That default is not described as browser support. Request templates
must be selected by request kind and added explicitly.

Catalog identifiers are metadata. Transport compatibility, authentication
scope, and connection/session ownership remain transport responsibilities.
Customizing returned settings does not amend or retain a validated identity
on the custom profile. Instantiation does not perform random draws.

Changing settings requires a new revision and a new explicit composition.
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

Capture references must match the fixture's retained `browser_version` or
`client_version` metadata. Generation reads a bounded metadata prefix and rejects
missing, ambiguous, or mismatched versions. Source and recipe builds are separate
citations and are not checked against capture headers.

Brave's Android 17 target reuses an Android 15 (API 35) WebSocket session capture
for its HTTP/2 settings comparison. Its HTTP/2 evidence names that older fixture
and keeps the reuse limitation. This adds provenance, not observation coverage
or a new target. The current QUIC and client-hint references remain Android 17.

## Declare request templates

Each declaration contains the complete ordered fields for HTTP/1.1 and HTTP/2,
an optional HTTP/3 list, HTTP/2 priority, and both client-hint flags. Field
records use the variants of `RequestField`, including required caller slots,
trust and forwarding values, proxy-authentication attempts, and hint positions.
An absent HTTP/3 list differs from a present empty list.

A declaration may inherit another template and replace complete fields.
Generation resolves this offline and emits static slices and strings. The
registry maps each supported request kind to one exact declaration. Missing
kinds return `UnavailableTemplate`. Template construction copies owned values
without calling browser factories or drawing random values. You can customize
the returned `RequestTemplate` without changing the definition or another copy.

The current catalog has 20 bindings backed by 18 definitions. Edge and Opera
reuse identical Chromium caller-User-Agent templates. Desktop Brave requires
caller `User-Agent` and `Accept-Language`. Android Brave retains its literal
User-Agent and requires caller `Accept-Language`. Field order includes GPC,
restart hints and disjoint proxy-authentication attempts.

Validation follows the native template rules. It preserves the shorter matching
restart-hint prefix and does not add dependencies between flags and slots.
Declarations allow 256 fields per protocol and 4,096-character ASCII names and
values. Values may contain tabs or be empty. These bounds apply to offline
declarations; custom Rust templates keep their existing validation rules.
Frozen full-field literals and unchanged browser factories provide independent
controls. The migration adds no browser observations or per-template evidence.

## Update the registry

Edit the JSON records and the closed target contract when adding a supported
target. Records cannot contain Rust expressions or arbitrary callable paths.
The target contract pins the build, target, environment, known architecture,
revision, and configured layers.

Each composition names all fourteen layers. A component identifier selects
one declaration of the required type. `null` preserves an absent layer and its
ordinary custom-profile default. TCP TLS is required. HTTP/3 is either absent
or contains all four TLS, QUIC, connection, and request components. References
must agree with the evidence states. Request templates remain separate choices.

Generation resolves and checks every component before writing any output.
Compiled definitions hold closed typed references, with no complete browser
factory dispatch. Construction keeps ordered values and runtime draw policies.
It does not sample them. Original browser factories and a separately frozen
ten-profile composition oracle provide comparison controls.

```sh
python scripts/dev/generate_profiles.py
python scripts/dev/generate_profiles.py --check
python -m unittest discover -s scripts/dev/tests -p test_generate_profiles.py
python -m unittest discover -s scripts/dev/tests -p test_generate_profile_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_http2_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_tls_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_quic_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_connection_components.py
python -m unittest discover -s scripts/dev/tests -p test_generate_tcp_components.py
python -m unittest scripts.dev.tests.test_generate_client_hints_profiles
python -m unittest scripts.dev.tests.test_generate_cookie_profiles
python -m unittest scripts.dev.tests.test_generate_proxy_connect_profiles
python -m unittest scripts.dev.tests.test_generate_websocket_profiles
python -m unittest scripts.dev.tests.test_generate_request_templates
python -m unittest scripts.dev.tests.test_generate_compositions
```

Generation sorts identifiers and emits fields and layers in fixed orders.
All fifteen generated files use `rustfmt::skip` to preserve their output.
The generator rejects duplicate JSON keys and identifiers, unknown values,
inconsistent metadata, missing or escaping files, unsupported absence claims,
and observed fields without capture references.

Input limits bound local tooling: 16 MiB of JSON, 4,096 definitions, nesting
depth 16 and strings of 4,096 characters. Registry records allow 16 references
per layer and 64 entries per field or limitation list. These are resource ceilings, not measured corpus
performance targets. The current records still repeat metadata; further
component migration and measurement will assess that cost.

The full gate and CI run the generator's tests, which reject any stale
generated file. Run profile tests through the Cargo lock helper. Compare
all stored settings and ordering against existing factories, then run the
affected backend replays before integrating a settings migration.

## Declare TLS components

Chrome 154 and Firefox 157 each have a TCP TLS definition. Their QUIC TLS
definitions inherit only unchanged fields and explicitly replace the others.
Edge, Brave, Opera, and Android definitions preserve their existing base
choices and whole-field overrides. Firefox for Android changes ticket order.
The Chromium Android definitions keep ECH GREASE without HTTPS records.
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

Opera 136 retains 32 identifiers and all 29 TCP and 20 QUIC draw slots,
including repeated orders. TCP draws once per client. QUIC draws once per
connection. Chromium 152 copies an `absl::flat_hash_set` with a new table seed
when preparing these configurations (`net/ssl/ssl_config_service.cc:101-123`,
`net/socket/ssl_client_socket.cc:233`, and
`net/quic/quic_chromium_client_session.cc:1750-1771`). The declaration keeps
the original observed candidates and weights. Generated native assertions
check every ID vector and candidate multiset. Frozen controls compare every
expanded candidate byte and its position against the original index arrays.

The generator checks version dependencies, key-share membership, ALPN and
ALPS bounds, trust-anchor vectors and candidate multisets, compression and
extension duplicates, and ECH payload and AEAD choices. Lists have resource
ceilings: 64 algorithms or extension entries, 64 trust-anchor candidates,
4,096 IDs per order, and 256 ALPN protocols. Native encoded-vector limits
still apply. These declarations add no browser observation coverage.

## Declare QUIC components

Chromium 154 and Firefox 157 have separate transport definitions. All 18
stored fields retain their values. Each wire parameter names a closed kind,
identifier width, length width, and typed payload policy. Ordered lists remain
ordered. A derived component replaces each complete field it overrides.

Parameter permutations, version GREASE placement, reserved payload ranges,
connection-ID lengths, and early-data choices remain runtime policies.
Generation and factory construction draw no random values. Fresh settings
own their wire vectors and Google connection-option lists.

The generator checks native transport and encoding bounds, required parameter
presence, duplicates, and field dependencies. Compiled recipes also obey the
current provider's two-version limit and 1,000-microsecond minimum ACK delay.
Those restrictions do not change custom profile APIs. Declarations allow at
most one record for each supported kind. Frozen factory controls compare all
values and policies; existing wire replays remain separate checks.

## Declare HTTP/1.1, DNS, and UDP components

These layers keep separate declarations and generated modules. HTTP/1.1
defines a per-origin connection limit and idle policy. Chromium checks idle
expiry when a request arrives. Firefox also closes connections on a timer.
DNS records store capacity, positive lifetimes, the record-TTL floor, and optional
negative lifetimes. UDP records store the port-randomization choice.
Firefox has no UDP recipe; generation does not add one.

Durations store seconds and nanoseconds, including zero. HTTP/1.1 timer
limits retain the native 65,535-second bound. Other duration records retain
the full Rust representation. An override replaces the entire typed field.

Compiled connection and cache counts range from 1 through `u32::MAX`, so
they fit both 32-bit and 64-bit hosts. Generated nonzero values are checked
in Rust const blocks. Invalid literals fail compilation. There is no runtime
panic or replacement value. Custom typed settings retain their host-sized
range; this declaration bound does not change their APIs.

## Declare TCP components

Chromium 154 and Firefox 157 have separate TCP definitions. Each keeps five
fields: no-delay, optional send buffer, keepalive, address selection, and
optional port randomization. Keepalive records select unchanged, fixed, or
scheduled timing. Address records select sequential attempts, racing, or a
backup connection. Their nested fields remain closed typed records.

Whole-second keepalive limits, probe counts, fallback delays, backup timeouts,
and the signed socket-option size follow native profile validation. Windows
build thresholds retain their full `u32` range. Send-buffer constants undergo
checked Rust const construction. Overrides replace complete nested policies.

Generation does not open sockets, choose addresses, change timers, or draw
random values. The transport still applies these policies on each connection.
Frozen controls compare every original field and composed profile. Backend
socket and timer checks remain separate from declaration validation.

## Declare client hints

Each component stores an ordered list of hint names, values, and delivery.
Names are unique lowercase ASCII tokens that start with a letter. Delivery
is either `Default` or `AcceptCh`. A `Literal` value keeps exact bytes,
including empty values and tabs. Lists allow at most 64 entries, and strings
at most 4,096 characters. These limits apply to offline declarations.

The eleven definitions retain seven desktop and four Android hint sets.
Brave omits the full-version and form-factor hints. Opera for Android keeps
its zero-byte form-factor value, distinct from a quoted empty string.
Every definition supplies its complete list, preserving its brand strings,
order, and delivery. The declaration adds no target or observation coverage.

Chrome, Edge, and Opera for Android each have one `Model` value, restricted
to the requested `sec-ch-ua-model` hint. Its default is `Pixel 7`. Generated
constructors use the existing model encoder. Public model adapters keep the
native printable-ASCII check and quote/backslash escaping. Caller models
retain their native range, including empty strings and lengths above the
offline ceiling. Only the captured default has browser observation coverage.
Brave's model remains a literal quoted empty string, with no model adapter.

Generated functions return fresh owned hint lists. Frozen original factories
and an independent original model encoder provide comparison controls.
Request placement and origin hint state remain runtime responsibilities.

## Declare Cookie and CONNECT components

Cookie placement stores the ordered names before which the automatic field
may appear. An empty list places it last. Generation uses the existing
constructor and returns fresh owned settings.
Matching still follows request order and ignores ASCII case.

CONNECT records store both ordered field lists, the rejected-stream policy,
and proxy connection sharing. Each field names an authority placeholder,
literal, request-copied value, or credentials placeholder. Firefox inherits
Chromium's unchanged HTTP/2 field list and replaces the other three fields.
Credentials remain caller-owned; declarations describe their position only.

The generator mirrors native CONNECT validation, including token spelling,
case-insensitive duplicates, placeholder counts, and HTTP/2 restrictions.
It refuses copied origin credentials. Literal values may be empty or contain
tabs, but must otherwise contain visible ASCII or spaces. Cookie names retain
their spelling and order. Declaration lists allow at most 64 entries and
strings at most 4,096 characters; custom typed APIs retain their native range.

Frozen factory controls compare all values and composed recipes. Cookie
insertion and CONNECT wire checks remain integration checks. These records
add no browser observations or authentication behavior.

## Declare WebSocket components

Chromium 154 and Firefox 157 each supply six complete settings fields.
Their connection records keep five policies, including ordered upgrade ALPN.
Opening fields retain their spelling and order, typed placeholders, and
optional URL-trust defaults. An absent value differs from an empty string.
Compression records keep the ordered offer and empty-message choice.

Existing branded and Android factories reuse these values. Seven catalog
profiles configure WebSockets. Edge, Opera, and Firefox for Android retain
no recipe for this layer. Generation adds no browser observation coverage.
H2 pseudo-header order and priority remain part of HTTP/2 settings.

The closed schema checks native profile invariants and bounds declarations:
256 fields per protocol, 256-byte token names, 4,096-byte ASCII values,
64 ALPN entries of at most 255 bytes, and four deflate parameters. Values
allow spaces and tabs, including empty strings. Repeated ordinary fields
and ALPN entries retain their order. These limits do not restrict custom
Rust settings. The facade still validates opening-handshake semantics.

Timeouts retain seconds and nanoseconds, or no limit. A present timeout
must be positive. Native validation checks the host clock's range.
Generated settings own fresh vectors and strings. Keys, masks, compression
state, and connection choice remain runtime responsibilities.
Frozen original controls compare all values and existing composition.

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
