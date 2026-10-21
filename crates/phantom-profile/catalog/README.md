# Add a browser profile

`profiles.json` owns each profile's identity, component selection, evidence,
and request-template associations. Generate Rust after editing the catalog:

```sh
python scripts/dev/generate_profiles.py
python scripts/dev/generate_profiles.py --check
```

Add a profile record with its exact build, platform, environment and revision.
Use schema 2 and put browser observations in `metadata.identity` with
`kind: "Observed"`. The `id` must match that metadata. Name its `target` as
browser, platform and major version, such as `ChromeWindows154`. Targets must
be unique.
This generates both the catalog registration and `chrome::v154_windows()`.
The constructor leaves the request template unset.

Give each record a fixed `selector`, such as `chrome-154-windows`. Use 1–64
lowercase ASCII letters or digits, with single hyphens between groups. Selectors
must be unique. Keep their exact profile mapping when adding newer recipes.

Select existing components in `composition` when their settings still apply.
Use `null` for layers without a recipe. HTTP/3 needs all four of its layers.
For changed settings, add a component in the corresponding `*-components.json`
file. A component can select a same-kind `base` and override specific values.
Prefer one shared base over a chain of version-by-version overrides.
Associate request kinds with entries in `request-templates.json`.

Every selected layer needs an evidence record with references. Keep the build
and location of each observation, including older builds whose settings you
reuse. `verified_fields` requires a retained capture. Source policies and reused
settings do not become observations of the new build.

For an external preset, use `identity.kind: "Peer"` with its project, exact
source commit, preset name and advertised browser release. Keep browser and
target platform in metadata; do not invent an observed build, OS release,
architecture or capture environment. Its ID is `peer/<project>/<preset>/rN`.
Name its target `Peer` followed by the capitalized project and preset words.
Peer definitions use the same components and generated registration, without
a browser factory. `ExternalSource` references pin the commit in an HTTPS URL;
`PeerCapture` references name retained peer fixtures with matching execution
metadata. Neither kind establishes browser fidelity.

You can omit empty `references`, `verified_fields`, and `limitations` arrays.
You can also omit evidence rows for unavailable layers: their composition
must still be `null`. The generated catalog lists every layer explicitly.
`Unavailable` means no recipe is supplied; generic client defaults may apply.
`IntentionallyAbsent` describes an explicit browser omission. Record specific
limitations once, rather than repeating this distinction in every row.

Keep capture comparisons independent of these declarations. The generator
checks types, references and capture metadata; it does not prove wire parity.
Add or extend the relevant browser and catalog tests using retained captures
or explicit expectations. Do not regenerate expected settings from the catalog
being tested.

## Next

Run the profile tests and the integration gate described in
[the working agreement](../../../AGENTS.md#verification-and-handoff).
