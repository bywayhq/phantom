# Add a browser profile

`profiles.json` selects each profile's components and request templates, with
its build, platform and sources. Generate Rust after editing the catalog:

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

Give each selected layer source locations and builds, including older builds
whose settings you reuse. Keep comparison details in the tests.

For an external preset, use `identity.kind: "Peer"` with its project, exact
source commit, preset name and advertised browser release. Set its browser and
target platform in metadata. Name it by browser and platform: for
example, ID `safari/26.0.1/macos/r1`, selector `safari-26-macos`, target
`SafariMacos26`. Source project and preset names belong in identity metadata.
Peer definitions use the same components and generated registration, without
a browser factory. `ExternalSource` references pin the commit in an HTTPS URL;
`PeerCapture` references name retained peer fixtures with matching execution
metadata.

Omit empty `references` and `limitations` arrays. Unavailable layers need no
row, but their composition must be `null`.
`Unavailable` means no recipe is supplied; generic client defaults may apply.
`IntentionallyAbsent` describes an explicit browser omission. Record each
specific limitation once.

The generator checks types, references and capture metadata. Test browser and
catalog behavior against retained captures or explicit expectations. Keep
expected settings independent of the catalog being tested.

## Next

Run the profile tests and the integration gate described in
[the working agreement](../../../AGENTS.md#verification-and-handoff).
