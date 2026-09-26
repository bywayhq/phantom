# Add a browser recipe

Add a browser build to Phantom's profile matrix: capture it, retain the
fixtures, write the recipe functions, replay the captures in tests, and update
the documentation that makes claims about it.

> For contributors who have read
> [Evidence rules](../explanation/validation.md#evidence-rules).

A [recipe](../reference/glossary.md#recipe) is the wire data for one browser
build at one protocol layer, returned by a function such as
`chromium::v154_tls`. The browser's layers together make its row in the
[profile reference](../reference/profiles.md). The matrix is meant to grow;
the [roadmap](../roadmap.md) queues the browsers still missing.

## Rules that shape every step

- Capture, record the capture in Validation, and only then write or change
  the recipe.
- The runtime never branches on the browser name or the host OS, so a new
  browser adds data in `phantom-profile` and no transport conditionals in
  `phantom-net`.
- Keep extension, SETTINGS, pseudo-header, and field order exactly as
  captured; normalize only the per-connection randomness listed in
  [Capture normalization](../explanation/validation.md#capture-normalization).
- Edge 153 showed that a Chromium fork can change the ClientHello, so each
  fork needs its own captures in every area. A layer it shares with Chrome is
  shared only after a test shows the capture equals the Chromium recipe.
- Phantom carries one version per browser: the current stable build on the
  capture host, or for an Android browser the build Play serves to the
  capture emulator. A new version replaces the old one.
- Captures come from the Windows 11 development host, and Android captures
  from the emulator on it. A Windows capture never backs a macOS or Linux
  recipe, and an emulator capture is not a phone capture.
- Launching a local browser needs the human's approval for the session, as
  the `browser-capture` skill in `.claude/skills/` states.

## Worked example: Chrome 154

Chrome 154.0.8037.58 entered the tree in six commits, each small enough to
review alone:

| Commit | Step |
| --- | --- |
| `7dadd86 test(fixtures): retain Chrome 154 transport and client-hint captures` | TLS, trust-anchor order, H2 startup, QUIC and H3, and client-hint fixtures |
| `01ecdb2 test(websocket): retain Chrome 154 WebSocket opening captures` | WebSocket fixtures |
| `01abb9b test(sse): retain Chrome 154 EventSource reconnect captures` | SSE fixtures |
| `b4b17b4 test(alt-svc): retain Chrome 154 Alt-Svc racing captures` | Alt-Svc racing fixtures |
| `be02e93 feat(profile): add the Chrome 154 browser recipes` | `chromium::v154_*`, replay tests, Validation, and Coverage |
| `f129363 refactor(profile)!: retire the superseded browser recipes` | Removal of Chrome 152 and 153 with their fixtures and re-exports |

Read `be02e93` with `git show` before you start. Its message records what
changed from the previous build and why each difference is in the recipe.

For a Chromium fork, the closer model is Edge 153: `eb883a2` retained its
captures, and `4a01b7f` added `crates/phantom-profile/src/edge.rs`, which
reuses the Chromium recipes and changes only what the captures show differs.
`brave.rs` and `opera.rs` follow the same pattern. Brave's request templates
are the Chromium templates with its field changes applied, and Opera, built
on Chromium 151, is compared with the Chrome 154 recipes because Phantom
carries one Chromium version.

## Step 1: capture each area

Capture the build in all seven areas. [Capture tools](../../scripts/capture/README.md)
has the options and scenarios for each tool, and
[Capture commands and launches](../explanation/validation.md#capture-commands-and-launches)
has the exact Chrome 154 commands and launch arguments to repeat.

| Area | Tool | Retained files |
| --- | --- | --- |
| TLS | `cargo run -p phantom-testkit --example capture_client_hello`, once per fresh browser process | `client-hello.txt`, plus `trust-anchor-orders.txt` when the order varies |
| HTTP/2 | `cargo run -p phantom-net --example capture_http2_tls`, once per fresh process | `client-startup.txt` |
| QUIC and HTTP/3 | `scripts/capture/chrome_http3.py --client-hello` | `client-startup.txt`, `quic-client-hello-{1,2}.txt` |
| Client hints | `scripts/capture/client_hints.py` | `navigation.txt` |
| WebSocket | `scripts/capture/http2_websocket.py` | One file per scenario |
| SSE | `scripts/capture/sse_reconnect.py` | One file per scenario |
| Alt-Svc racing | `scripts/capture/alt_svc_race.py` | One file per scenario |

- The Python tools launch browsers through `browser_launch.py`, which knows
  `chrome`, `edge`, `brave`, `opera`, and `firefox`. For another browser,
  add it to `CHROMIUM_BROWSERS` or `BROWSERS` and to `CLIENT_NAMES`, with a
  case in `scripts/capture/tests/test_browser_launch.py`, or capture with
  `--browser manual`.
- [`startup_capture.py`](../../scripts/capture/README.md#connection-startup-launches)
  runs the TLS, H2, or QUIC listener and launches the browser with the
  Chrome 154 arguments for that layer. Those listeners serve only the first
  connection, so for a browser that abandons its startup connections, as
  Opera 135 does, pass `--navigate devtools`.
- Take several fresh processes per layer. The Chrome 154 set used 61 TLS
  processes, 3 for H2 and QUIC, and 2 to 10 runs per scenario elsewhere, and
  Validation reports each count.
- Launch headless unless the section says otherwise, and record any headful
  run. Captures in different launch modes are compared, never assumed equal.
- Some layers cannot be captured. TCP socket options do not appear on the
  wire, so `chromium::v154_tcp` rests on Chromium source at the release tag.
  Edge has no TCP recipe, because its network source is not public. Say which
  layers have no evidence; do not borrow another browser's.

## Step 2: retain the fixtures

Place each file at `fixtures/<area>/<browser>/<exact-version>/<host>/`, for
example `fixtures/tls/edge/153.0.4234.48/windows-11-26200/client-hello.txt`.
Each fixture's header records the browser, exact version, operating system,
launch mode, and launch arguments, with the profile path replaced by a
placeholder.

- `.gitattributes` marks `fixtures/**` as `-text`. Never rewrite a fixture's
  line endings.
- The tools refuse to write credentials, authorization fields, and cookies
  other than their own probe cookie. Do not edit a fixture to add them.
- Keep rationale out of the fixture. It goes in Validation in step 5.
- Commit the fixtures on their own, as in `7dadd86`, with the sample counts
  and the differences from the previous build in the message.

## Step 3: write the recipe functions

Recipes live in `crates/phantom-profile/src/<browser>.rs`, one module per
browser family: `chromium.rs`, `edge.rs`, and `firefox.rs` today. A new
module needs a `pub mod` line in `crates/phantom-profile/src/lib.rs`.

- Name each function `v<major>_<layer>`, such as `v154_tls`, `v154_http2`,
  `v154_quic`, `v154_http3`, `v154_http3_request`, `v154_websocket`,
  `v154_tcp`, and `v154_cookie_placement`. Recipes whose values carry
  platform data keep the platform in the name:
  `v154_windows_client_hints`, `v154_windows_navigation_template`, and
  `v154_windows_fetch_no_store_template`.
- The rustdoc of each function names the exact build and host it was captured
  on, and states what it shares with another recipe and why.
- A complete recipe set is self-contained, as `chromium::v154_*` and
  `firefox::v156_*` are. A fork may build on the current Chromium recipes and
  change only what its captures show. `edge::v153_tls` is
  `chromium::v154_tls()` with `requested_trust_anchor_ids` set to `None`.
- Leave `User-Agent` in a request template as a required caller slot
  (`RequestField::required_caller`) when no headful capture backs a literal
  value, as the Edge templates do.
- Express a captured behavior through existing settings. If a setting cannot
  express it, add the setting to the profile type and apply it in the
  transport; never add a branch on the browser.
- Re-export the public functions from the `profile` module of
  `crates/phantom/src/lib.rs`, next to the `chromium`, `firefox`, and `edge`
  modules there.

## Step 4: replay the captures in tests

Each recipe needs a test that reads its retained fixture and compares it with
the recipe through the same public path users take. Name tests
`<browser>_<major>_...` after the behavior they check.

| Layer | Where the replay lives | Example test |
| --- | --- | --- |
| TLS | `crates/phantom-net/src/tls/tests/` | `edge_153_tls_recipe_matches_windows_capture` |
| TLS fixture metadata | `crates/phantom-testkit/tests/browser_client_hello_fixtures/` | `chrome_154_fixture_retains_exact_metadata_and_client_hello` |
| HTTP/2 startup | `crates/phantom-net/tests/browser_http2_fixtures/` | `chrome_154_http2_recipe_matches_windows_capture` |
| HTTP/2 from session captures | `crates/phantom-profile/src/<browser>/tests.rs` | `edge_153_http2_session_capture_matches_the_chromium_recipe` |
| QUIC | `crates/phantom-profile/src/chromium/quic_tests.rs` and `crates/phantom-net/src/http3/tests/connector.rs` | `edge_153_quic_client_hello_recipe_matches_windows_capture` |
| HTTP/3 | `crates/phantom-profile/src/chromium/http3_tests.rs` | `edge_153_h3_capture_matches_the_chromium_recipe` |
| Client hints | `crates/phantom-profile/src/<browser>/tests.rs` | `edge_153_windows_client_hints_match_navigation_capture` |
| Request templates | `crates/phantom-profile/src/request_template/tests.rs` | `edge_153_navigation_matches_every_captured_page_request` |
| WebSocket | `crates/phantom-profile/src/websocket/tests.rs` | `chromium_154_websocket_recipe_matches_chromium_family_captures` |
| SSE reconnect | `crates/phantom/tests/sse_browser_reconnect.rs` | Replays the SSE fixtures against the client |

- Where a fork shares a Chromium layer, add a test that replays the fork's
  capture against the Chromium recipe, as the `edge_153_*_matches_the_chromium_recipe`
  tests do.
- Where a value varies per connection, test the distribution, not one
  sample. `firefox_156_recipe_draws_either_ech_grease_aead_per_connection`
  is the model.
- When you retire the previous build, repoint or remove every test that read
  its fixtures, and record any coverage you lose.

## Step 5: update the documentation

- [Validation](../explanation/validation.md#browser-recipes): add a section
  for the build with the sample counts, the result against the previous
  build, the capture commands, the retained fixtures, and its limits. Add or
  update its row in [Trust at a glance](../explanation/validation.md#trust-at-a-glance).
- [Coverage](../reference/coverage.md#browser-profiles): the builds, how the
  recipes differ, and any recorded coverage loss.
- [Profile reference](../reference/profiles.md): the browser's row and its
  recipe names.
- `README.md` names the browsers in its feature table, and the
  [roadmap](../roadmap.md) queues planned browsers. Update both.

A retirement is a breaking change to public API. Use a `!` subject and a
`BREAKING CHANGE:` footer that lists the removed functions and their
replacements, as `f129363` does.

## Step 6: run the checks

1. Run the capture tests after capturing:

   ```sh
   uv run --no-project --python 3.10 --with aioquic==1.3.0 \
     --with h2==4.4.1 --with hpack==4.2.0 \
     python -m unittest discover -s scripts/capture/tests -p 'test_*.py'
   ```

2. While iterating, run the new tests by name, for example
   `cargo test -p phantom-profile edge_153`.
3. Before handing off, run the full gate in
   [CONTRIBUTING.md](../../CONTRIBUTING.md#run-the-checks) and read its output.

## Next

- [Capture tools](../../scripts/capture/README.md): options, scenarios, and
  retained fields for each capture tool.
- [Validation](../explanation/validation.md#chrome-154-recipes): the Chrome
  154 section to model a new section on.
- [CONTRIBUTING.md](../../CONTRIBUTING.md#commits-and-pull-requests): commit
  and pull request rules.
