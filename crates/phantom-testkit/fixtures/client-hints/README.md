# Navigation fixture

Use `phantom_testkit::fixtures::CHROME_154_WINDOWS_NAVIGATION` to inspect
retained first-navigation and Accept-CH follow-up field order and hint values.
The public constant works in an installed crate without a checkout.

## Provenance

The packaged document is byte-identical to
`fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/navigation.txt`
in the repository. Its SHA-256 is `e8296686c4874a9d6d9c783d6e0e028167b7cd89d5ca37df9c840da57a5796c7`.
The capture tool is `scripts/capture/client_hints.py`, described in the
[capture guide](https://github.com/bywayhq/phantom/blob/main/scripts/capture/README.md).

| Browser | Exact build | Platform | Launch mode | Captured at (Unix seconds) |
| --- | --- | --- | --- | --- |
| Google Chrome | 154.0.8037.97 | Windows 11 Home 10.0.26200 x64 | headless | 1790971324 |

The `phantom-client-hints-v2` document retains three HTTP/1.1 runs, with
`run_0_first_field_order` and `run_0_second_field_order` for the first run.
It records ordered field names and client-hint values, not a raw request
head. It does not establish other field values, HTTP/2 or HTTP/3 ordering,
TLS behavior, or live server acceptance.

## Next

- [Phantom testkit](../../README.md): capture and comparison examples.
