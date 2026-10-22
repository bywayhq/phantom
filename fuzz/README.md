# Fuzzing

These `cargo-fuzz` targets feed arbitrary bytes to parsers that read data from
a peer or proxy. They cover Phantom-owned bounded wire decoders, Quinn's QUIC
transport-parameter decoder as Phantom uses it, and the production parsers
reachable through the public API of `phantom-net` and the `phantom` facade.
They are not general fuzz coverage of the BoringSSL, HTTP/2, QUIC, or
WebSocket engines.

| Target | Parser | Entry point |
| --- | --- | --- |
| `client_hello` | TLS ClientHello capture and profile-import decoder | `phantom_testkit::tls` re-export of `phantom_profile::client_hello` |
| `sse` | Incremental SSE event decoding and encoded-byte limits | Private `SseStream` decoder through an opt-in fuzzing seam |
| `http2_frame` | Test-kit HTTP/2 frame capture | `phantom_testkit::http2` |
| `quic_transport_parameters` | Quinn transport parameters (production) | `TransportParameters::read` |
| `http1_response` | HTTP/1.1 response heads and bodies (production) | `Http1Connection::connect` and `send_get` over an in-memory origin |
| `http_connect_response` | HTTP CONNECT proxy response heads (production) | `connect_http_tunnel` over an in-memory stream |
| `proxy_basic_challenge` | `Proxy-Authenticate` challenge lists (production) | `validate_basic_proxy_challenge` |
| `cookie_jar` | `Set-Cookie` storage and `Cookie` construction (production) | `CookieJar::set_cookie` and `CookieJar::request_value` |
| `cookie_snapshot` | Caller-persisted cookie entries (production) | `Client::import_cookies` |
| `alt_svc_snapshot` | Caller-persisted Alt-Svc entries (production) | `Client::import_alt_svc` |
| `https_record` | DNS responses and HTTPS record RDATA (production) | `dns::https_answers_from_message` and `HttpsRecord::from_rdata` |
| `ech_config_list` | An HTTPS record's `ECHConfigList` (production) | `dns::EchConfigList::parse` |

`client_hello` covers the decoder shared by captures and profile imports. It
does not parse live TLS handshakes. `http2_frame` covers test-kit captures,
not the HTTP/2 engine used for requests.

## Run a target

Install the pinned `cargo-fuzz` version, then run a target from `fuzz/` with a
nightly toolchain. Each command uses the input-size limit (`-max_len`) that CI
uses for that target:

```console
cargo install cargo-fuzz --version 0.13.2 --locked
cd fuzz
cargo +nightly fuzz run alt_svc_snapshot -- -max_len=16384
cargo +nightly fuzz run client_hello -- -max_len=65536
cargo +nightly fuzz run cookie_jar -- -max_len=16384
cargo +nightly fuzz run cookie_snapshot -- -max_len=16384
cargo +nightly fuzz run ech_config_list -- -max_len=65537
cargo +nightly fuzz run http1_response -- -max_len=16384
cargo +nightly fuzz run http_connect_response -- -max_len=65536
cargo +nightly fuzz run http2_frame -- -max_len=262144
cargo +nightly fuzz run https_record -- -max_len=65536
cargo +nightly fuzz run proxy_basic_challenge -- -max_len=16384
cargo +nightly fuzz run quic_transport_parameters -- -max_len=65536
cargo +nightly fuzz run sse -- -max_len=65536
```

Targets that link `phantom-net` also build BoringSSL, so they need the native
prerequisites in [CONTRIBUTING.md](../CONTRIBUTING.md#development-setup).

On a Windows host the built target loads the MSVC AddressSanitizer runtime at
startup. Put the MSVC `Hostx64/x64` directory on `PATH` before
`cargo fuzz run`, or the target exits with `STATUS_DLL_NOT_FOUND` before
libFuzzer starts.

The 256 KiB limit for `http2_frame` keeps mutation throughput high. A
dedicated run may raise it to the largest HTTP/2 frame: a 16,777,215-byte
payload plus the nine-byte frame header.

The 16 KiB limit for `http1_response` stays under the 32 KiB response-head
limit: both the head observer and the protocol engine reparse their buffered
head on every read, so a longer head combined with one-byte reads costs
quadratic time and would report a timeout rather than a defect. That bound
excludes the observer's head-byte limit, so `ResponseHeadTooLarge` cannot
occur under this run's input limit. Short fields can still reach the
field-count limit and produce `TooManyResponseHeaders`. Deterministic
regressions cover both boundaries in
[`src/http1_response/tests.rs`](src/http1_response/tests.rs).

## What the targets feed

Each target decodes the raw input, then also uses the input to perturb valid
structural seeds, so mutations also exercise nearly valid messages. The QUIC
target calls Quinn's real decoder in both endpoint roles. Its seeds cover
ordered, reordered, duplicate, truncated, and malformed-varint parameters,
including the shape from Quinn advisory
[GHSA-6xvm-j4wr-6v98](https://github.com/quinn-rs/quinn/security/advisories/GHSA-6xvm-j4wr-6v98).

`http1_response` takes the read-chunk size and the transaction count from a
control prefix it strips before the response payload begins, so neither shares
a byte with the response or with the perturbation offset, and every read
boundary is reachable for any response. Its origin scripts one response per
transaction and releases each only once the matching request has been written,
so a second transaction reaches a second response head — the path that resets
the ordered-header observer — rather than end of stream.

`alt_svc_snapshot` checks that exported snapshots pass import revalidation,
including the alternative host's relationship to the request host.

`cookie_jar` checks that untrustworthy origins can neither store nor receive
`Secure` cookies. For loopback and `localhost`, which are trustworthy under
either scheme, [`TRUSTWORTHY_URL_PAIRS`](src/cookie_jar.rs) checks that HTTP
and HTTPS store and return the same cookies. The `127.0.0.1` case checks
storage; `app.localhost` also checks matching, where the dependency's own
secure-host rule differs. Each jar is read over its original scheme to keep
schemeful `Partitioned` cookie keys intact.

`cookie_snapshot` covers the import path `cookie_jar` does not: entries a
caller persisted and hands back through `Client::import_cookies`. It asserts
that a rejected snapshot leaves the jar empty, that no stored `Secure` cookie
has an `http` source scheme unless its host is loopback or `localhost`, and
that an exported snapshot imports again to the same number of cookies.

`https_record` decodes its input as a DNS response with hickory's parser and
runs the answer extraction that `HttpsRecordResolver::lookup` runs: the
CNAME-chain owner check, hickory's RDATA re-encoding, and Phantom's RFC 9460
parser. It also parses the raw input as one record's RDATA. Every record that
parses must keep the RFC 9460 rules the parser promises, such as strictly
increasing keys and every `mandatory` key present, and all answers of one
lookup must share one owner. `dns::https_answers_from_message` is a hidden
fuzzing seam, not supported API. The facade's choice of `h3` from the records
and its one-day TTL cap are private to `phantom` and not reached; nor is the
resolver's own response handling, such as ID matching and follow-up queries.

`ech_config_list` parses its input, and a structural seed it perturbs, as
the `ECHConfigList` a direct connection checks before it offers a record's
`ech` to the TLS client. Every list that parses must hold a configuration,
and every configuration the client would use must have version `0xfe0d`, a
public key, a public name, and a cipher suite. The 65,537-byte limit is the
largest list: a two-byte length and 65,535 bytes of configurations.

## Where a check belongs

`alt_svc_snapshot`, `cookie_jar`, `cookie_snapshot`, `ech_config_list`,
`http1_response`, and `https_record` keep their harness, their seeds, and their fixed-threshold
checks in `src/`, and their `fuzz_targets/` binaries are wrappers. A seed that stops parsing then fails
`cargo test --manifest-path fuzz/Cargo.toml`, which the lint job runs on the
project toolchain, rather than silently weakening every fuzz iteration. A
check that only ever sees one fixed input belongs there and not in the fuzz
loop; the targets assert only what constrains mutated input. The five older
targets still check their seeds in-loop under an `input.is_empty()` guard.

## When a target fails

Minimize a crash or timeout, and add the minimized input as an ordinary
deterministic regression test before you delete the generated artifact.

Generated corpora, artifacts, coverage output, and build products are never
committed.

## CI

The [Parser fuzzing](../.github/workflows/fuzz.yml) workflow runs every target
under AddressSanitizer:

- pull requests and pushes to `main` that change parser paths: 15 seconds per
  target;
- the weekly schedule and manual dispatch: five minutes per target.

CI keeps one corpus per target in the Actions cache. Every run starts from the
newest saved corpus, and only scheduled runs save it back.

The `sse` target enables Phantom's optional `fuzzing` feature. Its doc-hidden
batch seam calls the production incremental decoder; it is not supported API.
The harness compares event prefixes, first errors, committed IDs and retry
delays across whole-buffer, bytewise and cyclic chunks. Literal seeds and
independent byte-limit controls cover BOM, CRLF, UTF-8 replacement and incomplete
EOF. Inputs and both decoder limits are bounded at 64 KiB. This target does not
exercise HTTP, reconnect timing or idle deadlines.

## Not fuzzed yet

These peer-facing production parsers have no pure public entry point. Fuzzing
them needs a reviewed fuzzing seam, not new public API:

- the Alt-Svc field parser, meaning `Alt-Svc` response fields, as distinct
  from the snapshot import that `alt_svc_snapshot` covers;
- SOCKS5 negotiation replies (the public API is TCP-only);
- the HTTP/2 and HTTP/3 ALPS decoders;
- the CONNECT-UDP Capsule Protocol decoder;
- the `Content-Encoding` and `Accept-Encoding` field grammar, with its chained
  `ContentDecoder`;
- `CookieJar::store_response_headers`, the step above `cookie_jar` that
  converts response `Set-Cookie` header bytes to text.
