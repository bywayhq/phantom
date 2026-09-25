# Fuzzing

These `cargo-fuzz` targets feed arbitrary bytes to parsers that read data from
a peer or proxy. They cover Phantom-owned bounded wire decoders, Quinn's QUIC
transport-parameter decoder as Phantom uses it, and the production parsers
reachable through the public API of `phantom-net` and the `phantom` facade.
They are not general fuzz coverage of the BoringSSL, HTTP/2, QUIC, or
WebSocket engines.

| Target | Parser | Entry point |
| --- | --- | --- |
| `client_hello` | Test-kit TLS ClientHello summary | `phantom_testkit::tls` |
| `http2_frame` | Test-kit HTTP/2 frame capture | `phantom_testkit::http2` |
| `quic_transport_parameters` | Quinn transport parameters (production) | `TransportParameters::read` |
| `http1_response` | HTTP/1.1 response heads and bodies (production) | `Http1Connection::connect` and `send_get` over an in-memory origin |
| `http_connect_response` | HTTP CONNECT proxy response heads (production) | `connect_http_tunnel` over an in-memory stream |
| `proxy_basic_challenge` | `Proxy-Authenticate` challenge lists (production) | `validate_basic_proxy_challenge` |
| `cookie_jar` | `Set-Cookie` storage and `Cookie` construction (production) | `CookieJar::set_cookie` and `CookieJar::request_value` |
| `cookie_snapshot` | Caller-persisted cookie entries (production) | `Client::import_cookies` |
| `alt_svc_snapshot` | Caller-persisted Alt-Svc entries (production) | `Client::import_alt_svc` |
| `https_record` | DNS responses and HTTPS record RDATA (production) | `dns::https_answers_from_message` and `HttpsRecord::from_rdata` |

`client_hello` and `http2_frame` decode test-kit captures, not the bytes a
peer sends Phantom; they check the evidence tooling, not a peer-facing parser.

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
cargo +nightly fuzz run http1_response -- -max_len=16384
cargo +nightly fuzz run http_connect_response -- -max_len=65536
cargo +nightly fuzz run http2_frame -- -max_len=262144
cargo +nightly fuzz run https_record -- -max_len=65536
cargo +nightly fuzz run proxy_basic_challenge -- -max_len=16384
cargo +nightly fuzz run quic_transport_parameters -- -max_len=65536
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
costs coverage, and the cost is paid elsewhere: no fuzzed response can reach
the observer's head-byte or field-count limits, so `ResponseHeadTooLarge` and
`TooManyResponseHeaders` are unreachable under fuzzing. Both are pinned by
deterministic regressions in
[`src/http1_response/tests.rs`](src/http1_response/tests.rs), which is where a
limit boundary belongs: it is a fixed threshold, not a mutated input.

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

Two targets also assert a policy invariant that a real confusion would break.
`cookie_jar` marks every stored field `Secure` and asserts that no request to
an origin that is not potentially trustworthy receives a `Cookie` field and
that no such origin can store one. `alt_svc_snapshot` asserts that a snapshot
the client exported passes the client's own import revalidation; the origin
half of that round trip is the real cross-check, because a stored
alternative's host is revalidated against the request host on the way in and
re-emitted verbatim on the way out.

`cookie_jar` asserts those two rules over named hosts, which no rule makes
trustworthy over `http://`. Loopback and `localhost` authorities are
trustworthy under either scheme, so
[`TRUSTWORTHY_URL_PAIRS`](src/cookie_jar.rs) carries a third assertion
instead: for each authority, the same fields stored over `http://` and over
`https://` must leave the same number of cookies and produce the same `Cookie`
field. That guards the symmetry between the jar's storage gate and its
matching gate, and it fails whichever of the two a change inverts.

Both pairs are needed, because the two gates fail on different hosts. The
`cookie_store` crate's own secure test accepts a loopback IP literal, so the
matching gate agrees on `127.0.0.1` whatever the jar does, and that pair
constrains storage alone. It accepts the exact host `localhost` and nothing
beneath it, so on `app.localhost` an `http://` request sees a `Secure` cookie
only through the jar's own trustworthy test, and that pair constrains both
gates. A loopback-only assertion stays green against a jar that has lost the
matching side entirely.

Each jar is read back over the scheme it was filled from, because a
`Partitioned` cookie's key is schemeful; the seed carries a `Partitioned`
field so the fuzzer reaches that path.

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

## Where a check belongs

`alt_svc_snapshot`, `cookie_jar`, `cookie_snapshot`, `http1_response`, and
`https_record` keep their harness, their seeds, and their fixed-threshold
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

## Not fuzzed yet

These peer-facing production parsers have no pure public entry point. Fuzzing
them needs a reviewed fuzzing seam, not new public API:

- the SSE decoder;
- the Alt-Svc field parser, meaning `Alt-Svc` response fields, as distinct
  from the snapshot import that `alt_svc_snapshot` covers;
- SOCKS5 negotiation replies (the public API is TCP-only);
- the HTTP/2 and HTTP/3 ALPS decoders;
- the CONNECT-UDP Capsule Protocol decoder;
- the `Content-Encoding` and `Accept-Encoding` field grammar, with its chained
  `ContentDecoder`;
- `CookieJar::store_response_headers`, the step above `cookie_jar` that
  converts response `Set-Cookie` header bytes to text.
