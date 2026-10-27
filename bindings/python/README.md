# Phantom for Python

Make sync or async requests with reusable native connection pools and browser
profiles. Read bodies in chunks or collect them within an explicit byte limit.

```python
from phantom_http import Client

PROFILE = "chrome-154-windows"

with Client(profile=PROFILE, context="navigation", timeout_ms=30_000) as client:
    with client.get("https://example.com/", params={"page": 1}) as response:
        response.raise_for_status()
        print(response.text(max_bytes=1_000_000))
```

This example uses Chrome's Windows settings. Choose other profiles from the
[catalog](https://github.com/bywayhq/phantom/blob/main/crates/phantom-profile/catalog/profiles.json)
and reuse the client for later requests. The navigation context supplies
page-load headers by default. Override it on individual requests:

```python
with Client(profile=PROFILE, context="navigation") as client:
    with client.get("https://example.com/") as page:
        page.read(max_bytes=1_000_000)
    with client.get(
        "https://example.com/data",
        context="fetch",
        headers=[("Referer", "https://example.com/")],
    ) as data:
        print(data.json(max_bytes=1_000_000))
```

Async requests accept the same `context` option. Omit it to use the client
default, or use `"raw"` to omit its template for one request. Named contexts
must exist in the selected catalog profile. Supported names are `navigation`,
`fetch`, `fetch_no_store`, `fetch_upload`, `script`, `stylesheet`, `image` and
`font`. Resource templates require `Referer`; fonts also require `Origin`.

The default protocol is negotiated from the profile. Set `protocol="h1"`,
`"h2"` or `"h3"` when you need an exact protocol.

## Install

Python packages are not published to PyPI yet. Install a matching candidate
from the [wheel workflow](https://github.com/bywayhq/phantom/blob/main/.github/workflows/python-wheels.yml):

```sh
python -m pip install path/to/file.whl
```

Candidates cover Linux x64 GNU (manylinux 2.28), Windows x64 MSVC and macOS arm64.
The wheels include dependency licenses and receipts with source, checksums and
tested hosts. Windows needs the x64 Visual C++ v14 runtime at least as recent as
the recorded build tools.

## Build from source

Use CPython 3.10+, Rust 1.88+ and the
[native build tools](https://github.com/bywayhq/phantom/blob/main/crates/phantom/src/docs/getting-started.md#install-the-build-tools).
From this directory, run `maturin develop` in a virtual environment with
Maturin 1.15.0. The package includes type hints and `py.typed`.

To install a source archive, run `pip install ./phantom_http-VERSION.tar.gz`.
It needs the same native tools and pins Rust 1.99.1 in `rust-toolchain.toml`.
If you override that compiler, recheck the build and runtime licenses.

## Streaming and lifetime

`AsyncClient` has the same options as `Client`. Use it inside an async event
loop and use `async with` for clients and responses:

```python
import asyncio
from phantom_http import AsyncClient


async def main():
    async with AsyncClient(
        profile=PROFILE, protocol="h2", context="navigation", timeout_ms=30_000
    ) as client:
        async with client.stream("GET", "https://example.com/") as response:
            async for chunk in response.iter_bytes():
                print(len(chunk))


asyncio.run(main())
```

Reads pull data on demand. `await response.read_chunk(maximum)` returns bytes
or `None` at EOF on async responses. Its limit is 1 byte through 1 MiB.
`read(max_bytes=N)`, `text(max_bytes=N)` and
`json(max_bytes=N)` consume the remaining body. Overflow closes the response.
`response.headers.get(name)` returns the first raw byte value, or `None`.
`get_list(name)` returns all matching values in order. Names match without
regard to case. The headers also remain a tuple of immutable
`ResponseHeader(name, value, sensitive)` records, preserving duplicate names,
raw bytes and compression markers.
`response.trailers` never reads the body. Its immutable snapshot is `pending`,
`unavailable` after failure or abandonment, or `complete` after validated EOF.
Complete `headers` use the same records; an empty tuple means no fields.
Completion survives later close and text/JSON parse errors.

Content stays encoded unless you pass request-only
`content_decoding=ContentDecoding.advertised(N)` and an `Accept-Encoding` header.
Import `ContentDecoding` from `phantom_http`. Its limit bounds the decoded stream;
`read(max_bytes=N)` separately bounds collection. Unknown or unadvertised codings
fail during reads. Headers remain unchanged. `decoded_content_codings` records
the selected chain in application order, independently of body completion.

Text uses your chosen Python codec and error policy, with UTF-8/strict defaults.
JSON uses Python's standard decoder. Collection bounds input bytes, not parsed
objects or parsing time. Parsing runs on your Python thread.

## WebSockets

Use `client.websocket(url)` with `with`, or `async with` on an async client:

```python
with Client(profile=PROFILE, context="raw") as client:
    with client.websocket("wss://example.com/events") as socket:
        socket.send("hello")
        print(socket.recv())
```

The default is HTTP/1.1, matching Rust. Set `protocol="profile"` to use the
profile's connection policy, or `"h2"` or `"h3"` for an exact protocol.
Openings keep the client's route, trust and
cookies. `headers` fills the profile's ordered opening fields.
`handshake_timeout_ms` inherits the profile deadline by default. Set `None`
to disable it, or a positive millisecond count for a finite limit.
`retry=WebSocketRetry(maximum=2, delay_ms=100)` enables connection-setup
retries before the opening reaches the origin. HTTP request timeouts,
retry/redirect policies and attempt budgets do not apply to WebSockets.

`send(str)` sends text and `send(bytes)` sends binary. `recv()` returns either
and raises `WebSocketClosed` on a peer Close. `receive()` also exposes
`WebSocketPing`, `WebSocketPong` and `WebSocketClose`. Ping replies are automatic.
Iteration ends on normal closure. One async reader and writer may run together.
`WebSocketLimits` bounds frames, reassembled messages and fragment counts.
Compression is currently off.

Reads pull messages without a background Python reader. Cancelling an operation
aborts that socket. `close()` or async `aclose()` completes the peer handshake
within five seconds by default, adjustable with `timeout_ms`. A pending reader
can receive the peer's Close reply. `send_close()` only flushes Close, leaving
you to receive the reply. Pass `None` for an empty Close frame. `abort()`
releases the socket immediately.
A rejected handshake has a readable `WebSocketError.response`.
Client shutdown waits for open responses and sockets. If it times out, finish
or close them and call `client.close()` again. Cancelling async shutdown leaves
those responses and sockets usable.

## Send a body

Use `post`, `put`, `patch`, `get`, `head`, `delete` or `options` for common
methods, or `request(method, url)` for any method. They accept the same request
options. `stream(method, url)` closes the response when its context exits.

```python
with Client(profile=PROFILE, context="fetch") as client:
    with client.post("https://example.com/items", json={"name": "sample"}) as response:
        response.raise_for_status()
    with client.post(
        "https://example.com/search", form=[("tag", "a"), ("tag", "b")]
    ) as response:
        response.raise_for_status()
```

Choose one of `json`, `form`, `body` or `upload`. JSON uses Python's encoder,
UTF-8 and compact separators; `json=None` sends `null`. Form accepts an ordered
mapping or pairs, preserving duplicate names. JSON and form bodies default to
a 16-MiB encoded limit; change it with `maximum_body_bytes`. They supply their
Content-Type after your caller headers. An existing matching header keeps its
position; conflicts and duplicates fail before sending. Template slots retain
the protocol's header placement.

`params` accepts a mapping or ordered pairs and appends to an existing query.
Duplicate names stay ordered, `None` values are omitted, and booleans become
`true` or `false`. Existing query escapes are preserved.

Use `body=b"..."` for replayable bytes or `upload=path` for a one-shot file
stream. Files use their opened length: growth is excluded and shrinkage fails.
You can also pass an async iterable of bytes to `AsyncClient`, or an iterable
to `Client`. Producers are one-shot. Native demand copies at most 64 KiB per chunk.
Set `body_length=N` for a known length. Checks cover demanded bytes and observed
EOF; unread suffixes are not validated. The total deadline includes file setup
and remains active after an early response.
Use `await client.aclose()` for explicit async shutdown; `close()` remains
available with the same awaitable behavior.

Set `trailers=(Header("X-Final", b"value"), ...)` for ordered static trailers;
HTTP/2 and HTTP/3 names must be lowercase. `expect_continue_ms=1000` opts into
100-continue; `None` disables it and zero is a zero wait. The wait spends the
request's head/total deadlines. Headers and trailers share a 256-field/64-KiB
input bound; core trailer restrictions also apply.

`PreparedBody.form(pairs, maximum_bytes=N)` encodes ordered UTF-8 pairs.
`PreparedBody.multipart(parts, boundary="explicit", maximum_bytes=N)` accepts
ordered `MultipartPart(name, str_or_bytes, filename=None, content_type=None)`
values. Import these types from `phantom_http`. Both return immutable native
bodies reusable as `body=prepared` across requests and clients. The cap includes
encoded framing; multipart text normalizes newlines and byte parts stay exact.
Declare a Content-Type template slot or supply `("Content-Type",
prepared.content_type)` in your chosen header position. `prepared.length` is the
encoded size; `to_bytes()` makes an explicit copy. No files or producers are read.

For a one-shot upload, mix these fields with `MultipartPart.stream(name, iterator)`
or `MultipartPart.file(name, path)`. Files open on demand; sources are read in order.

```python
from phantom_http import MultipartPart, StreamingMultipartBody

parts = [MultipartPart("tag", "one"), MultipartPart.file("file", "data.bin")]
body = StreamingMultipartBody(parts, boundary="explicit", maximum_bytes=1_000_000)
```

Pass it as `body=body` with the same Content-Type placement. The first request
takes ownership of the sources. The encoded cap includes framing.

Use `await response.aclose()` to wait for cooperative producer cleanup.
Noncooperative cleanup can time out and remains owned for a later close.
`Error.original` and `.cleanup_error` expose upload failures explicitly;
error messages omit their text.

Close an unused response or leave its context manager. Concurrent reads fail.
Cancelling a request interrupts setup/upload; cancelling a read closes that
response. Other multiplexed streams remain usable. Cleanup may finish later.

## Request settings

Protocols are `h1`, `h2`, `h3` and `negotiated` (HTTP/2 or HTTP/1.1). Direct
`h2` with an HTTP URL uses cleartext prior knowledge. Unknown profiles and
unsupported combinations fail. Redirect following and caller retries are opt-in.

Use `redirect_policy=RedirectPolicy.limited(5)` on a client or request.
Add `credential_headers=("x-api-key",)` to strip custom secrets permanently
when a redirect changes origin. Standard credentials are always stripped.
Use `network=NetworkOptions(public_only=True)` to admit only public destination
IPs for new direct connections. Proxies and custom streams are unsupported;
existing connections remain reusable.
`redirect_history_limit=3` retains the first selected hops, including their URLs.
Use `retry_policy=RetryPolicy(status_retry=StatusRetry(statuses=(503,),
maximum=2, delay=0.1))` for eligible status retries. Import these types from
`phantom_http`. Connection retries, replay controls, capped backoff, jitter and
bounded `Retry-After` use the same core policies. Delays are seconds. Request
policies replace client policies; empty policies disable them. Attempts share
the total deadline and budget, with the core's body-replay and credential rules.

Pass `context="navigation"` or `"fetch"` for that catalog profile's headers.
The default, `None`, and `"raw"` use caller fields only. Headers are ordered
pairs, including duplicates: `headers=[("x-example", b"value")]`. Values accept
bytes or Latin-1 text. H2/H3 caller names must be lowercase. Use
`Header("x-secret", b"value", sensitive=True)` for never-index encoding.

Responses expose ordered byte-valued headers, `status`, `url`,
`redirects_followed` and `connection_setup_retries`. The last count covers
caller-enabled setup retries only. HTTP error statuses remain responses until
you call `raise_for_status()` for a 4xx or 5xx status.

## Routing and trust

`base_url="https://example.com/api/"` resolves `"child"` to `/api/child`;
`"/child"` starts at the origin root. Routing defaults to direct and ignores
proxy environment variables. `proxy`
accepts HTTP(S), SOCKS4(a) and SOCKS5(h) URIs. Use
`Proxy(uri, username="user", password="secret")` for HTTP Basic or SOCKS5 auth;
credentials belong outside the URI. `Trust(roots=(der,), proxy_roots=(der,))`
adds separate origin/proxy roots while retaining certificate verification.
`Trust(server_spki_pins=(digest,), proxy_server_spki_pins=(digest,))` adds
optional origin/proxy pin policies: one to 32 supplied SHA-256 digests of the
leaf's DER SubjectPublicKeyInfo, each exactly 32 bytes. Pins supplement verified
trust; `None` omits a policy, and an empty tuple is invalid. A proxy pin requires
TLS when a proxy is used; direct routes remain usable.

For client authentication, parse a reusable native owner with
`ClientCertificate.from_pem(chain_bytes, key_bytes)` or
`from_der((leaf_der, intermediate_der), key_der)`. Keys must be unencrypted;
inputs are bounded as described by `ClientCertificate`. Pass it as
`client_certificate=identity`, or use ordered
`client_certificates_for=(("https://api.example", identity),)` overrides.
The last matching origin wins; server verification remains enabled. Certificates
are sent only when requested by an origin, never on the outer proxy TLS hop.

Pass `network=NetworkOptions(host_overrides=(HostOverride("api.example",
("127.0.0.1",)),), local_addresses=("127.0.0.1",))` to override DNS and bind
sources while keeping SNI and Host. `interface` binds a named interface; missing
source families never fall back to an unbound socket. Import both types from
`phantom_http`. Overrides are ordered: the last matching host wins; an empty
address tuple blocks resolution. Network settings share 1024 entries and 64 KiB.

On Linux and macOS, `NetworkOptions(unix_socket="/run/service.sock")` opens
direct H1/H2 connections through that path while retaining the request URL's
authority and TLS verification. Forks retain it; encrypted checkpoints, proxies,
H3 and DNS/source overrides cannot be combined with it. TCP profile options do
not apply. Windows returns a typed unsupported-platform error.

Pass `pool=PoolOptions(max_concurrent_http1_requests_per_origin=2)` to tune
operational pool limits. Import `PoolOptions` from `phantom_http`; omitted
fields retain core defaults. Counts apply per pool key (origin and route),
retention counts entries, and `negotiated_setup_wait_limit` is seconds. These
limits are separate from profile wire settings and binding admission.

## Budgets and deadlines

Attach one `AttemptBudget(maximum)` as `budget` across requests and clients.
Origin attempts, including internal resends, spend it atomically. Admissions
are not refunded, even if no bytes are sent. DNS, setup and proxy negotiation
are separate. `try_admit()` charges attempts made outside Phantom only.

Use `timeout_ms` for a total deadline through body completion, or client
`Timeouts(connect=5, total=30)` for phase limits in seconds. Phases are
`pool_admission`, `connect`, `response_head`, `read_idle` and `total`.
Response-head time includes upload. Omitted client limits are disabled.
Request `TimeoutOverrides` inherits omitted fields, disables `None` fields
and applies finite nonnegative numbers, including zero. For example,
`TimeoutOverrides(total=None, read_idle=2)` disables total but limits idle reads.
Do not combine `timeout_ms` and `timeouts`. Total zero rejects before sending;
other zero phase timers can race ready work.

## Manage session state

Cookies are enabled by default. Use `client.cookies.set(url, set_cookie)`,
`for_url(url)` and `clear()`; `cookies=False` disables storage. Matching uses
top-level navigation semantics, independently of the header template.

`close_idle_connections()` retires idle connections; `refresh_connections()`
retires pools while active responses finish. Both retain learned state. Clear
it explicitly with `clear_session_tickets()`, `clear_dns_cache()`,
`clear_client_hints()`, `clear_alt_svc()` or `clear_alt_svc_racing_history()`.
These clears are synchronous; the pool controls are awaitable on `AsyncClient`.

`close(timeout_ms=5000)` closes admission and waits for active work. Read or
close bodies first. Expiry leaves admission closed; other clients stay usable.

Use `client.fork(sharing=SessionSharing(cookies=True, tickets=True))` for new
pools sharing selected live state. Import `SessionSharing` from `phantom_http`;
selectors are `cookies`, `dns`, `client_hints`, `discovery` and `tickets`, all
false by default. Selected learning, expiry and clearing are shared; other state
starts empty. Sharing does not enable disabled features. Profile, routes, trust
and timeouts are retained. Close either client independently, or fork a closed
source into an open client. Sync forks retain the creating-thread rule.

Export encrypted state with `checkpoint = await client.export_session(key)`,
then `restored = await client.restore_session(checkpoint, key)`; sync clients
have the same methods. Supply a secret random 32-byte key. Checkpoints contain
enabled cookies, direct Alt-Svc and TLS tickets, within 32 MiB. Address DNS,
client hints and racing history start empty. Restore uses the receiving
client's compatible configuration and returns independent pools;
it never changes the receiver. `receiving_routes` lists request-only ticket
routes (URI strings, `Proxy`, or `None` for direct). Core expiry and isolation
checks apply; unsupported state/configuration raises `SessionSnapshotError`.
No configuration or file I/O is serialized. Already-started CPU work continues
if the awaiting task is cancelled; an unpublished restored client is discarded.

## Transfer limits and counters

Use one `TransferControl(limits=TransferLimits(download_bytes=1_000_000))`
across requests with `transfer_control=control`; both classes are imported from
`phantom_http`. Optional upload/download caps accept zero; integer
`upload_bytes_per_second` and `download_bytes_per_second` rates must be positive.
Downloads count encoded body bytes. `control.snapshot()` returns five exact
body counters; reserved quota survives cancellation and decoded frames can lead
the application's buffered cursor. Headers and transport overhead are excluded.
Caps apply across attempts; failures retain `Error.kind == "transfer"`.

## Observe a request

Pass a fresh `RequestDiagnostics(maximum_events=128)` as `diagnostics=` to
observe one request. `snapshot()` returns `None` before attachment, then frozen
records with exact nanosecond timings and available endpoint/TLS/certificate
facts. Missing values are unobserved; overlapping intervals must not be summed.
Response-head completion is separate from body completion. The single-use
observer survives failure or cancellation; capacity omissions are counted.

## Author profiles

```python
import json
from phantom_http import Profile

profile = Profile.from_catalog(PROFILE, context="fetch")
document = profile.describe()
custom = Profile.import_json(json.dumps(document).encode("utf-8"))
with Client(profile=custom, protocol="h1", context="profile") as client:
    with client.request("GET", "https://example.com/") as response:
        body = response.read(max_bytes=1_000_000)
```

`describe()` returns an editable mapping; `export_json()` returns its complete
JSON bytes. Import validates the schema, ordering and 16 MiB input limit.
`ProfileError.kind` and `.field` identify failures without supplied values.
Documents can contain literal headers; treat them as sensitive.

Profiles are immutable. Import creates new settings with `catalog_id=None`.
Use `context="profile"` for an attached template.
Named contexts require a catalog-owned profile; imports cannot borrow them.

Use `Profile.import_ja3(text, base=profile)`, `import_akamai`,
`import_ja4(text, format="original", base=profile)`, `import_client_hello`
or `import_quic_transport` for partial observations. Each returns an immutable
`ImportedProfile` with `profile`, `observed_fields` and `supplemented_fields`.
JA3/JA4 require raw descriptions, not hashes. JA4 also accepts `format="sorted"`.
ClientHello input includes its four-byte handshake header, without TLS records;
QUIC input is extension 57's payload. Missing settings come from the explicit
base.

## Synchronous calls and errors

`Client` uses one reusable Python event loop. Call it from its creating thread,
outside an active event loop. Client and response support `with`; Control-C
cancels and settles pending work before rethrowing.

Failures derive from `Error` and expose `kind`, `protocol` and `timeout_phase`.
Specific errors include `TimeoutError`, `AttemptBudgetExhausted`, `ClientClosed`,
`BodyLimitExceeded` and `DecodeError`. Messages omit request inputs and backend
causes. Cancellation remains `asyncio.CancelledError`. Argument conversion can
raise Python's usual type/value/overflow errors. `HTTPStatusError.response`
retains the response and its readable body.

## Next

See the [library guides](https://github.com/bywayhq/phantom/blob/main/crates/phantom/src/docs/overview.md).
After `maturin develop`, run the loopback tests from this directory with
the independent HTTP/3 peer setup:

```sh
python ../../scripts/dev/binding_h3_peer.py -- uv run --active --no-project \
  --with h2==4.4.1 python -m unittest discover -s tests
```
