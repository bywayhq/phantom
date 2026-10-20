# Phantom for Python

Reuse a client with an exact browser profile and an explicit HTTP protocol.
Read response bodies in chunks, or collect them with a byte limit.

```python
from phantom_http import AsyncClient


async def fetch():
    async with AsyncClient(
        profile="chrome/154.0.8037.97/windows-11-26200/r1",
        protocol="negotiated",
        context="navigation",
        timeout_ms=30_000,
    ) as client:
        response = await client.request("GET", "https://example.com/")
        async with response:
            return await response.read(max_bytes=1_000_000)
```

Build locally with CPython 3.10 or newer, Rust 1.88 and Phantom's
[native build tools](../../crates/phantom/src/docs/getting-started.md#install-the-build-tools).
From this directory, run `maturin develop` inside a virtual environment.
Maturin 1.9.4 or newer selects extension linking for this build only.
Ordinary Cargo checks retain Python linking.

## Native wheel candidates

The [wheel workflow](../../.github/workflows/python-wheels.yml) builds optimized
candidates for Linux x64 GNU, Windows x64 MSVC and macOS arm64. Each successful
artifact includes its source revision, toolchain, wheel checksum, dependency
notices, native linkage and tested runtime. It is uploaded only after a fresh,
cache-free installation outside the checkout passes the Python loopback tests.
Failures retain command logs without marking a wheel verified.

Download a matching verified candidate and run `python -m pip install path/to/file.whl`.
Keep the wheel's included licenses when redistributing it. Candidates are not
published to PyPI. Linux uses a native `linux_x86_64` tag, without a manylinux
compatibility claim. The receipt covers its recorded host and CPython version;
older operating systems, libc versions and other Python runtimes are unverified.
Windows needs the Microsoft x64 Visual C++ v14 runtime, at least as recent as
the recorded MSVC build tools. OS/SDK runtime licenses are separate from the
wheel's Rust and native dependency notices.

To produce a candidate from a clean checkout, run the helper from the repository
root through `scripts/dev/with-cargo-lock.sh` with `--release-candidate`,
`--target` and a new `--output` directory. Without those options, the helper
keeps the ordinary development build used by the gate.

The package includes inline type hints and `py.typed` for Python 3.10 or newer.
Sync and async clients expose the same explicit request options to editors and
type checkers. Headers retain their order, including duplicate names.

## Requests and state

`AsyncClient` requires `profile` and `protocol`. Protocols are `h1`, `h2`, `h3`
and `negotiated` (the library's HTTP/2 and HTTP/1.1 policy). No template is
selected unless you pass `context="navigation"` or `context="fetch"`.
Unknown profiles and unavailable contexts fail. No retries or protocol fallbacks
are enabled by the wrapper.
For direct `http://` URLs, `h2` selects cleartext HTTP/2 prior knowledge.

Pass ordered `headers=[("x-first", b"one"), ("x-second", b"two")]`.
Values accept bytes or Latin-1 text. Other text requires explicit encoding into
bytes. The library enforces the selected protocol and template rules.
HTTP/2 and HTTP/3 require lowercase caller header names.
Use `Header("x-secret", b"value", sensitive=True)` alongside pairs to request
never-index encoding in HTTP/2 and HTTP/3. This does not encrypt a header.
Responses retain ordered duplicate header pairs with byte values. HTTP error
statuses are responses; this slice does not raise for them automatically.

The route defaults to direct and ignores proxy environment variables. `proxy`
accepts HTTP(S), SOCKS4(a) and SOCKS5(h) URIs. For HTTP Basic or SOCKS5
authentication, pass `Proxy(uri, username="user", password="secret")`.
Supply credentials together, separately from the URI. SOCKS4 credentials,
CONNECT-UDP and custom profile documents are not exposed yet.

Set `base_url="https://example.com/api/"` to resolve relative request URLs.
`"child"` joins to `/api/child`; `"/child"` starts at the origin's root.
`Trust(roots=(der_bytes,), proxy_roots=(proxy_der_bytes,))` adds separate
origin and HTTPS-proxy roots. Certificate and hostname verification stay enabled.

Cookies are enabled by default. Use `client.cookies.set(url, set_cookie)`,
`for_url(url)` and `clear()`. Cookie matching uses Phantom's top-level navigation
context; selecting a fetch header template does not supply a browser cookie
context. Pass `cookies=False` to disable storage.

Create `AttemptBudget(maximum)` and pass the same object as `budget` to requests
across clients. Initial attempts and resends consume admissions atomically.
Admissions are not refunded; they can fail before sending bytes. DNS, connection
setup and proxy negotiation are separate work. The budget does not enable retries.

`timeout_ms` on the client or request covers the library operation through body
completion across internal attempts. File opening occurs before its clock starts.
Inactive Python consumers must still close their response bodies.
For phase limits in seconds, use `timeouts=Timeouts(connect=5, total=30)`.
The phases are `pool_admission`, `connect`, `response_head`, `read_idle` and
`total`. Response-head time includes upload. Each omitted client limit is
disabled. A request's `TimeoutOverrides` inherits omitted fields (`INHERIT`),
disables explicit `None` fields and applies finite numbers, including zero.
For example, `TimeoutOverrides(total=None, read_idle=2)` disables the inherited
total limit while limiting body-read idle time. Pass `timeouts` or `timeout_ms`,
never both. Durations must be finite and nonnegative.
With zero, an already-ready operation can send bytes before expiry is observed.

## Streaming and lifetime

Use `body=b"..."` for replayable bytes or `upload=path` for an 8 KiB file stream.
They are mutually exclusive. File uploads use the opened file's length, stop at
that length if it grows and fail if it shrinks. They are one-shot: a required
resend returns a request-body error. Arbitrary Python upload producers are not
accepted or collected implicitly.

`await response.read_chunk(maximum)` returns bytes or `None` at EOF. The chunk
limit is 1 through 1 MiB. `async for chunk in response.iter_bytes()` reads only
as you ask for chunks; there is no background body collector. `read(max_bytes=N)`
closes the body if its bound is exceeded. Content is not decoded automatically.
Trailers are consumed but not exposed by this slice.

Use `text(max_bytes=N, encoding="utf-8", errors="strict")` or `json(max_bytes=N)`
to collect and decode the remaining body. Text uses your chosen Python codec
and standard error policy; it does not guess from headers. JSON uses Python's
standard decoder, including UTF-8/16/32 detection. Neither helper decompresses
content or caches the body. The byte limit does not bound decoded allocations
or parsing time. Parsing runs on your Python thread after the native read.
`DecodeError` reports `encoding`, `text_decode` or `json_decode` without content.

`status_code` aliases `status`. Call `raise_for_status()` explicitly to reject
400 through 599; redirects remain ordinary responses. `HTTPStatusError.response`
retains the original response, with its body still readable.

Use response context managers, or call `response.close()` when stopping early.
Concurrent reads fail. Cancelling a read closes that response permanently.
Cancelling a request drops its native operation, including setup or upload.
It does not close another request on a shared multiplexed connection.
Cancellation can return before background connection cleanup finishes.

`await client.close(timeout_ms=5000)` closes admission and waits for active
requests and bodies. Read or close them first. Expiry returns `TimeoutError`;
admission stays closed. Close does not abort unrelated active operations.
The shared Tokio runtime remains available to other clients.

`await client.close_idle_connections()` releases idle pools without interrupting
active responses. `await client.refresh_connections()` retires current pools
while active owners finish. Both retain cookies, tickets and discovery state.
Use `clear_session_tickets()`, `clear_dns_cache()`, `clear_client_hints()`,
`clear_alt_svc()` or `clear_alt_svc_racing_history()` to clear selected state.
These clearing calls are synchronous on both clients. The two pool controls
are synchronous on `Client`.

## Synchronous calls and errors

`Client` wraps the same async API on one reusable Python event loop. Use it from
its creating thread, outside an active event loop. `request`, `read`, `iter_bytes`
and `close` are synchronous. Both client and response support `with`.
Control-C cancels and settles the pending operation before rethrowing.

Failures derive from `Error` and expose `kind`, `protocol` and `timeout_phase`.
Specific classes include `TimeoutError`, `AttemptBudgetExhausted`, `ClientClosed`
and `BodyLimitExceeded`. Messages omit URLs, credentials and backend causes.
Cancellation remains `asyncio.CancelledError`. Python argument conversion can
also raise normal `TypeError`, `ValueError` or `OverflowError`.

## Next

See the [library guides](../../crates/phantom/src/docs/overview.md) for protocol
and profile limits.

After `maturin develop`, run the loopback tests with
`uv run --active --no-project --with h2==4.4.1 python -m unittest discover -s tests`.
