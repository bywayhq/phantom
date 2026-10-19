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
Ordinary Cargo checks retain Python linking. Prebuilt wheels and a supported
installation matrix are separate release work.

## Requests and state

`AsyncClient` requires `profile` and `protocol`. Protocols are `h1`, `h2`, `h3`
and `negotiated` (the library's HTTP/2 and HTTP/1.1 policy). No template is
selected unless you pass `context="navigation"` or `context="fetch"`.
Unknown profiles and unavailable contexts fail. No retries or protocol fallbacks
are enabled by the wrapper.
For direct `http://` URLs, `h2` selects cleartext HTTP/2 prior knowledge.

Pass ordered `headers=[("X-First", b"one"), ("X-Second", b"two")]`.
Values accept bytes or Latin-1 text. Other text requires explicit encoding into
bytes. The library enforces the selected protocol and template rules.
Responses retain ordered duplicate header pairs with byte values. HTTP error
statuses are responses; this slice does not raise for them automatically.

The route defaults to direct and ignores proxy environment variables. `proxy`
accepts HTTP(S), SOCKS4(a) and SOCKS5(h) URIs. Proxy credentials, CONNECT-UDP,
custom trust configuration and custom profile documents are not exposed yet.

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

Use response context managers, or call `response.close()` when stopping early.
Concurrent reads fail. Cancelling a read closes that response permanently.
Cancelling a request drops its native operation, including setup or upload.
It does not close another request on a shared multiplexed connection.
Cancellation can return before background connection cleanup finishes.

`await client.close(timeout_ms=5000)` closes admission and waits for active
requests and bodies. Read or close them first. Expiry returns `TimeoutError`;
admission stays closed. Close does not abort unrelated active operations.
The shared Tokio runtime remains available to other clients.

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
