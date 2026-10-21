"""Type-check this consumer against the installed package, outside the checkout."""

from collections.abc import AsyncGenerator, Awaitable, Generator
from pathlib import Path
from typing import cast

from phantom_http import (
    INHERIT,
    AsyncClient,
    AsyncResponse,
    AttemptBudget,
    BodyLimitExceeded,
    Client,
    ConnectionRetry,
    ContentDecoding,
    Cookies,
    DecodeError,
    Error,
    Header,
    HTTPStatusError,
    ImportedProfile,
    Profile,
    ProfileError,
    Proxy,
    RedirectHistory,
    RedirectPolicy,
    Response,
    RetryPolicy,
    SessionSharing,
    StatusRetry,
    TimeoutOverrides,
    Timeouts,
    TransferControl,
    TransferLimits,
    TransferSnapshot,
    Trust,
)


def headers() -> Generator[tuple[str, str | bytes], None, None]:
    yield "X-Duplicate", b"first"
    yield "X-Duplicate", "second"


def synchronous(profile: str, url: str, upload: Path) -> bytes:
    budget = AttemptBudget(10)
    _remaining: int = budget.remaining
    budget.try_admit()
    with Client(
        profile=profile,
        protocol="negotiated",
        context="navigation",
        proxy=Proxy("http://proxy.invalid", username="user", password="secret"),
        cookies=True,
        base_url="https://origin.invalid/api/",
        trust=Trust(roots=(b"DER",), proxy_roots=(b"DER",)),
        timeouts=Timeouts(connect=1, total=5),
        redirect_policy=RedirectPolicy.limited(3),
        retry_policy=RetryPolicy(
            connection_failures=ConnectionRetry(
                maximum=2, delay=0.1, maximum_delay=1, full_jitter=True
            ),
            reused_connection_replay=True,
            unprocessed_replays=1,
            status_retry=StatusRetry(
                statuses=(429, 503), maximum=2, delay=0, retry_after_limit=1
            ),
            maximum_retries=3,
            http2_fallback=False,
        ),
    ) as client:
        _closed: bool = client.is_closed
        jar: Cookies = client.cookies
        jar.set(url, "seen=yes; Path=/")
        _cookie: str | None = jar.for_url(url)
        _count: int = len(jar)
        jar.clear()
        client.close_idle_connections()
        client.refresh_connections()
        _tickets: int = client.clear_session_tickets()
        client.clear_dns_cache()
        client.clear_client_hints()
        client.clear_alt_svc()
        client.clear_alt_svc_racing_history()
        response: Response = client.request(
            "PUT", url, headers=headers(), upload=upload, budget=budget, timeout_ms=1000
        )
        with response:
            _status: int = response.status
            _protocol: str = response.protocol
            _effective_url: str = response.url
            _redirects: int = response.redirects_followed
            _setup_retries: int = response.connection_setup_retries
            _codings: tuple[str, ...] = response.decoded_content_codings
            _history: RedirectHistory | None = response.redirect_history
            _fields: list[tuple[str, bytes]] = response.headers
            collected: bytes = response.read(max_bytes=1_000_000)
        with client.request("POST", url, body=b"bytes") as streamed:
            chunks: Generator[bytes, None, None] = streamed.iter_bytes(8192)
            for chunk in chunks:
                _payload: bytes = chunk
            chunks.close()
        client.close(timeout_ms=1000)
    return collected


async def asynchronous(profile: str, url: str) -> bytes:
    async with AsyncClient(profile=profile, protocol="h2", context="fetch") as client:
        response: AsyncResponse = await client.request(
            "GET",
            url,
            headers=[Header("X-Secret", b"value", sensitive=True), ("X-Other", "x")],
            budget=AttemptBudget(2),
            timeouts=TimeoutOverrides(connect=INHERIT, total=None, read_idle=0),
            content_decoding=ContentDecoding.advertised(2**64 - 1),
            redirect_policy=RedirectPolicy.none(),
            redirect_history_limit=2,
            retry_policy=RetryPolicy.none(),
        )
        async with response:
            _effective_url: str = response.url
            _redirects: int = response.redirects_followed
            _setup_retries: int = response.connection_setup_retries
            _codings: tuple[str, ...] = response.decoded_content_codings
            retained = response.redirect_history
            if retained is not None:
                _omitted: int = retained.omitted_hops
                for hop in retained.entries:
                    _url: str = hop.to_url
                    _status: int = hop.status
            _first: bytes | None = await response.read_chunk(1)
            collected: bytes = await response.read(max_bytes=10**100)
            # A subsequent read remains a valid call at EOF, including a bool bound.
            _eof: bytes = await response.read(max_bytes=True)
        async with await client.request("GET", url) as streamed:
            chunks: AsyncGenerator[bytes, None] = streamed.iter_bytes(8192)
            async for chunk in chunks:
                _payload: bytes = chunk
            # Mypy's stdlib stub includes Any in this coroutine's send type.
            await cast(Awaitable[None], chunks.aclose())
        await client.close(timeout_ms=1000)
    return collected


def error_fields(error: Error) -> tuple[str, str, str | None, str | None]:
    _original: BaseException | None = error.original
    _cleanup: BaseException | None = error.cleanup_error
    if isinstance(error, BodyLimitExceeded):
        _category: str = error.category
    return error.category, error.kind, error.protocol, error.timeout_phase


def response_readers(text_response: Response, json_response: Response) -> object:
    _status: int = text_response.status_code
    text_response.raise_for_status()
    _text: str = text_response.text(max_bytes=100, encoding="latin-1", errors="replace")
    return json_response.json(max_bytes=100)


async def async_response_readers(
    text_response: AsyncResponse, json_response: AsyncResponse
) -> object:
    text_response.raise_for_status()
    _text: str = await text_response.text(max_bytes=100)
    return await json_response.json(max_bytes=100)


def response_errors(error: DecodeError | HTTPStatusError) -> None:
    _kind: str = error.kind
    if isinstance(error, HTTPStatusError):
        _status: int = error.status_code
        _response: Response | AsyncResponse = error.response


def authored_profile(exact_id: str, document: bytes, error: ProfileError) -> Profile:
    catalog = Profile.from_catalog(exact_id, context="fetch")
    _identity: str | None = catalog.catalog_id
    _editable: dict[str, object] = catalog.describe()
    imported = Profile.import_json(document)
    _document: bytes = imported.export_json()
    _field: str = error.field
    Client(profile=imported, protocol="h1", context="profile")
    AsyncClient(profile=catalog, protocol="h2", context="navigation")
    return imported


def import_observations(base: Profile, raw: str, data: bytes) -> ImportedProfile:
    _ja3: ImportedProfile = Profile.import_ja3(raw, base=base)
    _hello: ImportedProfile = Profile.import_client_hello(data, base=base)
    _akamai: ImportedProfile = Profile.import_akamai(raw, base=base)
    _original: ImportedProfile = Profile.import_ja4(raw, format="original", base=base)
    _sorted: ImportedProfile = Profile.import_ja4(raw, format="sorted", base=base)
    imported = Profile.import_quic_transport(data, base=base)
    _observed: tuple[str, ...] = imported.observed_fields
    _supplemented: tuple[str, ...] = imported.supplemented_fields
    Client(profile=imported.profile, protocol="h3")
    return imported


def fork_client(client: Client) -> Client:
    selection = SessionSharing(cookies=True, dns=True, client_hints=True)
    return client.fork(sharing=selection)


async def use_async_fork(client: AsyncClient, url: str) -> None:
    async with (
        client.fork(sharing=SessionSharing(discovery=True, tickets=True)) as fork,
        await fork.request("GET", url) as response,
    ):
        _payload: bytes = await response.read(max_bytes=100)


def upload_sync(client: Client, url: str) -> None:
    def chunks() -> Generator[bytes, None, None]:
        yield b"one"

    with client.request("POST", url, body=chunks(), body_length=3) as response:
        response.read(max_bytes=100)


def checkpoint_sync(client: Client, key: bytes) -> Client:
    snapshot: bytes = client.export_session(key)
    return client.restore_session(
        snapshot, key, receiving_routes=(None, Proxy("http://proxy.invalid:80"))
    )


async def checkpoint_async(client: AsyncClient, key: bytes) -> AsyncClient:
    snapshot: bytes = await client.export_session(key)
    return await client.restore_session(snapshot, key)


async def upload_async(client: AsyncClient, url: str) -> None:
    async def chunks() -> AsyncGenerator[bytes, None]:
        yield b"one"

    response = await client.request("POST", url, body=chunks(), body_length=3)
    await response.aclose()


async def transfer_async(
    client: AsyncClient, sync: Client, url: str
) -> TransferSnapshot:
    control = TransferControl(limits=TransferLimits(download_bytes=2**64 - 1))
    response = await client.request("GET", url, transfer_control=control)
    await response.read(max_bytes=100)
    with sync.request("POST", url, body=b"data", transfer_control=control) as other:
        other.read(max_bytes=100)
    snapshot: TransferSnapshot = control.snapshot()
    _exact_count: int = snapshot.download_encoded_bytes
    return snapshot


async def request_body_controls(client: AsyncClient, sync: Client, url: str) -> None:
    fields = (Header("x-repeat", b"one", sensitive=True), ("x-repeat", "two"))
    response = await client.request(
        "POST", url, body=b"data", trailers=fields, expect_continue_ms=0
    )
    await response.aclose()
    with sync.request(
        "POST", url, body=b"data", trailers=fields, expect_continue_ms=1000
    ):
        pass


async def prepared_body_usage(client: AsyncClient, sync: Client) -> None:
    from phantom_http import MultipartPart, PreparedBody, PreparedBodyError

    body = PreparedBody.form([("tag", "one"), ("tag", "two")], maximum_bytes=1024)
    part = MultipartPart("field", b"bytes", filename="data.bin")
    encoded = PreparedBody.multipart([part], boundary="explicit", maximum_bytes=4096)
    content_type: str = encoded.content_type
    length: int = encoded.length
    payload: bytes = encoded.to_bytes()
    try:
        response = await client.request(
            "POST",
            "/",
            body=body,
            body_length=body.length,
            headers=[("content-type", body.content_type)],
        )
        await response.aclose()
        with sync.request(
            "POST", "/", body=encoded, headers=[("content-type", content_type)]
        ) as reply:
            reply.read(max_bytes=0)
    except PreparedBodyError as error:
        kind: str = error.kind
        print(kind, length, payload)


async def diagnostics_usage(client: AsyncClient, sync: Client) -> None:
    from phantom_http import RequestDiagnostics, RequestTimeline

    diagnostics = RequestDiagnostics(maximum_events=128)
    timeline: RequestTimeline | None = diagnostics.snapshot()
    response = await client.request("GET", "/", diagnostics=diagnostics)
    await response.aclose()
    if timeline is not None:
        elapsed: int | None = timeline.send_elapsed_ns
        for event in timeline.events:
            started: int = event.started_ns
            if event.connection is not None:
                info = event.connection.origin_tls.info
                if info is not None:
                    certificates: tuple[bytes, ...] | None = info.peer_certificates_der
                    print(certificates, elapsed, started)
    with sync.request("GET", "/", diagnostics=RequestDiagnostics(1)):
        pass
