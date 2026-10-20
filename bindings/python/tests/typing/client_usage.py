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
    Cookies,
    DecodeError,
    Error,
    Header,
    HTTPStatusError,
    Proxy,
    Response,
    TimeoutOverrides,
    Timeouts,
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
        )
        async with response:
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
