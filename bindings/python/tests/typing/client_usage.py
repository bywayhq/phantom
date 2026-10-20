"""Type-check this consumer against the installed package, outside the checkout."""

from collections.abc import AsyncGenerator, Awaitable, Generator
from pathlib import Path
from typing import cast

from phantom_http import (
    AsyncClient,
    AsyncResponse,
    AttemptBudget,
    BodyLimitExceeded,
    Client,
    Cookies,
    Error,
    Response,
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
        proxy=None,
        cookies=True,
        timeout_ms=5000,
    ) as client:
        _closed: bool = client.is_closed
        jar: Cookies = client.cookies
        jar.set(url, "seen=yes; Path=/")
        _cookie: str | None = jar.for_url(url)
        _count: int = len(jar)
        jar.clear()
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
            "GET", url, headers=headers(), budget=AttemptBudget(2)
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
