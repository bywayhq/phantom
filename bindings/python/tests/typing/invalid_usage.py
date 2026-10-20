"""Each marked line must fail with exactly its listed mypy error code."""

from phantom_http import (
    AsyncClient,
    Client,
    Header,
    Proxy,
    TimeoutOverrides,
    Timeouts,
    Trust,
)


def synchronous(profile: str, url: str) -> None:
    Client(profile=profile, protocol="h4")  # E: arg-type
    Client(profile=profile, protocol="h1", context="image")  # E: arg-type
    Client(profile=profile, protocol="h1", retries=2)  # E: call-arg
    Client(profile=profile, protocol="h1", timeouts=TimeoutOverrides())  # E: arg-type
    Timeouts(connect="slow")  # E: arg-type
    TimeoutOverrides(total="inherit")  # E: arg-type
    Proxy("http://proxy.invalid", username=1)  # E: arg-type
    Trust(roots=[b"DER"])  # E: arg-type
    Header("X-Secret", "value", sensitive="yes")  # E: arg-type
    with Client(profile=profile, protocol="h1") as client:
        wrong_headers: list[tuple[str, int]] = [("X-Number", 1)]
        client.request("GET", url, headers=wrong_headers)  # E: arg-type
        client.request("GET", url, headers={"X-Name": "value"})  # E: dict-item
        client.request("GET", url, budget=5)  # E: arg-type
        client.request("PUT", url, upload=b"file")  # E: arg-type
        client.request("POST", url, body="text")  # E: arg-type
        client.request("GET", url, retries=2)  # E: call-arg
        client.request("GET", url, timeouts=Timeouts())  # E: arg-type
        response = client.request("GET", url)
        _text: str = response.read(max_bytes=100)  # E: assignment


async def asynchronous(profile: str, url: str) -> None:
    async with AsyncClient(profile=profile, protocol="h2") as client:
        response = await client.request("GET", url)
        _number: int = await response.read(max_bytes=100)  # E: assignment
