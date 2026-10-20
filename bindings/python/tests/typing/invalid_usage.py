"""Each marked line must fail with exactly its listed mypy error code."""

from phantom_http import (
    AsyncClient,
    Client,
    Header,
    Profile,
    Proxy,
    SessionSharing,
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
        response.text()  # E: call-arg
        response.json(max_bytes="100")  # E: arg-type
        _bytes: bytes = response.text(max_bytes=100)  # E: assignment
        _data: dict[str, str] = response.json(max_bytes=100)  # E: assignment
        response.url = "different"  # E: misc
        response.connection_setup_retries = 0  # E: misc


async def asynchronous(profile: str, url: str) -> None:
    async with AsyncClient(profile=profile, protocol="h2") as client:
        response = await client.request("GET", url)
        _number: int = await response.read(max_bytes=100)  # E: assignment
        _bytes: bytes = await response.text(max_bytes=100)  # E: assignment


def profile_documents() -> None:
    Profile.import_json("document")  # E: arg-type
    Profile.from_catalog("exact", context="profile")  # E: arg-type
    Client(profile={}, protocol="h1")  # E: arg-type
    profile = Profile.from_catalog("exact")
    profile.catalog_id = "other"  # E: misc


def sharing_configuration(client: Client) -> None:
    SessionSharing(cookies=1)  # E: arg-type
    client.fork(sharing={})  # E: arg-type
    client.fork(cookies=True)  # E: call-arg
    selection = SessionSharing()
    selection.dns = True  # E: misc
