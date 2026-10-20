"""Each marked line must fail with exactly its listed mypy error code."""

from collections.abc import AsyncGenerator

from phantom_http import (
    AsyncClient,
    Client,
    ConnectionRetry,
    ContentDecoding,
    Header,
    Profile,
    Proxy,
    RedirectPolicy,
    RetryPolicy,
    SessionSharing,
    StatusRetry,
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
        client.request("GET", url, content_decoding={})  # E: arg-type
        ContentDecoding.advertised(1.5)  # E: arg-type
        response.decoded_content_codings = ()  # E: misc
        client.request("GET", url, redirect_policy={})  # E: arg-type
        client.request("GET", url, redirect_history_limit=1.5)  # E: arg-type
        RedirectPolicy.limited("3")  # E: arg-type
        history = response.redirect_history
        if history is not None:
            history.omitted_hops = 0  # E: misc
            history.entries[0].from_url = "different"  # E: misc
        response.redirect_history = None  # E: misc


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


def retry_configuration(client: Client) -> None:
    client.request("GET", "http://origin.invalid", retry_policy={})  # E: arg-type
    RetryPolicy(connection_failures={})  # E: arg-type
    RetryPolicy(status_retry={})  # E: arg-type
    RetryPolicy(maximum_retries=1.5)  # E: arg-type
    ConnectionRetry(maximum="2", delay=0)  # E: arg-type
    StatusRetry(statuses=[503], maximum=1, delay=0)  # E: arg-type
    settings = RetryPolicy.none()
    settings.maximum_retries = 1  # E: misc


def compact_profiles(base: Profile) -> None:
    Profile.import_ja3("raw")  # E: call-arg
    Profile.import_akamai("raw", base="catalog")  # E: arg-type
    Profile.import_ja4("raw", base=base)  # E: call-arg
    Profile.import_ja4("raw", format="auto", base=base)  # E: arg-type
    Profile.import_client_hello("bytes", base=base)  # E: arg-type
    Profile.import_quic_transport(bytearray(), base=base)  # E: arg-type
    imported = Profile.import_ja3("raw", base=base)
    imported.profile = base  # E: misc
    imported.observed_fields = ()  # E: misc


async def invalid_upload(client: AsyncClient, sync: Client, url: str) -> None:
    await client.request("POST", url, body=[b"one"])  # E: arg-type

    async def chunks() -> AsyncGenerator[bytes, None]:
        yield b"one"

    sync.request("POST", url, body=chunks())  # E: arg-type
    await client.request("POST", url, body_length=1.5)  # E: arg-type
