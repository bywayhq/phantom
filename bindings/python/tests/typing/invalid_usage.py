"""Each marked line must fail with exactly its listed mypy error code."""

from collections.abc import AsyncGenerator

from phantom_http import (
    AsyncClient,
    Client,
    ConnectionRetry,
    ContentDecoding,
    Header,
    HostOverride,
    NetworkOptions,
    Profile,
    Proxy,
    RedirectPolicy,
    Response,
    RetryPolicy,
    SessionSharing,
    StatusRetry,
    TimeoutOverrides,
    Timeouts,
    TransferControl,
    TransferLimits,
    Trust,
)


def synchronous(profile: str, url: str) -> None:
    Client(profile=profile, protocol="h4")  # E: arg-type
    Client(profile=profile, protocol="h1", context="imaginary")  # E: arg-type
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
        client.get(url, context="imaginary")  # E: arg-type
        client.get(url, context="profile")  # E: arg-type
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


def invalid_checkpoints(client: Client) -> None:
    client.export_session("secret")  # E: arg-type
    client.restore_session(bytearray(), b"key")  # E: arg-type
    client.restore_session(b"snapshot", b"key", receiving_routes=[1])  # E: list-item


def invalid_transfer(client: Client) -> None:
    TransferLimits(upload_bytes=0.5)  # E: arg-type
    TransferControl(limits={})  # E: arg-type
    client.request("GET", "http://origin.invalid", transfer_control={})  # E: arg-type
    control = TransferControl()
    control.limits = TransferLimits()  # E: misc
    limits = TransferLimits()
    limits.download_bytes = 1  # E: misc
    control.snapshot().upload_body_bytes = 1  # E: misc


async def invalid_body_controls(client: AsyncClient, sync: Client, url: str) -> None:
    await client.request("POST", url, trailers={"x": "value"})  # E: dict-item
    sync.request("POST", url, trailers=[("x", 1)])  # E: list-item
    await client.request("POST", url, expect_continue_ms=0.5)  # E: arg-type


def invalid_prepared(client: Client) -> None:
    from phantom_http import MultipartPart, PreparedBody

    PreparedBody.form([("name", b"bytes")], maximum_bytes=10)  # E: list-item
    PreparedBody.multipart(
        [("name", "value")],  # E: list-item
        boundary="B",
        maximum_bytes=99,
    )
    MultipartPart("name", [b"bytes"])  # E: arg-type
    body = PreparedBody.form([], maximum_bytes=0)
    body.length = 1  # E: misc
    MultipartPart("name", "value").name = "changed"  # E: misc
    client.request("POST", "/", body=body)


def invalid_diagnostics(client: Client) -> None:
    from phantom_http import RequestDiagnostics

    RequestDiagnostics(1.5)  # E: arg-type
    client.request("GET", "/", diagnostics={})  # E: arg-type
    observer = RequestDiagnostics()
    observer.maximum_events = 1  # E: misc
    snapshot = observer.snapshot()
    if snapshot is not None:
        snapshot.admitted_attempts = 0  # E: misc
        snapshot.events[0].started_ns = 0  # E: misc
        snapshot.events.append(snapshot.events[0])  # E: attr-defined


Trust(server_spki_pins=[bytes(32)])  # E: arg-type
Trust(proxy_server_spki_pins=("private",))  # E: arg-type


def invalid_client_certificates() -> None:
    from phantom_http import ClientCertificate

    certificate = ClientCertificate.from_pem(b"chain", b"key")
    ClientCertificate.from_pem("chain", b"key")  # E: arg-type
    ClientCertificate.from_der([b"DER"], b"key")  # E: arg-type
    Client(profile="exact", protocol="h1", client_certificate=b"key")  # E: arg-type
    AsyncClient(
        profile="exact",
        protocol="h2",
        client_certificates_for=(("https://example", b"key"),),  # E: arg-type
    )
    certificate._native = certificate._native  # E: misc


def invalid_received_trailers(response: Response) -> None:
    from phantom_http import ResponseHeader, ResponseTrailers

    response.trailers = ResponseTrailers("pending", None)  # E: misc
    response.trailers.state = "unavailable"  # E: misc
    ResponseTrailers("future", None)  # E: arg-type
    ResponseHeader("x", "text", False)  # E: arg-type
    response.headers[0].sensitive = False  # E: misc
    response.headers.append(ResponseHeader("x", b"value", False))  # E: attr-defined
    fields = response.trailers.headers
    if fields is not None:
        fields[0].sensitive = False  # E: misc
        fields.append(ResponseHeader("x", b"value", False))  # E: attr-defined


def invalid_streaming_multipart(client: Client) -> None:
    from phantom_http import MultipartPart, StreamingMultipartBody

    MultipartPart.stream("name", [b"value"])  # E: arg-type
    MultipartPart.file("name", b"path")  # E: arg-type
    StreamingMultipartBody([], boundary=b"B", maximum_bytes=99)  # E: arg-type
    StreamingMultipartBody([], boundary="B", maximum_bytes=1.5)  # E: arg-type
    part = MultipartPart.file("name", "path")
    part.filename = "changed"  # E: misc
    body = StreamingMultipartBody([part], boundary="B", maximum_bytes=99)
    body.content_type = "changed"  # E: misc
    client.request("POST", "/", body=[part])  # E: list-item


HostOverride("host.invalid", ["127.0.0.1"])  # E: arg-type
NetworkOptions(host_overrides=[HostOverride("host.invalid")])  # E: arg-type
NetworkOptions(local_addresses=(123,))  # E: arg-type
NetworkOptions(interface=123)  # E: arg-type
NetworkOptions(())  # E: misc
NetworkOptions().interface = "lo"  # E: misc
NetworkOptions(unix_socket=123)  # E: arg-type
NetworkOptions().unix_socket = "/other"  # E: misc
Client(profile="exact", protocol="h1", network={})  # E: arg-type


def invalid_pools() -> None:
    from phantom_http import PoolOptions

    PoolOptions(1)  # E: misc
    PoolOptions(max_retained_http1_connections=1.5)  # E: arg-type
    PoolOptions(negotiated_setup_wait_limit="private")  # E: arg-type
    PoolOptions().max_http2_connections_per_origin = 2  # E: misc
    Client(profile="exact", protocol="h1", pool={})  # E: arg-type


def invalid_convenience(client: Client, url: str) -> None:
    client.get(url, timeout_ms="slow")  # E: arg-type
    client.get(url, params={"page": object()})  # E: arg-type
    client.post(url, form={"field": 1})  # E: arg-type
    client.stream("GET", url, unknown=True)  # E: call-arg


async def invalid_websocket(client: AsyncClient, sync: Client) -> None:
    from phantom_http import WebSocketLimits, WebSocketRetry

    client.websocket("ws://local", protocol="negotiated")  # E: arg-type
    WebSocketLimits(maximum_frame_bytes="unbounded")  # E: arg-type
    WebSocketLimits().maximum_fragments = 1  # E: misc
    WebSocketRetry(maximum="two")  # E: arg-type
    client.websocket("ws://local", retry={})  # E: arg-type
    async with client.websocket("ws://local") as socket:
        await socket.send({"data": "value"})  # E: arg-type
        await socket.ping("text")  # E: arg-type
        await socket.aclose(timeout_ms="slow")  # E: arg-type
    with sync.websocket("ws://local") as blocking:
        blocking.send(1)  # E: arg-type
