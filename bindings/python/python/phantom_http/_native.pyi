from collections.abc import Awaitable
from os import PathLike
from typing import Literal, TypeAlias

from ._configuration import RetryPolicy
from ._network import NetworkOptions
from ._pool import PoolOptions

class NativeError(Exception): ...
class NativeProfileError(Exception): ...

class NativeEventSource:
    status: int
    protocol: str
    url: str
    headers: list[tuple[str, bytes, bool]]
    last_event_id: str
    retry_ms: int
    reconnects: int
    is_closed: bool
    def next_event(self) -> Awaitable[tuple[str, str, str] | None]: ...
    def close(self) -> None: ...
    def wait_idle(self) -> Awaitable[None]: ...
    def wait_closed(self, timeout_ms: int) -> Awaitable[None]: ...

class NativeWebSocket:
    status: int
    protocol: str
    selected_protocol: str | None
    headers: list[tuple[str, bytes, bool]]
    is_closed: bool
    def send(self, data: str | bytes) -> Awaitable[None]: ...
    def receive(
        self,
    ) -> Awaitable[
        tuple[
            Literal["text", "binary", "ping", "pong", "close"],
            str | bytes | None,
            int | None,
        ]
    ]: ...
    def ping(self, data: bytes) -> Awaitable[None]: ...
    def pong(self, data: bytes) -> Awaitable[None]: ...
    def close(self, code: int | None, reason: str) -> Awaitable[None]: ...
    def abort(self) -> None: ...

class NativeClientCertificate:
    @staticmethod
    def from_pem(
        certificate_chain: bytes, private_key: bytes
    ) -> NativeClientCertificate: ...
    @staticmethod
    def from_der(
        certificate_chain: tuple[bytes, ...], private_key: bytes
    ) -> NativeClientCertificate: ...

_DiagnosticOutcome: TypeAlias = Literal[
    "not_started", "pending", "response_head", "failed", "cancelled"
]
_DiagnosticProtocol: TypeAlias = Literal["h0.9", "h1.0", "h1", "h2", "h3"]
_DiagnosticPhase: TypeAlias = Literal[
    "attempt_admission",
    "pool_admission",
    "connection_acquisition",
    "connection_use",
    "resolution_wait",
    "tcp_connect",
    "tls_handshake",
    "quic_handshake",
    "send_response_head",
    "response_body",
]
_DiagnosticEventOutcome: TypeAlias = Literal[
    "pending", "completed", "failed", "interrupted", "abandoned", "cached", "early_data"
]
_DiagnosticEndpointScope: TypeAlias = Literal[
    "unavailable", "tcp_socket", "quic_endpoint"
]
_DiagnosticTlsState: TypeAlias = Literal[
    "not_used", "unavailable", "pending", "established"
]
_DiagnosticTlsInfo: TypeAlias = tuple[
    bool, int | None, int | None, bytes | None, bool, list[bytes] | None
]
_DiagnosticTls: TypeAlias = tuple[_DiagnosticTlsState, _DiagnosticTlsInfo | None]
_DiagnosticConnection: TypeAlias = tuple[
    bool,
    _DiagnosticEndpointScope,
    str | None,
    str | None,
    _DiagnosticTls,
    _DiagnosticTls,
]
_DiagnosticEvent: TypeAlias = tuple[
    int,
    int,
    int | None,
    _DiagnosticProtocol | None,
    _DiagnosticPhase,
    int,
    int | None,
    _DiagnosticEventOutcome,
    _DiagnosticConnection | None,
]
_DiagnosticTimeline: TypeAlias = tuple[
    _DiagnosticOutcome, int | None, list[_DiagnosticEvent], int, int
]

class NativeRequestDiagnostics:
    def __init__(self, maximum_events: int) -> None: ...
    def snapshot(self) -> _DiagnosticTimeline | None: ...

class NativePreparedBody:
    @staticmethod
    def encoded(
        input: bytes, content_type: str, maximum_bytes: int
    ) -> NativePreparedBody: ...
    @staticmethod
    def form(
        pairs: list[tuple[str, str]], maximum_bytes: int
    ) -> NativePreparedBody: ...
    @staticmethod
    def multipart(
        boundary: str,
        parts: list[tuple[str, str | bytes, str | None, str | None]],
        maximum_bytes: int,
    ) -> NativePreparedBody: ...
    @property
    def content_type(self) -> str: ...
    @property
    def length(self) -> int: ...
    def to_bytes(self) -> bytes: ...

class NativeTransferControl:
    def __init__(
        self,
        upload_bytes: int | None = None,
        download_bytes: int | None = None,
        upload_bytes_per_second: int | None = None,
        download_bytes_per_second: int | None = None,
    ) -> None: ...
    def snapshot(self) -> tuple[int, int, int, int, int]: ...

class NativeProfile:
    @staticmethod
    def from_catalog(exact_id: str, context: str | None = None) -> NativeProfile: ...
    @staticmethod
    def import_json(document: bytes) -> NativeProfile: ...
    @staticmethod
    def import_ja3(
        description: str,
        base: NativeProfile,
    ) -> tuple[NativeProfile, list[str], list[str]]: ...
    @staticmethod
    def import_client_hello(
        handshake: bytes,
        base: NativeProfile,
    ) -> tuple[NativeProfile, list[str], list[str]]: ...
    @staticmethod
    def import_akamai(
        description: str,
        base: NativeProfile,
    ) -> tuple[NativeProfile, list[str], list[str]]: ...
    @staticmethod
    def import_ja4(
        description: str,
        format: str,
        base: NativeProfile,
    ) -> tuple[NativeProfile, list[str], list[str]]: ...
    @staticmethod
    def import_quic_transport(
        parameters: bytes,
        base: NativeProfile,
    ) -> tuple[NativeProfile, list[str], list[str]]: ...
    def export_json(self) -> bytes: ...
    @property
    def catalog_id(self) -> str | None: ...

class AttemptBudget:
    def __init__(self, maximum: int) -> None: ...
    @property
    def remaining(self) -> int: ...
    def try_admit(self) -> None: ...

class NativeCookies:
    def set(self, url: str, set_cookie: str) -> None: ...
    def for_url(self, url: str) -> str | None: ...
    def clear(self) -> None: ...
    def __len__(self) -> int: ...

class NativeUpload:
    def __init__(self, length: int | None = None) -> None: ...
    def credit(self) -> Awaitable[bool]: ...
    def terminal(self) -> Awaitable[None]: ...
    def write(self, bytes: bytes, offset: int, length: int) -> None: ...
    def finish(self) -> None: ...
    def fail(self) -> None: ...
    def abort(self) -> None: ...

class NativeStreamingMultipart:
    def __init__(
        self,
        boundary: str,
        parts: list[tuple[int, str, object, str | None, str | None]],
        maximum_bytes: int,
    ) -> None: ...
    @staticmethod
    def content_type_for(boundary: str) -> str: ...
    @property
    def content_type(self) -> str: ...
    def next_part(self) -> Awaitable[int | None]: ...
    def credit(self) -> Awaitable[bool]: ...
    def terminal(self) -> Awaitable[None]: ...
    def write(self, bytes: bytes, offset: int, length: int) -> None: ...
    def finish(self) -> None: ...
    def fail(self) -> None: ...
    def abort(self) -> None: ...

class NativeResponse:
    def events(
        self, maximum_line_bytes: int, maximum_event_bytes: int
    ) -> NativeEventStream: ...
    @property
    def url(self) -> str: ...
    @property
    def redirects_followed(self) -> int: ...
    @property
    def connection_setup_retries(self) -> int: ...
    @property
    def decoded_content_codings(self) -> list[str]: ...
    @property
    def redirect_history(
        self,
    ) -> tuple[list[tuple[str, str, str, str, int]], int] | None: ...
    @property
    def status(self) -> int: ...
    @property
    def protocol(self) -> str: ...
    @property
    def headers(self) -> list[tuple[str, bytes, bool]]: ...
    @property
    def trailers(self) -> tuple[str, list[tuple[str, bytes, bool]] | None]: ...
    def close(self) -> None: ...
    def read_chunk(self, maximum: int) -> Awaitable[bytes | None]: ...
    def read(self, maximum: int) -> Awaitable[bytes]: ...

class NativeEventStream:
    @property
    def last_event_id(self) -> str: ...
    @property
    def retry_ms(self) -> int | None: ...
    def next_event(self) -> Awaitable[tuple[str, str, str] | None]: ...

class NativeClient:
    def event_source(
        self,
        url: str,
        protocol: str,
        headers: list[tuple[str, bytes, bool]] | None,
        last_event_id_slot: int | None,
        maximum_line_bytes: int,
        maximum_event_bytes: int,
        idle_timeout: float | None,
        initial_retry: float,
        min_retry: float | None,
        max_reconnects: int,
        timeouts: list[tuple[str, float | None]] | None,
        inherit_proxy: bool,
        proxy: str | None,
        proxy_username: str | None,
        proxy_password: str | None,
    ) -> Awaitable[NativeEventSource]: ...
    def abort(self) -> None: ...
    def websocket(
        self,
        url: str,
        protocol: str,
        headers: list[tuple[str, bytes, bool]],
        maximum_frame_bytes: int,
        maximum_message_bytes: int,
        maximum_fragments: int,
        inherit_handshake_timeout: bool,
        handshake_timeout_ms: int | None,
        maximum_connection_failures: int | None,
        retry_delay_ms: int,
    ) -> Awaitable[NativeWebSocket]: ...
    def __init__(
        self,
        profile: str | NativeProfile,
        protocol: str,
        context: str | None = None,
        proxy: str | None = None,
        cookies: bool = True,
        timeout_ms: int | None = None,
        base_url: str | None = None,
        roots: list[bytes] = ...,
        proxy_roots: list[bytes] = ...,
        proxy_username: str | None = None,
        proxy_password: str | None = None,
        timeouts: list[tuple[str, float | None]] | None = None,
        redirect_maximum_hops: int | None = None,
        retry_policy: RetryPolicy | None = None,
        server_spki_pins: tuple[bytes, ...] | None = None,
        proxy_server_spki_pins: tuple[bytes, ...] | None = None,
        client_certificate: NativeClientCertificate | None = None,
        client_certificates_for: tuple[tuple[str, NativeClientCertificate], ...]
        | None = None,
        network: NetworkOptions | None = None,
        pool: PoolOptions | None = None,
        redirect_credential_headers: tuple[str, ...] | None = None,
    ) -> None: ...
    @property
    def cookies(self) -> NativeCookies: ...
    @property
    def is_closed(self) -> bool: ...
    def fork(
        self,
        cookies: bool,
        dns: bool,
        client_hints: bool,
        discovery: bool,
        tickets: bool,
    ) -> NativeClient: ...
    def export_session(self, key: bytes) -> bytes: ...
    def restore_session(
        self,
        snapshot: bytes,
        key: bytes,
        receiving_routes: list[tuple[str | None, str | None, str | None]],
    ) -> NativeClient: ...
    def request(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, bytes, bool]],
        body: bytes | None = None,
        upload: str | PathLike[str] | None = None,
        budget: AttemptBudget | None = None,
        timeout_ms: int | None = None,
        timeouts: list[tuple[str, float | None]] | None = None,
        maximum_decoded_bytes: int | None = None,
        redirect_maximum_hops: int | None = None,
        redirect_history_limit: int | None = None,
        retry_policy: RetryPolicy | None = None,
        producer: NativeUpload | None = None,
        transfer_control: NativeTransferControl | None = None,
        trailers: list[tuple[str, bytes, bool]] | None = None,
        expect_continue_ms: int | None = None,
        prepared_body: NativePreparedBody | None = None,
        body_length: int | None = None,
        diagnostics: NativeRequestDiagnostics | None = None,
        multipart: NativeStreamingMultipart | None = None,
        redirect_credential_headers: tuple[str, ...] | None = None,
        context: str | None = None,
    ) -> Awaitable[NativeResponse]: ...
    def close_idle_connections(self) -> Awaitable[None]: ...
    def refresh_connections(self) -> Awaitable[None]: ...
    def clear_session_tickets(self) -> int: ...
    def clear_dns_cache(self) -> None: ...
    def clear_client_hints(self) -> None: ...
    def clear_alt_svc(self) -> None: ...
    def clear_alt_svc_racing_history(self) -> None: ...
    def shutdown(self, timeout_ms: int) -> Awaitable[None]: ...
