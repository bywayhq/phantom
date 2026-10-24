"""Multiplexed SSE capture transports; shared scenarios live in sse_reconnect.

Headers are the ordered byte pairs delivered by HPACK/QPACK decoding, not
compressed header representations. A stream END_STREAM is the close stimulus;
a stream reset before response headers is the reset stimulus on these protocols.
H2 also retains the client preface and frames through its first request headers.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, urlsplit

from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    generate_certificate,
    peer_disconnected,
    server_context,
)
from .sse_reconnect import (
    CONNECTION_CLEANUP_SECONDS,
    MAX_REQUEST_HEAD,
    ListenAddress,
    ReconnectServer,
    RecordedConnection,
    RecordedRequest,
    Stimulus,
    raise_capture_failures,
    validate_retained_headers,
)

MAX_CONNECTIONS = 128
MAX_REQUESTS = 128
MAX_RECEIVED = 8 * 1024 * 1024
MAX_H2_STARTUP = 128 * 1024


@dataclass(frozen=True)
class H2Startup:
    wire: bytes
    settings: tuple[tuple[int, int], ...]
    connection_window_updates: tuple[int, ...]
    first_stream_id: int


def decode_h2_startup(data: bytes) -> H2Startup | None:
    """Read the literal prefix through the first complete request header block."""
    from .http2_analysis import split_frames

    if len(data) > MAX_H2_STARTUP:
        raise ValueError("SSE H2 startup exceeds the input limit")
    frames, _ = split_frames([(0, data)], "client", preface=True)
    if not frames:
        return None
    if frames[0].frame_type != 4 or frames[0].flags & 1 or frames[0].stream_id != 0:
        raise ValueError("SSE H2 startup does not begin with client SETTINGS")

    settings = []
    updates = []
    first_stream = None
    end = len(CONNECTION_PREFACE)
    for frame in frames:
        end += 9 + len(frame.payload)
        if first_stream is None:
            if frame.frame_type == 4 and not frame.flags & 1:
                settings.extend(
                    (
                        int.from_bytes(frame.payload[i : i + 2], "big"),
                        int.from_bytes(frame.payload[i + 2 : i + 6], "big"),
                    )
                    for i in range(0, len(frame.payload), 6)
                )
            elif frame.frame_type == 8 and frame.stream_id == 0:
                updates.append(int.from_bytes(frame.payload, "big") & 0x7FFFFFFF)
            elif frame.frame_type == 1:
                first_stream = frame.stream_id
        if first_stream is not None and frame.frame_type in (1, 9) and frame.flags & 4:
            return H2Startup(data[:end], tuple(settings), tuple(updates), first_stream)
    return None


def library_versions(protocol):
    from importlib.metadata import version

    packages = {"h2": "4.4.1", "hpack": "4.2.0"}
    if protocol == "h3":
        packages["aioquic"] = "1.3.0"
    for package, expected in packages.items():
        if version(package) != expected:
            raise ValueError(f"SSE capture requires {package}=={expected}")
    return " ".join(f"{package} {version(package)}" for package in packages)


class MultiplexedServer(ReconnectServer):
    def __init__(self) -> None:
        super().__init__()
        self.certificate = generate_certificate()

    def url(self, run) -> str:
        if self.address is None:
            raise RuntimeError("server has not started")
        return f"https://{HOSTNAME}:{self.address[1]}{run.page_path()}"

    def record_connection(self, run, protocol):
        if len(run.connections) >= MAX_CONNECTIONS:
            raise ValueError("SSE run exceeds the connection limit")
        record = RecordedConnection(run.now(), protocol=protocol)
        run.connections.append(record)
        return record, len(run.connections) - 1

    def opening(self, run, connection, index, stream_id, headers):
        if len(run.requests) >= MAX_REQUESTS:
            raise ValueError("SSE run exceeds the request limit")
        headers = [(bytes(name), bytes(value)) for name, value in headers]
        if sum(len(name) + len(value) for name, value in headers) > MAX_REQUEST_HEAD:
            raise ValueError("SSE request headers exceed the capture limit")
        request = RecordedRequest(
            index,
            connection.request_count,
            run.now(),
            b"",
            [],
            "other",
            stream_id=stream_id,
            decoded_headers=headers,
        )
        # Refuse credentials before retaining or serving the request.
        run.requests.append(request)
        validate_retained_headers(run)
        connection.request_count += 1
        parts = urlsplit(request.target.decode("latin-1"))
        if parts.path == run.page_path():
            request.kind = "page"
            return request, Stimulus(
                content_type=b"text/html; charset=utf-8",
                body=run.page(),
                ending="response",
            )
        if parts.path not in {
            f"/sse/{run.scenario.name}",
            f"/sse/{run.scenario.name}/target",
        } or parse_qs(parts.query).get("run") != [run.token]:
            return request, Stimulus(status=404, content_type=None, ending="response")
        stimulus = run.claim_attempt(request)
        return request, replace(
            stimulus,
            headers=tuple(
                (name, value.replace(b"{target}", run.target_path().encode()))
                for name, value in stimulus.headers
            ),
        )

    def spawn(self, operation, run):
        async def owned():
            try:
                await operation
            except asyncio.CancelledError:
                if asyncio.current_task() not in self.cancelled:
                    return asyncio.CancelledError()
            except BaseException as error:
                run.done.set()
                return error
            return None

        task = asyncio.create_task(owned())
        self.tasks.add(task)
        return task

    def finished_stimulus(self, run, request, stimulus):
        if request.kind == "sse":
            run.stimulus_finished(request, stimulus)
            request.stimulus = (
                "stream-reset" if stimulus.ending == "reset" else "end-stream"
            )

    def client_reset(self, run, index, stream_id, code):
        request = next(
            (
                request
                for request in reversed(run.requests)
                if request.connection == index and request.stream_id == stream_id
            ),
            None,
        )
        if request is not None:
            request.client_reset = run.now()
            request.client_reset_code = code
            if request.kind == "sse" and request.stimulus is None:
                run.stimulus_finished(request, run.scenario.attempts[request.attempt])
                request.stimulus = "client-stream-reset"

    def launch_plan(self, args):
        from .cookie_crumbs import tcp_launch_plan

        return tcp_launch_plan(args, self.certificate, self.address[0], self.address[1])


class H2ReconnectServer(MultiplexedServer):
    """TLS H2 only: negotiation and RequestReceived both witness the protocol."""

    async def start(self, host, port):
        ListenAddress(host, port)
        context = server_context(self.certificate)
        context.set_alpn_protocols(["h2"])
        self.server = await asyncio.start_server(
            self.accept,
            host,
            port,
            ssl=context,
            limit=MAX_REQUEST_HEAD,
            ssl_handshake_timeout=CONNECTION_CLEANUP_SECONDS,
        )
        self.address = self.server.sockets[0].getsockname()[:2]

    async def wait_writer_closed(self, writer):
        try:
            await writer.wait_closed()
        except OSError as error:
            # Proactor TLS teardown can report ERROR_NETNAME_DELETED (64)
            # as ConnectionResetError after the accepted transport closes.
            reset = (
                isinstance(error, ConnectionResetError)
                and getattr(error, "winerror", None) == 64
            )
            if not writer.transport.is_closing() or not (
                peer_disconnected(error) or reset
            ):
                raise

    async def handle(self, reader, writer, run):
        import h2.events
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.errors import ErrorCodes

        primary = None
        terminal_reset = None
        connection = None
        closed = False
        workers = {}
        try:
            if run is None:
                return None
            if writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
                raise ValueError("SSE TLS connection did not negotiate h2")
            connection, index = self.record_connection(run, "h2")
            engine = H2Connection(
                H2Configuration(
                    client_side=False,
                    header_encoding=None,
                    normalize_inbound_headers=False,
                )
            )
            engine.initiate_connection()
            writer.write(engine.data_to_send())
            credit = asyncio.Event()

            async def respond(request, stimulus):
                stream_id = request.stream_id
                if stimulus.ending == "reset":
                    engine.reset_stream(stream_id, ErrorCodes.CANCEL)
                else:
                    fields = [(b":status", str(stimulus.status).encode())]
                    if stimulus.content_type is not None:
                        fields.append((b"content-type", stimulus.content_type))
                    fields.extend(stimulus.headers)
                    fields.append((b"cache-control", b"no-store"))
                    engine.send_headers(stream_id, fields, end_stream=False)
                    writer.write(engine.data_to_send())
                    await writer.drain()
                    body = stimulus.body
                    while body:
                        credit.clear()
                        size = min(
                            engine.local_flow_control_window(stream_id),
                            engine.max_outbound_frame_size,
                            len(body),
                        )
                        if size <= 0:
                            await credit.wait()
                            continue
                        engine.send_data(stream_id, body[:size])
                        body = body[size:]
                        writer.write(engine.data_to_send())
                        await writer.drain()
                    if stimulus.ending == "hold-close":
                        await asyncio.sleep(stimulus.hold_seconds)
                    engine.end_stream(stream_id)
                writer.write(engine.data_to_send())
                await writer.drain()
                self.finished_stimulus(run, request, stimulus)

            received = 0
            startup_bytes = bytearray()
            startup = None
            while data := await reader.read(64 * 1024):
                received += len(data)
                if received > MAX_RECEIVED:
                    raise ValueError("SSE H2 connection exceeds the input limit")
                if not connection.h2_startup:
                    startup_bytes.extend(data[: MAX_H2_STARTUP - len(startup_bytes)])
                    startup = decode_h2_startup(bytes(startup_bytes))
                    if startup is None and len(startup_bytes) == MAX_H2_STARTUP:
                        raise ValueError("SSE H2 startup exceeds the input limit")
                for event in engine.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        request, stimulus = self.opening(
                            run, connection, index, event.stream_id, event.headers
                        )
                        if not connection.h2_startup:
                            if (
                                startup is None
                                or startup.first_stream_id != event.stream_id
                            ):
                                raise ValueError(
                                    "SSE H2 request has no complete startup"
                                )
                            # Retain bytes only after opening validates the request fields.
                            connection.h2_startup = startup.wire
                            startup_bytes.clear()
                        workers[event.stream_id] = self.spawn(
                            respond(request, stimulus), run
                        )
                    elif isinstance(event, h2.events.TrailersReceived):
                        raise ValueError("unexpected SSE request trailers")
                    elif isinstance(event, h2.events.DataReceived):
                        if event.data:
                            raise ValueError("unexpected SSE request body")
                        engine.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamReset):
                        self.client_reset(run, index, event.stream_id, event.error_code)
                        worker = workers.get(event.stream_id)
                        if worker is not None and not worker.done():
                            self.cancelled.add(worker)
                            worker.cancel()
                    elif isinstance(
                        event,
                        (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged),
                    ):
                        credit.set()
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return None
                writer.write(engine.data_to_send())
                await writer.drain()
            connection.client_eof = run.now()
        except BaseException as error:
            windows_read_reset = (
                isinstance(error, ConnectionResetError)
                and getattr(error, "winerror", None) == 64
            )
            if not (
                isinstance(error, asyncio.CancelledError)
                and asyncio.current_task() in self.cancelled
            ) and (windows_read_reset or not peer_disconnected(error)):
                primary = error
                # Browser disposal may reset this accepted TLS socket after
                # the terminal observation, before finish_run detaches run.
                if (
                    windows_read_reset
                    and connection is not None
                    and run.terminated is not None
                    and run.done.is_set()
                ):
                    terminal_reset = (error, run.now())
        finally:
            for worker in workers.values():
                if not worker.done():
                    self.cancelled.add(worker)
                    worker.cancel()
            try:
                writer.close()
                closed = True
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    self.failures.append(error)
        if (
            terminal_reset is not None
            and primary is terminal_reset[0]
            and closed
            and writer.transport.is_closing()
        ):
            connection.peer_reset = terminal_reset[1]
            connection.peer_reset_winerror = 64
            primary = None
        return primary


class H3ReconnectServer(MultiplexedServer):
    """Own QUIC connections until their close timers and stream workers retire."""

    def __init__(self):
        super().__init__()
        self.protocols = []
        self.transport = None
        self.endpoint = None
        self.retired = None
        self.stopping = False
        self.replace_listener = False

    def failed(self, error, run):
        self.failures.append(error)
        if run is not None:
            run.done.set()

    def udp_error(self, error):
        # error_received has no peer identity. This is a run-level cleanup
        # observation, never a QUIC close code or a per-connection attribution.
        protocols = self.protocols
        run = protocols[0].run if protocols else None
        code = getattr(error, "winerror", None)
        if (
            isinstance(error, OSError)
            and (
                code == 1234
                or (isinstance(error, ConnectionResetError) and code == 10054)
            )
            and self.run is None
            and self.cleanup is not None
            and not self.cleanup.done()
            and not self.failures
            and run is not None
            and run.terminated is not None
            and run.done.is_set()
            and all(
                protocol.run is run and protocol.record is not None
                for protocol in protocols
            )
            and len(run.udp_cleanup_disconnects) < MAX_CONNECTIONS
        ):
            run.udp_cleanup_disconnects.append((run.now(), code))
            self.replace_listener = True
        else:
            self.failed(error, self.run)

    async def start(self, host, port):
        if sys.platform == "win32" and (
            sys.implementation.name != "cpython" or sys.version_info[:3] < (3, 12, 3)
        ):
            raise RuntimeError(
                "Windows SSE H3 capture requires CPython 3.12.3 or later"
            )

        from aioquic.asyncio import QuicConnectionProtocol
        from aioquic.asyncio.server import QuicServer
        from aioquic.buffer import Buffer, BufferReadError
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import (
            ConnectionTerminated,
            ProtocolNegotiated,
            StopSendingReceived,
            StreamDataReceived,
            StreamReset,
        )
        from aioquic.quic.packet import pull_quic_header

        from .quic_resumption import load_certificate
        from .reserved_ports import open_past_reserved_ports

        ListenAddress(host, port)
        retired = asyncio.get_running_loop().create_future()
        owner = self

        class Protocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.run = owner.run
                self.http = None
                self.record = None
                self.received = 0
                self.opened = set()
                self.workers = {}
                owner.protocols.append(self)
                if self.run is None:
                    self.close()
                elif len(owner.protocols) > MAX_CONNECTIONS:
                    owner.failed(
                        ValueError("SSE QUIC connection limit exceeded"), self.run
                    )
                    self.close()

            def datagram_received(self, data, addr):
                try:
                    super().datagram_received(data, addr)
                except BaseException as error:
                    owner.failed(error, self.run)
                    self.close()

            def transmit(self):
                try:
                    super().transmit()
                except BaseException as error:
                    owner.failed(error, self.run)

            def _handle_timer(self):
                try:
                    super()._handle_timer()
                except BaseException as error:
                    owner.failed(error, self.run)
                    self.close()

            def quic_event_received(self, event):
                if self.run is None:
                    return
                if isinstance(event, ProtocolNegotiated):
                    if event.alpn_protocol != "h3":
                        raise ValueError("SSE QUIC connection did not negotiate h3")
                    self.record, self.index = owner.record_connection(self.run, "h3")
                    self.http = H3Connection(self._quic)
                if isinstance(event, StreamDataReceived):
                    self.received += len(event.data)
                    if self.received > MAX_RECEIVED:
                        raise ValueError("SSE H3 connection exceeds the input limit")
                if isinstance(event, ConnectionTerminated) and self.record is not None:
                    self.record.closed = self.run.now()
                    self.record.close_code = event.error_code
                if isinstance(event, (StreamReset, StopSendingReceived)):
                    if self.record is not None:
                        owner.client_reset(
                            self.run, self.index, event.stream_id, event.error_code
                        )
                    worker = self.workers.get(event.stream_id)
                    if worker is not None and not worker.done():
                        owner.cancelled.add(worker)
                        worker.cancel()
                if self.http is None:
                    return
                for http_event in self.http.handle_event(event):
                    if isinstance(http_event, HeadersReceived):
                        if http_event.stream_id in self.opened:
                            raise ValueError("unexpected SSE request trailers")
                        self.opened.add(http_event.stream_id)
                        request, stimulus = owner.opening(
                            self.run,
                            self.record,
                            self.index,
                            http_event.stream_id,
                            http_event.headers,
                        )
                        self.workers[http_event.stream_id] = owner.spawn(
                            self.respond(request, stimulus), self.run
                        )
                    elif isinstance(http_event, DataReceived) and http_event.data:
                        raise ValueError("unexpected SSE request body")

            async def respond(self, request, stimulus):
                stream_id = request.stream_id
                if stimulus.ending == "reset":
                    self._quic.reset_stream(stream_id, 0x10C)
                else:
                    fields = [(b":status", str(stimulus.status).encode())]
                    if stimulus.content_type is not None:
                        fields.append((b"content-type", stimulus.content_type))
                    fields.extend(stimulus.headers)
                    fields.append((b"cache-control", b"no-store"))
                    self.http.send_headers(stream_id, fields, end_stream=False)
                    if stimulus.body:
                        self.http.send_data(stream_id, stimulus.body, end_stream=False)
                    self.transmit()
                    if stimulus.ending == "hold-close":
                        await asyncio.sleep(stimulus.hold_seconds)
                    self.http.send_data(stream_id, b"", end_stream=True)
                self.transmit()
                owner.finished_stimulus(self.run, request, stimulus)

        class Endpoint(QuicServer):
            def datagram_received(self, data, addr):
                if owner.endpoint is not self:
                    return
                try:
                    if owner.run is None:
                        try:
                            header = pull_quic_header(
                                Buffer(data=data),
                                host_cid_length=self._configuration.connection_id_length,
                            )
                        except (BufferReadError, ValueError):
                            return
                        if header.destination_cid not in self._protocols:
                            return
                    super().datagram_received(data, addr)
                except BaseException as error:
                    owner.failed(error, owner.run)

            def error_received(self, error):
                if owner.endpoint is self:
                    owner.udp_error(error)
                else:
                    owner.failed(error, None)

            def connection_lost(self, error):
                run = owner.run if owner.endpoint is self else None
                if error is not None:
                    owner.failed(error, run)
                elif not owner.stopping:
                    owner.failed(
                        ConnectionError("SSE QUIC listener closed unexpectedly"),
                        run,
                    )
                if not retired.done():
                    retired.set_result(None)

        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        load_certificate(config, self.certificate)

        async def open_at(host, port):
            return await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Endpoint(configuration=config, create_protocol=Protocol),
                local_addr=(host, port),
            )

        self.transport, self.endpoint = await open_past_reserved_ports(
            open_at, host, port
        )
        self.retired = retired
        self.address = self.transport.get_extra_info("sockname")[:2]

    def launch_plan(self, args):
        from .quic_resumption import launch_plan

        return launch_plan(
            args.browser,
            args.browser_path,
            headless=not args.headful,
            listen_host=self.address[0],
            port=self.address[1],
            certificate=self.certificate,
            field_trial_config=False,
        )

    async def collect_connections(self) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + CONNECTION_CLEANUP_SECONDS
        try:
            # Closing only emits CONNECTION_CLOSE and arms aioquic's drain
            # timer. Let that timer run while accepted workers are collected.
            close_failed = False
            for protocol in self.protocols:
                try:
                    protocol.close()
                except BaseException as error:
                    self.failures.append(error)
                    close_failed = True
            await super().collect_connections()
            wait_started = loop.time()
            if self.protocols and not close_failed:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            *(protocol.wait_closed() for protocol in self.protocols)
                        ),
                        timeout=max(0, deadline - loop.time()),
                    )
                except asyncio.TimeoutError as error:
                    now = loop.time()
                    pending = [p for p in self.protocols if not p._closed.is_set()]
                    pto = max(
                        (p._quic._loss.get_probe_timeout() for p in pending), default=0
                    )
                    remaining = max(
                        (max(0, (p._quic._close_at or now) - now) for p in pending),
                        default=0,
                    )
                    raise asyncio.TimeoutError(
                        "SSE QUIC cleanup timed out "
                        f"(workers={wait_started - started:.3f}s, "
                        f"wait={now - wait_started:.3f}s, pending={len(pending)}, "
                        f"max_pto={pto:.3f}s, close_remaining={remaining:.3f}s)"
                    ) from error
        except BaseException as error:
            self.failures.append(error)
        finally:
            # aioquic 1.3.0 schedules these two handles; retire even on timeout.
            for protocol in self.protocols:
                for attribute in ("_timer", "_transmit_task"):
                    handle = getattr(protocol, attribute)
                    if handle is not None:
                        handle.cancel()
                        setattr(protocol, attribute, None)
                protocol._timer_at = None
            if all(protocol._closed.is_set() for protocol in self.protocols):
                self.protocols.clear()

        if self.replace_listener and not self.stopping and not self.failures:
            # CPython's Proactor UDP receive loop does not rearm after an
            # OSError. Retire that endpoint before the next fresh client runs.
            address = self.address
            await self.retire_listener(deadline)
            if self.failures:
                return
            self.stopping = False
            await asyncio.wait_for(
                self.start(*address),
                timeout=max(0, deadline - asyncio.get_running_loop().time()),
            )
            self.replace_listener = False

    async def retire_listener(self, deadline):
        self.stopping = True
        try:
            self.endpoint.close()
            if any(not protocol._closed.is_set() for protocol in self.protocols):
                # Failed graceful cleanup remains a capture failure. Abort its
                # endpoint: Proactor close can strand a newly queued close
                # datagram's write completion without connection_lost.
                self.transport.abort()
            await asyncio.wait_for(
                asyncio.shield(self.retired),
                timeout=max(0, deadline - asyncio.get_running_loop().time()),
            )
        finally:
            # Endpoint.close can rearm connection handles after an interrupted
            # protocol close. Keep their retirement owned by this endpoint.
            for protocol in self.protocols:
                for attribute in ("_timer", "_transmit_task"):
                    handle = getattr(protocol, attribute)
                    if handle is not None:
                        handle.cancel()
                        setattr(protocol, attribute, None)
                protocol._timer_at = None
            self.protocols.clear()

    async def close(self):
        self.stopping = True
        primary = None
        try:
            await self.finish_run()
        except BaseException as error:
            primary = error
        failures = []
        if self.endpoint is not None:
            try:
                await self.retire_listener(
                    asyncio.get_running_loop().time() + CONNECTION_CLEANUP_SECONDS
                )
            except BaseException as error:
                failures.append(error)
        raise_capture_failures(self, primary, failures)


def secure_server(protocol):
    library_versions(protocol)
    if protocol == "h2":
        return H2ReconnectServer()
    if protocol == "h3":
        return H3ReconnectServer()
    raise ValueError("unsupported secure SSE protocol")
