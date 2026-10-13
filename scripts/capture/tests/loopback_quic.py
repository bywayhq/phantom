"""A QUIC client bound to 127.0.0.1 for scripted tests.

`aioquic.asyncio.connect` binds a dual-stack socket on `::`, which a test
must not do, so tests open their client connections through this helper.
"""

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from scripts.capture.reserved_ports import open_past_reserved_ports


@contextlib.asynccontextmanager
async def connect_loopback(
    port: int,
    configuration: QuicConfiguration,
    create_protocol: Callable[..., QuicConnectionProtocol],
    *,
    session_ticket_handler=None,
    wait_connected: bool = True,
) -> AsyncIterator[QuicConnectionProtocol]:
    connection = QuicConnection(
        configuration=configuration, session_ticket_handler=session_ticket_handler
    )
    transport, protocol = await open_past_reserved_ports(
        lambda host, port: asyncio.get_running_loop().create_datagram_endpoint(
            lambda: create_protocol(connection), local_addr=(host, port)
        ),
        "127.0.0.1",
        0,
    )

    primary = None
    try:
        protocol.connect(("127.0.0.1", port), transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_errors = []
        queued_transmit = protocol._transmit_task
        try:
            protocol.close()
            await protocol.wait_closed()
        except BaseException as error:
            cleanup_errors.append(error)

        if cleanup_errors:
            handles = (queued_transmit, protocol._timer, protocol._transmit_task)
            protocol._timer = None
            protocol._timer_at = None
            protocol._transmit_task = None

            for handle in handles:
                if handle is not None:
                    try:
                        handle.cancel()
                    except BaseException as error:
                        cleanup_errors.append(error)

        try:
            if cleanup_errors:
                transport.abort()
            else:
                transport.close()
        except BaseException as error:
            cleanup_errors.append(error)

        cleanup = None
        for error in cleanup_errors:
            if cleanup is None:
                cleanup = error
            elif isinstance(cleanup, Exception) and not isinstance(error, Exception):
                _retain_cleanup_failure(error, cleanup)
                cleanup = error
            else:
                _retain_cleanup_failure(cleanup, error)

        if cleanup is not None:
            if primary is None:
                raise cleanup

            _retain_cleanup_failure(primary, cleanup)


def _retain_cleanup_failure(primary: BaseException, cleanup: BaseException) -> None:
    current = primary
    visited = set()
    while id(current) not in visited:
        if current is cleanup:
            return

        visited.add(id(current))
        previous = getattr(current, "capture_cleanup_failure", None)
        if previous is None:
            current.capture_cleanup_failure = cleanup
            return

        current = previous
