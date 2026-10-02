"""UDP binds to port 0 that survive a Windows reserved port block.

Windows hands out UDP ports for binds to port 0 from one counter for the whole
host. When the counter reaches a reserved block (`netsh int ipv4 show
excludedportrange protocol=udp`), the bind can fail with WSAENOBUFS (os error
10055) and the counter moves past the block, so the next bind gets a port.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

WSAENOBUFS = 10055
RESERVED_PORT_RETRIES = 3

T = TypeVar("T")


async def open_past_reserved_ports(
    open_at: Callable[[str, int], Awaitable[T]], host: str, port: int
) -> T:
    """Return `await open_at(host, port)`, retrying a refused bind to port 0."""
    retries = 0
    while True:
        try:
            return await open_at(host, port)
        except OSError as error:
            refused = getattr(error, "winerror", None) == WSAENOBUFS
            if port != 0 or not refused or retries == RESERVED_PORT_RETRIES:
                raise
            retries += 1
