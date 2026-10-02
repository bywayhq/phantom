import asyncio
import unittest

from scripts.capture.reserved_ports import WSAENOBUFS, open_past_reserved_ports


class RefusedAtReservedBlock(OSError):
    winerror = WSAENOBUFS


def open_over(port: int, outcomes: list[OSError | None]) -> tuple[object, int]:
    """Open with one outcome per bind; return the result and the bind count."""
    binds = 0

    async def open_at(host: str, port: int) -> str:
        nonlocal binds
        outcome = outcomes[binds]
        binds += 1
        if outcome is not None:
            raise outcome
        return f"{host}:{port}"

    try:
        result: object = asyncio.run(
            open_past_reserved_ports(open_at, "127.0.0.1", port)
        )
    except OSError as error:
        result = error
    return result, binds


class ReservedPortTests(unittest.TestCase):
    def test_a_bind_to_port_zero_refused_at_a_reserved_block_is_retried(self) -> None:
        refused = RefusedAtReservedBlock()

        self.assertEqual(open_over(0, [refused, None]), ("127.0.0.1:0", 2))

    def test_the_error_is_returned_after_three_retries(self) -> None:
        refused = RefusedAtReservedBlock()

        self.assertEqual(open_over(0, [refused] * 5), (refused, 4))

    def test_other_errors_and_explicit_ports_are_not_retried(self) -> None:
        refused = RefusedAtReservedBlock()
        in_use = OSError("address in use")

        self.assertEqual(open_over(0, [in_use, None]), (in_use, 1))
        self.assertEqual(open_over(9447, [refused, None]), (refused, 1))


if __name__ == "__main__":
    unittest.main()
