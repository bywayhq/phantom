import asyncio
import struct
import unittest
from unittest.mock import patch

from scripts.capture import native_dns
from scripts.capture.reserved_ports import open_past_reserved_ports

NAME = "native.phantom.test"
QUESTION = bytes.fromhex("066e6174697665077068616e746f6d04746573740000010001")
QUERY = bytes.fromhex("123401000001000000000000") + QUESTION
ANSWER = (
    bytes.fromhex("123485000001000100000000")
    + QUESTION
    + bytes.fromhex("c00c000100010000000500047f000001")
)
HTTPS_RDATA = bytes.fromhex("00010000010003026832000500080006fe0d00020000")


def named_query(name: str, kind: int) -> bytes:
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return (
        bytes.fromhex("123401000001000000000000")
        + labels
        + b"\x00"
        + struct.pack("!HH", kind, 1)
    )


def query_kind(kind: int) -> bytes:
    return QUERY[:-4] + struct.pack("!HH", kind, 1)


def framed(wire: bytes) -> bytes:
    return struct.pack("!H", len(wire)) + wire


class DnsWireTests(unittest.TestCase):
    def test_https_answer_keeps_captured_rdata_and_exact_name_scope(self) -> None:
        record = native_dns.HttpsAnswer(8443, HTTPS_RDATA)
        service = "_8443._https.server.phantom.test"
        query = named_query(service, 65)
        expected = (
            bytes.fromhex("123485000001000100000000")
            + query[12:]
            + bytes.fromhex("c00c00410001000000050016")
            + HTTPS_RDATA
        )
        self.assertEqual(
            native_dns.response(
                query,
                native_dns.question(query),
                "server.phantom.test",
                5,
                https_answer=record,
            ),
            expected,
        )
        for name in ("server.phantom.test", service):
            with self.subTest(name=name):
                for kind in (1, 28):
                    wire = named_query(name, kind)
                    answer = native_dns.response(
                        wire,
                        native_dns.question(wire),
                        "server.phantom.test",
                        5,
                        https_answer=record,
                    )
                    self.assertEqual(
                        answer[6:8], (1 if kind == 1 else 0).to_bytes(2, "big")
                    )
                    if kind == 1:
                        self.assertEqual(answer[-4:], b"\x7f\x00\x00\x01")
        for name, kind, code in (
            ("server.phantom.test", 65, 0),
            ("_8444._https.server.phantom.test", 65, 5),
            ("other.test", 1, 5),
        ):
            wire = named_query(name, kind)
            answer = native_dns.response(
                wire,
                native_dns.question(wire),
                "server.phantom.test",
                5,
                https_answer=record,
            )
            self.assertEqual(answer[3] & 15, code)
            self.assertEqual(answer[6:8], b"\x00\x00")

    def test_https_input_rejects_malformed_records_and_oversized_udp_before_binding(
        self,
    ) -> None:
        for port in (0, 443, 65536, True, "8443"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                native_dns.HttpsAnswer(port, HTTPS_RDATA)
        for rdata in (
            bytearray(HTTPS_RDATA),
            b"",
            b"\x00\x00\x00",
            HTTPS_RDATA[:-1],
            HTTPS_RDATA + b"\x00",
            HTTPS_RDATA[:3] + HTTPS_RDATA[10:] + HTTPS_RDATA[3:10],
            HTTPS_RDATA[:7] + b"\x00h2" + HTTPS_RDATA[10:],
            HTTPS_RDATA[:14] + b"\x00\x05" + HTTPS_RDATA[16:],
        ):
            with self.subTest(rdata=rdata), self.assertRaises(ValueError):
                native_dns.HttpsAnswer(8443, rdata)
        ech = (450).to_bytes(2, "big") + b"x" * 450
        large = HTTPS_RDATA[:10] + struct.pack("!HH", 5, len(ech)) + ech
        with self.assertRaisesRegex(ValueError, "512-byte"):
            native_dns.NativeDnsServer(
                "server.phantom.test", https_answer=native_dns.HttpsAnswer(8443, large)
            )

    def test_https_response_including_opt_fits_exact_udp_boundary(self) -> None:
        name = "_8443._https.server.phantom.test"
        value_size = 512 - len(name) - 41 - 14
        for extra in (0, 1):
            size = value_size + extra
            value = (size - 2).to_bytes(2, "big") + b"x" * (size - 2)
            rdata = HTTPS_RDATA[:10] + struct.pack("!HH", 5, size) + value
            record = native_dns.HttpsAnswer(8443, rdata)
            if extra:
                with self.assertRaisesRegex(ValueError, "512-byte"):
                    native_dns.NativeDnsServer(
                        "server.phantom.test", https_answer=record
                    )
            else:
                native_dns.NativeDnsServer("server.phantom.test", https_answer=record)
                wire = named_query(name, 65)
                wire = (
                    wire[:10]
                    + b"\x00\x01"
                    + wire[12:]
                    + bytes.fromhex("0000290200000000000000")
                )
                answer = native_dns.response(
                    wire,
                    native_dns.question(wire),
                    "server.phantom.test",
                    5,
                    https_answer=record,
                )
                self.assertEqual(len(answer), 512)

    def test_two_a_answers_keep_wire_order_and_equal_ttl(self) -> None:
        expected = (
            bytes.fromhex("123485000001000200000000")
            + QUESTION
            + bytes.fromhex("c00c000100010000000500047f000002")
            + bytes.fromhex("c00c000100010000000500047f000001")
        )
        self.assertEqual(
            native_dns.response(
                QUERY, native_dns.question(QUERY), NAME, 5, ("127.0.0.2", "127.0.0.1")
            ),
            expected,
        )
        for answers in (
            (),
            ("127.0.0.1",) * 2,
            ("127.0.0.1",) * 3,
            ("192.0.2.1",),
            ("::1",),
            (None,),
            ["127.0.0.1"],
        ):
            with self.subTest(answers=answers), self.assertRaises(ValueError):
                native_dns.NativeDnsServer(NAME, ipv4_answers=answers)

    def test_a_answer_has_exact_address_ttl_and_no_recursion_or_dnssec_claim(
        self,
    ) -> None:
        self.assertEqual(
            native_dns.response(QUERY, native_dns.question(QUERY), NAME, 5), ANSWER
        )

    def test_aaaa_and_https_are_authoritative_nodata_without_negative_ttl_claim(
        self,
    ) -> None:
        for kind in (28, 65):
            with self.subTest(kind=kind):
                query = query_kind(kind)
                expected = bytes.fromhex("123485000001000000000000") + query[12:]
                self.assertEqual(
                    native_dns.response(query, native_dns.question(query), NAME, 5),
                    expected,
                )

    def test_case_id_rd_and_original_question_are_preserved(self) -> None:
        wire = bytes.fromhex("beef00000001000000000000") + QUESTION.replace(
            b"native", b"NaTiVe"
        )
        self.assertEqual(native_dns.question(wire).name, NAME)
        answer = native_dns.response(wire, native_dns.question(wire), NAME, 0)
        self.assertEqual(answer[:12], bytes.fromhex("beef84000001000100000000"))
        self.assertEqual(answer[12 : 12 + len(QUESTION)], wire[12:])
        self.assertEqual(answer[-10:], bytes.fromhex("0000000000047f000001"))

    def test_other_names_and_types_are_refused_without_answer_or_authority(
        self,
    ) -> None:
        for wire in (QUERY.replace(b"native", b"absent"), query_kind(15)):
            with self.subTest(wire=wire):
                self.assertEqual(
                    native_dns.response(wire, native_dns.question(wire), NAME, 5),
                    bytes.fromhex("123481050001000000000000") + wire[12:],
                )

    def test_empty_edns0_is_echoed_with_bounded_payload_and_no_flags(self) -> None:
        wire = (
            QUERY[:10]
            + b"\x00\x01"
            + QUESTION
            + bytes.fromhex("000029ffff000000000000")
        )
        self.assertEqual(
            native_dns.response(wire, native_dns.question(wire), NAME, 5),
            ANSWER[:10]
            + b"\x00\x01"
            + ANSWER[12:]
            + bytes.fromhex("0000291000000000000000"),
        )

    def test_malformed_and_unsupported_queries_are_rejected(self) -> None:
        cases = {
            "short header": QUERY[:11],
            "compression": QUERY[:12] + bytes.fromhex("c00c00010001"),
            "two questions": QUERY[:4] + b"\x00\x02" + QUERY[6:],
            "answer section": QUERY[:6] + b"\x00\x01" + QUERY[8:],
            "truncated label": QUERY[:12] + b"\x3fshort",
            "truncated class": QUERY[:-1],
            "wrong class": QUERY[:-1] + b"\x03",
            "trailing bytes": QUERY + b"x",
            "reply": QUERY[:2] + b"\x81\x00" + QUERY[4:],
            "dnssec flag": QUERY[:2] + b"\x01\x20" + QUERY[4:],
            "edns options": QUERY[:10]
            + b"\x00\x01"
            + QUESTION
            + bytes.fromhex("000029100000000000000100"),
            "edns flags": QUERY[:10]
            + b"\x00\x01"
            + QUESTION
            + bytes.fromhex("0000291000000080000000"),
            "oversize": QUERY + b"x" * native_dns.MAX_MESSAGE,
        }
        for name, wire in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                native_dns.question(wire)

    def test_hostname_port_address_and_ttl_are_validated_before_binding(self) -> None:
        for arguments in (
            ("bad..name",),
            ("-bad.test",),
            ("bad-.test",),
            ("é.test",),
            (NAME, "0.0.0.0"),
            (NAME, "127.0.0.1", -1),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                native_dns.NativeDnsServer(*arguments)
        for ttl in (-1, 86401, True):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                native_dns.NativeDnsServer(NAME, ttl=ttl)
        self.assertEqual(
            native_dns.NativeDnsServer("NaTiVe.Phantom.Test.").hostname, NAME
        )


class Replies(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received = asyncio.Queue()
        self.closed = asyncio.Event()

    def datagram_received(self, data: bytes, peer: tuple) -> None:
        self.received.put_nowait((data, peer))

    def connection_lost(self, error: Exception | None) -> None:
        self.closed.set()


class NativeDnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_positive_https_udp_and_tcp_preserve_record_and_journal(self) -> None:
        await self.server.close()
        self.server = native_dns.NativeDnsServer(
            "server.phantom.test",
            "127.0.0.1",
            0,
            https_answer=native_dns.HttpsAnswer(8443, HTTPS_RDATA),
        )
        await self.server.start()
        query = named_query("_8443._https.server.phantom.test", 65)
        expected = (
            bytes.fromhex("123485000001000100000000")
            + query[12:]
            + bytes.fromhex("c00c00410001000000050016")
            + HTTPS_RDATA
        )
        transport, replies = await self.udp()
        transport.sendto(query)
        actual, _ = await asyncio.wait_for(replies.received.get(), 2)
        self.assertEqual(actual, expected)
        reader, writer = await self.tcp()
        writer.write(framed(query))
        await writer.drain()
        self.assertEqual(await self.read_frame(reader), expected)
        self.assertEqual(
            [entry["response_hex"] for entry in self.server.records()],
            [expected.hex()] * 2,
        )

    async def test_udp_and_tcp_send_both_a_records_without_reordering(self) -> None:
        await self.server.close()
        self.server = native_dns.NativeDnsServer(
            NAME, "127.0.0.1", 0, ipv4_answers=("127.0.0.2", "127.0.0.1")
        )
        await self.server.start()
        expected = (
            bytes.fromhex("123485000001000200000000")
            + QUESTION
            + bytes.fromhex(
                "c00c000100010000000500047f000002c00c000100010000000500047f000001"
            )
        )
        transport, replies = await self.udp()
        transport.sendto(QUERY)
        answer, _ = await asyncio.wait_for(replies.received.get(), 2)
        self.assertEqual(answer, expected)
        reader, writer = await self.tcp()
        writer.write(framed(QUERY))
        await writer.drain()
        self.assertEqual(await self.read_frame(reader), expected)
        records = self.server.records()
        self.assertEqual(
            [entry["response_hex"] for entry in records], [expected.hex()] * 2
        )
        self.assertGreaterEqual(records[0]["response_queued_ns"], records[0]["unix_ns"])
        self.assertGreaterEqual(
            records[1]["response_drained_ns"], records[1]["unix_ns"]
        )

    async def asyncSetUp(self) -> None:
        self.server = native_dns.NativeDnsServer(NAME, "127.0.0.1", 0)
        await self.server.start()
        self.expected_failure = False
        self.clients = []
        self.datagrams = []

    async def asyncTearDown(self) -> None:
        for writer in self.clients:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                if not self.expected_failure:
                    raise
        if self.expected_failure:
            with self.assertRaises(native_dns.NativeDnsFailure):
                await self.server.close()
        else:
            await self.server.close()
        for transport, replies in self.datagrams:
            transport.close()
            await asyncio.wait_for(replies.closed.wait(), 2)
        self.assertFalse(self.server.handlers)
        self.assertFalse(self.server.writers)
        self.assertTrue(self.server.udp_closed.is_set())
        self.assertFalse(self.server.tcp.is_serving())

    async def udp(self) -> tuple:
        async def open_at(host: str, port: int) -> tuple:
            return await asyncio.get_running_loop().create_datagram_endpoint(
                Replies, local_addr=(host, port), remote_addr=self.server.address
            )

        transport, replies = await open_past_reserved_ports(open_at, "127.0.0.1", 0)
        self.datagrams.append((transport, replies))
        return transport, replies

    async def tcp(self) -> tuple:
        reader, writer = await asyncio.open_connection(*self.server.address)
        self.clients.append(writer)
        return reader, writer

    async def read_frame(self, reader: asyncio.StreamReader) -> bytes:
        size = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), 2), "big")
        return await asyncio.wait_for(reader.readexactly(size), 2)

    async def test_udp_a_aaaa_https_journal_and_idempotent_shutdown(self) -> None:
        transport, replies = await self.udp()
        for kind in (1, 28, 65):
            transport.sendto(query_kind(kind))
            answer, peer = await asyncio.wait_for(replies.received.get(), 2)
            self.assertEqual(peer, self.server.address)
            self.assertEqual(
                answer,
                ANSWER
                if kind == 1
                else bytes.fromhex("123485000001000000000000") + query_kind(kind)[12:],
            )
        records = self.server.records()
        self.assertEqual([record["kind"] for record in records], [1, 28, 65])
        self.assertTrue(all(record["transport"] == "udp" for record in records))
        self.assertTrue(
            all(record["response_queued_ns"] >= record["unix_ns"] for record in records)
        )
        self.assertTrue(all(record["error"] is None for record in records))
        self.assertEqual(bytes.fromhex(records[0]["query_hex"]), QUERY)
        self.assertEqual(bytes.fromhex(records[0]["response_hex"]), ANSWER)
        records[0]["error"] = "not the owner journal"
        self.assertIsNone(self.server.records()[0]["error"])
        await self.server.close()
        await self.server.close()

    async def test_tcp_coalesced_and_partial_frames_return_independent_replies(
        self,
    ) -> None:
        reader, writer = await self.tcp()
        writer.write(framed(QUERY) + framed(query_kind(65))[:1])
        await writer.drain()
        self.assertEqual(await self.read_frame(reader), ANSWER)
        writer.write(framed(query_kind(65))[1:])
        await writer.drain()
        self.assertEqual(
            await self.read_frame(reader),
            bytes.fromhex("123485000001000000000000") + query_kind(65)[12:],
        )
        records = self.server.records()
        self.assertEqual([record["kind"] for record in records], [1, 65])
        self.assertTrue(all(record["transport"] == "tcp" for record in records))
        self.assertTrue(
            all(
                record["response_drained_ns"] >= record["unix_ns"] for record in records
            )
        )

    async def test_retry_scene_drops_only_the_first_owned_udp_a_question(self) -> None:
        await self.server.close()
        self.server = native_dns.NativeDnsServer(
            NAME, "127.0.0.1", 0, drop_first_udp_a=True
        )
        await self.server.start()
        reader, writer = await self.tcp()
        writer.write(framed(QUERY))
        await writer.drain()
        self.assertEqual(await self.read_frame(reader), ANSWER)

        transport, replies = await self.udp()
        other = QUERY.replace(b"native", b"absent")
        for wire, answer in (
            (other, bytes.fromhex("123481050001000000000000") + other[12:]),
            (
                query_kind(28),
                bytes.fromhex("123485000001000000000000") + query_kind(28)[12:],
            ),
        ):
            transport.sendto(wire)
            self.assertEqual(
                (await asyncio.wait_for(replies.received.get(), 2))[0], answer
            )

        transport.sendto(QUERY)
        transport.sendto(query_kind(65))
        self.assertEqual(
            (await asyncio.wait_for(replies.received.get(), 2))[0],
            bytes.fromhex("123485000001000000000000") + query_kind(65)[12:],
        )
        retry_transport, retry_replies = await self.udp()
        retry = b"\xab\xcd" + QUERY[2:]
        retry_transport.sendto(retry)
        self.assertEqual(
            (await asyncio.wait_for(retry_replies.received.get(), 2))[0],
            b"\xab\xcd" + ANSWER[2:],
        )
        transport.sendto(QUERY)
        self.assertEqual((await asyncio.wait_for(replies.received.get(), 2))[0], ANSWER)

        records = self.server.records()
        dropped = records[3]
        self.assertEqual(dropped["query_hex"], QUERY.hex())
        self.assertEqual(dropped["peer"], transport.get_extra_info("sockname"))
        self.assertIsInstance(dropped["unix_ns"], int)
        self.assertEqual(dropped["disposition"], "dropped-first-udp-a")
        self.assertIsNone(dropped["response_hex"])
        self.assertIsNone(dropped["error"])
        self.assertNotIn("response_queued_ns", dropped)
        self.assertNotIn("response_drained_ns", dropped)
        self.assertEqual(records[5]["query_hex"], retry.hex())
        self.assertNotEqual(records[5]["peer"], dropped["peer"])
        self.assertEqual(sum("disposition" in row for row in records), 1)
        self.assertTrue(replies.received.empty())

    async def test_silent_peer_drops_every_owned_udp_type_without_preparing_a_reply(
        self,
    ) -> None:
        await self.server.close()
        self.server = native_dns.NativeDnsServer(
            NAME, "127.0.0.1", 0, drop_owned_udp=True
        )
        await self.server.start()
        transport, replies = await self.udp()
        for kind in (1, 28, 65, 1):
            transport.sendto(query_kind(kind))
        other = QUERY.replace(b"native", b"absent")
        transport.sendto(other)
        refused, _ = await asyncio.wait_for(replies.received.get(), 2)
        self.assertEqual(
            refused, bytes.fromhex("123481050001000000000000") + other[12:]
        )
        records = self.server.records()
        self.assertEqual(len(records), 5)
        for row in records[:4]:
            self.assertEqual(row["disposition"], "dropped-owned-udp")
            self.assertIsNone(row["response_hex"])
            self.assertIsNone(row["error"])
            self.assertNotIn("response_queued_ns", row)
            self.assertNotIn("response_drained_ns", row)
        self.assertTrue(replies.received.empty())

    async def test_silent_peer_refuses_tcp_before_an_answer_or_unbounded_handler(
        self,
    ) -> None:
        await self.server.close()
        self.server = native_dns.NativeDnsServer(
            NAME, "127.0.0.1", 0, drop_owned_udp=True
        )
        await self.server.start()
        self.expected_failure = True
        reader, writer = await self.tcp()
        await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertEqual(
            str(self.server.failures[0]), "silent native DNS peer does not support TCP"
        )
        self.assertEqual(self.server.accepted, 1)
        self.assertFalse(self.server.handlers)
        try:
            data = await asyncio.wait_for(reader.read(), 2)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            data = b""
        self.assertEqual(data, b"")
        self.assertEqual(self.server.records(), [])

    def test_silent_and_drop_once_modes_cannot_be_combined(self) -> None:
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            native_dns.NativeDnsServer(NAME, drop_owned_udp=True, drop_first_udp_a=True)

    async def test_malformed_udp_stops_peer_with_raw_error_and_no_answer(self) -> None:
        self.expected_failure = True
        transport, replies = await self.udp()
        transport.sendto(b"broken")
        await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertEqual(self.server.records()[0]["query_hex"], b"broken".hex())
        self.assertIsNone(self.server.records()[0]["response_hex"])
        self.assertIn("length", self.server.records()[0]["error"])
        self.assertTrue(replies.received.empty())

    async def test_tcp_truncated_payload_retains_actual_partial_bytes(self) -> None:
        self.expected_failure = True
        _, writer = await self.tcp()
        writer.write(struct.pack("!H", len(QUERY)) + QUERY[:9])
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(self.server.failed.wait(), 2)
        record = self.server.records()[0]
        self.assertEqual(record["query_hex"], QUERY[:9].hex())
        self.assertEqual(record["declared_size"], len(QUERY))
        self.assertIn("payload is truncated", record["error"])
        self.assertIsNone(record["response_hex"])

    async def test_tcp_truncated_length_and_oversize_are_rejected_without_payload(
        self,
    ) -> None:
        self.expected_failure = True
        _, writer = await self.tcp()
        writer.write(b"\x10\x01")
        await writer.drain()
        await asyncio.wait_for(self.server.failed.wait(), 2)
        record = self.server.records()[0]
        self.assertEqual(record["declared_size"], 4097)
        self.assertEqual(record["query_hex"], "")
        self.assertIsNone(record["response_hex"])

    async def test_tcp_one_byte_length_is_retained_on_disconnect(self) -> None:
        self.expected_failure = True
        _, writer = await self.tcp()
        writer.write(b"\x00")
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(self.server.failed.wait(), 2)
        record = self.server.records()[0]
        self.assertEqual(record["length_hex"], "00")
        self.assertEqual(record["query_hex"], "")
        self.assertIn("length is truncated", record["error"])

    async def test_idle_tcp_has_a_bounded_deadline(self) -> None:
        self.expected_failure = True
        with patch.object(native_dns, "IO_SECONDS", 0.05):
            await self.tcp()
            await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertIsInstance(self.server.failures[0], TimeoutError)

    async def test_partial_tcp_payload_is_retained_when_read_deadline_expires(
        self,
    ) -> None:
        self.expected_failure = True
        _, writer = await self.tcp()
        writer.write(struct.pack("!H", len(QUERY)) + QUERY[:9])
        await writer.drain()
        await asyncio.wait_for(self.server.failed.wait(), native_dns.IO_SECONDS + 2)
        record = self.server.records()[0]
        self.assertEqual(record["query_hex"], QUERY[:9].hex())
        self.assertEqual(record["declared_size"], len(QUERY))
        self.assertIn("timed out", record["error"])
        self.assertIsNone(record["response_hex"])

    async def test_query_limit_rejects_before_another_response(self) -> None:
        self.expected_failure = True
        transport, replies = await self.udp()
        with patch.object(native_dns, "MAX_QUERIES", 1):
            transport.sendto(QUERY)
            self.assertEqual(
                (await asyncio.wait_for(replies.received.get(), 2))[0], ANSWER
            )
            transport.sendto(QUERY)
            await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertEqual(len(self.server.records()), 1)
        self.assertIsNone(self.server.records()[0]["error"])
        self.assertTrue(replies.received.empty())

    async def test_active_connection_limit_does_not_admit_another_handler(self) -> None:
        self.expected_failure = True
        with patch.object(native_dns, "MAX_ACTIVE_TCP", 1):
            await self.tcp()
            await self.tcp()
            await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertLessEqual(len(self.server.handlers), 1)
        self.assertEqual(self.server.accepted, 2)

    async def test_lifetime_connection_limit_rejects_after_a_clean_disconnect(
        self,
    ) -> None:
        self.expected_failure = True
        with patch.object(native_dns, "MAX_TCP_CONNECTIONS", 1):
            _, writer = await self.tcp()
            writer.close()
            await writer.wait_closed()
            await self.tcp()
            await asyncio.wait_for(self.server.failed.wait(), 2)
        self.assertEqual(self.server.accepted, 2)
        self.assertIn("connection limit", str(self.server.failures[0]))

    async def test_udp_send_failure_retains_prepared_reply_without_a_queue_event(
        self,
    ) -> None:
        self.expected_failure = True
        failed = OSError("DNS send failed")
        with patch.object(self.server.udp, "sendto", side_effect=failed):
            native_dns._Datagrams(self.server).datagram_received(
                QUERY, ("127.0.0.1", 9)
            )
        record = self.server.records()[0]
        self.assertEqual(record["response_hex"], ANSWER.hex())
        self.assertNotIn("response_queued_ns", record)
        self.assertEqual(record["error"], "DNS send failed")
        self.assertIs(self.server.failures[0], failed)

    async def test_failed_writer_cleanup_is_retained_and_retried_with_primary_error(
        self,
    ) -> None:
        self.expected_failure = True
        primary = ValueError("DNS parse failed")
        cleanup = OSError("DNS close failed")

        class Writer:
            def __init__(self) -> None:
                self.attempts = 0

            def close(self) -> None:
                pass

            async def wait_closed(self) -> None:
                self.attempts += 1
                if self.attempts == 1:
                    raise cleanup

        writer = Writer()
        self.server.writers.add(writer)
        self.server.fail(primary)
        with self.assertRaises(native_dns.NativeDnsFailure) as first:
            await self.server.close()
        self.assertEqual(first.exception.failures, (primary, cleanup))
        self.assertIn(writer, self.server.writers)
        with self.assertRaises(native_dns.NativeDnsFailure) as second:
            await self.server.close()
        self.assertEqual(second.exception.failures, (primary, cleanup))
        self.assertEqual(writer.attempts, 2)
        self.assertNotIn(writer, self.server.writers)

    async def test_shutdown_cancels_partial_frame_without_hiding_a_failure(
        self,
    ) -> None:
        _, writer = await self.tcp()
        writer.write(b"\x00")
        await writer.drain()
        await self.server.close()
        self.assertFalse(self.server.failures)
        self.assertFalse(self.server.handlers)
        self.assertFalse(self.server.writers)

    async def test_close_cancellation_keeps_one_collectable_cleanup_owner(self) -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        original = self.server.shutdown

        async def delayed() -> None:
            entered.set()
            await release.wait()
            await original()

        with patch.object(self.server, "shutdown", delayed):
            close = asyncio.create_task(self.server.close())
            await entered.wait()
            owner = self.server.cleanup
            close.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await close
            self.assertFalse(owner.done())
            release.set()
            await self.server.close()
            self.assertIs(self.server.cleanup, owner)

    async def test_listener_join_failure_remains_collectable_without_live_writers(
        self,
    ) -> None:
        self.expected_failure = True
        failure = OSError("DNS listener join failed")
        original = self.server.tcp.wait_closed
        calls = 0

        async def interrupted() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise failure
            await original()

        with patch.object(self.server.tcp, "wait_closed", interrupted):
            with self.assertRaises(native_dns.NativeDnsFailure):
                await self.server.close()
            self.assertFalse(self.server.cleanup_complete)
            self.assertFalse(self.server.writers)
            with self.assertRaises(native_dns.NativeDnsFailure) as second:
                await self.server.close()
            self.assertEqual(second.exception.failures, (failure,))
        self.assertEqual(calls, 2)
        self.assertTrue(self.server.cleanup_complete)

    async def test_occupied_port_is_not_replaced_and_original_peer_still_answers(
        self,
    ) -> None:
        other = native_dns.NativeDnsServer(NAME, *self.server.address)
        with self.assertRaises(native_dns.NativeDnsFailure) as failure:
            await other.start()
        self.assertIsInstance(failure.exception.failures[0], OSError)
        with self.assertRaises(native_dns.NativeDnsFailure):
            await other.close()
        transport, replies = await self.udp()
        transport.sendto(QUERY)
        self.assertEqual((await asyncio.wait_for(replies.received.get(), 2))[0], ANSWER)


if __name__ == "__main__":
    unittest.main()
