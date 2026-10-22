"""Check adopted Chrome Linux settings against retained independent peer bytes."""

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from hpack import Decoder

from scripts.capture.http2_analysis import (
    analyze_http2,
    decode_header_block,
    split_frames,
)
from scripts.capture.http2_session import ConnectionRecord
from scripts.capture.quic_resumption import is_tls_grease, parse_client_hello

DIRECTORY = (
    Path(__file__).resolve().parents[3]
    / "crates/phantom-profile/tests/fixtures/peers/httpcloak-1.7.3-chrome-155-linux"
)


class ChromeLinuxPeerTests(unittest.TestCase):
    def test_manifest_covers_every_retained_file(self):
        manifest = json.loads((DIRECTORY / "sha256.json").read_text(encoding="utf-8"))
        files = {
            p.relative_to(DIRECTORY).as_posix()
            for p in DIRECTORY.rglob("*")
            if p.is_file() and p != DIRECTORY / "sha256.json"
        }
        self.assertEqual(set(manifest), files)
        for name, digest in manifest.items():
            with self.subTest(file=name):
                self.assertEqual(
                    hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest(), digest
                )

    def test_six_processes_finish_exact_requests_on_one_h2_connection(self):
        for mode, count in (("baseline", 2), ("boundary", 9)):
            for number in range(1, 4):
                run = DIRECTORY / f"observations-v1/{mode}-{number}"
                with self.subTest(run=run.name):
                    self.assertEqual(
                        json.loads((run / "exit.json").read_text()), {"returncode": 0}
                    )
                    self.assertEqual(
                        json.loads((run / "failures.json").read_text()), []
                    )
                    completion = json.loads((run / "run.json").read_text())
                    self.assertEqual(completion["connection_count"], 1)
                    self.assertFalse(completion["timed_out"])
                    record = self.record(run)
                    client, trailing = split_frames(
                        record.client_chunks, "client", preface=True
                    )
                    server, server_trailing = split_frames(
                        record.server_chunks, "server", preface=False
                    )
                    self.assertEqual((trailing, server_trailing), (0, 0))
                    self.assertEqual(client[0].frame_type, 4)
                    self.assertEqual(
                        client[0].payload.hex(),
                        "000100010000000200000000000400600000000600040000",
                    )
                    self.assertEqual(
                        (client[1].frame_type, client[1].payload.hex()), (8, "00ef0001")
                    )
                    settings = [
                        f.payload
                        for f in server
                        if f.frame_type == 4 and not f.flags & 1
                    ]
                    self.assertEqual(len(settings), 1)
                    self.assertEqual(settings[0][:6], bytes.fromhex("000100001000"))
                    blocks = analyze_http2(record).client_headers
                    streams = list(range(1, count * 2, 2))
                    self.assertEqual([b.stream_id for b in blocks], streams)
                    self.assertEqual(
                        [f.stream_id for f in client if f.frame_type == 1], streams
                    )
                    for block in blocks:
                        self.assertEqual(
                            (
                                block.priority.exclusive,
                                block.priority.depends_on,
                                block.priority.weight,
                            ),
                            (True, 0, 256),
                        )
                        self.assertEqual(block.continuation_count, 0)
                        self.assertTrue(block.flags & 4)
                        self.assertEqual(
                            [f.name for f in block.fields[:4]],
                            [b":method", b":authority", b":scheme", b":path"],
                        )
                    for stream in streams:
                        for frames in (client, server):
                            self.assertTrue(
                                any(
                                    f.stream_id == stream
                                    and f.frame_type in (0, 1)
                                    and f.flags & 1
                                    for f in frames
                                )
                            )
                    self.assertEqual(
                        (run / "response-1.body").read_bytes(), b"peer capture\n"
                    )
                    self.assertEqual((run / f"response-{count}.body").read_bytes(), b"")

    def test_navigation_literals_match_independent_first_and_reused_blocks(self):
        repo = DIRECTORY.parents[5]
        expected = json.loads(
            (
                repo
                / "crates/phantom/src/fingerprint/tests/fixtures/chrome-155-linux-navigation.json"
            ).read_text(encoding="utf-8")
        )
        literals = [
            (f["name"].encode(), f["value"].encode()) for f in expected["http2_fields"]
        ]
        self.assertEqual(len(literals), 13)
        self.assertEqual(expected["http1_fields"], [])
        self.assertIsNone(expected["http3_fields"])
        for mode in ("baseline", "boundary"):
            for number in range(1, 4):
                run = DIRECTORY / f"observations-v1/{mode}-{number}"
                blocks = analyze_http2(self.record(run)).client_headers
                for index in (0, 1):
                    with self.subTest(run=run.name, request=index):
                        self.assertEqual(
                            [(f.name, f.value) for f in blocks[index].fields[4:]],
                            literals,
                        )

    def test_cookies_and_full_table_boundary_preserve_actual_dynamic_state(self):
        for number in range(1, 4):
            run = DIRECTORY / f"observations-v1/boundary-{number}"
            decoder = Decoder()
            decoded = []
            for block in analyze_http2(self.record(run)).client_headers:
                fields = decode_header_block(decoder, block.block)
                decoded.append((fields, tuple(decoder.header_table.dynamic_entries)))
            with self.subTest(run=number):
                for position, representation, indexes in (
                    (2, "incremental", [32, 32]),
                    (3, "indexed", [63, 62]),
                ):
                    fields = decoded[position][0]
                    cookies = [f for f in fields if f.name == b"cookie"]
                    self.assertEqual(
                        [f.value for f in cookies], [b"one=alpha", b"two=beta"]
                    )
                    self.assertEqual(
                        [f.representation for f in cookies], [representation] * 2
                    )
                    self.assertEqual([f.index for f in cookies], indexes)
                    self.assertEqual(
                        [f.name for f in fields[-3:]],
                        [b"cookie", b"cookie", b"priority"],
                    )
                for position, size in ((4, 3073), (5, 4096), (7, 4097)):
                    fields, table = decoded[position]
                    field = next(f for f in fields if f.name == b"x-hpack-size")
                    self.assertEqual(32 + len(field.name) + len(field.value), size)
                    self.assertEqual(
                        field.representation,
                        "without-indexing" if size == 4097 else "incremental",
                    )
                    self.assertEqual((field.name, field.value) in table, size <= 4096)
                marker = (b"x-table-marker", b"retained-marker")
                for position in (6, 7, 8):
                    self.assertIn(marker, decoded[position][1])
                field = next(f for f in decoded[8][0] if f.name == marker[0])
                self.assertEqual((field.representation, field.index), ("indexed", 62))

    def test_fresh_tls_keeps_literal_offer_and_dynamic_grease(self):
        for mode in ("baseline", "boundary"):
            for number in range(1, 4):
                hello = parse_client_hello(
                    (
                        DIRECTORY
                        / f"observations-v1/{mode}-{number}/connection-0.hello.bin"
                    ).read_bytes()
                )
                with self.subTest(run=f"{mode}-{number}"):
                    self.assertTrue(is_tls_grease(hello.cipher_suites[0]))
                    self.assertEqual(
                        hello.cipher_suites[1:],
                        (
                            0x1301,
                            0x1302,
                            0x1303,
                            0xC02B,
                            0xC02F,
                            0xC02C,
                            0xC030,
                            0xCCA9,
                            0xCCA8,
                            0xC013,
                            0xC014,
                            0x009C,
                            0x009D,
                            0x002F,
                            0x0035,
                        ),
                    )
                    self.assertEqual(
                        hello.extension(16),
                        bytes.fromhex("000c02683208687474702f312e31"),
                    )
                    self.assertEqual(
                        hello.extension(17613), bytes.fromhex("0003026832")
                    )
                    self.assertEqual(hello.extension(27), bytes.fromhex("020002"))
                    self.assertEqual(hello.extension(35), b"")
                    self.assertEqual(
                        hello.extension(0), b"\x00\x16\x00\x00\x13server.phantom.test"
                    )
                    self.assertEqual(
                        hello.extension(10)[4:], bytes.fromhex("11ec001d00170018")
                    )
                    self.assertEqual(
                        hello.extension(13)[4:],
                        bytes.fromhex("09040905090604030804040105030805050108060601"),
                    )
                    self.assertEqual(len(hello.extension(0xCA34)), 186)
                    self.assertEqual(
                        hello.extension(0xFE0D)[:5], bytes.fromhex("0000010001")
                    )
                    self.assertIn(len(hello.extension(0xFE0D)), (218, 250, 282))

    def test_public_client_keeps_peer_ordered_fields_and_dynamic_state(self):
        def normalized(name, value):
            if name == b":authority":
                host, separator, port = value.rpartition(b":")
                self.assertEqual(host, b"server.phantom.test")
                self.assertEqual(separator, b":")
                self.assertTrue(port.isdigit())
                return host + b":<port>"
            return value

        for mode, count in (("baseline", 2), ("boundary", 9)):
            for number in range(1, 4):
                name = f"{mode}-{number}"
                records = [
                    self.record(DIRECTORY / prefix / name)
                    for prefix in ("phantom/observations", "observations-v1")
                ]
                blocks = [analyze_http2(record).client_headers for record in records]
                self.assertEqual([len(value) for value in blocks], [count, count])
                frames = [
                    split_frames(record.client_chunks, "client", preface=True)[0]
                    for record in records
                ]
                with self.subTest(run=name):
                    for kind in (4, 8):
                        self.assertEqual(
                            [f.payload for f in frames[0] if f.frame_type == kind],
                            [f.payload for f in frames[1] if f.frame_type == kind],
                        )
                    decoders = [Decoder(), Decoder()]
                    for pair in zip(*blocks, strict=True):
                        actual, peer = pair
                        self.assertEqual(
                            (
                                actual.stream_id,
                                actual.flags,
                                actual.priority,
                                actual.continuation_count,
                            ),
                            (
                                peer.stream_id,
                                peer.flags,
                                peer.priority,
                                peer.continuation_count,
                            ),
                        )
                        fields, tables = [], []
                        for block, decoder in zip(pair, decoders, strict=True):
                            fields.append(
                                [
                                    replace(f, value=normalized(f.name, f.value))
                                    for f in block.fields
                                ]
                            )
                            decode_header_block(decoder, block.block)
                            tables.append(
                                [
                                    (name, normalized(name, value))
                                    for name, value in decoder.header_table.dynamic_entries
                                ]
                            )
                        self.assertEqual(fields[0], fields[1])
                        self.assertEqual(tables[0], tables[1])

    @staticmethod
    def record(run):
        return ConnectionRecord(
            "tls",
            0,
            client_chunks=[(0, (run / "connection-0.client.bin").read_bytes())],
            server_chunks=[(0, (run / "connection-0.server.bin").read_bytes())],
        )


if __name__ == "__main__":
    unittest.main()
