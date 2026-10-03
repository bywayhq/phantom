import unittest
from pathlib import Path

from scripts.capture.http2_session import CONNECTION_PREFACE
from scripts.capture.http_lifecycle import (
    ETAG,
    FORMAT,
    SCENARIOS,
    ConnectionRecord,
    FrameLog,
    Run,
    page,
    recorded_values,
    reply_for,
    request_path,
)

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/lifecycle"
CHROME = FIXTURES / "chrome/154.0.8037.97/windows-11-26200"
FIREFOX = FIXTURES / "firefox/157.0/windows-11-26200"


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream.to_bytes(4, "big")
        + payload
    )


def fixture_lines(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines()
    )


class FrameLogTests(unittest.TestCase):
    def test_counts_data_frames_and_records_goaway_fields(self) -> None:
        record = ConnectionRecord(0, "main", 0.0)
        log = FrameLog(record)
        data = (
            CONNECTION_PREFACE
            + frame(0x1, 0x25, 5, b"\x82")
            + frame(0x0, 0x1, 5, b"x" * 10)
            + frame(
                0x7,
                0x0,
                0,
                (0).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"Failed ping.",
            )
        )
        log.feed(data[:20], 1.0)
        log.feed(data[20:], 2.0)
        log.name_request(5, "/b")

        self.assertEqual(record.data_frames, 1)
        self.assertEqual(
            record.frames,
            [
                "ms:2.000,type:HEADERS,flags:0x25,stream:5,length:1,path:/b",
                "ms:2.000,type:GOAWAY,flags:0x00,stream:0,length:20,"
                'last_stream:0,error:1,debug:"Failed ping."',
            ],
        )

    def test_connection_end_names_each_observed_close(self) -> None:
        record = ConnectionRecord(0, "main", 0.0)
        self.assertEqual(record.end(), "open")
        record.close_notify = 1.0
        record.eof = 1.0
        self.assertEqual(record.end(), "close_notify+eof")
        self.assertTrue(record.ended)


class ResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = Run("revalidate", "token", 1000, "https://h1")

    def test_a_matching_validator_gets_304_and_a_first_request_200(self) -> None:
        first = reply_for("revalidate", "GET", "/etag", {}, self.run)
        second = reply_for(
            "revalidate", "GET", "/etag", {"if-none-match": ETAG}, self.run
        )
        dated = reply_for(
            "revalidate", "GET", "/last-modified", {"if-modified-since": "x"}, self.run
        )

        self.assertEqual((first.status, first.body), (200, b"v1"))
        self.assertEqual((second.status, second.body), (304, b""))
        self.assertEqual(dated.status, 304)
        self.assertIn(("etag", ETAG), first.fields)

    def test_stall_sends_part_of_a_declared_body(self) -> None:
        reply = reply_for("close", "GET", "/stall", {}, self.run)
        self.assertTrue(reply.stall)
        self.assertIn(("content-length", str(1024 * 1024)), reply.fields)

    def test_recorded_values_hide_the_multipart_boundary(self) -> None:
        values = recorded_values(
            [
                ("Content-Type", "multipart/form-data; boundary=----abc"),
                ("Expect", "100-continue"),
                ("accept", "*/*"),
            ]
        )
        self.assertEqual(
            values,
            {
                "content-type": "multipart/form-data; boundary=<boundary>",
                "expect": "100-continue",
            },
        )

    def test_request_path_drops_the_run_token(self) -> None:
        self.assertEqual(request_path("/b?run=0123"), "/b")

    def test_every_scenario_has_a_page_that_reports_to_done(self) -> None:
        for scenario in SCENARIOS:
            body = page(scenario, "token", "https://h1", 75000).decode()
            self.assertIn("/done?run=token", body)
        self.assertIn("await wait(75000);", page("idle-ping", "t", "", 75000).decode())
        self.assertIn("https://h1/stall", page("close", "t", "https://h1", 1).decode())


class RetainedFixtureTests(unittest.TestCase):
    def test_fixtures_hold_no_token_or_certificate(self) -> None:
        for path in sorted(FIXTURES.glob("*/*/*/*.txt")):
            text = path.read_text(encoding="ascii")
            self.assertTrue(text.startswith(f"format={FORMAT}\n"), path)
            self.assertIn("run=<token>", text, path)
            self.assertNotIn("BEGIN CERTIFICATE", text, path)

    def test_chrome_ends_every_connection_without_close_notify(self) -> None:
        for name in ("close.txt", "ping-unanswered.txt"):
            lines = fixture_lines(CHROME / name)
            ends = [
                value
                for key, value in lines.items()
                if key.startswith("connection_") and key.count("_") == 1
            ]
            self.assertTrue(ends, name)
            for value in ends:
                self.assertNotIn("close_notify+", value, name)

    def test_firefox_sends_close_notify_on_each_close(self) -> None:
        lines = fixture_lines(FIREFOX / "close.txt")
        for index in range(int(lines["connection_count"])):
            self.assertIn("end:close_notify+eof", lines[f"connection_{index}"])

    def test_no_upload_carries_expect(self) -> None:
        for directory in (CHROME, FIREFOX):
            for name in ("upload-h1.txt", "upload-h2.txt"):
                text = (directory / name).read_text(encoding="ascii").lower()
                self.assertNotIn("expect", text, directory / name)


if __name__ == "__main__":
    unittest.main()
