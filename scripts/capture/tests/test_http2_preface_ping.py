import unittest
from pathlib import Path

from scripts.capture.http2_preface_ping import FORMAT, FrameLog, page, request_path
from scripts.capture.http2_session import CONNECTION_PREFACE

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/http2/chrome/154.0.8037.58/windows-11-26200/preface-ping.txt"
)


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream.to_bytes(4, "big")
        + payload
    )


class FrameLogTests(unittest.TestCase):
    def test_splits_frames_across_reads_and_keeps_only_ping_payloads(self) -> None:
        data = (
            CONNECTION_PREFACE
            + frame(0x1, 0x25, 5, b"\x82\x84")
            + frame(0x6, 0x0, 0, (1).to_bytes(8, "big"))
            + frame(0x0, 0x1, 5, b"x" * 100)
        )
        log = FrameLog()
        log.feed(data[:30], 1.0)
        log.feed(data[30:], 2.5)
        log.name_request(5, "/b")
        self.assertEqual(
            [item.line() for item in log.frames],
            [
                "ms:2.500,type:HEADERS,flags:0x25,stream:5,length:2,path:/b",
                "ms:2.500,type:PING,flags:0x00,stream:0,length:8,"
                "payload:0000000000000001",
                "ms:2.500,type:DATA,flags:0x01,stream:5,length:100",
            ],
        )

    def test_rejects_an_invalid_preface(self) -> None:
        with self.assertRaises(ValueError):
            FrameLog().feed(b"GET / HTTP/1.1\r\n\r\n" + b"x" * 16, 0.0)

    def test_request_path_drops_the_run_token(self) -> None:
        self.assertEqual(request_path(b"/b?run=0123"), "/b")

    def test_page_waits_the_configured_times(self) -> None:
        body = page("token", 11.5, 9.0).decode()
        self.assertIn("await wait(11500);", body)
        self.assertIn("await wait(9000);", body)
        self.assertIn("method: 'POST'", body)


class RetainedFixtureTests(unittest.TestCase):
    def test_fixture_holds_no_request_token_or_certificate(self) -> None:
        text = FIXTURE.read_text(encoding="ascii")
        values = dict(line.split("=", 1) for line in text.splitlines())
        self.assertEqual(values["format"], FORMAT)
        self.assertIn("<token>", values["launch_arguments"])
        self.assertIn("<certificate-spki>", values["launch_arguments"])
        frames = [value for key, value in values.items() if key.startswith("frame_")]
        self.assertEqual(len(frames) - 1, int(values["frame_count"]))


if __name__ == "__main__":
    unittest.main()
