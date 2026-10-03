import json
import tempfile
import unittest
from pathlib import Path

from scripts.capture.alps_accept_ch import field_name, load_netlog, netlog_lines

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/client-hints/chrome/154.0.8037.97/windows-11-26200/alps-accept-ch.txt"
)
CONSTANTS = {
    "logEventTypes": {
        "HTTP2_SESSION_RECV_ACCEPT_CH": 1,
        "URL_REQUEST_START_JOB": 2,
        "URL_REQUEST_DELEGATE_CONNECTED": 3,
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS": 4,
    },
    "logSourceType": {"HTTP2_SESSION": 1, "URL_REQUEST": 2},
    "logEventPhase": {"PHASE_BEGIN": 1, "PHASE_END": 2, "PHASE_NONE": 0},
}


def event(kind: int, source: tuple[int, int], **params) -> dict:
    return {
        "type": kind,
        "source": {"type": source[0], "id": source[1]},
        "params": params,
    }


class NetLogTests(unittest.TestCase):
    def test_a_restarted_navigation_shows_an_aborted_request_then_a_sent_one(
        self,
    ) -> None:
        url = "https://server.phantom.test:5/"
        data = {
            "constants": CONSTANTS,
            "events": [
                event(
                    1,
                    (1, 9),
                    accept_ch="Sec-CH-UA-Arch",
                    origin="https://server.phantom.test:5",
                ),
                event(
                    1,
                    (1, 10),
                    accept_ch="Sec-CH-UA-Model",
                    origin="https://www.example",
                ),
                event(2, (2, 20), url=url),
                event(3, (2, 20), net_error=-3),
                event(2, (2, 21), url=url),
                event(
                    4,
                    (2, 21),
                    headers=[":method: GET", "accept: */*", 'sec-ch-ua-arch: "x86"'],
                ),
                event(2, (2, 22), url="https://other.test/"),
            ],
        }

        self.assertEqual(
            netlog_lines(data),
            [
                'accept_ch_frame="Sec-CH-UA-Arch"',
                "url_request_0=path:/,delegate_connected_error:-3,sent_headers:false,fields:none",
                "url_request_1=path:/,delegate_connected_error:none,sent_headers:true,"
                "fields::method|accept|sec-ch-ua-arch",
            ],
        )

    def test_a_cut_off_netlog_still_loads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "netlog.json"
            path.write_text(
                json.dumps({"constants": CONSTANTS, "events": []})[:-2] + ",\n",
                encoding="utf-8",
            )
            self.assertEqual(load_netlog(path)["events"], [])

    def test_field_names_keep_the_pseudo_header_colon(self) -> None:
        self.assertEqual(field_name(":path: /"), ":path")
        self.assertEqual(field_name("accept: */*"), "accept")


class RetainedFixtureTests(unittest.TestCase):
    def test_the_navigation_restarts_once_with_the_hints_after_accept(self) -> None:
        lines = dict(
            line.split("=", 1)
            for line in FIXTURE.read_text(encoding="ascii").splitlines()
        )
        self.assertIn(
            "delegate_connected_error:-3,sent_headers:false",
            lines["netlog_url_request_0"],
        )
        fields = lines["netlog_url_request_1"].split("fields:", 1)[1].split("|")
        accept = fields.index("accept")
        self.assertEqual(
            fields[accept + 1 : accept + 4],
            ["sec-ch-ua-arch", "sec-ch-ua-platform-version", "sec-fetch-site"],
        )
        self.assertNotIn("sec-ch-ua-arch", lines["netlog_url_request_2"])


if __name__ == "__main__":
    unittest.main()
