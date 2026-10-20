"""Reject unequal workloads and retain real response observation boundaries."""

import unittest

import phantom_python_client as adapter


class ConfigurationTests(unittest.TestCase):
    def test_unsupported_work_is_rejected_instead_of_normalized(self):
        for supplied in (
            {"protocol": "negotiated"},
            {"route": "connect"},
            {"gzip": True},
            {"template": True},
            {"method": "POST", "upload_bytes": 10},
            {"redirects": 1},
            {"cancel_after_bytes": 1},
            {"workers": 1},
            {"concurrency": True},
            {"peer_workers": False},
            {"requests": 0},
            {"unknown": 0},
        ):
            with self.subTest(supplied=supplied), self.assertRaises(ValueError):
                adapter.configuration(supplied)

    def test_peer_must_have_exact_origin_count_and_verified_loopback_identity(self):
        self.assertEqual(
            adapter.peer_urls({"urls": ["https://127.0.0.1:12345/"]}, 1),
            ["https://127.0.0.1:12345/"],
        )
        for urls in ([], ["http://127.0.0.1:12345/"], ["https://example.com/"]):
            with self.subTest(urls=urls), self.assertRaises(ValueError):
                adapter.peer_urls({"urls": urls}, 1)


class ObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_collection_has_head_and_completion_but_no_fabricated_first_byte(
        self,
    ):
        class Response:
            status = 200
            protocol = "h2"
            redirects_followed = 0
            connection_setup_retries = 0
            closed = False

            async def read(self, *, max_bytes):
                self.maximum = max_bytes
                return b"ZZ"

            def close(self):
                self.closed = True

        response = Response()

        class Client:
            async def request(self, method, url):
                return response

        config = adapter.configuration({"consume": "collect", "bytes": 2})
        record = adapter.sample(0)
        await adapter.execute(
            config, ["https://127.0.0.1:12345/"], Client(), None, record
        )
        self.assertIsNone(record["error"])
        self.assertGreater(record["head_ns"], 0)
        self.assertGreaterEqual(record["complete_ns"], record["head_ns"])
        self.assertIsNone(record["first_byte_ns"])
        self.assertEqual(record["bytes"], 2)
        self.assertEqual(response.maximum, 2)
        self.assertTrue(response.closed)

        response.protocol = "h1"
        record = adapter.sample(0)
        await adapter.execute(
            config, ["https://127.0.0.1:12345/"], Client(), None, record
        )
        self.assertIsNotNone(record["error"])
        self.assertEqual(record["bytes"], 0)


if __name__ == "__main__":
    unittest.main()
