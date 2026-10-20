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
            {"method": "PUT", "upload_bytes": 10},
            {"upload_bytes": 10},
            {"cancel_stage": "upload"},
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

            async def aclose(self):
                self.close()

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

    async def test_known_length_source_is_bounded_and_preserves_every_byte(self):
        for size in (0, 1, 65536, 65537, 16 * 1024 * 1024):
            parts = []
            async for part in adapter.upload(size):
                self.assertLessEqual(len(part), 65536)
                self.assertEqual(part.count(b"U"), len(part))
                parts.append(len(part))
            self.assertEqual(sum(parts), size)

    async def test_cancelled_prefix_closes_selected_response_and_keeps_other_complete(
        self,
    ):
        class Response:
            status = 200
            protocol = "h2"
            redirects_followed = 0
            connection_setup_retries = 0
            closed = False

            async def iter_bytes(self, size):
                self.maximum = size
                for _ in range(8):
                    yield b"Z"

            async def aclose(self):
                self.closed = True

        responses = []
        urls = []

        class Client:
            async def request(self, method, url):
                urls.append(url)
                response = Response()
                responses.append(response)
                return response

        config = adapter.configuration(
            {
                "cancel_after_bytes": 2,
                "bytes": 8,
                "warmup": 1,
                "concurrency": 2,
                "requests": 2,
                "chunk_delay_ms": 1,
            }
        )
        for identifier in (0, 1):
            record = adapter.sample(identifier)
            await adapter.execute(
                config, ["https://127.0.0.1:12345/"], Client(), None, record
            )
            self.assertIsNone(record["error"])
            self.assertEqual(record["cancelled"], identifier == 0)
            self.assertEqual(record["bytes"], 2 if identifier == 0 else 8)
        self.assertTrue(all(response.closed for response in responses))
        self.assertEqual(
            urls, ["https://127.0.0.1:12345/?cancel=1", "https://127.0.0.1:12345/"]
        )
        self.assertEqual(responses[0].maximum, 2)

    async def test_upload_passes_exact_length_and_cleanup_errors_are_retained(self):
        class Response:
            status = 200
            protocol = "h2"
            redirects_followed = 0
            connection_setup_retries = 0

            async def read(self, *, max_bytes):
                return b"Z"

            async def aclose(self):
                raise RuntimeError("cleanup failed")

        class Client:
            async def request(self, method, url, *, body, body_length):
                self.method, self.length = method, body_length
                self.payload = b"".join([part async for part in body])
                return Response()

        client = Client()
        config = adapter.configuration(
            {"method": "POST", "upload_bytes": 65537, "consume": "collect", "bytes": 1}
        )
        record = adapter.sample(0)
        await adapter.execute(
            config, ["https://127.0.0.1:12345/"], client, None, record
        )
        self.assertEqual((client.method, client.length), ("POST", 65537))
        self.assertEqual(client.payload, b"U" * 65537)
        self.assertIn("cleanup failed", record["error"])
        self.assertFalse(record["cancelled"])


if __name__ == "__main__":
    unittest.main()
