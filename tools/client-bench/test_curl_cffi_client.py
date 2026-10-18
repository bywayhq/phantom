"""Adapter contract checks without importing a particular native curl build."""

import unittest

import curl_cffi_client as adapter
from client_result import validate_result


class ConfigurationTests(unittest.TestCase):
    def test_unsupported_work_is_rejected_instead_of_changed(self):
        for setting in (
            {"protocol": "construct"},
            {"route": "socks5"},
            {"route": "connect", "protocol": "h3"},
            {"proxy_auth": True},
            {"profile": "firefox"},
            {"workers": 2},
            {"gzip": True},
            {"template": True},
            {"diagnostic_events": 128},
            {"speculative_tls": True},
            {"proxy_delay_ms": 1},
            {"unknown": 1},
            {"requests": True},
            {"concurrency": 0},
            {"peer_workers": True},
            {"upload_bytes": 1},
            {"method": "POST", "upload_bytes": 16 * 1024 * 1024 + 1},
            {"method": "PATCH"},
            {"redirects": 4},
            {"redirects": 1},
            {"method": "POST", "consume": "collect", "redirects": 1},
        ):
            with self.subTest(setting=setting), self.assertRaises(ValueError):
                adapter.configuration({"workers": 1} | setting)

    def test_proxy_identity_is_local_and_credentials_are_explicit(self):
        config = adapter.configuration(
            {"workers": 1, "route": "connect", "proxy_auth": True}
        )
        self.assertEqual(
            adapter.proxy_url(config, {"proxy": "127.0.0.1:1234"}),
            "http://bench:bench@127.0.0.1:1234",
        )
        for address in (
            "example.com:443",
            "127.0.0.1:0",
            "user@127.0.0.1:1234",
            "127.0.0.1:1234/",
            "127.0.0.1:1234?bypass=1",
        ):
            with self.subTest(address=address), self.assertRaises(ValueError):
                adapter.proxy_url(config, {"proxy": address})

    def test_peer_must_match_the_local_secure_workload(self):
        for url in (
            "http://127.0.0.1:1234/",
            "https://example.com:443/",
            "https://user@127.0.0.1:1234/",
            "https://127.0.0.1/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                adapter.peer_urls({"urls": [url]}, 1)
        self.assertEqual(
            adapter.peer_urls({"urls": ["https://127.0.0.1:1234/"]}, 1),
            ["https://127.0.0.1:1234/"],
        )


class Response:
    status_code = 200
    http_version = 3
    content = b"ZZ"

    def __init__(self, chunks=(b"Z", b"Z")):
        self.chunks = chunks
        self.closed = False

    async def aiter_content(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


class Session:
    def __init__(self, response):
        self.response = response
        self.closed = False

    async def request(self, method, url, **kwargs):
        self.method, self.arguments = method, kwargs
        return self.response

    async def close(self):
        self.closed = True


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_post_upload_passes_the_exact_payload_to_the_public_request_api(self):
        config = adapter.configuration(
            {"workers": 1, "method": "POST", "upload_bytes": 65536, "bytes": 2}
        )
        session = Session(Response())
        record = adapter.sample(0)
        await adapter.execute(
            config, ["https://127.0.0.1:1234/"], session, lambda: session, 3, record
        )
        self.assertIsNone(record["error"])
        self.assertEqual(session.method, "POST")
        self.assertEqual(session.arguments["data"], b"U" * 65536)

    async def test_stream_and_collect_keep_real_completion_and_missing_head(self):
        for consume in ("stream", "collect"):
            config = adapter.configuration(
                {
                    "workers": 1,
                    "requests": 1,
                    "warmup": 0,
                    "bytes": 2,
                    "consume": consume,
                }
            )
            response = Response()
            session = Session(response)
            record = adapter.sample(0)
            await adapter.execute(
                config,
                ["https://127.0.0.1:1234/"],
                session,
                lambda s=session: s,
                3,
                record,
            )
            self.assertIsNone(record["error"])
            self.assertTrue(response.closed)
            self.assertFalse(session.closed)
            self.assertEqual(record["bytes"], 2)
            self.assertIsNone(record["head_ns"])
            if consume == "stream":
                self.assertIsNotNone(record["first_byte_ns"])
            else:
                self.assertIsNone(record["first_byte_ns"])
            validate_result(
                {
                    "config": config,
                    "elapsed_ns": record["complete_ns"] + 1,
                    "samples": [record],
                    "heap_instrumented": False,
                    "observer_storage_bytes": 0,
                    "unavailable_timings": {"head_ns": adapter.HEAD_UNAVAILABLE},
                },
                config,
            )

    async def test_protocol_payload_and_length_errors_are_retained_and_closed(self):
        config = adapter.configuration({"workers": 1, "bytes": 2, "cold": True})
        for response, protocol in (
            (Response(), 2),
            (Response((b"XY",)), 3),
            (Response((b"Z",)), 3),
        ):
            with self.subTest(protocol=protocol, chunks=response.chunks):
                session = Session(response)
                record = adapter.sample(0)
                await adapter.execute(
                    config,
                    ["https://127.0.0.1:1234/"],
                    None,
                    lambda s=session: s,
                    protocol,
                    record,
                )
                self.assertIsNotNone(record["error"])
                self.assertTrue(response.closed)
                self.assertTrue(session.closed)

    async def test_request_and_cleanup_errors_are_retained_and_handles_close(self):
        class BrokenResponse(Response):
            async def aclose(self):
                self.closed = True
                raise OSError("response close failed")

        class BrokenSession(Session):
            async def close(self):
                self.closed = True
                raise OSError("session close failed")

        config = adapter.configuration({"workers": 1, "bytes": 2, "cold": True})
        for chunks in ((b"ZZ",), (b"XY",)):
            with self.subTest(chunks=chunks):
                response = BrokenResponse(chunks)
                session = BrokenSession(response)
                record = adapter.sample(0)
                await adapter.execute(
                    config,
                    ["https://127.0.0.1:1234/"],
                    None,
                    lambda s=session: s,
                    3,
                    record,
                )
                self.assertTrue(response.closed)
                self.assertTrue(session.closed)
                self.assertIn(
                    "response cleanup: OSError: response close failed", record["error"]
                )
                self.assertIn(
                    "session cleanup: OSError: session close failed", record["error"]
                )
                if chunks == (b"XY",):
                    self.assertIn(
                        "ValueError: incorrect response content", record["error"]
                    )

    async def test_cancelled_response_cleanup_still_closes_the_owned_session(self):
        import asyncio

        class CancelledResponse(Response):
            async def aclose(self):
                self.closed = True
                raise asyncio.CancelledError

        config = adapter.configuration({"workers": 1, "bytes": 2, "cold": True})
        response = CancelledResponse()
        session = Session(response)
        with self.assertRaises(asyncio.CancelledError):
            await adapter.execute(
                config,
                ["https://127.0.0.1:1234/"],
                None,
                lambda: session,
                3,
                adapter.sample(0),
            )
        self.assertTrue(response.closed)
        self.assertTrue(session.closed)

    async def test_workers_cover_each_id_once_with_a_bounded_task_set(self):
        import asyncio
        from unittest.mock import patch

        config = adapter.configuration({"workers": 1, "requests": 17, "concurrency": 3})
        records = [adapter.sample(index) for index in range(17)]
        active, peak, seen = 0, 0, []

        async def execute(config, urls, shared, create, protocol, record):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            seen.append(record["id"])
            await asyncio.sleep(0)
            active -= 1

        with patch.object(adapter, "execute", execute):
            await adapter.run_workers(config, [], None, None, None, records)
        self.assertEqual(sorted(seen), list(range(17)))
        self.assertEqual(peak, 3)


if __name__ == "__main__":
    unittest.main()
