"""Mixed request contexts retain one client's pools and ordered wire fields."""

import asyncio
import unittest

from phantom_http import AsyncClient, AttemptBudget, Client, Error, Profile
from test_uploads import Handler, server

PROFILE = "chrome-154-windows"


class ContextHandler(Handler):
    def do_GET(self):
        self.server.records.append(
            (self.path, list(self.headers.raw_items()), self.client_address)
        )
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.flush()


def request_fields(record):
    return {name.lower(): value for name, value in record[1]}


class SyncContextTests(unittest.TestCase):
    def test_navigation_fetch_raw_and_default_reuse_one_connection(self):
        with server(ContextHandler) as (peer, url):
            with Client(
                profile=PROFILE, protocol="h1", context="navigation", timeout_ms=5000
            ) as client:
                for path, options in (
                    ("/page", {}),
                    ("/data", {"context": "fetch"}),
                    ("/raw", {"context": "raw"}),
                    ("/next-page", {}),
                ):
                    with client.get(
                        url + path, headers=[("Referer", url + "/page")], **options
                    ) as response:
                        self.assertEqual(response.read(max_bytes=0), b"")

            records = peer.records
            self.assertEqual(len(records), 4)
            self.assertEqual(len({record[2] for record in records}), 1)
            self.assertEqual(
                [request_fields(record).get("sec-fetch-mode") for record in records],
                ["navigate", "cors", None, "navigate"],
            )
            self.assertEqual(
                [request_fields(record).get("sec-fetch-dest") for record in records],
                ["document", "empty", None, "document"],
            )


class AsyncContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_fetch_and_navigation_do_not_change_the_default(self):
        with server(ContextHandler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="navigation", timeout_ms=5000
            ) as client:

                async def send(context, index):
                    async with client.stream(
                        "GET",
                        f"{url}/{context}/{index}",
                        context=context,
                        headers=[("Referer", url + "/page")],
                    ) as response:
                        await response.read(max_bytes=0)

                await asyncio.gather(
                    *(
                        send(context, index)
                        for index in range(8)
                        for context in ("navigation", "fetch")
                    )
                )
                response = await client.get(url + "/default")
                await response.read(max_bytes=0)

            self.assertEqual(len(peer.records), 17)
            for record in peer.records:
                fields = request_fields(record)
                expected = "cors" if record[0].startswith("/fetch/") else "navigate"
                self.assertEqual(fields["sec-fetch-mode"], expected)

    async def test_unavailable_context_prevents_send_and_preserves_budget(self):
        with server(ContextHandler) as (peer, url):
            async with AsyncClient(profile=PROFILE, protocol="h1") as client:
                budget = AttemptBudget(1)
                with self.assertRaises(Error) as caught:
                    await client.get(url, context="font", budget=budget)
                self.assertEqual(caught.exception.kind, "request_template")
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(peer.records, [])

                response = await client.get(url, context="navigation", budget=budget)
                await response.read(max_bytes=0)
                self.assertEqual(budget.remaining, 0)
            self.assertEqual(len(peer.records), 1)

    async def test_imported_template_remains_default_without_catalog_contexts(self):
        profile = Profile.import_json(
            Profile.from_catalog(PROFILE, context="navigation").export_json()
        )
        with server(ContextHandler) as (peer, url):
            async with AsyncClient(
                profile=profile, protocol="h1", context="profile"
            ) as client:
                with self.assertRaises(Error) as caught:
                    await client.get(url, context="fetch")
                self.assertEqual(caught.exception.kind, "request_template")
                for path, options in (("/default", {}), ("/raw", {"context": "raw"})):
                    response = await client.get(url + path, **options)
                    await response.read(max_bytes=0)
            self.assertEqual(
                [
                    request_fields(record).get("sec-fetch-mode")
                    for record in peer.records
                ],
                ["navigate", None],
            )

    async def test_resource_contexts_require_their_fields_and_keep_distinct_headers(
        self,
    ):
        with server(ContextHandler) as (peer, url):
            async with AsyncClient(
                profile="chrome-156-windows", protocol="h1"
            ) as client:
                for context in ("script", "stylesheet", "image", "font"):
                    response = await client.get(
                        url + "/" + context,
                        context=context,
                        headers=[("Referer", url + "/page"), ("Origin", url)],
                    )
                    await response.read(max_bytes=0)
            self.assertEqual(
                [request_fields(record)["sec-fetch-dest"] for record in peer.records],
                ["script", "style", "image", "font"],
            )

    async def test_invalid_context_does_not_open_upload_or_send(self):
        with server(ContextHandler) as (peer, url):
            async with AsyncClient(profile=PROFILE, protocol="h1") as client:
                with self.assertRaises(Error) as caught:
                    await client.post(url, context="profile", upload="does-not-exist")
                self.assertEqual(caught.exception.kind, "invalid_context")
                self.assertEqual(peer.records, [])
