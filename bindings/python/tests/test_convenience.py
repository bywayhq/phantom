"""Public conveniences against an independent HTTP request reader."""

import json
import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    AttemptBudgetExhausted,
    Client,
    Profile,
    RedirectPolicy,
)
from test_request_bodies import Handler
from test_uploads import PROFILE, server


class ConvenienceHandler(Handler):
    do_GET = Handler.do_POST
    do_PUT = Handler.do_POST

    def end_headers(self):
        self.send_header("X-Tag", "one")
        self.send_header("x-tag", "two")
        super().end_headers()


class AsyncConvenienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_json_fills_required_content_type_and_length_template_slots(self):
        document = Profile.from_catalog(PROFILE, context="fetch").describe()
        template = document["profile"]["request_template"]
        fields = template["http1_fields"]
        fields[:] = [
            {"variant": "Literal", "name": "x-before", "value": "1"},
            {"variant": "Caller", "name": "content-type", "required": True},
            {"variant": "Literal", "name": "x-middle", "value": "2"},
            {"variant": "Caller", "name": "content-length", "required": True},
            {"variant": "Literal", "name": "x-after", "value": "3"},
            *(
                field
                for field in fields
                if field.get("name", "").lower()
                not in ("content-type", "content-length")
            ),
        ]
        profile = Profile.import_json(json.dumps(document).encode())
        with server(ConvenienceHandler) as (peer, url):
            async with AsyncClient(
                profile=profile, protocol="h1", context="profile"
            ) as client:
                response = await client.post(url, json={"z": 1, "a": 2})
                await response.read(max_bytes=0)
            record = peer.records[0]
            names = [name.lower() for name, _ in record[2]]
            before = names.index("x-before")
            self.assertEqual(
                names[before : before + 5],
                ["x-before", "content-type", "x-middle", "content-length", "x-after"],
            )
            self.assertEqual(record[3], b'{"z":1,"a":2}')
            self.assertIn(("content-length", "13"), record[2])

    async def test_json_redirect_reuses_body_and_shared_budget(self):
        with server(ConvenienceHandler) as (peer, url):
            async with AsyncClient(profile=PROFILE, context="raw") as client:
                budget = AttemptBudget(2)
                async with client.stream(
                    "POST",
                    url + "/redirect",
                    json={"city": "Zürich"},
                    headers=[("X-Before", "1"), ("X-After", "2")],
                    redirect_policy=RedirectPolicy.limited(1),
                    budget=budget,
                ) as response:
                    self.assertEqual(response.protocol, "h1")
                    self.assertEqual(
                        response.headers.get_list("X-TAG"), [b"one", b"two"]
                    )
                    await response.read(max_bytes=0)
                self.assertEqual(budget.remaining, 0)
                with self.assertRaises(AttemptBudgetExhausted):
                    await client.get(url, budget=budget)
            records = peer.records
            self.assertEqual(len(records), 2)
            self.assertEqual(
                [record[3] for record in records], ['{"city":"Zürich"}'.encode()] * 2
            )
            self.assertEqual([record[1] for record in records], ["/redirect", "/final"])
            fields = records[0][2]
            names = [name.lower() for name, _ in fields]
            before = names.index("x-before")
            self.assertEqual(
                names[before : before + 3], ["x-before", "x-after", "content-type"]
            )
            self.assertIn(("content-type", "application/json"), fields)

    async def test_form_query_order_and_limits_before_budget(self):
        with server(ConvenienceHandler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                budget = AttemptBudget(1)
                with self.assertRaises(ValueError):
                    await client.post(
                        url, json="é", maximum_body_bytes=3, budget=budget
                    )
                self.assertEqual(budget.remaining, 1)
                response = await client.post(
                    url + "/?raw=%2f",
                    params=[("tag", "one"), ("tag", "two")],
                    form=[("tag", "one"), ("tag", "two"), ("space", "a b")],
                    budget=budget,
                )
                await response.read(max_bytes=0)
            record = peer.records[0]
            self.assertEqual(record[1], "/?raw=%2f&tag=one&tag=two")
            self.assertEqual(record[3], b"tag=one&tag=two&space=a+b")
            self.assertIn(
                ("content-type", "application/x-www-form-urlencoded;charset=UTF-8"),
                record[2],
            )


class SyncConvenienceTests(unittest.TestCase):
    def test_stream_context_and_form_use_the_same_public_path(self):
        with server(ConvenienceHandler) as (peer, url):
            with Client(profile=PROFILE, context="raw") as client:
                with client.stream("PUT", url, json=None) as response:
                    self.assertEqual(response.headers.get("x-tag"), b"one")
                    self.assertEqual(response.read(max_bytes=0), b"")
                with client.post(url, form={"space": "a b"}) as response:
                    response.read(max_bytes=0)
            self.assertEqual(
                [record[3] for record in peer.records], [b"null", b"space=a+b"]
            )
