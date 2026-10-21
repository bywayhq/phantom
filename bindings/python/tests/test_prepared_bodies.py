"""Core-encoded prepared bodies against an independent raw HTTP/1 reader."""

import unittest

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    MultipartPart,
    PreparedBody,
    PreparedBodyError,
    RedirectPolicy,
)
from test_request_bodies import Handler
from test_uploads import PROFILE, server

FORM_TYPE = "application/x-www-form-urlencoded;charset=UTF-8"
FORM = b"tag=one&tag=two&space=a+b&plus=%2B&utf8=%C3%A9"
MULTIPART = (
    b'--a:b\r\nContent-Disposition: form-data; name="tag"\r\n\r\none\r\ntwo\r\n'
    b'--a:b\r\nContent-Disposition: form-data; name="tag"; filename="a%22.bin"'
    b"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\n\xff\r\n"
    b'--a:b\r\nContent-Disposition: form-data; name="custom"'
    b"\r\nContent-Type: Text/Plain\r\n\r\nlast\r\n--a:b--\r\n"
)


def form():
    return PreparedBody.form(
        [
            ("tag", "one"),
            ("tag", "two"),
            ("space", "a b"),
            ("plus", "+"),
            ("utf8", "é"),
        ],
        maximum_bytes=len(FORM),
    )


def multipart(maximum=None):
    return PreparedBody.multipart(
        [
            MultipartPart("tag", "one\ntwo"),
            MultipartPart("tag", b"\x00\n\xff", filename='a".bin'),
            MultipartPart("custom", "last", content_type="Text/Plain"),
        ],
        boundary="a:b",
        maximum_bytes=len(MULTIPART) if maximum is None else maximum,
    )


class PreparedTests(unittest.IsolatedAsyncioTestCase):
    async def test_form_replays_and_remains_reusable_after_client_shutdown(self):
        body = form()
        self.assertEqual(body.to_bytes(), FORM)
        self.assertEqual(body.length, len(FORM))
        self.assertEqual(body.content_type, FORM_TYPE)
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                budget = AttemptBudget(2)
                response = await client.request(
                    "POST",
                    url + "/redirect",
                    body=body,
                    headers=(("Content-Type", body.content_type),),
                    redirect_policy=RedirectPolicy.limited(1),
                    budget=budget,
                )
                await response.read(max_bytes=0)
                self.assertEqual(budget.remaining, 0)
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as other:
                response = await other.request(
                    "POST",
                    url,
                    body=body,
                    body_length=body.length,
                    headers=(("Content-Type", body.content_type),),
                )
                await response.read(max_bytes=0)
            self.assertEqual([record[3] for record in peer.records], [FORM] * 3)

    async def test_multipart_exact_encoding_and_header_position(self):
        body = multipart()
        self.assertEqual(body.to_bytes(), MULTIPART)
        self.assertEqual(body.content_type, 'multipart/form-data; boundary="a:b"')
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                response = await client.request(
                    "POST",
                    url,
                    body=body,
                    headers=(
                        ("X-Before", "1"),
                        ("Content-Type", body.content_type),
                        ("X-After", "2"),
                    ),
                )
                await response.read(max_bytes=0)
            self.assertEqual(peer.records[0][3], MULTIPART)
            fields = peer.records[0][2]
            names = [name for name, _ in fields]
            position = names.index("Content-Type")
            self.assertEqual(
                names[position - 1 : position + 2],
                ["X-Before", "Content-Type", "X-After"],
            )
            self.assertIn(("Content-Length", str(len(MULTIPART))), fields)

    async def test_content_type_conflicts_and_length_fail_before_dispatch_or_budget(
        self,
    ):
        body = form()
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                for headers in (
                    (),
                    (("Content-Type", "wrong/type"),),
                    (("Content-Type", FORM_TYPE), ("content-type", FORM_TYPE)),
                ):
                    budget = AttemptBudget(1)
                    with (
                        self.subTest(headers=headers),
                        self.assertRaises(Error) as failed,
                    ):
                        await client.request(
                            "POST", url, body=body, headers=headers, budget=budget
                        )
                    self.assertEqual(failed.exception.kind, "invalid_header")
                    self.assertEqual(budget.remaining, 1)
                budget = AttemptBudget(1)
                with self.assertRaisesRegex(ValueError, "encoded length"):
                    await client.request(
                        "POST", url, body=body, body_length=0, budget=budget
                    )
                self.assertEqual(budget.remaining, 1)
            self.assertEqual(peer.records, [])

    def test_encoded_caps_metadata_collision_and_errors_are_core_categories(self):
        self.assertEqual(PreparedBody.form([], maximum_bytes=0).to_bytes(), b"")
        self.assertEqual(
            PreparedBody.form([("", "")], maximum_bytes=1).to_bytes(), b"="
        )
        cases = [
            (lambda: PreparedBody.form([("x", " ")], maximum_bytes=2), "too_large"),
            (lambda: multipart(len(MULTIPART) - 1), "too_large"),
            (
                lambda: PreparedBody.multipart(
                    [], boundary="bad boundary", maximum_bytes=99
                ),
                "invalid_boundary",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("private\x01", b"x")],
                    boundary="B",
                    maximum_bytes=999,
                ),
                "invalid_name",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("x", b"x", filename="private\x01")],
                    boundary="B",
                    maximum_bytes=999,
                ),
                "invalid_filename",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("x", b"x", content_type="private/type; x=y")],
                    boundary="B",
                    maximum_bytes=999,
                ),
                "invalid_content_type",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("x", b"private--B")], boundary="B", maximum_bytes=999
                ),
                "boundary_collision",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("é" * 2049, b"x")], boundary="B", maximum_bytes=9999
                ),
                "too_large",
            ),
            (
                lambda: PreparedBody.multipart(
                    [MultipartPart("x", b"")] * 1025, boundary="B", maximum_bytes=10**6
                ),
                "too_many_parts",
            ),
        ]
        for prepare, kind in cases:
            with (
                self.subTest(kind=kind),
                self.assertRaises(PreparedBodyError) as failed,
            ):
                prepare()
            self.assertEqual(failed.exception.kind, kind)
            self.assertNotIn("private", str(failed.exception))

    def test_payload_has_no_header_sized_cap_and_empty_framing_is_bounded(self):
        payload = b"x" * 131072
        form = PreparedBody.form(
            [("x", "x" * len(payload))], maximum_bytes=len(payload) + 2
        )
        self.assertEqual(form.to_bytes(), b"x=" + payload)
        body = PreparedBody.multipart(
            [MultipartPart("x", payload)],
            boundary="B",
            maximum_bytes=len(payload) + 256,
        )
        self.assertIn(payload, body.to_bytes())
        self.assertEqual(
            PreparedBody.multipart([], boundary="B", maximum_bytes=7).to_bytes(),
            b"--B--\r\n",
        )
        with self.assertRaises(PreparedBodyError) as failed:
            PreparedBody.multipart([], boundary="B", maximum_bytes=6)
        self.assertEqual(failed.exception.kind, "too_large")


class SyncPreparedTests(unittest.TestCase):
    def test_native_owner_reuses_exact_bytes_on_sync_requests(self):
        body = multipart()
        with server(Handler) as (peer, url):
            with Client(profile=PROFILE, protocol="h1", context="raw") as client:
                for _ in range(2):
                    with client.request(
                        "POST",
                        url,
                        body=body,
                        headers=(("Content-Type", body.content_type),),
                    ) as response:
                        response.read(max_bytes=0)
            self.assertEqual([record[3] for record in peer.records], [MULTIPART] * 2)
