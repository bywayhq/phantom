import argparse
import contextlib
import io
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest import mock

from scripts.capture import cookie_crumbs

METADATA = cookie_crumbs.CaptureMetadata(
    "scripted", "1", "test", "127.0.0.1:0", "manual", "none"
)
INVALID = ("1\ninjected=true", "1\rignored=true", "1\t0", "1\x00", "1\x7f", "café")


class CookieMetadataTests(unittest.IsolatedAsyncioTestCase):
    def test_fixture_rejects_non_printable_metadata(self):
        for field in fields(METADATA):
            for value in INVALID:
                with (
                    self.subTest(field=field.name, value=repr(value)),
                    self.assertRaisesRegex(ValueError, field.name),
                ):
                    cookie_crumbs.fixture(
                        cookie_crumbs.SCENARIOS["h1"],
                        [],
                        replace(METADATA, **{field.name: value}),
                        4096,
                    )
        text = cookie_crumbs.fixture(cookie_crumbs.SCENARIOS["h1"], [], METADATA, 4096)
        for field in fields(METADATA):
            self.assertEqual(
                text.splitlines().count(
                    f"{field.name}={getattr(METADATA, field.name)}"
                ),
                1,
            )

    async def test_direct_capture_rejects_bad_metadata_before_acquisition(self):
        with (
            mock.patch.object(
                cookie_crumbs,
                "generate_certificate",
                side_effect=AssertionError("invalid metadata reached acquisition"),
            ) as certificate,
            mock.patch.object(Path, "mkdir") as mkdir,
            mock.patch.object(cookie_crumbs, "BrowserDriver") as browser,
        ):
            for field in ("client", "client_version", "operating_system"):
                for value in INVALID:
                    args = argparse.Namespace(
                        client="scripted",
                        client_version="1",
                        operating_system="test",
                        repeat=1,
                        run_timeout=1.0,
                        observation=0.0,
                        scenario=["h1"],
                        browser="manual",
                        listen="127.0.0.1",
                    )
                    setattr(args, field, value)
                    with (
                        self.subTest(field=field, value=repr(value)),
                        self.assertRaisesRegex(ValueError, field),
                    ):
                        await cookie_crumbs.capture(args)
            certificate.assert_not_called()
            mkdir.assert_not_called()
            browser.assert_not_called()

    def test_cli_rejects_bad_metadata_before_capture_or_package_probes(self):
        base = [
            "--browser",
            "manual",
            "--client-version",
            "1",
            "--operating-system",
            "test",
            "--output-dir",
            "unused-output",
        ]
        with (
            mock.patch.object(cookie_crumbs, "capture") as capture,
            mock.patch.object(
                cookie_crumbs.metadata,
                "version",
                side_effect=lambda name: cookie_crumbs.SUPPORTED[name],
            ) as version,
            mock.patch.object(
                cookie_crumbs.asyncio, "run", side_effect=lambda op: op.close()
            ),
        ):
            for field in ("client", "client-version", "operating-system"):
                for value in INVALID:
                    with self.subTest(field=field, value=repr(value)):
                        with (
                            contextlib.redirect_stderr(io.StringIO()),
                            self.assertRaises(SystemExit) as raised,
                        ):
                            cookie_crumbs.main([*base, f"--{field}", value])
                        self.assertEqual(raised.exception.code, 2)
            capture.assert_not_called()
            version.assert_not_called()


if __name__ == "__main__":
    unittest.main()
