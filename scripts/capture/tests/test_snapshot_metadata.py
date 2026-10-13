import argparse
import asyncio
import contextlib
import io
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest import mock

from scripts.capture import snapshot
from scripts.capture.cookie_crumbs import CaptureMetadata

METADATA = CaptureMetadata(
    client="scripted",
    client_version="1.0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
INVALID = ("1\ninjected=true", "1\rignored=true", "1\t0", "1\x00", "1\x7f", "café")


class SnapshotMetadataTests(unittest.IsolatedAsyncioTestCase):
    def test_render_rejects_non_printable_metadata_before_fixture_publication(self):
        run = snapshot.SnapshotRun("metadata", 1, 2, 0.0)
        for field in fields(METADATA):
            for value in INVALID:
                metadata = replace(METADATA, **{field.name: value})
                with self.subTest(field=field.name, value=repr(value)):
                    with self.assertRaises(ValueError) as raised:
                        snapshot.render_snapshot(run, metadata)
                    self.assertIn(field.name, str(raised.exception))

        text = snapshot.render_snapshot(run, METADATA)
        for field in fields(METADATA):
            self.assertEqual(
                text.splitlines().count(
                    f"{field.name}={getattr(METADATA, field.name)}"
                ),
                1,
            )

    async def test_direct_capture_rejects_bad_metadata_before_acquisition(self):
        loop = asyncio.get_running_loop()
        original_handler = loop.get_exception_handler()
        with (
            mock.patch.object(
                snapshot,
                "generate_certificate",
                side_effect=AssertionError(
                    "bad metadata reached certificate generation"
                ),
            ) as certificate,
            mock.patch.object(
                snapshot,
                "serving",
                side_effect=AssertionError("bad metadata reached listener acquisition"),
            ) as serving,
            mock.patch.object(snapshot, "BrowserDriver") as browser,
        ):
            for field in ("client_version", "operating_system"):
                for value in INVALID:
                    args = argparse.Namespace(
                        repeat=1,
                        run_timeout=1.0,
                        observation=0.0,
                        client_version="1.0",
                        operating_system="test",
                    )
                    setattr(args, field, value)
                    with self.subTest(field=field, value=repr(value)):
                        with self.assertRaises(ValueError) as raised:
                            await snapshot.capture(args)
                        self.assertIn(field, str(raised.exception))
                        with self.assertRaises(ValueError) as raised:
                            await snapshot.capture_run(args, None)
                        self.assertIn(field, str(raised.exception))
                        self.assertIs(loop.get_exception_handler(), original_handler)

            certificate.assert_not_called()
            serving.assert_not_called()
            browser.assert_not_called()

    def test_cli_rejects_bad_metadata_before_capture_or_package_probes(self):
        base = [
            "--browser",
            "chrome",
            "--browser-path",
            "unused-browser",
            "--client-version",
            "1.0",
            "--operating-system",
            "test",
            "--output-dir",
            "unused-output",
        ]
        with (
            mock.patch.object(snapshot, "capture") as capture,
            mock.patch.object(snapshot.metadata, "version") as version,
            mock.patch.object(Path, "mkdir") as mkdir,
        ):
            for field in ("client-version", "operating-system"):
                for value in INVALID:
                    stderr = io.StringIO()
                    with (
                        self.subTest(field=field, value=repr(value)),
                        contextlib.redirect_stderr(stderr),
                    ):
                        with self.assertRaises(SystemExit) as raised:
                            snapshot.main([*base, f"--{field}", value])
                        self.assertEqual(raised.exception.code, 2)
                        self.assertIn(field.replace("-", "_"), stderr.getvalue())

            capture.assert_not_called()
            version.assert_not_called()
            mkdir.assert_not_called()
