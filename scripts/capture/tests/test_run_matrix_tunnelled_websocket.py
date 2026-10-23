"""Tunnel route and origin protocol remain distinct capture jobs."""

import tempfile
import unittest
from pathlib import Path

from scripts.capture.run_matrix import CompletionRecords, ManifestError, expand_manifest


def capture(arguments):
    return {
        "tool": "tunnelled_websocket",
        "browsers": ["firefox"],
        "scenarios": ["accept"],
        "output_dir": "fixtures/{browser}",
        "args": arguments,
    }


def manifest(*captures):
    return {
        "operating_system": "Test host",
        "repeat": 1,
        "browsers": {"firefox": {"path": "owned-firefox", "version": "158.0"}},
        "captures": list(captures),
    }


class TunnelledWebSocketManifestTests(unittest.TestCase):
    def test_http2_proxy_leg_has_an_independent_job_and_output(self):
        jobs = expand_manifest(
            manifest(
                capture(["--proxy=https", "--origin-alpn=h1"]),
                capture(["--proxy=https", "--proxy-alpn=h2", "--origin-alpn=h1"]),
                capture(["--proxy=https", "--proxy-alpn=h2"]),
            ),
            base=Path("owned"),
        )
        self.assertEqual(
            [job.outputs[0].name for job in jobs],
            [
                "https-h1-accept.txt",
                "https-h2-h1-accept.txt",
                "https-h2-negotiate-accept.txt",
            ],
        )
        self.assertEqual(
            [job.id for job in jobs],
            [
                "tunnelled_websocket/firefox/accept/https/h1",
                "tunnelled_websocket/firefox/accept/https-h2/h1",
                "tunnelled_websocket/firefox/accept/https-h2/negotiate",
            ],
        )
        with self.assertRaisesRegex(ManifestError, "appears twice"):
            expand_manifest(
                manifest(
                    capture(["--proxy=https"]),
                    capture(["--proxy=https", "--proxy-alpn=h1"]),
                ),
                base=Path("owned"),
            )

    def test_all_routes_and_origin_offers_have_distinct_jobs_and_outputs(self):
        selections = [
            (proxy, origin)
            for proxy in ("http", "https", "socks5")
            for origin in ("h1", "negotiate")
        ]
        jobs = expand_manifest(
            manifest(
                *(
                    capture(["--proxy", proxy, "--origin-alpn", origin])
                    for proxy, origin in selections
                )
            ),
            base=Path("owned"),
        )
        self.assertEqual(len(jobs), 6)
        self.assertEqual(len({job.id for job in jobs}), 6)
        self.assertEqual(len({job.outputs[0] for job in jobs}), 6)
        for job, (proxy, origin) in zip(jobs, selections, strict=True):
            self.assertEqual(
                job.id, f"tunnelled_websocket/firefox/accept/{proxy}/{origin}"
            )
            self.assertEqual(job.outputs[0].name, f"{proxy}-{origin}-accept.txt")
            command = job.command("owned-python")
            self.assertEqual(command[2], "scripts.capture.tunnelled_websocket")
            self.assertEqual(command[command.index("--proxy") + 1], proxy)
            self.assertEqual(command[command.index("--origin-alpn") + 1], origin)
            self.assertTrue(job.exclusive)

    def test_default_origin_offer_and_equals_arguments_use_canonical_identity(self):
        default = expand_manifest(
            manifest(capture(["--proxy=https"])), base=Path("owned")
        )[0]
        explicit = expand_manifest(
            manifest(capture(["--proxy", "https", "--origin-alpn=negotiate"])),
            base=Path("owned"),
        )[0]
        self.assertEqual(default.id, explicit.id)
        self.assertEqual(default.outputs, explicit.outputs)
        with self.assertRaisesRegex(ManifestError, "appears twice"):
            expand_manifest(
                manifest(
                    capture(["--proxy=https"]),
                    capture(["--proxy=https", "--origin-alpn=negotiate"]),
                ),
                base=Path("owned"),
            )

    def test_missing_unknown_and_repeated_route_options_fail_before_execution(self):
        for arguments in (
            [],
            ["--proxy"],
            ["--proxy=direct"],
            ["--proxy=http", "--origin-alpn=h3"],
            ["--proxy=http", "--origin-alpn="],
            ["--proxy=http", "--origin-alpn"],
            ["--proxy=http", "--proxy=socks5"],
            ["--proxy=http", "--origin-alpn=h1", "--origin-alpn=negotiate"],
            ["--proxy=http", "--prox=https"],
            ["--proxy=http", "--origin-alpn=h1", "--origin-a=negotiate"],
            ["--p", "http"],
            ["--proxy=http", "--proxy-alpn=h2"],
            ["--proxy=socks5", "--proxy-alpn=h2"],
            ["--proxy=https", "--proxy-alpn=h3"],
            ["--proxy=https", "--proxy-alpn=h1", "--proxy-alpn=h2"],
            ["--proxy=https", "--proxy-a=h2"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ManifestError):
                expand_manifest(manifest(capture(arguments)), base=Path("owned"))

    def test_completed_tunnel_route_does_not_skip_a_different_route_or_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            jobs = expand_manifest(
                manifest(
                    capture(["--proxy=http", "--origin-alpn=h1"]),
                    capture(["--proxy=https", "--origin-alpn=h1"]),
                    capture(["--proxy=http", "--origin-alpn=negotiate"]),
                ),
                base=base,
            )
            records = CompletionRecords(base / "completed")
            jobs[0].outputs[0].parent.mkdir(parents=True)
            jobs[0].outputs[0].write_bytes(b"format=owned-control\n")
            records.remember(jobs[0], shared_host=False, concurrency=1)
            self.assertIsNone(records.mismatch(jobs[0]))
            for job in jobs[1:]:
                self.assertEqual(records.mismatch(job), "no completion record")

    def test_secure_sse_protocol_job_identities_are_preserved(self):
        captures = []
        for protocol in ("h1", "h2", "h3"):
            item = capture(["--protocol", protocol])
            item.update(
                tool="sse_reconnect",
                scenarios=["reconnect-204"],
                output_dir=f"sse/{protocol}",
            )
            captures.append(item)
        jobs = expand_manifest(manifest(*captures), base=Path("owned"))
        self.assertEqual(
            [job.id for job in jobs],
            [f"sse_reconnect/firefox/reconnect-204/{p}" for p in ("h1", "h2", "h3")],
        )
